//! Thin entrypoint: attest, read this Instance's identity and its Secrets (the provider key only
//! when some model goes to the external provider), then serve the `/v1` routes over TLS on
//! `:8443` until SIGTERM, refreshing the leaf and the Secrets every five minutes. A failed read of the Secrets is retried; a lost identity ends the process: the
//! runtime is gone when the Revision is revoked, and the front must not go on serving with what
//! it read before. All logic lives in `run`, which maps every error to a non-zero exit and never
//! panics.

use std::sync::Arc;

use alpha_client::runtime::{RuntimeSocket, refresh_forever};
use alpha_client::tls::{InstanceCert, kms_ca, serve, server_config};
use alpha_inference::{
    AppState, COMPLETION_TIMEOUT, Config, Error, Secrets, Upstream, own, router,
};
use tokio::net::TcpListener;
use zeroize::Zeroizing;

const PORT: u16 = 8443;

#[tokio::main]
async fn main() {
    let code = match run().await {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("alpha-inference: {e}");
            1
        }
    };
    std::process::exit(code);
}

async fn read_secrets(runtime: &RuntimeSocket, external: bool) -> Result<Secrets, Error> {
    let provider_key = if external {
        let key = runtime
            .secret("redpill-api-key")
            .await
            .map_err(|e| Error::internal(format!("secret redpill-api-key: {e}")))?;
        Some(Zeroizing::new(String::from_utf8(key.to_vec()).map_err(
            |_| Error::internal("redpill-api-key is not utf8"),
        )?))
    } else {
        None
    };
    let caller_bearer = runtime
        .secret("caller-bearer")
        .await
        .map_err(|e| Error::internal(format!("secret caller-bearer: {e}")))?;
    Ok(Secrets {
        provider_key,
        caller_bearer: Zeroizing::new(caller_bearer.to_vec()),
    })
}

async fn run() -> Result<(), Error> {
    let config = Config::from_env()?;
    let runtime = RuntimeSocket::default();

    runtime.wait_attested().await;
    let identity = runtime
        .identity()
        .await
        .map_err(|e| Error::internal(format!("identity: {e}")))?;
    eprintln!(
        "alpha-inference: attested as app {} revision {}",
        identity.app_id, identity.compose_hash
    );
    let cert =
        Arc::new(InstanceCert::new(&identity).map_err(|e| Error::internal(format!("tls: {e}")))?);
    let tls_config =
        server_config(cert.clone()).map_err(|e| Error::internal(format!("tls: {e}")))?;

    let secrets = read_secrets(&runtime, config.external.is_some()).await?;
    let upstream = Upstream::new(&config)?;
    let kms_ca = kms_ca(&identity).map_err(|e| Error::internal(format!("kms ca: {e}")))?;
    let own = own::servers(&config.own, &kms_ca, cert.clone(), COMPLETION_TIMEOUT)?;
    let state = Arc::new(AppState {
        config,
        secrets: parking_lot::RwLock::new(secrets),
        upstream,
        own,
    });
    let app = router(state.clone());

    let listener = TcpListener::bind(("0.0.0.0", PORT))
        .await
        .map_err(|e| Error::internal(format!("bind :{PORT}: {e}")))?;

    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|e| Error::internal(format!("sigterm: {e}")))?;
    let mut outcome = Ok(());
    serve(listener, tls_config, app, async {
        tokio::select! {
            _ = term.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
            failed = refresh_forever(&runtime, &cert, |_| refresh(&runtime, &state)) => {
                outcome = Err(Error::internal(format!("refresh: {failed}")));
            }
        }
    })
    .await;
    outcome
}

async fn refresh(runtime: &RuntimeSocket, state: &AppState) -> Result<(), Error> {
    *state.secrets.write() = read_secrets(runtime, state.config.external.is_some()).await?;
    Ok(())
}
