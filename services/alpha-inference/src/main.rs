//! Thin entrypoint: attest, read this Instance's identity and both Secrets, then serve the
//! `/v1` routes over TLS on `:8443` until SIGTERM, refreshing the leaf and both Secrets every
//! five minutes. A refresh that fails ends the process: the runtime removes its socket when the
//! Revision is revoked, and the front must not go on serving with what it read before. All
//! logic lives in `run`, which maps every error to a non-zero exit and never panics.

use std::sync::Arc;
use std::time::Duration;

use alpha_client::runtime::RuntimeSocket;
use alpha_client::tls::{InstanceCert, serve, server_config};
use alpha_inference::{AppState, Config, Error, Secrets, Upstream, router};
use tokio::net::TcpListener;
use zeroize::Zeroizing;

const PORT: u16 = 8443;
/// Every five minutes: a renewed leaf is served and rotated Secrets take effect, without a
/// restart.
const RENEW_INTERVAL: Duration = Duration::from_secs(300);

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

async fn read_secrets(runtime: &RuntimeSocket) -> Result<Secrets, Error> {
    let provider_key = runtime
        .secret("redpill-api-key")
        .await
        .map_err(|e| Error::internal(format!("secret redpill-api-key: {e}")))?;
    let caller_bearer = runtime
        .secret("caller-bearer")
        .await
        .map_err(|e| Error::internal(format!("secret caller-bearer: {e}")))?;
    Ok(Secrets {
        provider_key: Zeroizing::new(
            String::from_utf8(provider_key.to_vec())
                .map_err(|_| Error::internal("redpill-api-key is not utf8"))?,
        ),
        caller_bearer: Zeroizing::new(caller_bearer.to_vec()),
    })
}

async fn run() -> Result<(), Error> {
    let config = Config::from_env()?;
    let runtime = RuntimeSocket::default();

    loop {
        match runtime.healthz().await {
            Ok(health) if health.attested => break,
            _ => tokio::time::sleep(Duration::from_secs(2)).await,
        }
    }
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

    let secrets = read_secrets(&runtime).await?;
    let upstream = Upstream::new(&config)?;
    let state = Arc::new(AppState {
        config,
        secrets: parking_lot::RwLock::new(secrets),
        upstream,
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
            failed = renew_forever(&runtime, &cert, &state) => outcome = Err(failed),
        }
    })
    .await;
    outcome
}

async fn renew_forever(runtime: &RuntimeSocket, cert: &InstanceCert, state: &AppState) -> Error {
    loop {
        tokio::time::sleep(RENEW_INTERVAL).await;
        let renewed = async {
            let identity = runtime
                .identity()
                .await
                .map_err(|e| Error::internal(format!("renew identity: {e}")))?;
            cert.replace(&identity)
                .map_err(|e| Error::internal(format!("renew tls: {e}")))?;
            *state.secrets.write() = read_secrets(runtime).await?;
            Ok::<(), Error>(())
        };
        if let Err(e) = renewed.await {
            return e;
        }
    }
}
