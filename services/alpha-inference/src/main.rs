//! Thin entrypoint: attest, read this Instance's identity and its Secrets — the caller bearer,
//! and the credential of each upstream kind this Revision uses — then serve the `/v1` routes
//! over TLS on `:8443` until SIGTERM, refreshing the leaf and the Secrets every five minutes. A failed read of the Secrets is retried; a lost identity ends the process: the
//! runtime is gone when the Revision is revoked, and the front must not go on serving with what
//! it read before. All logic lives in `run`, which maps every error to a non-zero exit and never
//! panics.

use std::collections::BTreeMap;
use std::sync::Arc;

use alpha_client::runtime::RuntimeIdentity;
use alpha_client::runtime::{RuntimeSocket, refresh_forever};
use alpha_client::tls::{InstanceCert, serve, server_config};
use alpha_inference::{AppState, Config, Error, Secrets, Upstream, guard, own, router};
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

async fn read_text(runtime: &RuntimeSocket, name: &str) -> Result<Zeroizing<String>, Error> {
    let value = runtime
        .secret(name)
        .await
        .map_err(|e| Error::internal(format!("secret {name}: {e}")))?;
    String::from_utf8(value.to_vec())
        .map(Zeroizing::new)
        .map_err(|_| Error::internal(format!("{name} is not utf8")))
}

/// Reads only the Secrets this Revision uses: the external provider's key when some model is
/// not ours, and each of our model servers' own bearer, under the name its entry gives.
async fn read_secrets(runtime: &RuntimeSocket, config: &Config) -> Result<Secrets, Error> {
    let provider_key = if config.external_models().is_empty() {
        Zeroizing::new(String::new())
    } else {
        read_text(runtime, "redpill-api-key").await?
    };
    let mut model_server_bearers = BTreeMap::new();
    for (model, server) in &config.model_servers {
        model_server_bearers.insert(model.clone(), read_text(runtime, &server.bearer).await?);
    }
    let caller_bearer = runtime
        .secret("caller-bearer")
        .await
        .map_err(|e| Error::internal(format!("secret caller-bearer: {e}")))?;
    let judge_bearer = runtime
        .secret("judge-bearer")
        .await
        .map_err(|e| Error::internal(format!("secret judge-bearer: {e}")))?;
    // A judge bearer that is empty or equal to the members' would let a member skip moderation.
    if judge_bearer.is_empty() || judge_bearer.as_slice() == caller_bearer.as_slice() {
        return Err(Error::internal(
            "judge-bearer must be set and differ from caller-bearer",
        ));
    }
    Ok(Secrets {
        provider_key,
        caller_bearer: Zeroizing::new(caller_bearer.to_vec()),
        model_server_bearers,
        judge_bearer: Zeroizing::new(judge_bearer.to_vec()),
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

    // Our model servers' CA is the last certificate of this Instance's own chain — the key
    // `alpha-runtime` already checked against the measured KMS CA.
    let kms_ca =
        alpha_client::tls::kms_ca(&identity).map_err(|e| Error::internal(format!("tls: {e}")))?;
    // Our leaf is the client certificate: a model server admits only the front's App.
    let own = own::Servers::new(&config.model_servers, &kms_ca, Some(&identity))?;
    let guard = guard::Guard::new(&config.guard, kms_ca, &identity)?;

    let secrets = read_secrets(&runtime, &config).await?;
    let upstream = Upstream::new(&config)?;
    let state = Arc::new(AppState {
        config,
        secrets: parking_lot::RwLock::new(secrets),
        upstream,
        own,
        guard,
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
            failed = refresh_forever(&runtime, &cert, |identity| refresh(&runtime, &state, identity)) => {
                outcome = Err(Error::internal(format!("refresh: {failed}")));
            }
        }
    })
    .await;
    outcome
}

async fn refresh(
    runtime: &RuntimeSocket,
    state: &AppState,
    identity: RuntimeIdentity,
) -> Result<(), Error> {
    // The judge and our model servers read this Instance's App from its leaf: present the
    // renewed one.
    state.guard.renew(&identity)?;
    state.own.renew(&identity)?;
    *state.secrets.write() = read_secrets(runtime, &state.config).await?;
    Ok(())
}
