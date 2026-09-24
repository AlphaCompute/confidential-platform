//! Thin entrypoint: attest, read this Instance's identity and its Secret, then serve over TLS on
//! `:8443`, accepting client certificates that chain to the KMS CA, until SIGTERM, refreshing
//! the leaf and the bearer every five minutes. A refresh that fails ends the process: the
//! runtime removes its socket when the Revision is revoked, and the judge must not go on serving
//! with what it read before. Every error is a non-zero exit.

use std::sync::Arc;
use std::time::Duration;

use alpha_client::runtime::RuntimeSocket;
use alpha_client::tls::InstanceCert;
use alpha_guard::{AppState, Config, Error, front_client, router};
use tokio::net::TcpListener;
use zeroize::Zeroizing;

const PORT: u16 = 8443;
const RENEW_INTERVAL: Duration = Duration::from_secs(300);

#[tokio::main]
async fn main() {
    let code = match run().await {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("alpha-guard: {e}");
            1
        }
    };
    std::process::exit(code);
}

async fn read_bearer(runtime: &RuntimeSocket) -> Result<Zeroizing<String>, Error> {
    let bearer = runtime
        .secret("inference-bearer")
        .await
        .map_err(|e| Error::internal(format!("secret inference-bearer: {e}")))?;
    String::from_utf8(bearer.to_vec())
        .map(Zeroizing::new)
        .map_err(|_| Error::internal("inference-bearer is not utf8"))
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
        "alpha-guard: attested as app {} revision {}",
        identity.app_id, identity.compose_hash
    );
    let cert =
        Arc::new(InstanceCert::new(&identity).map_err(|e| Error::internal(format!("tls: {e}")))?);
    let kms_ca =
        alpha_client::tls::kms_ca(&identity).map_err(|e| Error::internal(format!("tls: {e}")))?;
    let tls_config = alpha_client::tls::mtls_server_config(cert.clone(), kms_ca.clone())
        .map_err(|e| Error::internal(format!("tls: {e}")))?;
    let front = front_client(kms_ca, config.inference_revisions.clone())?;

    let state = Arc::new(AppState {
        config,
        inference_bearer: parking_lot::RwLock::new(read_bearer(&runtime).await?),
        front,
    });
    let app = router(state.clone());

    let listener = TcpListener::bind(("0.0.0.0", PORT))
        .await
        .map_err(|e| Error::internal(format!("bind :{PORT}: {e}")))?;
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|e| Error::internal(format!("sigterm: {e}")))?;
    let mut outcome = Ok(());
    alpha_client::tls::serve(listener, tls_config, app, async {
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
            *state.inference_bearer.write() = read_bearer(runtime).await?;
            Ok::<(), Error>(())
        };
        if let Err(e) = renewed.await {
            return e;
        }
    }
}
