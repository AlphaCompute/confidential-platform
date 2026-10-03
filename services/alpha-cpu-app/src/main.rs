//! Thin entrypoint: wait for the runtime to attest, take this Instance's identity, then serve
//! over TLS on `:8443` until SIGTERM, refreshing the leaf every five minutes. A refresh that
//! keeps failing for ten minutes ends the process: the runtime is gone when the Revision is
//! revoked, and the Endpoint must not go on presenting a leaf it can no longer renew. Every error
//! is a non-zero exit.

use std::error::Error;
use std::sync::Arc;

use alpha_client::runtime::{RuntimeSocket, refresh_forever};
use alpha_client::tls::InstanceCert;
use alpha_cpu_app::{AppState, router};
use tokio::net::TcpListener;
use tokio::signal::unix::{SignalKind, signal};

const PORT: u16 = 8443;

#[tokio::main]
async fn main() {
    let code = match run().await {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("alpha-cpu-app: {e}");
            1
        }
    };
    std::process::exit(code);
}

async fn run() -> Result<(), Box<dyn Error>> {
    let runtime = RuntimeSocket::default();
    runtime.wait_attested().await;
    let identity = runtime.identity().await?;
    eprintln!(
        "alpha-cpu-app: attested as app {} revision {}",
        identity.app_id, identity.compose_hash
    );
    let cert = Arc::new(InstanceCert::new(&identity)?);
    let tls_config = alpha_client::tls::server_config(cert.clone())?;
    let app = router(Arc::new(AppState::new(RuntimeSocket::default(), &identity)));

    let listener = TcpListener::bind(("0.0.0.0", PORT)).await?;
    let mut term = signal(SignalKind::terminate())?;
    let mut outcome = Ok(());
    alpha_client::tls::serve(listener, tls_config, app, async {
        tokio::select! {
            _ = term.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
            failed = refresh_forever(|| refresh(&runtime, &cert)) => outcome = Err(failed.into()),
        }
    })
    .await;
    outcome
}

async fn refresh(runtime: &RuntimeSocket, cert: &InstanceCert) -> Result<(), alpha_client::Error> {
    runtime.identity().await.and_then(|i| cert.replace(&i))
}
