use std::sync::Arc;
use std::time::SystemTime;

use alpha_runtime::{Config, Error, Exit, Runtime, SOCKET_PATH};
use p256::ecdsa::SigningKey;
use tokio::net::UnixListener;

// ponytail: eprintln and no metrics, like alpha-kms; the external receiver with
// runtime_pubkey_sha256 on every line is chosen at the first deploy.
#[tokio::main]
async fn main() {
    let code = match run().await {
        Ok(exit) => exit.code(),
        Err(e) => {
            eprintln!("alpha-runtime: {e}");
            e.exit_code()
        }
    };
    std::process::exit(code);
}

async fn run() -> Result<Exit, Error> {
    let config = Config::from_env()?;
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| Error::Key(format!("rng: {e}")))?;
    let key = SigningKey::from_bytes(&seed.into()).map_err(|e| Error::Key(e.to_string()))?;
    let app_compose =
        alpha_tsm::app_compose().map_err(|e| Error::Evidence(format!("app_compose: {e}")))?;
    let runtime = Runtime::new(
        config,
        &key,
        Arc::new(SystemTime::now),
        alpha_runtime::tsm_evidence(),
        alpha_client::system_time_provider(),
        app_compose,
    )?;
    let attested = runtime.attest().await?;
    eprintln!(
        "alpha-runtime: attested as app {} revision {} until {}",
        attested.identity.app_id,
        attested.identity.compose_hash,
        alpha_runtime::socket::rfc3339(attested.not_after)
    );

    let socket = |e: std::io::Error| Error::Socket(format!("{SOCKET_PATH}: {e}"));
    match std::fs::remove_file(SOCKET_PATH) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(socket(e)),
    }
    let listener = UnixListener::bind(SOCKET_PATH).map_err(socket)?;
    // Connecting needs write permission on the socket and tenant services run as any uid;
    // the volume mount, not the mode, decides who reaches it.
    std::fs::set_permissions(
        SOCKET_PATH,
        std::os::unix::fs::PermissionsExt::from_mode(0o666),
    )
    .map_err(socket)?;
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|e| Error::Socket(format!("SIGTERM handler: {e}")))?;
    let shutdown = async move {
        tokio::select! {
            _ = term.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
    };
    let exit = runtime.run(listener, shutdown).await;
    let _ = std::fs::remove_file(SOCKET_PATH);
    Ok(exit)
}
