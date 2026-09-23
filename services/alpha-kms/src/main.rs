use std::sync::Arc;
use std::time::SystemTime;

use alpha_kms::{CollateralSource, Config, Node, node, platform, tls};
use sqlx::postgres::PgPoolOptions;
use tokio::net::TcpListener;

/// The release key's public half; the private half is held by a person, never by CI.
const RELEASE_KEY_HEX: &str = include_str!("../release-key.pub");

const LISTEN: &str = "0.0.0.0:8443";

// ponytail: eprintln and no metrics; the external log/metrics receiver with
// runtime_pubkey_sha256 on every line is chosen at the first deploy.
#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("alpha-kms: {e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(&alpha_kms::env("ALPHACOMPUTE_DATABASE_URL")?)
        .await
        .map_err(|e| format!("database: {e}"))?;
    if std::env::args().nth(1).as_deref() == Some("migrate") {
        alpha_kms::migrate(&pool)
            .await
            .map_err(|e| format!("migrate: {e}"))?;
        return Ok(());
    }
    let release_key = alpha_core::hex_bytes::<32>(RELEASE_KEY_HEX.trim())
        .and_then(|b| ed25519_dalek::VerifyingKey::from_bytes(&b).ok())
        .ok_or("release-key.pub is not an Ed25519 public key")?;
    let event_log = alpha_tsm::event_log().map_err(|e| format!("event log: {e}"))?;
    let node = Node::new(
        pool,
        Config::from_env()?,
        Arc::new(SystemTime::now),
        CollateralSource::Pccs(alpha_kms::env("ALPHACOMPUTE_PCCS_URL")?),
        alpha_kms::random().map_err(|e| e.message)?,
        event_log,
        release_key,
    )?;
    platform::start(&node).await;
    tokio::spawn(platform::run(node.clone()));
    start_phase(&node).await;

    let listener = TcpListener::bind(LISTEN)
        .await
        .map_err(|e| format!("bind {LISTEN}: {e}"))?;
    let app = alpha_kms::router(node.clone());
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|e| format!("SIGTERM handler: {e}"))?;
    let shutdown = async move {
        tokio::select! {
            _ = term.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
    };
    let config = tls::server_config(node.server_cert.clone()).map_err(|e| e.message)?;
    alpha_client::tls::serve(listener, config, app, shutdown).await;
    Ok(())
}

async fn start_phase(node: &Arc<Node>) {
    #[cfg(feature = "dev-root")]
    if let Some(root) = &node.config.dev_root_kek {
        match node::unwrap_intermediates(node, root).await {
            Ok(keys) => {
                if let Err(e) = node.start_serving(keys) {
                    eprintln!("dev root: {}", e.message);
                }
                return;
            }
            Err(e) => eprintln!("dev root: {}", e.message),
        }
    }
    match node::try_join(node).await {
        Ok(()) => eprintln!("joined; serving"),
        Err(e) => eprintln!("sealed: {}; waiting for unseal", e.message),
    }
}
