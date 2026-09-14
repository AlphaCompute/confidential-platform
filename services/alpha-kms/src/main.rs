use std::sync::Arc;
use std::time::SystemTime;

use alpha_kms::{CollateralSource, Config, Node, NodeParams, node, platform, tls};
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
    let config = Config::from_env()?;
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(&config.database_url)
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
    let mut nonce_key = [0u8; 32];
    getrandom::fill(&mut nonce_key).map_err(|e| e.to_string())?;
    let event_log = alpha_tsm::event_log().map_err(|e| format!("event log: {e}"))?;
    let node = Node::new(NodeParams {
        pool,
        collateral: CollateralSource::Pccs(config.pccs_url.clone()),
        config,
        clock: Arc::new(SystemTime::now),
        nonce_key,
        event_log,
        release_key,
    })?;
    platform::start(&node).await;
    tokio::spawn(platform::run(node.clone()));
    start_phase(&node).await;

    let listener = TcpListener::bind(LISTEN)
        .await
        .map_err(|e| format!("bind {LISTEN}: {e}"))?;
    let app = alpha_kms::router(node.clone());
    let shutdown = async {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("SIGTERM handler");
        tokio::select! {
            _ = term.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
    };
    tls::serve(listener, node.server_cert.clone(), app, shutdown).await;
    Ok(())
}

#[cfg(feature = "dev-root")]
async fn start_phase(node: &Arc<Node>) {
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
    join_or_wait(node).await;
}

#[cfg(not(feature = "dev-root"))]
async fn start_phase(node: &Arc<Node>) {
    join_or_wait(node).await;
}

async fn join_or_wait(node: &Arc<Node>) {
    match node::try_join(node).await {
        Ok(()) => eprintln!("joined; serving"),
        Err(e) => eprintln!("sealed: {}; waiting for unseal", e.message),
    }
}
