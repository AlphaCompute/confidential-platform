use std::str::FromStr;
use std::sync::Arc;
use std::time::SystemTime;

use alpha_kms::{CollateralSource, Config, Node, NodeGuest, db_auth, node, platform, tls};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
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
    // D10 (draft, `alpha_kms::db_auth`): `ALPHACOMPUTE_DATABASE_AUTH=client-cert` connects with a
    // client certificate from a CA derived from the db-volume key, so no password exists; `url`
    // (the default) connects with ALPHACOMPUTE_DATABASE_URL as given, as the prototype nodes do.
    // A Kata node refuses a URL with a password either way: its measured env is public (#87).
    // The rows are sealed either way (`store`), so this decides who may connect, not who may read.
    let url = alpha_kms::env("ALPHACOMPUTE_DATABASE_URL")?;
    let auth = db_auth::mode(std::env::var(db_auth::MODE_ENV).ok().as_deref())?;
    let quote_source =
        alpha_kms::quote_source(std::env::var("ALPHACOMPUTE_QUOTE_SOURCE").ok().as_deref())?;
    db_auth::check_url(&url, auth, quote_source.is_some())?;
    let connect = PgConnectOptions::from_str(&url).map_err(|e| format!("database: {e}"))?;
    let options = PgPoolOptions::new()
        .max_connections(8)
        .acquire_timeout(std::time::Duration::from_secs(10));
    if std::env::args().nth(1).as_deref() == Some("migrate") {
        if auth == db_auth::Mode::ClientCert {
            // TODO(draft): a migration needs a connection before any node holds the volume key.
            // QUESTION(PRD-05 Q49): who runs migrations against the client-cert Postgres? Proposed:
            // a serving node, at start_serving, under an advisory lock, so no separate credential
            // exists; until then this refuses.
            return Err(
                "migrate: client-cert mode has no database credential before unseal (D10 draft)"
                    .into(),
            );
        }
        let pool = options
            .connect_with(connect)
            .await
            .map_err(|e| format!("database: {e}"))?;
        alpha_kms::migrate(&pool)
            .await
            .map_err(|e| format!("migrate: {e}"))?;
        return Ok(());
    }
    // Lazy: with M2(a) the database's volume opens only after custodians unseal this node and it
    // hands the Postgres pod its key, so the node starts, and answers the Node API, without it.
    let pool = options.connect_lazy_with(connect.clone());
    let release_key = alpha_core::hex_bytes::<32>(RELEASE_KEY_HEX.trim())
        .and_then(|b| ed25519_dalek::VerifyingKey::from_bytes(&b).ok())
        .ok_or("release-key.pub is not an Ed25519 public key")?;
    let guest = match quote_source {
        None => {
            NodeGuest::prototype(alpha_tsm::event_log().map_err(|e| format!("event log: {e}"))?)?
        }
        Some(source) => {
            let path = std::path::Path::new(alpha_tsm::coco::INITDATA_PATH);
            let initdata =
                alpha_tsm::coco::initdata(path).map_err(|e| format!("init-data: {e}"))?;
            NodeGuest::coco(source, initdata)?
        }
    };
    let node = Node::new(
        pool,
        Config::from_env()?,
        Arc::new(SystemTime::now),
        CollateralSource::Pccs(alpha_kms::env("ALPHACOMPUTE_PCCS_URL")?),
        alpha_kms::random().map_err(|e| e.message)?,
        guest,
        release_key,
    )?;
    if auth == db_auth::Mode::ClientCert {
        db_auth::enable(&node, connect);
    }
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
        match alpha_kms::db_volume::open_database(node, root).await {
            Ok(keys) => {
                if let Err(e) = node.start_serving(keys).await {
                    eprintln!("dev root: {}", e.message);
                }
                return;
            }
            Err(e) => eprintln!("dev root: {}", e.message),
        }
    }
    match node::try_join(node).await {
        Ok(()) => {
            eprintln!("joined; serving");
            node.maintain().await;
        }
        Err(e) => eprintln!("sealed: {}; waiting for unseal", e.message),
    }
}
