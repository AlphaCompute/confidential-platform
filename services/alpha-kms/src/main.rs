use std::str::FromStr;
use std::sync::Arc;
use std::time::SystemTime;

use alpha_kms::{CollateralSource, Config, Node, node, platform, tls};
use alpha_tsm::Substrate;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use tokio::net::TcpListener;
use zeroize::Zeroizing;

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
    let url = alpha_kms::env("ALPHACOMPUTE_DATABASE_URL")?;
    let options = PgConnectOptions::from_str(&url).map_err(|e| format!("database: {e}"))?;
    if std::env::args().nth(1).as_deref() == Some("migrate") {
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .map_err(|e| format!("database: {e}"))?;
        alpha_kms::migrate(&pool)
            .await
            .map_err(|e| format!("migrate: {e}"))?;
        return Ok(());
    }
    let release_key = alpha_channel::platform::release_key().map_err(|e| e.to_string())?;
    let mut config = Config::from_env()?;
    config.database_password = url_password(&url)?;
    let pool_options = PgPoolOptions::new().max_connections(8);
    let pool = match (config.substrate, &config.database_password) {
        (Substrate::Kata, Some(_)) => {
            return Err(
                "ALPHACOMPUTE_DATABASE_URL carries a password, and a Kata pod's \
                        init-data is readable by the host"
                    .into(),
            );
        }
        (Substrate::Kata, None) => pool_options.connect_lazy_with(options),
        (Substrate::Dstack, _) => pool_options
            .connect_with(options)
            .await
            .map_err(|e| format!("database: {e}"))?,
    };
    let revision = match config.substrate {
        Substrate::Dstack => {
            let event_log = alpha_tsm::event_log().map_err(|e| format!("event log: {e}"))?;
            alpha_attest::event_log_compose_hash(&event_log)
                .ok_or("the event log carries no compose-hash event")?
        }
        Substrate::Kata => alpha_tsm::init_data().map_err(|e| format!("init-data: {e}"))?,
    };
    let node = Node::new(
        pool,
        config,
        Arc::new(SystemTime::now),
        CollateralSource::Pccs(alpha_kms::env("ALPHACOMPUTE_PCCS_URL")?),
        alpha_kms::random().map_err(|e| e.message)?,
        revision,
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
        match node::serve_from_root(node, root).await {
            Ok(()) => return,
            Err(e) => eprintln!("dev root: {}", e.message),
        }
    }
    match node::try_join(node).await {
        Ok(()) => eprintln!("joined; serving"),
        Err(e) => eprintln!("sealed: {}; waiting for unseal", e.message),
    }
}

/// The URL's password, percent-decoded as sqlx reads it: a dstack node hands it to a Kata joiner.
fn url_password(url: &str) -> Result<Option<Zeroizing<String>>, String> {
    let parsed = reqwest::Url::parse(url).map_err(|e| format!("ALPHACOMPUTE_DATABASE_URL: {e}"))?;
    parsed
        .password()
        .map(|p| {
            percent_encoding::percent_decode_str(p)
                .decode_utf8()
                .map(|p| Zeroizing::new(p.into_owned()))
                .map_err(|e| format!("ALPHACOMPUTE_DATABASE_URL password: {e}"))
        })
        .transpose()
}
