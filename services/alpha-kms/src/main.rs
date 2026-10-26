use std::str::FromStr;
use std::sync::Arc;
use std::time::SystemTime;

use alpha_kms::{CollateralSource, Config, Node, node, platform, tls};
use alpha_tsm::Substrate;
use sqlx::ConnectOptions;
use sqlx::postgres::{PgAuthMethod, PgChannelBinding, PgConnectOptions, PgPoolOptions};
use tokio::net::TcpListener;

const LISTEN: &str = "0.0.0.0:8443";

// ponytail: JSON lines on stderr, which a Kata pod's policy keeps from the host, and metrics on
// loopback only, which nothing outside a Kata pod reaches; the upgrade is a collector App that
// scrapes and receives both with runtime_pubkey_sha256 added.
#[tokio::main]
async fn main() {
    if let Err(step) = run().await {
        alpha_client::error!("exit", step = step);
        std::process::exit(1);
    }
}

/// The failed step; its error text may carry a peer's answer, so it stays out of the line.
async fn run() -> Result<(), &'static str> {
    let url = alpha_kms::env("ALPHACOMPUTE_DATABASE_URL").map_err(|_| "config")?;
    let options = PgConnectOptions::from_str(&url).map_err(|_| "config")?;
    if std::env::args().nth(1).as_deref() == Some("migrate") {
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .map_err(|_| "database")?;
        alpha_kms::migrate(&pool).await.map_err(|_| "migrate")?;
        return Ok(());
    }
    let release_keys = alpha_channel::platform::release_keys().map_err(|_| "release_keys")?;
    let config = Config::from_env().map_err(|_| "config")?;
    let pool_options = PgPoolOptions::new().max_connections(8);
    let pool = match config.substrate {
        Substrate::Kata => {
            check_kata_database(&options).map_err(|_| "config")?;
            pool_options.connect_lazy_with(options)
        }
        Substrate::Dstack => pool_options
            .connect_with(options)
            .await
            .map_err(|_| "database")?,
    };
    let revision = match config.substrate {
        Substrate::Dstack => {
            let event_log = alpha_tsm::event_log().map_err(|_| "event_log")?;
            alpha_attest::event_log_compose_hash(&event_log).ok_or("event_log")?
        }
        Substrate::Kata => alpha_tsm::init_data().map_err(|_| "init_data")?,
    };
    let node = Node::new(
        pool,
        config,
        Arc::new(SystemTime::now),
        CollateralSource::Pccs(alpha_kms::env("ALPHACOMPUTE_PCCS_URL").map_err(|_| "config")?),
        alpha_kms::random().map_err(|_| "random")?,
        revision,
        release_keys,
    )
    .map_err(|_| "node")?;
    platform::start(&node).await;
    tokio::spawn(platform::run(node.clone()));
    start_phase(&node).await;

    let listener = TcpListener::bind(LISTEN).await.map_err(|_| "bind")?;
    let app = alpha_client::metrics::serve(alpha_kms::router(node.clone()))
        .await
        .map_err(|_| "metrics")?;
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|_| "signal")?;
    let shutdown = async move {
        tokio::select! {
            _ = term.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
    };
    let config = tls::server_config(node.server_cert.clone()).map_err(|_| "tls")?;
    alpha_client::tls::serve(listener, config, app, shutdown).await;
    Ok(())
}

async fn start_phase(node: &Arc<Node>) {
    #[cfg(feature = "dev-root")]
    if let Some(root) = &node.config.dev_root_kek {
        match node::serve_from_root(node, root).await {
            Ok(()) => return,
            Err(e) => alpha_client::error!("dev_root_failed", error = e.code),
        }
    }
    match node::try_join(node).await {
        Ok(()) => alpha_client::info!("joined"),
        Err(e) => alpha_client::warn!("sealed", error = e.code),
    }
}

/// A Kata pod's env and mounts are readable by the host, so the effective password, from the
/// URL, `?password=`, `PGPASSWORD` or a pgpass file, must be absent. `require_auth` keeps
/// cleartext and MD5 refused should `channel_binding` ever stop implying it.
fn check_kata_database(options: &PgConnectOptions) -> Result<(), String> {
    if options.to_url_lossy().password().is_some() {
        return Err(
            "a Kata node takes its database password only from bootstrap, unseal or \
                    join, yet ALPHACOMPUTE_DATABASE_URL, PGPASSWORD or a pgpass file gives one"
                .into(),
        );
    }
    if options.get_channel_binding() == PgChannelBinding::Require
        && options.get_require_auth() == Some(&[PgAuthMethod::ScramSha256][..])
    {
        return Ok(());
    }
    Err("ALPHACOMPUTE_DATABASE_URL of a Kata node must carry \
         channel_binding=require&require_auth=scram-sha-256"
        .into())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn a_kata_url_must_bind_scram_to_the_tls_connection_and_carry_no_password() {
        let check = |query: &str| {
            let url = format!("postgres://alpha_kms_node@pg/alpha?sslmode=require{query}");
            check_kata_database(&PgConnectOptions::from_str(&url).unwrap())
        };
        assert!(check("&channel_binding=require&require_auth=scram-sha-256").is_ok());
        assert!(check("").is_err());
        assert!(check("&channel_binding=require").is_err());
        assert!(check("&require_auth=scram-sha-256").is_err());
        assert!(check("&channel_binding=require&require_auth=scram-sha-256,md5").is_err());
        let bound = "&channel_binding=require&require_auth=scram-sha-256";
        assert!(check(&format!("{bound}&password=x")).is_err());
        let userinfo = format!("postgres://alpha_kms_node:x@pg/alpha?sslmode=require{bound}");
        assert!(check_kata_database(&PgConnectOptions::from_str(&userinfo).unwrap()).is_err());
    }
}
