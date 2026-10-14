use std::str::FromStr;
use std::sync::Arc;
use std::time::SystemTime;

use alpha_kms::{CollateralSource, Config, Node, node, platform, tls};
use alpha_tsm::Substrate;
use sqlx::ConnectOptions;
use sqlx::postgres::{PgAuthMethod, PgChannelBinding, PgConnectOptions, PgPoolOptions};
use tokio::net::TcpListener;

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
    let release_keys = alpha_channel::platform::release_keys().map_err(|e| e.to_string())?;
    let config = Config::from_env()?;
    let pool_options = PgPoolOptions::new().max_connections(8);
    let pool = match config.substrate {
        Substrate::Kata => {
            check_kata_database(&options)?;
            pool_options.connect_lazy_with(options)
        }
        Substrate::Dstack => pool_options
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
        release_keys,
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
