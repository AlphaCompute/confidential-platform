//! Thin entrypoint: attest, read this Instance's identity and its Secrets (the provider key only
//! when some model goes to the external provider), migrate the front's own database, then serve the `/v1` routes over TLS on
//! `:8443` until SIGTERM, refreshing the leaf and the Secrets every five minutes. A failed read of the Secrets is retried; a lost identity ends the process: the
//! runtime is gone when the Revision is revoked, and the front must not go on serving with what
//! it read before. `alpha-inference migrate` stops after the migration. All logic lives in `run`, which maps every error to a non-zero exit and never
//! panics.

use std::sync::Arc;
use std::time::Duration;

use alpha_client::runtime::{RuntimeSocket, refresh_forever};
use alpha_client::tls::{InstanceCert, kms_ca, serve, server_config};
use alpha_inference::{
    AppState, COMPLETION_TIMEOUT, Config, Error, Secrets, Upstream, keys, org_models, own, router,
};
use sqlx::postgres::PgPoolOptions;
use tokio::net::TcpListener;
use zeroize::Zeroizing;

const PORT: u16 = 8443;
/// Past this, a stalled database cannot hold the exit; the rows still unwritten are lost.
const USAGE_DRAIN: Duration = Duration::from_secs(10);

#[tokio::main]
async fn main() {
    let code = match run().await {
        Ok(()) => 0,
        Err(e) => {
            alpha_client::error!("exit", error = e.code());
            1
        }
    };
    std::process::exit(code);
}

async fn read_secrets(runtime: &RuntimeSocket, external: bool) -> Result<Secrets, Error> {
    let provider_key = if external {
        let key = runtime
            .secret("redpill-api-key")
            .await
            .map_err(|e| Error::internal(format!("secret redpill-api-key: {e}")))?;
        Some(Zeroizing::new(String::from_utf8(key.to_vec()).map_err(
            |_| Error::internal("redpill-api-key is not utf8"),
        )?))
    } else {
        None
    };
    Ok(Secrets {
        provider_key,
        caller_bearer: secret(runtime, "caller-bearer").await?,
        admin_bearer: secret(runtime, "admin-bearer").await?,
    })
}

async fn secret(runtime: &RuntimeSocket, name: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
    runtime
        .secret(name)
        .await
        .map_err(|e| Error::internal(format!("secret {name}: {e}")))
}

async fn run() -> Result<(), Error> {
    let config = Config::from_env()?;
    let runtime = RuntimeSocket::default();

    runtime.wait_attested().await;
    let identity = runtime
        .identity()
        .await
        .map_err(|e| Error::internal(format!("identity: {e}")))?;
    alpha_client::info!(
        "attested",
        app_id = identity.app_id,
        revision = &identity.compose_hash,
    );
    let database_url = String::from_utf8(secret(&runtime, "database-url").await?.to_vec())
        .map_err(|_| Error::internal("database-url is not utf8"))?;
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(&database_url)
        .await
        .map_err(|e| Error::internal(format!("database: {e}")))?;
    keys::migrate(&pool)
        .await
        .map_err(|e| Error::internal(format!("migrate: {e}")))?;
    if std::env::args().nth(1).as_deref() == Some("migrate") {
        return Ok(());
    }
    let keys_key = runtime
        .key(keys::KEY_PURPOSE)
        .await
        .map_err(|e| Error::internal(format!("key {}: {e}", keys::KEY_PURPOSE)))?;

    let cert =
        Arc::new(InstanceCert::new(&identity).map_err(|e| Error::internal(format!("tls: {e}")))?);
    let tls_config =
        server_config(cert.clone()).map_err(|e| Error::internal(format!("tls: {e}")))?;

    let secrets = read_secrets(&runtime, config.external.is_some()).await?;
    let upstream = Upstream::new(&config)?;
    let kms_ca = kms_ca(&identity).map_err(|e| Error::internal(format!("kms ca: {e}")))?;
    let own = own::servers(&config.own, &kms_ca, cert.clone(), COMPLETION_TIMEOUT)?;
    let org_clients = org_models::Clients::new(kms_ca, cert.clone());
    let state = Arc::new(AppState {
        config,
        secrets: parking_lot::RwLock::new(secrets),
        upstream,
        own,
        org_clients,
        pool,
        keys_key,
        usage_tasks: Default::default(),
    });
    let app = alpha_client::metrics::serve(router(state.clone()))
        .await
        .map_err(|e| Error::internal(format!("metrics: {e}")))?;

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
            failed = refresh_forever(&runtime, &cert, |_| refresh(&runtime, &state)) => {
                outcome = Err(Error::internal(format!("refresh: {failed}")));
            }
        }
    })
    .await;
    state.usage_tasks.close();
    if tokio::time::timeout(USAGE_DRAIN, state.usage_tasks.wait())
        .await
        .is_err()
    {
        alpha_client::error!("usage_rows_unwritten_at_exit");
    }
    outcome
}

async fn refresh(runtime: &RuntimeSocket, state: &AppState) -> Result<(), Error> {
    *state.secrets.write() = read_secrets(runtime, state.config.external.is_some()).await?;
    Ok(())
}
