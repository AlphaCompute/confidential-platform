//! Thin entrypoint: attest, read this Instance's identity, its Secrets and the connectors key
//! from the runtime socket, migrate the broker's own database, then serve over TLS on `:8443`,
//! accepting client certificates that chain to the KMS CA, until SIGTERM, refreshing the leaf, the Secrets and the key every five minutes. A refresh
//! that fails ends the process: the runtime removes its socket when the Revision is revoked,
//! and the broker must not go on serving with what it read before.
//! `alpha-broker migrate` stops after the migration. Every error is a non-zero exit.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use alpha_broker::{AppState, Config, Error, Secrets, oauth, router, store};
use alpha_client::runtime::RuntimeSocket;
use alpha_client::tls::InstanceCert;
use sqlx::postgres::PgPoolOptions;
use tokio::net::TcpListener;
use zeroize::Zeroizing;

const PORT: u16 = 8443;
const RENEW_INTERVAL: Duration = Duration::from_secs(300);

#[tokio::main]
async fn main() {
    let code = match run().await {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("alpha-broker: {e}");
            1
        }
    };
    std::process::exit(code);
}

async fn secret(runtime: &RuntimeSocket, name: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
    runtime
        .secret(name)
        .await
        .map_err(|e| Error::internal(format!("secret {name}: {e}")))
}

fn utf8(name: &str, bytes: &[u8]) -> Result<Zeroizing<String>, Error> {
    String::from_utf8(bytes.to_vec())
        .map(Zeroizing::new)
        .map_err(|_| Error::internal(format!("secret {name} is not utf8")))
}

async fn read_secrets(runtime: &RuntimeSocket) -> Result<Secrets, Error> {
    let mut client_secrets = HashMap::new();
    for provider in oauth::PROVIDERS {
        let name = format!("{}-client-secret", provider.name);
        let value = utf8(&name, &secret(runtime, &name).await?)?;
        client_secrets.insert(provider.name, value);
    }
    let connect_bearer = secret(runtime, "connect-bearer").await?;
    let proxy_bearer = secret(runtime, "proxy-bearer").await?;
    let connectors_key = runtime
        .key("connectors")
        .await
        .map_err(|e| Error::internal(format!("key connectors: {e}")))?;
    Ok(Secrets {
        client_secrets,
        connect_bearer,
        proxy_bearer,
        connectors_key,
    })
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
        "alpha-broker: attested as app {} revision {}",
        identity.app_id, identity.compose_hash
    );

    let database_url = utf8("database-url", &secret(&runtime, "database-url").await?)?;
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(&database_url)
        .await
        .map_err(|e| Error::internal(format!("database: {e}")))?;
    store::migrate(&pool)
        .await
        .map_err(|e| Error::internal(format!("migrate: {e}")))?;
    if std::env::args().nth(1).as_deref() == Some("migrate") {
        return Ok(());
    }

    let cert =
        Arc::new(InstanceCert::new(&identity).map_err(|e| Error::internal(format!("tls: {e}")))?);
    let kms_ca =
        alpha_client::tls::kms_ca(&identity).map_err(|e| Error::internal(format!("tls: {e}")))?;
    let tls_config = alpha_client::tls::mtls_server_config(cert.clone(), kms_ca)
        .map_err(|e| Error::internal(format!("tls: {e}")))?;
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| Error::internal(format!("http client: {e}")))?;
    let state = Arc::new(AppState {
        config,
        secrets: parking_lot::RwLock::new(read_secrets(&runtime).await?),
        pool,
        http,
        tokens: Default::default(),
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
            *state.secrets.write() = read_secrets(runtime).await?;
            Ok::<(), Error>(())
        };
        if let Err(e) = renewed.await {
            return e;
        }
    }
}
