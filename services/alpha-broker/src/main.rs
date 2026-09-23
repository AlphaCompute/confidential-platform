//! Thin entrypoint: attest, read this Instance's identity, its Secrets and the connectors key
//! from the runtime socket, migrate the broker's own database, then serve over TLS on `:8443`,
//! accepting client certificates that chain to the KMS CA, until SIGTERM, refreshing the leaf, the Secrets and the key every five minutes. A refresh
//! that fails ends the process: the runtime removes its socket when the Revision is revoked,
//! and the broker must not go on serving with what it read before.
//! `alpha-broker migrate` stops after the migration. Every error is a non-zero exit.

use std::sync::Arc;
use std::time::Duration;

use alpha_broker::{AppState, Config, Error, Secrets, router, store, tls};
use alpha_client::runtime::RuntimeSocket;
use alpha_client::tls::InstanceCert;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
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
    let google_client_secret = utf8(
        "google-client-secret",
        &secret(runtime, "google-client-secret").await?,
    )?;
    let connect_bearer = secret(runtime, "connect-bearer").await?;
    let proxy_bearer = secret(runtime, "proxy-bearer").await?;
    let connectors_key = runtime
        .key("connectors")
        .await
        .map_err(|e| Error::internal(format!("key connectors: {e}")))?;
    Ok(Secrets {
        google_client_secret,
        connect_bearer,
        proxy_bearer,
        connectors_key,
    })
}

async fn run() -> Result<(), Error> {
    let config = Config::from_env()?;
    let runtime = RuntimeSocket::default();

    loop {
        match runtime.healthz().await {
            Ok(health) if health.attested => break,
            _ => tokio::time::sleep(Duration::from_secs(2)).await,
        }
    }
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
    // The last certificate of this Instance's own chain is the KMS CA that alpha-runtime
    // already checked against the measured one, so a CA rotation needs only a restart.
    let kms_ca = CertificateDer::pem_slice_iter(identity.certificate_chain.as_bytes())
        .last()
        .ok_or_else(|| Error::internal("certificate chain is empty"))?
        .map_err(|e| Error::internal(format!("certificate chain: {e}")))?;
    let tls_config = tls::server_config(cert.clone(), kms_ca)?;
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
    tls::serve(listener, tls_config, app, async {
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
