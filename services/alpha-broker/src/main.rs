//! Thin entrypoint: attest, read this Instance's identity, its Secrets and the connectors key
//! from the runtime socket, migrate the broker's own database, then serve over TLS on `:8443`
//! until SIGTERM, refreshing the leaf, the Secrets and the key every five minutes.
//! `alpha-broker migrate` stops after the migration. Every error is a non-zero exit.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use alpha_broker::{AppState, Config, Error, Secrets, router, store};
use alpha_client::runtime::RuntimeSocket;
use alpha_client::tls::{InstanceCert, server_config};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::service::TowerToHyperService;
use sqlx::postgres::PgPoolOptions;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
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
    let connectors_key = runtime
        .key("connectors")
        .await
        .map_err(|e| Error::internal(format!("key connectors: {e}")))?;
    Ok(Secrets {
        google_client_secret,
        connect_bearer,
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
    let tls_config =
        server_config(cert.clone()).map_err(|e| Error::internal(format!("tls: {e}")))?;
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
    });
    let app = router(state.clone());

    let listener = TcpListener::bind(("0.0.0.0", PORT))
        .await
        .map_err(|e| Error::internal(format!("bind :{PORT}: {e}")))?;
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|e| Error::internal(format!("sigterm: {e}")))?;
    let renew = tokio::spawn(renew_forever(runtime, cert, state));
    serve_tls(listener, tls_config, app, async move {
        tokio::select! {
            _ = term.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
    })
    .await;
    renew.abort();
    Ok(())
}

async fn renew_forever(runtime: RuntimeSocket, cert: Arc<InstanceCert>, state: Arc<AppState>) {
    loop {
        tokio::time::sleep(RENEW_INTERVAL).await;
        if let Ok(identity) = runtime.identity().await {
            let _ = cert.replace(&identity);
        }
        if let Ok(secrets) = read_secrets(&runtime).await {
            *state.secrets.write() = secrets;
        }
    }
}

/// Accepts TLS connections until `shutdown` resolves, then drains the ones already open.
async fn serve_tls(
    listener: TcpListener,
    tls_config: Arc<rustls::ServerConfig>,
    app: axum::Router,
    shutdown: impl Future<Output = ()>,
) {
    let acceptor = TlsAcceptor::from(tls_config);
    let graceful = GracefulShutdown::new();
    let mut shutdown = std::pin::pin!(shutdown);
    loop {
        let (stream, _) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(accepted) => accepted,
                Err(_) => continue,
            },
            () = &mut shutdown => break,
        };
        let acceptor = acceptor.clone();
        let app = app.clone();
        let watcher = graceful.watcher();
        tokio::spawn(async move {
            let Ok(tls) = acceptor.accept(stream).await else {
                return;
            };
            let service = TowerToHyperService::new(app);
            let builder = Builder::new(TokioExecutor::new());
            let conn = builder.serve_connection(TokioIo::new(tls), service);
            let _ = watcher.watch(conn).await;
        });
    }
    graceful.shutdown().await;
}
