//! `alpha-control migrate` applies the migrations and returns. Otherwise the API serves TLS on
//! `:8443` with a Let's Encrypt certificate for the public name, ordered through TLS-ALPN-01 on
//! that same port behind the passthrough Gateway, and `/healthz` and `/ready` on plain `:8080`,
//! until SIGTERM. Every error is a non-zero exit.

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use alpha_client::acme::{self, ACME_TLS_ALPN, Edge, Route};
use alpha_control::{AppState, Error, Oidc, migrate, probes, router};
use rustls::ServerConfig;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use tokio::net::TcpListener;
use zeroize::Zeroizing;

const PORT: u16 = 8443;
const PROBE_PORT: u16 = 8080;

#[tokio::main]
async fn main() {
    let code = match run().await {
        Ok(()) => 0,
        Err(e) => {
            // No message here carries a setting's value: the URL's parse error is dropped.
            let detail = e.to_string();
            alpha_client::error!("exit", error = alpha_client::log::Field::text(&detail));
            1
        }
    };
    alpha_client::log::flush();
    std::process::exit(code);
}

fn env(name: &str) -> Result<String, Error> {
    std::env::var(name).map_err(|_| Error::internal(format!("{name} is required")))
}

/// The token endpoint is trusted because TLS authenticates it, and links to the signer page must
/// be absolute. Neither carries a fragment or surrounding whitespace; a query is allowed only
/// where `query` says so, because ticket paths follow the signer URL.
fn https_env(name: &str, query: bool) -> Result<String, Error> {
    let value = env(name)?;
    match reqwest::Url::parse(&value) {
        Ok(url)
            if url.scheme() == "https"
                && url.host_str().is_some()
                && (query || url.query().is_none())
                && url.fragment().is_none()
                && value.trim() == value =>
        {
            Ok(value)
        }
        _ => Err(Error::internal(format!(
            "{name} must be an https URL with a host, no fragment{} and no surrounding whitespace",
            if query { "" } else { ", no query" }
        ))),
    }
}

fn hex_env(name: &str) -> Result<Zeroizing<[u8; 32]>, Error> {
    let bytes = Zeroizing::new(
        data_encoding::HEXLOWER_PERMISSIVE
            .decode(env(name)?.trim().as_bytes())
            .unwrap_or_default(),
    );
    <[u8; 32]>::try_from(bytes.as_slice())
        .map(Zeroizing::new)
        .map_err(|_| Error::internal(format!("{name} must be 64 hex digits")))
}

/// The challenge certificate for the CA's validation, the public one for everyone else.
#[derive(Debug)]
struct Resolver {
    name: String,
    edge: Arc<Edge>,
}

impl ResolvesServerCert for Resolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        match acme::route(&self.name, hello.server_name(), hello.alpn()) {
            Route::Challenge => self.edge.challenge.read().clone(),
            _ => self.edge.served.read().clone(),
        }
    }
}

async fn run() -> Result<(), Error> {
    let options = PgConnectOptions::from_str(&env("ALPHACOMPUTE_DATABASE_URL")?)
        .map_err(|_| Error::internal("ALPHACOMPUTE_DATABASE_URL is not a Postgres URL"))?;
    if std::env::args().nth(1).as_deref() == Some("migrate") {
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await?;
        return migrate(&pool)
            .await
            .map_err(|e| Error::internal(format!("migrate: {e}")));
    }
    let operator_token_sha256 = *hex_env("ALPHACOMPUTE_OPERATOR_TOKEN_SHA256")?;
    let public_name = env("ALPHACOMPUTE_PUBLIC_NAME")?;
    let platform_document_url = env("ALPHACOMPUTE_PLATFORM_DOCUMENT_URL")?;
    let signer_url = https_env("ALPHACOMPUTE_SIGNER_URL", false)?
        .trim_end_matches('/')
        .to_owned();
    let kms_endpoints = env("ALPHACOMPUTE_KMS_ENDPOINTS")?
        .split(',')
        .map(|e| e.trim().to_owned())
        .filter(|e| !e.is_empty())
        .collect::<Vec<_>>();
    // The pin only holds over TLS.
    let https_base = |e: &String| {
        reqwest::Url::parse(e)
            .is_ok_and(|u| u.scheme() == "https" && u.host_str().is_some() && u.query().is_none())
    };
    if kms_endpoints.is_empty() || !kms_endpoints.iter().all(https_base) {
        return Err(Error::internal(
            "ALPHACOMPUTE_KMS_ENDPOINTS must list one or more https URLs with a host and no query",
        ));
    }
    let oidc = Oidc {
        issuer: env("ALPHACOMPUTE_OIDC_ISSUER")?,
        token_endpoint: https_env("ALPHACOMPUTE_OIDC_TOKEN_ENDPOINT", true)?,
        client_id: env("ALPHACOMPUTE_OIDC_CLIENT_ID")?,
    };
    let release_keys = alpha_client::platform::release_keys()
        .map_err(|e| Error::internal(format!("release keys: {e}")))?;
    // The certificate and ACME account keys derive from it, so a restart finds its certificate
    // in CT instead of spending one of the CA's five duplicate orders a week.
    let acme_key = Zeroizing::new(hex_env("ALPHACOMPUTE_ACME_KEY")?.to_vec());

    let pool = PgPoolOptions::new()
        .max_connections(8)
        .acquire_timeout(Duration::from_secs(5))
        .connect_lazy_with(options);
    let state = Arc::new(AppState {
        pool,
        operator_token_sha256,
        platform_document_url,
        release_keys,
        kms_endpoints,
        signer_url,
        oidc,
        code_lookups: Default::default(),
    });

    let bind = |port: u16| async move {
        TcpListener::bind(("0.0.0.0", port))
            .await
            .map_err(|e| Error::internal(format!("bind :{port}: {e}")))
    };
    let probe_listener = bind(PROBE_PORT).await?;
    let probe_router = probes(state.clone());
    tokio::spawn(async move { axum::serve(probe_listener, probe_router).await });

    // ponytail: one replica. The challenge lives in this process, so the CA's validation can reach
    // a second replica that lacks it; the upgrade is one replica that orders and the others that
    // find its certificate in CT.
    let edge = Arc::new(Edge::default());
    tokio::spawn(acme::issue_forever(
        edge.clone(),
        public_name.clone(),
        acme_key,
    ));
    let mut tls = ServerConfig::builder_with_provider(alpha_client::tls::provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| Error::internal(format!("tls: {e}")))?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(Resolver {
            name: public_name,
            edge,
        }));
    tls.alpn_protocols = vec![b"http/1.1".to_vec(), ACME_TLS_ALPN.to_vec()];

    let app = alpha_client::metrics::serve(router(state))
        .await
        .map_err(|e| Error::internal(format!("metrics: {e}")))?;
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|e| Error::internal(format!("sigterm: {e}")))?;
    alpha_client::tls::serve(bind(PORT).await?, Arc::new(tls), app, async {
        term.recv().await;
    })
    .await;
    Ok(())
}
