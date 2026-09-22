//! CPU HMAC service: TLS and secret material come only from the measured runtime
//! socket. Each request reauthorizes its secret; no secret/key is logged or persisted.
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Query, State},
    http::StatusCode,
    routing::{get, post},
};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit, Mac};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
    service::TowerToHyperService,
};
use parking_lot::RwLock;
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, path::Path, sync::Arc, time::Duration};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use zeroize::Zeroizing;

const SECRET: &str = "cpu-app-key";
type Refusal = (StatusCode, &'static str);

#[derive(Debug)]
struct Certificates(RwLock<Arc<CertifiedKey>>);
impl ResolvesServerCert for Certificates {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.read().clone())
    }
}

#[derive(Clone)]
pub struct Application {
    runtime: reqwest::Client,
    identity: Value,
    certificates: Arc<Certificates>,
}

fn denied() -> Refusal {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        "runtime authorization unavailable",
    )
}

fn field<'a>(value: &'a Value, name: &str) -> Result<&'a str, Refusal> {
    value.get(name).and_then(Value::as_str).ok_or_else(denied)
}

async fn read_runtime(client: &reqwest::Client, route: &str) -> Result<Value, Refusal> {
    let mut response = client
        .get(format!("http://runtime{route}"))
        .send()
        .await
        .map_err(|_| denied())?
        .error_for_status()
        .map_err(|_| denied())?;
    let mut bytes = Zeroizing::new(Vec::new());
    while let Some(chunk) = response.chunk().await.map_err(|_| denied())? {
        if bytes.len().saturating_add(chunk.len()) > 262144 {
            return Err(denied());
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| denied())
}

fn certified(identity: &Value) -> Result<Arc<CertifiedKey>, Refusal> {
    let pkcs8 = Zeroizing::new(
        BASE64_URL_SAFE_NO_PAD
            .decode(field(identity, "tls_private_key")?)
            .map_err(|_| denied())?,
    );
    let provider = alpha_client::tls::provider();
    let key = provider
        .key_provider
        .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            pkcs8.to_vec(),
        )))
        .map_err(|_| denied())?;
    let chain: Vec<CertificateDer<'static>> = identity
        .get("certificate_chain")
        .ok_or_else(denied)?
        .as_array()
        .ok_or_else(denied)?
        .iter()
        .map(|v| {
            alpha_client::tls::cert_from_pem(v.as_str().ok_or_else(denied)?).map_err(|_| denied())
        })
        .collect::<Result<_, _>>()?;
    if chain.len() != 2 {
        return Err(denied());
    }
    let certified = CertifiedKey::new(chain, key);
    certified.keys_match().map_err(|_| denied())?;
    Ok(Arc::new(certified))
}

impl Application {
    pub async fn connect(socket: &Path) -> Result<Self, Refusal> {
        let runtime = reqwest::Client::builder()
            .unix_socket(socket)
            .timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| denied())?;
        let mut identity = read_runtime(&runtime, "/v1/identity").await?;
        let certificates = Arc::new(Certificates(RwLock::new(certified(&identity)?)));
        // Retain only public identity after transferring the key into the TLS resolver.
        if let Some(fields) = identity.as_object_mut() {
            fields.remove("tls_private_key");
        }
        let app = Self {
            runtime,
            identity,
            certificates,
        };
        app.authorized_key().await?;
        Ok(app)
    }

    async fn authorized_key(&self) -> Result<Zeroizing<Vec<u8>>, Refusal> {
        let fresh = read_runtime(&self.runtime, "/v1/identity").await?;
        for name in ["org_id", "app_id", "compose_hash"] {
            if field(&fresh, name)? != field(&self.identity, name)? {
                return Err(denied());
            }
        }
        *self.certificates.0.write() = certified(&fresh)?;
        let reply = read_runtime(&self.runtime, &format!("/v1/secrets/{SECRET}")).await?;
        let key = Zeroizing::new(
            BASE64_URL_SAFE_NO_PAD
                .decode(field(&reply, "value")?)
                .map_err(|_| denied())?,
        );
        if key.len() < 32
            || field(&reply, "content_sha256")?
                != format!("sha256:{}", hex::encode(Sha256::digest(&key)))
        {
            return Err(denied());
        }
        Ok(key)
    }

    pub fn router(&self) -> Router {
        Router::new()
            .route("/healthz", get(health))
            .route("/v1/hmac", post(authenticate))
            .layer(DefaultBodyLimit::max(65536))
            .with_state(self.clone())
    }

    pub async fn serve(
        &self,
        listener: TcpListener,
        shutdown: impl std::future::Future<Output = ()>,
    ) -> Result<(), String> {
        let mut config = ServerConfig::builder_with_provider(alpha_client::tls::provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| e.to_string())?
            .with_no_client_auth()
            .with_cert_resolver(self.certificates.clone());
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(config));
        tokio::pin!(shutdown);
        loop {
            let accepted = tokio::select! { result=listener.accept()=>result, ()=&mut shutdown=>return Ok(()) };
            let (tcp, _) = accepted.map_err(|e| e.to_string())?;
            let acceptor = acceptor.clone();
            let app = self.clone();
            tokio::spawn(async move {
                let _ = tokio::time::timeout(Duration::from_secs(60), async move {
                    // Refresh the certificate and policy before accepting a connection.
                    app.authorized_key().await?;
                    let tls = acceptor.accept(tcp).await.map_err(|_| denied())?;
                    let _ = Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(tls), TowerToHyperService::new(app.router()))
                        .await;
                    Ok::<(), Refusal>(())
                })
                .await;
            });
        }
    }
}

async fn health(
    State(app): State<Application>,
    Query(query): Query<HashMap<String, String>>,
) -> Result<Json<Value>, Refusal> {
    app.authorized_key().await?;
    Ok(Json(
        json!({"schema_version":1,"ready":true,"secret_access":true,
        "org_id":field(&app.identity,"org_id")?,"app_id":field(&app.identity,"app_id")?,"compose_hash":field(&app.identity,"compose_hash")?,
        "challenge":query.get("challenge")}),
    ))
}

async fn authenticate(State(app): State<Application>, body: Bytes) -> Result<Json<Value>, Refusal> {
    let key = app.authorized_key().await?;
    let mut mac = Hmac::<Sha256>::new_from_slice(&key).map_err(|_| denied())?;
    mac.update(&body);
    Ok(Json(
        json!({"hmac_sha256":hex::encode(mac.finalize().into_bytes())}),
    ))
}
