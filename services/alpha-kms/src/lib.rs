//! The key broker: six tables, twelve routes on one TLS port, one process-wide state.

pub mod audit;
pub mod body;
pub mod certs;
pub mod control;
pub mod error;
pub mod instance;
pub mod keys;
pub mod node;
pub mod platform;
pub mod tls;

use std::sync::{Arc, Mutex, RwLock};
use std::time::{Instant, SystemTime};

use alpha_attest::{Collateral, EventLogEntry, PlatformDocument};
use alpha_core::ComposeHash;
use axum::Router;
use axum::extract::{Request, State};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use p256::ecdsa::SigningKey;
use p256::pkcs8::{EncodePrivateKey, EncodePublicKey};
use sqlx::PgPool;
use zeroize::Zeroizing;

use crate::error::ApiError;

pub struct Config {
    pub database_url: String,
    pub kms_endpoints: Vec<String>,
    pub pccs_url: String,
    pub platform_document_url: String,
    #[cfg(feature = "dev-root")]
    pub dev_root_kek: Option<Zeroizing<[u8; 32]>>,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let var = |name: &str| std::env::var(name).map_err(|_| format!("{name} is not set"));
        Ok(Self {
            database_url: var("ALPHACOMPUTE_DATABASE_URL")?,
            kms_endpoints: var("ALPHACOMPUTE_KMS_ENDPOINTS")?
                .split(',')
                .map(|s| s.trim().trim_end_matches('/').to_owned())
                .filter(|s| !s.is_empty())
                .collect(),
            pccs_url: var("ALPHACOMPUTE_PCCS_URL")?,
            platform_document_url: var("ALPHACOMPUTE_PLATFORM_DOCUMENT_URL")?,
            #[cfg(feature = "dev-root")]
            dev_root_kek: std::env::var("ALPHACOMPUTE_KMS_DEV_ROOT_KEK")
                .ok()
                .map(|hex| {
                    alpha_core::hex_bytes::<32>(hex.trim())
                        .map(Zeroizing::new)
                        .ok_or("ALPHACOMPUTE_KMS_DEV_ROOT_KEK is not 64 hex digits")
                })
                .transpose()?,
        })
    }
}

/// Where DCAP collateral comes from: the PCCS in production, a fixed capture in tests.
pub enum CollateralSource {
    Pccs(String),
    Fixed(Box<Collateral>),
}

/// The two intermediates in memory after unseal, join or bootstrap.
pub struct Intermediates {
    pub tenant_kek_root: Zeroizing<[u8; 32]>,
    pub ca_key_der: Zeroizing<Vec<u8>>,
    pub ca_cert_der: Vec<u8>,
}

impl Intermediates {
    pub fn ca_key(&self) -> rcgen::KeyPair {
        certs::key_pair(&self.ca_key_der)
    }

    pub fn ca_pem(&self) -> String {
        certs::pem(&self.ca_cert_der)
    }
}

pub enum Phase {
    Sealed { shares: Vec<Vec<u8>> },
    Serving(Arc<Intermediates>),
}

pub struct Bucket {
    tokens: f64,
    last: Instant,
}

// ponytail: chosen without load data; set from the renewal rate once two nodes run on Phala.
const BUCKET_CAPACITY: f64 = 200.0;
const BUCKET_REFILL_PER_SEC: f64 = 100.0;

pub type Clock = Arc<dyn Fn() -> SystemTime + Send + Sync>;

pub struct Node {
    pub pool: PgPool,
    pub config: Config,
    pub clock: Clock,
    pub collateral: CollateralSource,
    pub nonce_key: [u8; 32],
    pub runtime_key: SigningKey,
    pub runtime_spki: Vec<u8>,
    pub xwing_key: alpha_crypto::PrivateKey,
    pub event_log: Vec<EventLogEntry>,
    pub compose_hash: ComposeHash,
    pub release_key: ed25519_dalek::VerifyingKey,
    pub platform: RwLock<Option<Arc<PlatformDocument>>>,
    pub phase: RwLock<Phase>,
    pub server_cert: Arc<tls::ServerCert>,
    bucket: Mutex<Bucket>,
}

pub struct NodeParams {
    pub pool: PgPool,
    pub config: Config,
    pub clock: Clock,
    pub collateral: CollateralSource,
    pub nonce_key: [u8; 32],
    pub event_log: Vec<EventLogEntry>,
    pub release_key: ed25519_dalek::VerifyingKey,
}

impl Node {
    pub fn new(params: NodeParams) -> Result<Arc<Self>, String> {
        let NodeParams {
            pool,
            config,
            clock,
            collateral,
            nonce_key,
            event_log,
            release_key,
        } = params;
        let compose_hash = alpha_attest::event_log_compose_hash(&event_log)
            .ok_or("the event log carries no compose-hash event")?;
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).expect("the system RNG never fails");
        let runtime_key =
            SigningKey::from_bytes((&seed).into()).map_err(|e| format!("runtime key: {e}"))?;
        let runtime_spki = runtime_key
            .verifying_key()
            .to_public_key_der()
            .map_err(|e| format!("runtime key: {e}"))?
            .into_vec();
        let pkcs8 = Zeroizing::new(
            runtime_key
                .to_pkcs8_der()
                .map_err(|e| format!("runtime key: {e}"))?
                .to_bytes()
                .to_vec(),
        );
        let server_cert = Arc::new(tls::ServerCert::sealed(&pkcs8, (clock)()));
        Ok(Arc::new(Self {
            pool,
            config,
            clock,
            collateral,
            nonce_key,
            runtime_key,
            runtime_spki,
            xwing_key: alpha_crypto::PrivateKey::generate(),
            event_log,
            compose_hash,
            release_key,
            platform: RwLock::new(None),
            phase: RwLock::new(Phase::Sealed { shares: Vec::new() }),
            server_cert,
            bucket: Mutex::new(Bucket {
                tokens: BUCKET_CAPACITY,
                last: Instant::now(),
            }),
        }))
    }

    pub fn now(&self) -> SystemTime {
        (self.clock)()
    }

    pub fn now_utc(&self) -> chrono::DateTime<chrono::Utc> {
        self.now().into()
    }

    pub fn platform_document(&self) -> Option<Arc<PlatformDocument>> {
        self.platform.read().unwrap().clone()
    }

    pub fn intermediates(&self) -> Result<Arc<Intermediates>, ApiError> {
        match &*self.phase.read().unwrap() {
            Phase::Serving(keys) => Ok(keys.clone()),
            Phase::Sealed { .. } => Err(ApiError::new("sealed", "node is sealed")),
        }
    }

    pub fn is_sealed(&self) -> bool {
        matches!(&*self.phase.read().unwrap(), Phase::Sealed { .. })
    }

    /// Enters the serving phase: intermediates in memory and a leaf from `ca` on the listener.
    pub fn start_serving(&self, keys: Intermediates) -> Result<(), ApiError> {
        let leaf = certs::issue_leaf(
            &keys.ca_key(),
            &keys.ca_cert_der,
            &self.runtime_spki,
            certs::node_sans(self.compose_hash),
            self.now(),
        )?;
        self.server_cert
            .serve(&self.runtime_pkcs8(), leaf, keys.ca_cert_der.clone());
        *self.phase.write().unwrap() = Phase::Serving(Arc::new(keys));
        Ok(())
    }

    pub fn runtime_pkcs8(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(
            self.runtime_key
                .to_pkcs8_der()
                .expect("a key we generated")
                .to_bytes()
                .to_vec(),
        )
    }

    fn take_token(&self) -> bool {
        let mut bucket = self.bucket.lock().unwrap();
        let now = Instant::now();
        let elapsed = now.duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * BUCKET_REFILL_PER_SEC).min(BUCKET_CAPACITY);
        bucket.last = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

async fn gate(State(node): State<Arc<Node>>, request: Request, next: Next) -> Response {
    if !node.take_token() {
        return ApiError::new("rate_limited", "global token bucket is empty").into_response();
    }
    let path = request.uri().path();
    let exempt = path.starts_with("/v1/node/") || path == "/healthz" || path == "/ready";
    if !exempt && node.is_sealed() {
        return ApiError::new("sealed", "node is sealed").into_response();
    }
    next.run(request).await
}

pub fn router(node: Arc<Node>) -> Router {
    Router::new()
        .route(
            "/healthz",
            get(|| async { axum::Json(serde_json::json!({"ok": true})) }),
        )
        .route("/ready", get(ready))
        .route("/v1/attest/nonce", post(instance::nonce))
        .route("/v1/attest", post(instance::attest))
        .route("/v1/secrets/{name}", get(instance::get_secret))
        .route("/v1/revisions", post(control::register_revision))
        .route(
            "/v1/revisions/{compose_hash}/revoke",
            post(control::revoke_revision),
        )
        .route("/v1/secrets/{name}", put(control::put_secret))
        .route("/v1/keys", post(control::register_key))
        .route("/v1/keys/{id}/revoke", post(control::revoke_key))
        .route("/v1/node/evidence", get(node::evidence))
        .route("/v1/node/bootstrap", post(node::bootstrap))
        .route("/v1/node/unseal", post(node::unseal))
        .route("/v1/node/join", post(node::join))
        .layer(middleware::from_fn_with_state(node.clone(), gate))
        .fallback(|| async { ApiError::not_found("no such route").into_response() })
        .with_state(node)
}

async fn ready(State(node): State<Arc<Node>>) -> Response {
    if let Err(e) = sqlx::query("select 1").execute(&node.pool).await {
        return ApiError::internal(format!("database: {e}")).into_response();
    }
    let sealed = node.is_sealed();
    let status = if sealed {
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    } else {
        axum::http::StatusCode::OK
    };
    (status, axum::Json(serde_json::json!({ "sealed": sealed }))).into_response()
}

pub async fn migrate(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    sqlx::migrate!("./migrations").run(pool).await
}
