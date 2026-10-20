//! The key broker: six tables, fourteen routes on one TLS port, one process-wide state.

#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )
)]

pub mod audit;
pub mod body;
pub mod certs;
pub mod channel;
pub mod control;
pub mod error;
pub mod instance;
pub mod keys;
pub mod node;
pub mod platform;
pub mod tls;
pub mod webauthn;

use std::sync::Arc;
use std::time::{Instant, SystemTime};

use alpha_attest::{Collateral, InstanceEvidence, PlatformDocument};
use alpha_core::ComposeHash;
use axum::Router;
use axum::extract::{Request, State};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use p256::ecdsa::SigningKey;
use p256::pkcs8::{EncodePrivateKey, EncodePublicKey};
use parking_lot::{Mutex, RwLock};
use sqlx::PgPool;
use zeroize::Zeroizing;

use crate::error::ApiError;

/// What the node keeps of its environment; the database and PCCS URLs are consumed on start.
pub struct Config {
    /// Read once at start: the substrate the node took its Revision from is the one it quotes on.
    pub substrate: alpha_tsm::Substrate,
    pub kms_endpoints: Vec<String>,
    pub platform_document_url: String,
    pub nvidia_ocsp_url: String,
    #[cfg(feature = "dev-root")]
    pub dev_root_kek: Option<Zeroizing<[u8; 32]>>,
}

pub fn env(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("{name} is not set"))
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        Ok(Self {
            substrate: alpha_tsm::Substrate::detect(std::path::Path::new(alpha_tsm::DSTACK_SOCKET)),
            kms_endpoints: env("ALPHACOMPUTE_KMS_ENDPOINTS")?
                .split(',')
                .map(|s| s.trim().trim_end_matches('/').to_owned())
                .filter(|s| !s.is_empty())
                .collect(),
            platform_document_url: env("ALPHACOMPUTE_PLATFORM_DOCUMENT_URL")?,
            nvidia_ocsp_url: env("ALPHACOMPUTE_NVIDIA_OCSP_URL")
                .unwrap_or_else(|_| alpha_client::NVIDIA_OCSP_URL.to_owned()),
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
    pub fn ca_key(&self) -> Result<rcgen::KeyPair, ApiError> {
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

// ponytail: chosen without load data; set from the renewal rate once two nodes run on Phala.
const BUCKET_CAPACITY: f64 = 200.0;
const BUCKET_REFILL_PER_SEC: f64 = 100.0;

pub type Clock = Arc<dyn Fn() -> SystemTime + Send + Sync>;

pub struct Node {
    pub pool: PgPool,
    pub config: Config,
    pub clock: Clock,
    pub collateral: CollateralSource,
    pub ocsp_http: reqwest::Client,
    pub nonce_key: [u8; 32],
    pub runtime_key: SigningKey,
    pub runtime_pkcs8: Zeroizing<Vec<u8>>,
    pub runtime_spki: Vec<u8>,
    pub xwing_key: alpha_crypto::PrivateKey,
    /// This node's Revision: its compose's in a dstack CVM, its init-data's in a Kata pod.
    pub compose_hash: ComposeHash,
    pub release_keys: alpha_client::platform::ReleaseKeys,
    pub platform: RwLock<Option<Arc<PlatformDocument>>>,
    pub phase: RwLock<Phase>,
    pub server_cert: Arc<tls::ServerCert>,
    /// On Kata only from bootstrap, unseal or the peer.
    database_password: RwLock<Option<Zeroizing<String>>>,
    bucket: Mutex<(f64, Instant)>,
}

impl Node {
    pub fn new(
        pool: PgPool,
        config: Config,
        clock: Clock,
        collateral: CollateralSource,
        nonce_key: [u8; 32],
        compose_hash: ComposeHash,
        release_keys: alpha_client::platform::ReleaseKeys,
    ) -> Result<Arc<Self>, String> {
        let runtime_key = SigningKey::from_bytes((&random::<32>().map_err(|e| e.message)?).into())
            .map_err(|e| format!("runtime key: {e}"))?;
        let runtime_spki = runtime_key
            .verifying_key()
            .to_public_key_der()
            .map_err(|e| format!("runtime key: {e}"))?
            .into_vec();
        let runtime_pkcs8 = Zeroizing::new(
            runtime_key
                .to_pkcs8_der()
                .map_err(|e| format!("runtime key: {e}"))?
                .to_bytes()
                .to_vec(),
        );
        let server_cert =
            Arc::new(tls::ServerCert::sealed(&runtime_pkcs8, (clock)()).map_err(|e| e.message)?);
        Ok(Arc::new(Self {
            pool,
            config,
            clock,
            collateral,
            ocsp_http: alpha_client::http()
                .build()
                .map_err(|e| format!("http client: {e}"))?,
            nonce_key,
            runtime_key,
            runtime_pkcs8,
            runtime_spki,
            xwing_key: alpha_crypto::PrivateKey::generate().map_err(|e| e.to_string())?,
            compose_hash,
            release_keys,
            platform: RwLock::new(None),
            phase: RwLock::new(Phase::Sealed { shares: Vec::new() }),
            server_cert,
            database_password: RwLock::new(None),
            bucket: Mutex::new((BUCKET_CAPACITY, Instant::now())),
        }))
    }

    pub fn is_kata(&self) -> bool {
        self.config.substrate == alpha_tsm::Substrate::Kata
    }

    /// A sealed Kata node has no database credential yet.
    pub fn has_database(&self) -> bool {
        !self.is_kata() || !self.is_sealed()
    }

    pub fn database_password(&self) -> Option<Zeroizing<String>> {
        self.database_password.read().clone()
    }

    pub fn use_database_password(&self, password: Zeroizing<String>) {
        let options = (*self.pool.connect_options()).clone().password(&password);
        self.pool.set_connect_options(options);
        *self.database_password.write() = Some(password);
    }

    pub fn evidence(&self, report_data: &[u8; 64]) -> Result<InstanceEvidence, ApiError> {
        alpha_tsm::evidence(self.config.substrate, report_data)
            .map_err(|e| ApiError::internal(format!("evidence: {e}")))
    }

    pub fn now(&self) -> SystemTime {
        (self.clock)()
    }

    pub fn now_utc(&self) -> chrono::DateTime<chrono::Utc> {
        self.now().into()
    }

    pub fn platform_document(&self) -> Option<Arc<PlatformDocument>> {
        self.platform.read().clone()
    }

    pub fn intermediates(&self) -> Result<Arc<Intermediates>, ApiError> {
        match &*self.phase.read() {
            Phase::Serving(keys) => Ok(keys.clone()),
            Phase::Sealed { .. } => Err(ApiError::new("sealed", "node is sealed")),
        }
    }

    pub fn is_sealed(&self) -> bool {
        matches!(&*self.phase.read(), Phase::Sealed { .. })
    }

    /// Enters the serving phase: intermediates in memory and a leaf from `ca` on the listener.
    pub fn start_serving(&self, keys: Intermediates) -> Result<(), ApiError> {
        self.issue_own_leaf(&keys)?;
        *self.phase.write() = Phase::Serving(Arc::new(keys));
        Ok(())
    }

    /// The listener's leaf from `ca`: `alphacompute://kms` and this node's Revision.
    pub fn issue_own_leaf(&self, keys: &Intermediates) -> Result<(), ApiError> {
        let leaf = certs::issue_leaf(
            &keys.ca_key()?,
            &keys.ca_cert_der,
            &self.runtime_spki,
            certs::node_sans(self.compose_hash),
            self.now(),
        )?;
        self.server_cert
            .serve(&self.runtime_pkcs8, leaf, keys.ca_cert_der.clone())
    }

    fn take_token(&self) -> bool {
        let mut bucket = self.bucket.lock();
        let (tokens, last) = *bucket;
        let now = Instant::now();
        let tokens = (tokens + now.duration_since(last).as_secs_f64() * BUCKET_REFILL_PER_SEC)
            .min(BUCKET_CAPACITY);
        let taken = tokens >= 1.0;
        *bucket = (if taken { tokens - 1.0 } else { tokens }, now);
        taken
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
        .route("/v1/keys/derive", post(instance::derive_key))
        .route("/v1/channel", post(channel::handshake))
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
    if node.is_sealed() {
        return (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(serde_json::json!({ "sealed": true })),
        )
            .into_response();
    }
    if let Err(e) = sqlx::query("select 1").execute(&node.pool).await {
        return ApiError::internal(format!("database: {e}")).into_response();
    }
    axum::Json(serde_json::json!({ "sealed": false })).into_response()
}

pub fn random<const N: usize>() -> Result<[u8; N], ApiError> {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).map_err(|e| ApiError::internal(format!("rng: {e}")))?;
    Ok(out)
}

pub fn later(now: SystemTime, by: std::time::Duration) -> Result<SystemTime, ApiError> {
    now.checked_add(by)
        .ok_or_else(|| ApiError::internal("time overflows the clock"))
}

pub fn rfc3339(t: impl Into<chrono::DateTime<chrono::Utc>>) -> String {
    t.into().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

pub async fn migrate(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    sqlx::migrate!("./migrations").run(pool).await
}
