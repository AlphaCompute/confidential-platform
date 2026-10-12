//! The key broker: eight tables, nineteen routes on one TLS port, one process-wide state.

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
pub mod trustee;
pub mod webauthn;

use std::sync::Arc;
use std::time::{Instant, SystemTime};

use alpha_attest::gpu::ccm::FortanixCcm;
use alpha_attest::gpu::nras::Nras;
use alpha_attest::{AnyEvidence, Collateral, EventLogEntry, GpuVerifier, PlatformDocument};
use alpha_core::ComposeHash;
use alpha_core::coco::{CPU_RUNTIME_CLASS, InitData};
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
    pub kms_endpoints: Vec<String>,
    pub platform_document_url: String,
    /// The GPU verifier backends a Kata pod's GPUs may be verified by; the platform document's
    /// `gpu_policy` decides which of them must all pass. See [`gpu_backends`].
    pub gpu_backends: Vec<Arc<dyn GpuVerifier>>,
    #[cfg(feature = "dev-root")]
    pub dev_root_kek: Option<Zeroizing<[u8; 32]>>,
}

pub fn env(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("{name} is not set"))
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        Ok(Self {
            kms_endpoints: env("ALPHACOMPUTE_KMS_ENDPOINTS")?
                .split(',')
                .map(|s| s.trim().trim_end_matches('/').to_owned())
                .filter(|s| !s.is_empty())
                .collect(),
            platform_document_url: env("ALPHACOMPUTE_PLATFORM_DOCUMENT_URL")?,
            gpu_backends: gpu_backends(std::env::var("ALPHACOMPUTE_FORTANIX_CCM_URL").ok())?,
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

/// The GPU verifier backends this node runs: NRAS always (it refuses every GPU until the release-signed
/// `gpu_policy` pins NRAS's keys and names the CC-mode claim), Fortanix CCM when `ccm_url` names its
/// endpoint (it refuses every GPU until F8), and never `local`, which is built after Dec 1. A backend
/// the `gpu_policy` lists that is not here refuses every GPU pod.
// ponytail: F8 — whether the CCM endpoint stays node configuration or moves into the release-signed
// `gpu_policy`, as `nras_url` is, is settled with Fortanix's API.
pub fn gpu_backends(ccm_url: Option<String>) -> Result<Vec<Arc<dyn GpuVerifier>>, String> {
    let nras = Nras::new().map_err(|e| e.to_string())?;
    let mut backends: Vec<Arc<dyn GpuVerifier>> = vec![Arc::new(nras)];
    if let Some(endpoint) = ccm_url {
        if !endpoint.starts_with("https://") {
            return Err("ALPHACOMPUTE_FORTANIX_CCM_URL is not an https:// URL".into());
        }
        backends.push(Arc::new(FortanixCcm { endpoint }));
    }
    Ok(backends)
}

/// A quote over `report_data` and the evidence behind it.
pub type EvidenceSource = Arc<dyn Fn(&[u8; 64]) -> Result<AnyEvidence, String> + Send + Sync>;

/// What this node is and where its evidence comes from. A prototype CVM is the compose-hash event
/// of its event log and quotes through the dstack guest agent. A Kata pod is the Revision v2 its
/// init-data stands for (the init-data's digest is the TD's MRCONFIGID) and quotes through the
/// CoCo source `alpha-runtime` uses, so a node is appraised as an Instance is.
pub struct NodeGuest {
    /// The node's Revision: what its leaf names and `kms_revisions` must list.
    pub compose_hash: ComposeHash,
    evidence: EvidenceSource,
}

impl NodeGuest {
    pub fn prototype(event_log: Vec<EventLogEntry>) -> Result<Self, String> {
        let compose_hash = alpha_attest::event_log_compose_hash(&event_log)
            .ok_or("the event log carries no compose-hash event")?;
        Ok(Self {
            compose_hash,
            evidence: Arc::new(move |report_data| {
                Ok(alpha_attest::Evidence {
                    format: alpha_attest::EVIDENCE_FORMAT.into(),
                    quote: alpha_tsm::quote(report_data).map_err(|e| format!("quote: {e}"))?,
                    event_log: event_log.clone(),
                }
                .into())
            }),
        })
    }

    /// A Kata pod with this init-data, quoting through `quote`. A KMS node runs on the CPU class,
    /// so it never asks for GPU evidence.
    pub fn coco(quote: alpha_tsm::coco::QuoteSource, initdata: Vec<u8>) -> Result<Self, String> {
        let source = alpha_tsm::coco::Source {
            quote,
            initdata: initdata.clone(),
            runtime_class: CPU_RUNTIME_CLASS.into(),
            gpu_count: 0,
        };
        Self::coco_with(
            &initdata,
            Arc::new(move |report_data| {
                source
                    .evidence(report_data)
                    .map(Into::into)
                    .map_err(|e| e.to_string())
            }),
        )
    }

    /// A Kata pod with this init-data and another evidence source (a test's synthetic one).
    pub fn coco_with(initdata: &[u8], evidence: EvidenceSource) -> Result<Self, String> {
        let revision = InitData::parse(initdata)
            .and_then(|d| d.revision())
            .map_err(|e| format!("init-data: {e}"))?;
        if revision.runtime_class != CPU_RUNTIME_CLASS {
            return Err(format!(
                "init-data: a KMS node runs on {CPU_RUNTIME_CLASS}, not {}",
                revision.runtime_class
            ));
        }
        Ok(Self {
            compose_hash: revision.hash().map_err(|e| format!("init-data: {e}"))?,
            evidence,
        })
    }

    pub fn evidence(&self, report_data: &[u8; 64]) -> Result<AnyEvidence, ApiError> {
        (self.evidence)(report_data).map_err(ApiError::internal)
    }
}

/// `ALPHACOMPUTE_QUOTE_SOURCE`, as `alpha-runtime` reads it: unset or `dstack` for a prototype
/// CVM, `coco-aa` or `coco-tsm` for a Kata pod. The agent policy pins it with the rest of the
/// container's environment.
pub fn quote_source(var: Option<&str>) -> Result<Option<alpha_tsm::coco::QuoteSource>, String> {
    use alpha_tsm::coco::QuoteSource::*;
    match var {
        None | Some("dstack") => Ok(None),
        Some("coco-aa") => Ok(Some(AttestationAgent)),
        Some("coco-tsm") => Ok(Some(ConfigfsTsm)),
        Some(other) => Err(format!(
            "ALPHACOMPUTE_QUOTE_SOURCE={other:?} is not dstack, coco-aa or coco-tsm"
        )),
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
    pub nonce_key: [u8; 32],
    pub runtime_key: SigningKey,
    pub runtime_pkcs8: Zeroizing<Vec<u8>>,
    pub runtime_spki: Vec<u8>,
    pub xwing_key: alpha_crypto::PrivateKey,
    pub guest: NodeGuest,
    pub compose_hash: ComposeHash,
    pub release_key: ed25519_dalek::VerifyingKey,
    pub platform: RwLock<Option<Arc<PlatformDocument>>>,
    pub phase: RwLock<Phase>,
    pub server_cert: Arc<tls::ServerCert>,
    bucket: Mutex<(f64, Instant)>,
}

impl Node {
    pub fn new(
        pool: PgPool,
        config: Config,
        clock: Clock,
        collateral: CollateralSource,
        nonce_key: [u8; 32],
        guest: NodeGuest,
        release_key: ed25519_dalek::VerifyingKey,
    ) -> Result<Arc<Self>, String> {
        let compose_hash = guest.compose_hash;
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
            nonce_key,
            runtime_key,
            runtime_pkcs8,
            runtime_spki,
            xwing_key: alpha_crypto::PrivateKey::generate().map_err(|e| e.to_string())?,
            guest,
            compose_hash,
            release_key,
            platform: RwLock::new(None),
            phase: RwLock::new(Phase::Sealed { shares: Vec::new() }),
            server_cert,
            bucket: Mutex::new((BUCKET_CAPACITY, Instant::now())),
        }))
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
        .route(
            "/v1/trustee/grants/{app_id}",
            put(control::put_trustee_grant),
        )
        .route(
            "/v1/trustee/attestations",
            post(trustee::register_attestation),
        )
        .route("/v1/trustee/releases", post(trustee::release))
        .route("/v1/trustee/state", get(trustee::state))
        .route("/v1/trustee/kbs-leaf", post(trustee::kbs_leaf))
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

#[cfg(test)]
mod tests {
    use alpha_attest::GpuVerifierKind;

    use super::*;

    #[test]
    fn quote_source_is_read_as_alpha_runtime_reads_it() {
        use alpha_tsm::coco::QuoteSource::*;
        assert_eq!(quote_source(None), Ok(None));
        assert_eq!(quote_source(Some("dstack")), Ok(None));
        assert_eq!(quote_source(Some("coco-aa")), Ok(Some(AttestationAgent)));
        assert_eq!(quote_source(Some("coco-tsm")), Ok(Some(ConfigfsTsm)));
        assert!(quote_source(Some("tdx")).is_err());
    }

    #[test]
    fn gpu_backends_are_nras_and_fortanix_ccm_when_named_never_local() {
        let kinds = |backends: Vec<Arc<dyn GpuVerifier>>| {
            backends.iter().map(|b| b.kind()).collect::<Vec<_>>()
        };
        assert_eq!(kinds(gpu_backends(None).unwrap()), [GpuVerifierKind::Nras]);
        assert_eq!(
            kinds(gpu_backends(Some("https://ccm.example".into())).unwrap()),
            [GpuVerifierKind::Nras, GpuVerifierKind::FortanixCcm]
        );
        assert!(gpu_backends(Some("http://ccm.example".into())).is_err());
    }
}
