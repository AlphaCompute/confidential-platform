//! The in-CVM sidecar: one P-256 key for the life of the Instance, attested to the KMS into a
//! one-hour leaf renewed ten minutes before it expires, handed to the tenant's containers over
//! a unix socket with four routes. Trust comes from the measured compose (the KMS CA's SPKI
//! hash, and the allowed KMS Revisions or the floor of the release-signed platform document that
//! lists them); the KMS endpoints are only where to look. In a Kata pod
//! the same variables come from the pod spec, and the evidence is the quote, with every GPU's
//! evidence when the pod has GPUs.

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

pub mod acme;
pub mod gpu;
pub mod proxy;
pub mod socket;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use alpha_attest::{AttestationResult, Collateral, InstanceEvidence};
use alpha_client::log::Field;
use alpha_client::platform::ReleaseKeys;
use alpha_client::tls::{self, InstanceSans};
use alpha_client::{
    AttestReply, AttestRequest, Client, DerivedKey, Identity, Pin, Secret, TimeProvider,
};
use alpha_core::{AppId, ComposeHash, MAX_INIT_DATA};
use base64::Engine;
use base64::prelude::{BASE64_STANDARD, BASE64_URL_SAFE_NO_PAD};
use p256::ecdsa::SigningKey;
use p256::pkcs8::{EncodePrivateKey, EncodePublicKey};
use parking_lot::{Mutex, RwLock};
use rustls::sign::CertifiedKey;
use tokio::net::UnixListener;
use tokio::sync::watch;
use zeroize::Zeroizing;

pub use alpha_client::runtime::{SOCKET_PATH, TLS_PORT};

/// Plain HTTP for the host: `GET /leaf` always, and `GET /ready` for a kubelet probe when a
/// readiness path is named. A Kata agent policy refuses exec, and the host cannot present an
/// Instance leaf to a caller-pinned Endpoint.
pub const PROBE_PORT: u16 = 8444;

pub const RENEW_BEFORE: Duration = Duration::from_secs(600);
const RETRY_AFTER: Duration = Duration::from_secs(30);
/// A quote request lost by the host's quote service never completes; without a bound, the
/// leaf would expire with no further attempt.
const ATTEST_TIMEOUT: Duration = Duration::from_secs(60);
/// Each missing Secret is a denied `secret.get` audit row on the KMS; the backoff doubles from
/// here up to `SECRETS_POLL`, so a Secret never set costs one row a minute.
const SECRETS_FIRST_RETRY: Duration = Duration::from_secs(2);
/// With every file written a pass hits the leaf's cache, so it costs nothing until a renewal.
const SECRETS_POLL: Duration = Duration::from_secs(60);

/// Intel signs the collateral, so its source does not matter; Intel's own PCS answers without a
/// key.
const INTEL_PCS: &str = "https://api.trustedservices.intel.com";
const COLLATERAL_TIMEOUT: Duration = Duration::from_secs(10);

/// Distinct purposes cached per leaf; beyond it a key is still served, derived again on every
/// read, so a caller naming ever new purposes cannot grow the process.
pub const CACHED_KEYS: usize = 64;

pub const EXIT_REFUSED: i32 = 1;
pub const EXIT_REVOKED: i32 = 78;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A missing or malformed environment variable; the message names it.
    #[error("config: {0}")]
    Config(String),
    #[error("runtime key: {0}")]
    Key(String),
    #[error("evidence: {0}")]
    Evidence(String),
    #[error("kms: {0}")]
    Kms(#[from] alpha_client::Error),
    /// The KMS answered with a chain that is not ours or not under the pinned CA.
    #[error("certificate: {0}")]
    Certificate(String),
    #[error("no valid certificate; the last attestation did not succeed or has expired")]
    NotAttested,
    #[error("socket: {0}")]
    Socket(String),
    #[error("platform document: {0}")]
    Platform(String),
    #[error("attestation timed out")]
    TimedOut,
}

impl Error {
    pub fn kind(&self) -> &'static str {
        match self {
            Error::Config(_) => "config",
            Error::Key(_) => "key",
            Error::Evidence(_) => "evidence",
            Error::Kms(e) => e.kind(),
            Error::Certificate(_) => "certificate",
            Error::NotAttested => "not_attested",
            Error::Socket(_) => "socket",
            Error::Platform(_) => "platform_document",
            Error::TimedOut => "timed_out",
        }
    }

    /// The one error that ends the process instead of being retried.
    pub fn revoked(&self) -> bool {
        matches!(self, Error::Kms(alpha_client::Error::Api(e)) if e.code == "revision_revoked")
    }

    pub fn exit_code(&self) -> i32 {
        if self.revoked() {
            EXIT_REVOKED
        } else {
            EXIT_REFUSED
        }
    }
}

/// Why `run` returned, as the process exit code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exit {
    Drained,
    Revoked,
    /// The leaf expired while attestations kept timing out; a restart is the last way to
    /// collect a quote again.
    QuoteStuck,
}

impl Exit {
    pub fn code(self) -> i32 {
        match self {
            Exit::Drained => 0,
            Exit::Revoked => EXIT_REVOKED,
            Exit::QuoteStuck => 1,
        }
    }
}

/// Each declaring service's tmpfs volume is mounted read-write here at `<SECRETS_DIR>/<service>`
/// and read-only at `/run/secrets` in that service, so a file reaches only the services that
/// declared it.
pub const SECRETS_DIR: &str = "/run/alpha-secrets";

/// Service name to the Secret names it declared.
pub type Secrets = BTreeMap<String, BTreeSet<String>>;

/// `ALPHACOMPUTE_SECRETS`: a JSON object of service name to an array of Secret names; unset
/// declares none.
pub fn parse_secrets(text: Option<&str>) -> Result<Secrets, Error> {
    let Some(text) = text else {
        return Ok(Secrets::default());
    };
    let refused = |m: String| Error::Config(format!("ALPHACOMPUTE_SECRETS: {m}"));
    let value = alpha_core::parse(text.as_bytes()).map_err(|e| refused(e.to_string()))?;
    let secrets: Secrets = serde_json::from_value(value).map_err(|e| refused(e.to_string()))?;
    // The wrap checks these too, but they become path segments under SECRETS_DIR and a
    // hand-written compose must not reach outside it.
    for (service, names) in &secrets {
        if !alpha_core::is_key_purpose(service) {
            return Err(refused(format!(
                "service {service:?} is not a lowercase path segment"
            )));
        }
        if let Some(name) = names.iter().find(|n| !alpha_core::is_key_purpose(n)) {
            return Err(refused(format!(
                "{service}: secret {name:?} is not a lowercase path segment"
            )));
        }
    }
    Ok(secrets)
}

/// `ALPHACOMPUTE_TLS_UPSTREAM`: `<service>:<port>`, the service a wrapped compose publishes,
/// reached over the compose network; unset means no TLS listener.
pub fn parse_upstream(text: Option<&str>) -> Result<Option<String>, Error> {
    let Some(text) = text else {
        return Ok(None);
    };
    let refused = |m: &str| Error::Config(format!("ALPHACOMPUTE_TLS_UPSTREAM: {text:?} {m}"));
    let (host, port) = text
        .rsplit_once(':')
        .ok_or_else(|| refused("is not <service>:<port>"))?;
    if !alpha_client::runtime::is_upstream_host(host) {
        return Err(refused("does not name a lowercase compose service"));
    }
    Some(port)
        .filter(|p| p.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|p| p.parse::<std::num::NonZeroU16>().ok())
        .ok_or_else(|| refused("does not end in a port from 1 to 65535"))?;
    Ok(Some(text.to_owned()))
}

/// `ALPHACOMPUTE_TLS_CALLER_APPS`: comma-separated App ids whose Instance leaves alone may open
/// the Endpoint; unset or empty admits any client.
pub fn parse_callers(text: Option<&str>, upstream: Option<&str>) -> Result<Vec<AppId>, Error> {
    let refused = |m: String| Error::Config(format!("ALPHACOMPUTE_TLS_CALLER_APPS: {m}"));
    let callers = list(text.unwrap_or_default())
        .map(|s| {
            s.parse()
                .map_err(|_| refused(format!("{s:?} is not an App id")))
        })
        .collect::<Result<Vec<AppId>, _>>()?;
    if !callers.is_empty() && upstream.is_none() {
        return Err(refused("set without ALPHACOMPUTE_TLS_UPSTREAM".into()));
    }
    Ok(callers)
}

/// `ALPHACOMPUTE_TLS_UPSTREAM_READY`: the upstream's own readiness path, such as vLLM's
/// `/health`; set, [`PROBE_PORT`] also serves plain-HTTP `GET /ready`.
pub fn parse_ready(text: Option<&str>, upstream: Option<&str>) -> Result<Option<String>, Error> {
    let Some(text) = text else {
        return Ok(None);
    };
    let refused = |m: &str| Error::Config(format!("ALPHACOMPUTE_TLS_UPSTREAM_READY: {m}"));
    if upstream.is_none() {
        return Err(refused("set without ALPHACOMPUTE_TLS_UPSTREAM"));
    }
    // It goes into a request line verbatim.
    if !text.starts_with('/') || text.len() > 256 || !text.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(refused(
            "is not a path: a leading /, printable ASCII without spaces, at most 256 bytes",
        ));
    }
    Ok(Some(text.to_owned()))
}

/// The KMS builds the runtime accepts, under the pinned CA either way.
#[derive(Clone, Debug)]
pub enum KmsRevisions {
    /// `ALPHACOMPUTE_KMS_REVISIONS`: a new KMS build needs a new Revision of the App.
    Listed(Vec<ComposeHash>),
    /// `ALPHACOMPUTE_PLATFORM_DOCUMENT_URL`: the `kms_revisions` of the document fetched before
    /// every attestation, at `ALPHACOMPUTE_PLATFORM_MIN_VERSION` or above, never below a
    /// version this process accepted.
    Document {
        url: String,
        min_version: u64,
        keys: Arc<ReleaseKeys>,
    },
}

impl KmsRevisions {
    pub fn parse(
        listed: Option<&str>,
        document_url: Option<&str>,
        min_version: Option<&str>,
    ) -> Result<Self, Error> {
        match (listed, document_url, min_version) {
            (Some(listed), None, None) => {
                let revisions = list(listed)
                    .map(|s| {
                        s.parse().map_err(|_| {
                            Error::Config(format!(
                                "ALPHACOMPUTE_KMS_REVISIONS: {s:?} is not sha256:<64 hex>"
                            ))
                        })
                    })
                    .collect::<Result<Vec<ComposeHash>, _>>()?;
                if revisions.is_empty() {
                    return Err(Error::Config("ALPHACOMPUTE_KMS_REVISIONS is empty".into()));
                }
                Ok(Self::Listed(revisions))
            }
            (None, Some(url), min_version) => {
                let url = url.trim();
                if !url.starts_with("https://") {
                    return Err(Error::Config(
                        "ALPHACOMPUTE_PLATFORM_DOCUMENT_URL is not https".into(),
                    ));
                }
                // Without a floor a host could serve the oldest signed document, which may list
                // a build every later one dropped.
                let min_version = min_version
                    .and_then(|v| v.trim().parse::<u64>().ok())
                    .filter(|v| *v > 0)
                    .ok_or_else(|| {
                        Error::Config(
                            "ALPHACOMPUTE_PLATFORM_MIN_VERSION is not a version from 1".into(),
                        )
                    })?;
                let keys = alpha_client::platform::release_keys()
                    .map_err(|e| Error::Config(format!("release keys: {e}")))?;
                Ok(Self::Document {
                    url: url.to_owned(),
                    min_version,
                    keys: Arc::new(keys),
                })
            }
            _ => Err(Error::Config(
                "set either ALPHACOMPUTE_KMS_REVISIONS, or ALPHACOMPUTE_PLATFORM_DOCUMENT_URL \
                 with ALPHACOMPUTE_PLATFORM_MIN_VERSION"
                    .into(),
            )),
        }
    }
}

/// The three environment variables and, when a service declared a Secret,
/// `ALPHACOMPUTE_SECRETS`; for a wrapped compose or a Kata pod with an Endpoint,
/// `ALPHACOMPUTE_TLS_UPSTREAM` and optionally its caller pin, readiness path or public name,
/// and the file `ALPHACOMPUTE_ACME_CACHE` that keeps the public certificate across restarts.
#[derive(Clone, Debug)]
pub struct Config {
    pub kms_ca_spki_sha256: [u8; 32],
    pub kms_revisions: KmsRevisions,
    pub kms_endpoints: Vec<String>,
    pub secrets: Secrets,
    pub tls_upstream: Option<String>,
    pub tls_callers: Vec<AppId>,
    pub tls_ready: Option<String>,
    pub public: Option<String>,
    pub acme_cache: Option<PathBuf>,
}

impl Config {
    pub fn from_env() -> Result<Self, Error> {
        let var = |name: &str| {
            std::env::var(name).map_err(|_| Error::Config(format!("{name} is not set")))
        };
        let optional = |name: &str| std::env::var(name).ok();
        let config = Self::parse(
            &var("ALPHACOMPUTE_KMS_CA_SPKI_SHA256")?,
            KmsRevisions::parse(
                optional("ALPHACOMPUTE_KMS_REVISIONS").as_deref(),
                optional("ALPHACOMPUTE_PLATFORM_DOCUMENT_URL").as_deref(),
                optional("ALPHACOMPUTE_PLATFORM_MIN_VERSION").as_deref(),
            )?,
            &var("ALPHACOMPUTE_KMS_ENDPOINTS")?,
            std::env::var("ALPHACOMPUTE_SECRETS").ok().as_deref(),
            std::env::var("ALPHACOMPUTE_TLS_UPSTREAM").ok().as_deref(),
            std::env::var("ALPHACOMPUTE_TLS_CALLER_APPS")
                .ok()
                .as_deref(),
            std::env::var("ALPHACOMPUTE_TLS_UPSTREAM_READY")
                .ok()
                .as_deref(),
        )?;
        let public = acme::parse_public_name(
            optional("ALPHACOMPUTE_PUBLIC_NAME").as_deref(),
            config.tls_upstream.as_deref(),
            &config.tls_callers,
        )?;
        Ok(Self {
            public,
            acme_cache: optional("ALPHACOMPUTE_ACME_CACHE").map(PathBuf::from),
            ..config
        })
    }

    pub fn parse(
        ca_spki_sha256: &str,
        kms_revisions: KmsRevisions,
        endpoints: &str,
        secrets: Option<&str>,
        tls_upstream: Option<&str>,
        tls_callers: Option<&str>,
        tls_ready: Option<&str>,
    ) -> Result<Self, Error> {
        let kms_ca_spki_sha256 = ca_spki_sha256
            .trim()
            .strip_prefix("sha256:")
            .and_then(alpha_core::hex_bytes::<32>)
            .ok_or_else(|| {
                Error::Config("ALPHACOMPUTE_KMS_CA_SPKI_SHA256 is not sha256:<64 hex>".into())
            })?;
        let kms_endpoints: Vec<String> = list(endpoints)
            .map(|s| s.trim_end_matches('/').to_owned())
            .collect();
        if kms_endpoints.is_empty() {
            return Err(Error::Config("ALPHACOMPUTE_KMS_ENDPOINTS is empty".into()));
        }
        let secrets = parse_secrets(secrets)?;
        let tls_upstream = parse_upstream(tls_upstream)?;
        let tls_callers = parse_callers(tls_callers, tls_upstream.as_deref())?;
        let tls_ready = parse_ready(tls_ready, tls_upstream.as_deref())?;
        Ok(Self {
            kms_ca_spki_sha256,
            kms_revisions,
            kms_endpoints,
            secrets,
            tls_upstream,
            tls_callers,
            tls_ready,
            public: None,
            acme_cache: None,
        })
    }
}

fn list(text: &str) -> impl Iterator<Item = &str> {
    text.split(',').map(str::trim).filter(|s| !s.is_empty())
}

/// Writes `value` to `dir/name` whole: a 0444 temp file in the same directory renamed over the
/// name. A file already holding `value` is left alone; `dir` is never created.
pub fn write_secret(dir: &Path, name: &str, value: &[u8]) -> std::io::Result<()> {
    let path = dir.join(name);
    if std::fs::read(&path)
        .map(Zeroizing::new)
        .is_ok_and(|current| current.as_slice() == value)
    {
        return Ok(());
    }
    // No Secret name starts with a dot, so the temp file never collides with one.
    let temp = dir.join(format!(".{name}.tmp"));
    let _ = std::fs::remove_file(&temp);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o444)
        .open(&temp)?;
    // The process umask narrows the mode given at creation, and the reading service usually
    // runs as another user.
    file.set_permissions(std::fs::Permissions::from_mode(0o444))?;
    file.write_all(value)?;
    drop(file);
    std::fs::rename(&temp, &path)
}

/// Whether every declared Secret is a file under `root`; what a declaring service's
/// `service_healthy` dependency waits on.
// ponytail: one health for the whole runtime, so a declaring service also waits for every other
// service's Secrets; acceptable while a tenant sets them in one session; the upgrade is a
// per-service check the wrap can point each service's dependency at.
pub fn healthcheck(root: &Path, secrets: &Secrets) -> bool {
    secrets.iter().all(|(service, names)| {
        let dir = root.join(service);
        names.iter().all(|name| dir.join(name).is_file())
    })
}

/// The outcome of one pass over the declared Secrets.
#[derive(Debug, PartialEq, Eq)]
pub enum Delivery {
    /// Every declared file holds the KMS's current value.
    Complete,
    /// These names are not stored yet, or could not be fetched or written.
    Incomplete(Vec<String>),
    /// The Revision is revoked; nothing more is written.
    Revoked,
}

pub type Clock = Arc<dyn Fn() -> SystemTime + Send + Sync>;

/// A quote over `report_data`, with the event log behind it on dstack; the TD in `main`, a
/// capture in tests.
pub type EvidenceSource = Arc<dyn Fn(&[u8; 64]) -> Result<InstanceEvidence, String> + Send + Sync>;

/// The bytes whose SHA-256 is the Instance's Revision, served on `/v1/identity` once a leaf
/// names that hash.
pub enum RevisionText {
    /// dstack: the guest agent's `app-compose.json`.
    Compose(String),
    /// Kata: the init-data TOML the pod's annotation carries.
    InitData(String),
}

/// Where a Kata pod mounts its init-data annotation through the downward API.
pub const INIT_DATA_PATH: &str = "/run/alpha-init-data/cc_init_data";

/// The init-data out of the annotation's text, `base64(gzip(toml))`; None when the pod mounts
/// none. The host can write anything there, so the leaf's Revision is what makes it the pod's.
pub fn read_init_data(path: &Path) -> Result<Option<String>, Error> {
    let refused = |m: String| Error::Evidence(format!("init-data {}: {m}", path.display()));
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(refused(e.to_string())),
    };
    // The same bound for the encoded annotation: gzip of TOML stays far below it.
    let annotation = read_under_limit(file).map_err(|m| refused(format!("annotation: {m}")))?;
    let gzip = BASE64_STANDARD
        .decode(annotation.trim())
        .map_err(|e| refused(format!("not base64: {e}")))?;
    read_under_limit(flate2::read::GzDecoder::new(gzip.as_slice()))
        .map(Some)
        .map_err(|m| refused(format!("not gzip of UTF-8 or too long: {m}")))
}

fn read_under_limit(reader: impl Read) -> Result<String, String> {
    let mut text = String::new();
    reader
        .take(MAX_INIT_DATA as u64)
        .read_to_string(&mut text)
        .map_err(|e| e.to_string())?;
    if text.len() >= MAX_INIT_DATA {
        return Err(format!("{MAX_INIT_DATA} bytes or more"));
    }
    Ok(text)
}

/// Without collateral the Instance still attests to the KMS; only a browser's own check waits for
/// the next renewal.
async fn collateral(quote: &[u8]) -> Option<Collateral> {
    let fetched = tokio::time::timeout(
        COLLATERAL_TIMEOUT,
        alpha_attest::fetch_collateral(INTEL_PCS, quote),
    )
    .await;
    if let Ok(Ok(collateral)) = fetched {
        return Some(collateral);
    }
    alpha_client::warn!("collateral_unavailable");
    None
}

/// How long to wait before renewing: ten minutes before `not_after`, or at once if that has passed.
pub fn renewal_delay(not_after: SystemTime, now: SystemTime) -> Duration {
    not_after
        .duration_since(now)
        .unwrap_or_default()
        .saturating_sub(RENEW_BEFORE)
}

/// What one successful attestation leaves behind, replaced whole on renewal.
pub struct Attested {
    pub identity: InstanceSans,
    pub chain_pem: Vec<String>,
    pub not_after: SystemTime,
    pub result: AttestationResult,
    /// The leaf and the runtime key as the TLS listener serves them.
    pub certified: Arc<CertifiedKey>,
    /// What the leaf's key was attested with, and Intel's collateral for the quote on an Endpoint
    /// with a public name, so a browser can appraise the TD itself.
    pub evidence: InstanceEvidence,
    pub nonce: [u8; 32],
    pub collateral: Option<Collateral>,
    client: Client,
    secrets: Mutex<HashMap<String, Secret>>,
    keys: Mutex<HashMap<String, DerivedKey>>,
}

pub struct Runtime {
    config: Config,
    pkcs8: Zeroizing<Vec<u8>>,
    spki: Vec<u8>,
    clock: Clock,
    time: TimeProvider,
    evidence: EvidenceSource,
    /// None in a Kata pod that mounts no init-data; the KMS names the Revision from the
    /// verified `MRCONFIGID` either way.
    revision: Option<RevisionText>,
    /// The version and `kms_revisions` of the newest platform document this process accepted.
    accepted: Mutex<Option<(u64, Vec<ComposeHash>)>>,
    attested: RwLock<Option<Arc<Attested>>>,
    revoked: watch::Sender<bool>,
}

impl Runtime {
    pub fn new(
        config: Config,
        key: &SigningKey,
        clock: Clock,
        evidence: EvidenceSource,
        time: TimeProvider,
        revision: Option<RevisionText>,
    ) -> Result<Arc<Self>, Error> {
        let key_error = |e: p256::pkcs8::Error| Error::Key(e.to_string());
        let spki = key
            .verifying_key()
            .to_public_key_der()
            .map_err(|e| key_error(e.into()))?
            .into_vec();
        let pkcs8 = Zeroizing::new(key.to_pkcs8_der().map_err(key_error)?.to_bytes().to_vec());
        Ok(Arc::new(Self {
            config,
            pkcs8,
            spki,
            clock,
            time,
            evidence,
            revision,
            accepted: Mutex::new(None),
            attested: RwLock::new(None),
            revoked: watch::Sender::new(false),
        }))
    }

    pub fn now(&self) -> SystemTime {
        (self.clock)()
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn spki(&self) -> &[u8] {
        &self.spki
    }

    pub fn tls_private_key(&self) -> &[u8] {
        &self.pkcs8
    }

    /// The Kata init-data read at start, the text of the leaf's Revision.
    pub fn init_data(&self) -> Option<&str> {
        match &self.revision {
            Some(RevisionText::InitData(text)) => Some(text),
            _ => None,
        }
    }

    pub fn is_revoked(&self) -> bool {
        *self.revoked.borrow()
    }

    /// The last attestation, whether or not its certificate is still valid.
    pub fn last(&self) -> Option<Arc<Attested>> {
        self.attested.read().clone()
    }

    /// The last attestation while its certificate is valid.
    pub fn attested(&self) -> Option<Arc<Attested>> {
        self.last().filter(|a| self.now() < a.not_after)
    }

    fn note(&self, error: Error) -> Error {
        if error.revoked() {
            self.revoked.send_replace(true);
        }
        error
    }

    /// Nonce → `report_data` → quote → leaf; the first call is the Instance's birth, later ones renew.
    pub async fn attest(&self) -> Result<Arc<Attested>, Error> {
        let attested = tokio::time::timeout(ATTEST_TIMEOUT, self.attest_inner())
            .await
            .unwrap_or(Err(Error::TimedOut))
            .map_err(|e| self.note(e))?;
        *self.attested.write() = Some(attested.clone());
        Ok(attested)
    }

    /// Each attestation dials under the Revisions current at that moment, so a connection from
    /// a build the latest document dropped is never reused.
    async fn attest_inner(&self) -> Result<Arc<Attested>, Error> {
        let pin =
            Pin::CaSpkiAndRevisions(self.config.kms_ca_spki_sha256, self.kms_revisions().await?);
        let kms = Client::configured(
            self.config.kms_endpoints.clone(),
            pin.clone(),
            None,
            self.time.clone(),
        )?;
        let nonce = kms.attest_nonce().await?;
        let nonce: [u8; 32] = alpha_client::decode("nonce", &nonce.nonce)?
            .try_into()
            .map_err(|_| alpha_client::Error::Invalid("nonce is not 32 bytes".into()))?;
        let report_data = alpha_attest::report_data(&self.spki, &nonce, None);
        let source = self.evidence.clone();
        let evidence = tokio::task::spawn_blocking(move || source(&report_data))
            .await
            .map_err(|e| Error::Evidence(e.to_string()))?
            .map_err(Error::Evidence)?;
        let reply = kms
            .attest(&AttestRequest {
                runtime_pubkey: BASE64_URL_SAFE_NO_PAD.encode(&self.spki),
                nonce: BASE64_URL_SAFE_NO_PAD.encode(nonce),
                evidence: evidence.clone(),
            })
            .await?;
        let collateral = match self.config.public {
            Some(_) => collateral(evidence.quote()).await,
            None => None,
        };
        self.accept(reply, pin, evidence, nonce, collateral)
    }

    /// A failed fetch, or a document not above the accepted one, keeps the accepted list.
    /// Nothing accepted yet, either refuses.
    async fn kms_revisions(&self) -> Result<Vec<ComposeHash>, Error> {
        let (url, min_version, keys) = match &self.config.kms_revisions {
            KmsRevisions::Listed(revisions) => return Ok(revisions.clone()),
            KmsRevisions::Document {
                url,
                min_version,
                keys,
            } => (url, *min_version, keys),
        };
        let fetched = alpha_client::platform::fetch_signed(url)
            .await
            .and_then(|signed| alpha_client::platform::verify(&signed, keys, self.now()));
        let mut accepted = self.accepted.lock();
        let current = accepted.as_ref().map(|(version, _)| *version);
        let newer = |version: u64| current.map_or(version >= min_version, |v| version > v);
        let refused = match fetched {
            Ok(doc) if newer(doc.version) => {
                let revisions: Vec<ComposeHash> =
                    doc.kms_revisions.iter().map(|r| r.compose_hash).collect();
                *accepted = Some((doc.version, revisions.clone()));
                return Ok(revisions);
            }
            Ok(doc) if Some(doc.version) == current => None,
            Ok(doc) => Some(format!(
                "version {} is below {}",
                doc.version,
                current.unwrap_or(min_version)
            )),
            Err(e) => Some(e.to_string()),
        };
        match (accepted.as_ref(), refused) {
            (Some((version, revisions)), refused) => {
                if refused.is_some() {
                    alpha_client::warn!("platform_document_refused", kept = *version);
                }
                Ok(revisions.clone())
            }
            (None, refused) => Err(Error::Platform(refused.unwrap_or_default())),
        }
    }

    /// The reply's chain is ours only if the leaf carries our key and the root the pinned one;
    /// the ids come from the leaf's SANs, never from the reply's text.
    fn accept(
        &self,
        reply: AttestReply,
        pin: Pin,
        evidence: InstanceEvidence,
        nonce: [u8; 32],
        collateral: Option<Collateral>,
    ) -> Result<Arc<Attested>, Error> {
        let chain: Vec<Vec<u8>> = reply
            .certificate_chain
            .iter()
            .map(|pem| tls::cert_from_pem(pem).map(|c| c.to_vec()))
            .collect::<Result<_, _>>()?;
        let [leaf, ca] = chain.as_slice() else {
            return Err(Error::Certificate("chain is not [leaf, ca]".into()));
        };
        if tls::spki_of(leaf).map_err(alpha_client::Error::from)? != self.spki {
            return Err(Error::Certificate(
                "leaf is not over the runtime key".into(),
            ));
        }
        if tls::spki_sha256(ca) != Some(self.config.kms_ca_spki_sha256) {
            return Err(Error::Certificate(
                "chain does not end at the pinned ca".into(),
            ));
        }
        let identity = tls::uri_sans(leaf)
            .and_then(|sans| tls::parse_instance_sans(&sans))
            .map_err(alpha_client::Error::from)?;
        if let Some(RevisionText::Compose(text) | RevisionText::InitData(text)) = &self.revision
            && alpha_core::compose_hash(text) != identity.compose_hash
        {
            return Err(Error::Certificate(
                "the app_compose or init-data read at start is not the leaf's Revision".into(),
            ));
        }
        let certified =
            tls::certified(chain.iter().cloned().map(Into::into).collect(), &self.pkcs8)?;
        let not_after = chrono::DateTime::parse_from_rfc3339(&reply.not_after)
            .map_err(|e| Error::Certificate(format!("not_after: {e}")))?
            .into();
        let client = Client::configured(
            self.config.kms_endpoints.clone(),
            pin,
            Some(Identity {
                chain: chain.clone(),
                pkcs8: self.pkcs8.to_vec(),
            }),
            self.time.clone(),
        )?;
        Ok(Arc::new(Attested {
            identity,
            chain_pem: reply.certificate_chain,
            not_after,
            result: reply.attestation_result,
            certified,
            evidence,
            nonce,
            collateral,
            client,
            secrets: Mutex::new(HashMap::new()),
            keys: Mutex::new(HashMap::new()),
        }))
    }

    /// From the KMS over mTLS with the current leaf, cached with it.
    pub async fn secret(&self, name: &str) -> Result<Secret, Error> {
        let attested = self.attested().ok_or(Error::NotAttested)?;
        if let Some(secret) = attested.secrets.lock().get(name) {
            return Ok(secret.clone());
        }
        let secret = attested
            .client
            .get_secret(name)
            .await
            .map_err(|e| self.note(e.into()))?;
        attested
            .secrets
            .lock()
            .insert(name.to_owned(), secret.clone());
        Ok(secret)
    }

    /// The App's key for `purpose`, derived by the KMS over mTLS with the current leaf, cached
    /// with it.
    pub async fn key(&self, purpose: &str) -> Result<DerivedKey, Error> {
        let attested = self.attested().ok_or(Error::NotAttested)?;
        if let Some(key) = attested.keys.lock().get(purpose) {
            return Ok(key.clone());
        }
        let key = attested
            .client
            .derive_key(purpose)
            .await
            .map_err(|e| self.note(e.into()))?;
        let mut keys = attested.keys.lock();
        if keys.len() < CACHED_KEYS {
            keys.insert(purpose.to_owned(), key.clone());
        }
        Ok(key)
    }

    /// One pass: every declared name fetched once, through the leaf's cache, and written into
    /// the directory of each service that declared it.
    // ponytail: files already written stay after a revocation or after a Secret leaves the App's
    // grant, until the volume's last container stops (the lifetime of a cached secret); the
    // upgrade is removing a delivered file once the KMS stops serving it.
    pub async fn deliver(&self, root: &Path) -> Delivery {
        if self.is_revoked() {
            return Delivery::Revoked;
        }
        let names: BTreeSet<&String> = self.config.secrets.values().flatten().collect();
        let Some(app_id) = self.attested().map(|a| a.identity.app_id) else {
            alpha_client::warn!("secrets_not_attested");
            return Delivery::Incomplete(names.into_iter().cloned().collect());
        };
        let mut incomplete = Vec::new();
        for name in names {
            // Secrets are unique per organization and name, so two Apps declaring the same name
            // would replace each other's value and grant.
            let secret = match self.secret(&format!("{app_id}.{name}")).await {
                Ok(secret) => secret,
                Err(e) if e.revoked() => return Delivery::Revoked,
                Err(e) => {
                    if !matches!(&e, Error::Kms(alpha_client::Error::Api(api)) if api.code == "not_found")
                    {
                        alpha_client::warn!(
                            "secret_unavailable",
                            secret = Field::text(name),
                            error = e.kind(),
                        );
                    }
                    incomplete.push(name.clone());
                    continue;
                }
            };
            let Ok(value) = BASE64_URL_SAFE_NO_PAD
                .decode(&secret.value)
                .map(Zeroizing::new)
            else {
                alpha_client::warn!("secret_not_base64url", secret = Field::text(name));
                incomplete.push(name.clone());
                continue;
            };
            let declaring = self
                .config
                .secrets
                .iter()
                .filter(|(_, declared)| declared.contains(name));
            for (service, _) in declaring {
                if let Err(e) = write_secret(&root.join(service), name, &value) {
                    alpha_client::error!(
                        "secret_write_failed",
                        secret = Field::text(name),
                        target_service = Field::text(service),
                        error = e.kind(),
                    );
                    if incomplete.last() != Some(name) {
                        incomplete.push(name.clone());
                    }
                }
            }
        }
        if incomplete.is_empty() {
            Delivery::Complete
        } else {
            Delivery::Incomplete(incomplete)
        }
    }

    async fn deliver_forever(&self, root: PathBuf) {
        if self.config.secrets.is_empty() {
            return;
        }
        let mut retry = SECRETS_FIRST_RETRY;
        let mut waiting = Vec::new();
        loop {
            match self.deliver(&root).await {
                Delivery::Revoked => return,
                Delivery::Complete => {
                    retry = SECRETS_FIRST_RETRY;
                    waiting.clear();
                    tokio::time::sleep(SECRETS_POLL).await;
                }
                Delivery::Incomplete(names) => {
                    if names != waiting {
                        alpha_client::warn!(
                            "secrets_waiting",
                            secrets = Field::text(&names.join(",")),
                        );
                        waiting = names;
                    }
                    tokio::time::sleep(retry).await;
                    retry = retry.saturating_mul(2).min(SECRETS_POLL);
                }
            }
        }
    }

    async fn renew_forever(&self) -> Exit {
        loop {
            let delay = match self.last() {
                Some(a) => renewal_delay(a.not_after, self.now()),
                None => Duration::ZERO,
            };
            tokio::time::sleep(delay).await;
            match self.attest().await {
                Ok(a) => alpha_client::info!("renewed", not_after = a.not_after),
                Err(e) if e.revoked() => return Exit::Revoked,
                Err(Error::TimedOut) if self.attested().is_none() => {
                    alpha_client::error!("attestation_stuck");
                    return Exit::QuoteStuck;
                }
                Err(e) => {
                    alpha_client::warn!("renewal_failed", error = e.kind());
                    tokio::time::sleep(RETRY_AFTER).await;
                }
            }
        }
    }

    /// Serves the socket, renews the leaf, keeps the declared Secret files under
    /// `secrets_root` current and, given `tls` and an upstream, proxies the Endpoint until
    /// `shutdown` resolves, the Revision is revoked or the leaf expires behind a stuck quote.
    /// Socket connections drain, except after a stuck quote; proxied ones drain on shutdown
    /// and are cut otherwise.
    pub async fn run(
        self: Arc<Self>,
        listener: UnixListener,
        secrets_root: PathBuf,
        tls: Option<proxy::Endpoint>,
        shutdown: impl Future<Output = ()>,
    ) -> Exit {
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(
            axum::serve(listener, socket::router(self.clone()))
                .with_graceful_shutdown(async move {
                    let _ = stopped.await;
                })
                .into_future(),
        );
        let delivery = tokio::spawn({
            let runtime = self.clone();
            async move { runtime.deliver_forever(secrets_root).await }
        });
        let (stop_proxy, proxy_stopped) = tokio::sync::oneshot::channel::<Exit>();
        let proxy = tls.map(|endpoint| {
            tokio::spawn(
                endpoint.serve(async move { proxy_stopped.await.unwrap_or(Exit::Revoked) }),
            )
        });
        let mut revoked = self.revoked.subscribe();
        let exit = tokio::select! {
            () = shutdown => Exit::Drained,
            _ = revoked.wait_for(|r| *r) => Exit::Revoked,
            exit = self.renew_forever() => exit,
        };
        delivery.abort();
        let _ = stop.send(());
        let _ = stop_proxy.send(exit);
        if exit == Exit::QuoteStuck {
            server.abort();
        } else {
            let _ = server.await;
        }
        if let Some(proxy) = proxy {
            let _ = proxy.await;
        }
        exit
    }
}

#[cfg(test)]
mod tests {
    use std::time::UNIX_EPOCH;

    use super::*;

    const HASH: &str = "sha256:ee097e09c4824eb6424202fe20ed882d19a33a563f3b3dd5988f3ff8ee1b8335";

    fn listed() -> KmsRevisions {
        KmsRevisions::parse(Some(HASH), None, None).unwrap()
    }

    #[test]
    fn config_parses_the_three_variables_and_refuses_empty_or_malformed_ones() {
        let c = Config::parse(
            &format!(" {HASH} "),
            listed(),
            "https://a:8443/,, https://b:8443",
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            c.kms_ca_spki_sha256,
            alpha_core::hex_bytes(&HASH[7..]).unwrap()
        );
        assert_eq!(c.kms_endpoints, ["https://a:8443", "https://b:8443"]);

        let refused = |a: &str, c: &str| {
            let Err(Error::Config(m)) = Config::parse(a, listed(), c, None, None, None, None)
            else {
                panic!("{a} {c} was accepted");
            };
            m
        };
        assert!(refused(&HASH[7..], "x").contains("CA_SPKI"));
        assert!(refused(HASH, " , ").contains("ENDPOINTS"));
        assert!(refused("", "x").contains("CA_SPKI"));
        assert!(c.secrets.is_empty());
        assert!(c.tls_upstream.is_none());
    }

    #[test]
    fn kms_revisions_are_a_list_or_a_document_url_with_a_floor_never_both() {
        let KmsRevisions::Listed(r) =
            KmsRevisions::parse(Some(&format!("{HASH}, {HASH},")), None, None).unwrap()
        else {
            panic!("not a list");
        };
        assert_eq!(r.len(), 2);
        let url = "https://sign.example/sign/platform.json";
        let KmsRevisions::Document {
            url: parsed,
            min_version,
            ..
        } = KmsRevisions::parse(None, Some(url), Some(" 12 ")).unwrap()
        else {
            panic!("not a document");
        };
        assert_eq!((parsed.as_str(), min_version), (url, 12));

        let refused = |listed, url, min| {
            let Err(Error::Config(m)) = KmsRevisions::parse(listed, url, min) else {
                panic!("{listed:?} {url:?} {min:?} was accepted");
            };
            m
        };
        assert!(refused(Some(""), None, None).contains("REVISIONS is empty"));
        assert!(refused(Some("sha256:zz"), None, None).contains("REVISIONS"));
        assert!(refused(None, Some("http://a/p.json"), Some("1")).contains("not https"));
        for min in [None, Some("0"), Some("x"), Some("-1")] {
            assert!(refused(None, Some(url), min).contains("MIN_VERSION"));
        }
        for (listed, url, min) in [
            (None, None, None),
            (Some(HASH), Some(url), Some("1")),
            (Some(HASH), None, Some("1")),
        ] {
            assert!(refused(listed, url, min).starts_with("set either"));
        }
    }

    #[test]
    fn secrets_parse_the_wraps_variable() {
        let wrap = r#"{"db":["db_password"],"web":["db_password","session_key"]}"#;
        let c = Config::parse(HASH, listed(), "https://a", Some(wrap), None, None, None).unwrap();
        let set = |names: &[&str]| names.iter().map(|n| n.to_string()).collect::<BTreeSet<_>>();
        assert_eq!(
            c.secrets,
            Secrets::from([
                ("db".into(), set(&["db_password"])),
                ("web".into(), set(&["db_password", "session_key"])),
            ])
        );
    }

    #[test]
    fn secrets_refuse_anything_but_the_wraps_shape() {
        for bad in [
            r#"{"a":[],"a":[]}"#,
            "[]",
            r#""x""#,
            r#"{"web":"x"}"#,
            r#"{"web":[1]}"#,
            r#"{"Web":["x"]}"#,
            r#"{"web":[".."]}"#,
            r#"{"web":["a/b"]}"#,
            r#"{"..":["x"]}"#,
            r#"{"web":[""]}"#,
            "not json",
        ] {
            let Err(Error::Config(m)) = parse_secrets(Some(bad)) else {
                panic!("{bad} was accepted");
            };
            assert!(m.starts_with("ALPHACOMPUTE_SECRETS:"), "{bad}: {m}");
            let Err(Error::Config(m)) =
                Config::parse(HASH, listed(), "https://a", Some(bad), None, None, None)
            else {
                panic!("{bad} was accepted by Config::parse");
            };
            assert!(m.contains("ALPHACOMPUTE_SECRETS"), "{bad}: {m}");
        }
    }

    #[test]
    fn the_tls_upstream_is_a_lowercase_service_and_a_port() {
        assert_eq!(parse_upstream(None).unwrap(), None);
        let c = Config::parse(
            HASH,
            listed(),
            "https://a",
            None,
            Some("web:80"),
            None,
            None,
        )
        .unwrap();
        assert_eq!(c.tls_upstream.as_deref(), Some("web:80"));
        assert_eq!(
            parse_upstream(Some("localhost:65535")).unwrap().as_deref(),
            Some("localhost:65535")
        );
        for bad in [
            "web",
            "web:",
            ":80",
            "web:0",
            "web:65536",
            "web:+80",
            "Web:80",
            "../x:80",
            "web:80:1",
            "web/x:80",
            " web:80x",
            "a..b:80",
        ] {
            let Err(Error::Config(m)) =
                Config::parse(HASH, listed(), "https://a", None, Some(bad), None, None)
            else {
                panic!("{bad} was accepted");
            };
            assert!(m.starts_with("ALPHACOMPUTE_TLS_UPSTREAM:"), "{bad}: {m}");
        }
    }

    #[test]
    fn caller_apps_and_the_ready_path_need_an_upstream_and_their_shape() {
        let app = "0199e4a0-0000-7000-8000-000000000001";
        let parse = |callers, ready| {
            Config::parse(
                HASH,
                listed(),
                "https://a",
                None,
                Some("web:80"),
                callers,
                ready,
            )
        };
        let callers = format!(" {app},, {app} ");
        let c = parse(Some(&callers), Some("/health")).unwrap();
        assert_eq!(c.tls_callers, [app.parse::<AppId>().unwrap(); 2]);
        assert_eq!(c.tls_ready.as_deref(), Some("/health"));
        assert!(parse(Some(""), None).unwrap().tls_callers.is_empty());

        let refused = |r: Result<Config, Error>, var: &str| {
            let Err(Error::Config(m)) = r else {
                panic!("accepted");
            };
            assert!(m.starts_with(var), "{m}");
        };
        let unwrapped =
            |callers, ready| Config::parse(HASH, listed(), "https://a", None, None, callers, ready);
        refused(unwrapped(Some(app), None), "ALPHACOMPUTE_TLS_CALLER_APPS:");
        refused(
            unwrapped(None, Some("/health")),
            "ALPHACOMPUTE_TLS_UPSTREAM_READY:",
        );
        refused(
            parse(Some("not-a-uuid"), None),
            "ALPHACOMPUTE_TLS_CALLER_APPS:",
        );
        for bad in [
            "health",
            "/a b",
            "/a\r\nX: y",
            &format!("/{}", "a".repeat(256)),
        ] {
            refused(parse(None, Some(bad)), "ALPHACOMPUTE_TLS_UPSTREAM_READY:");
        }
    }

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("alpha-runtime-{}", alpha_core::KeyId::mint()));
        std::fs::create_dir(&dir).unwrap();
        dir
    }

    fn mode(path: &Path) -> u32 {
        std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(path).unwrap().permissions())
            & 0o777
    }

    #[test]
    fn a_secret_file_is_replaced_whole_and_stays_read_only() {
        let dir = temp_dir();
        let file = dir.join("k");
        write_secret(&dir, "k", b"one").unwrap();
        assert_eq!(std::fs::read(&file).unwrap(), b"one");
        assert_eq!(mode(&file), 0o444);

        write_secret(&dir, "k", b"two").unwrap();
        assert_eq!(std::fs::read(&file).unwrap(), b"two");
        assert_eq!(mode(&file), 0o444);
        assert!(!dir.join(".k.tmp").exists());

        std::fs::write(dir.join(".k.tmp"), b"half").unwrap();
        write_secret(&dir, "k", b"three").unwrap();
        assert_eq!(std::fs::read(&file).unwrap(), b"three");
        assert_eq!(mode(&file), 0o444);
        assert!(!dir.join(".k.tmp").exists());

        let missing = dir.join("missing");
        assert!(write_secret(&missing, "k", b"x").is_err());
        assert!(!missing.exists());
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn healthcheck_needs_every_declared_file() {
        let root = temp_dir();
        assert!(healthcheck(&root, &Secrets::new()));
        let web = root.join("web");
        std::fs::create_dir(&web).unwrap();
        let mut secrets = parse_secrets(Some(r#"{"web":["a","b"]}"#)).unwrap();
        assert!(!healthcheck(&root, &secrets));
        write_secret(&web, "a", b"1").unwrap();
        assert!(!healthcheck(&root, &secrets));
        std::fs::create_dir(web.join("b")).unwrap();
        assert!(!healthcheck(&root, &secrets), "a directory is not a file");
        std::fs::remove_dir(web.join("b")).unwrap();
        write_secret(&web, "b", b"2").unwrap();
        assert!(healthcheck(&root, &secrets));
        secrets.insert("db".into(), BTreeSet::from(["a".to_owned()]));
        assert!(!healthcheck(&root, &secrets));
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn renewal_is_ten_minutes_before_not_after_and_immediate_afterwards() {
        let t0 = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let not_after = t0 + Duration::from_secs(3600);
        assert_eq!(renewal_delay(not_after, t0), Duration::from_secs(3000));
        assert_eq!(
            renewal_delay(not_after, t0 + Duration::from_secs(3000)),
            Duration::ZERO
        );
        assert_eq!(
            renewal_delay(not_after, t0 + Duration::from_secs(3599)),
            Duration::ZERO
        );
        assert_eq!(
            renewal_delay(not_after, t0 + Duration::from_secs(7200)),
            Duration::ZERO
        );
    }

    #[test]
    fn init_data_is_read_from_the_annotation_and_a_bomb_is_refused() {
        let annotation = |bytes: &[u8]| {
            let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
            gzip.write_all(bytes).unwrap();
            BASE64_STANDARD.encode(gzip.finish().unwrap())
        };
        let dir = temp_dir();
        let path = dir.join("cc_init_data");
        assert_eq!(read_init_data(&path).unwrap(), None);

        let init_data = std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../testdata/attest/b300-kata-4.0.0/k3-app.toml"),
        )
        .unwrap();
        std::fs::write(&path, annotation(&init_data)).unwrap();
        let read = read_init_data(&path).unwrap().unwrap();
        assert_eq!(read.as_bytes(), init_data);

        std::fs::write(&path, annotation(&vec![b' '; MAX_INIT_DATA])).unwrap();
        assert!(read_init_data(&path).is_err());
        std::fs::write(&path, vec![b'A'; MAX_INIT_DATA]).unwrap();
        assert!(read_init_data(&path).is_err());
        std::fs::write(&path, "not base64").unwrap();
        assert!(read_init_data(&path).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn only_revision_revoked_exits_78() {
        let api = |code: &str| {
            Error::Kms(alpha_client::Error::Api(alpha_client::ApiError {
                code: code.into(),
                message: String::new(),
                request_id: String::new(),
                status: 409,
            }))
        };
        assert!(api("revision_revoked").revoked());
        assert_eq!(api("revision_revoked").exit_code(), 78);
        assert_eq!(Exit::Revoked.code(), 78);
        assert_eq!(Exit::Drained.code(), 0);
        for e in [
            api("attestation_unknown"),
            api("not_found"),
            Error::Kms(alpha_client::Error::Connect("down".into())),
            Error::Config("x".into()),
            Error::NotAttested,
        ] {
            assert!(!e.revoked(), "{e}");
            assert_eq!(e.exit_code(), 1);
        }
    }
}
