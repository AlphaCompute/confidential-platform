//! The in-CVM sidecar: one P-256 key for the life of the Instance, attested to the KMS into a
//! one-hour leaf renewed ten minutes before it expires, handed to the tenant's containers over
//! a unix socket with four routes. Trust comes from the measured compose (the KMS CA's SPKI
//! hash and the allowed KMS Revisions); the KMS endpoints are only where to look.

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

pub mod proxy;
pub mod socket;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use alpha_attest::{AttestationResult, EVIDENCE_FORMAT, Evidence};
use alpha_client::tls::{self, InstanceSans};
use alpha_client::{
    AttestReply, AttestRequest, Client, DerivedKey, Identity, Pin, Secret, TimeProvider,
};
use alpha_core::ComposeHash;
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use p256::ecdsa::SigningKey;
use p256::pkcs8::{EncodePrivateKey, EncodePublicKey};
use parking_lot::{Mutex, RwLock};
use rustls::sign::CertifiedKey;
use tokio::net::UnixListener;
use tokio::sync::watch;
use zeroize::Zeroizing;

pub use alpha_client::runtime::{SOCKET_PATH, TLS_PORT};

pub const RENEW_BEFORE: Duration = Duration::from_secs(600);
const RETRY_AFTER: Duration = Duration::from_secs(30);
/// Each missing Secret is a denied `secret.get` audit row on the KMS; the backoff doubles from
/// here up to `SECRETS_POLL`, so a Secret never set costs one row a minute.
const SECRETS_FIRST_RETRY: Duration = Duration::from_secs(2);
/// With every file written a pass hits the leaf's cache, so it costs nothing until a renewal.
const SECRETS_POLL: Duration = Duration::from_secs(60);

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
}

impl Error {
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
}

impl Exit {
    pub fn code(self) -> i32 {
        match self {
            Exit::Drained => 0,
            Exit::Revoked => EXIT_REVOKED,
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

/// The service a wrapped compose publishes, reached over the compose network.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Upstream {
    pub host: String,
    pub port: u16,
}

impl std::fmt::Display for Upstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

/// `ALPHACOMPUTE_TLS_UPSTREAM`: `<service>:<port>`; unset means no TLS listener.
pub fn parse_upstream(text: Option<&str>) -> Result<Option<Upstream>, Error> {
    let Some(text) = text else {
        return Ok(None);
    };
    let refused = |m: &str| Error::Config(format!("ALPHACOMPUTE_TLS_UPSTREAM: {text:?} {m}"));
    let (host, port) = text
        .rsplit_once(':')
        .ok_or_else(|| refused("is not <service>:<port>"))?;
    if !alpha_core::is_key_purpose(host) {
        return Err(refused("does not name a lowercase compose service"));
    }
    let port = Some(port)
        .filter(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|p| p.parse::<u16>().ok())
        .filter(|p| *p != 0)
        .ok_or_else(|| refused("does not end in a port from 1 to 65535"))?;
    Ok(Some(Upstream {
        host: host.to_owned(),
        port,
    }))
}

/// The three environment variables and, when a service declared a Secret,
/// `ALPHACOMPUTE_SECRETS`; for a wrapped compose, `ALPHACOMPUTE_TLS_UPSTREAM`.
#[derive(Clone, Debug)]
pub struct Config {
    pub kms_ca_spki_sha256: [u8; 32],
    pub kms_revisions: Vec<ComposeHash>,
    pub kms_endpoints: Vec<String>,
    pub secrets: Secrets,
    pub tls_upstream: Option<Upstream>,
}

impl Config {
    pub fn from_env() -> Result<Self, Error> {
        let var = |name: &str| {
            std::env::var(name).map_err(|_| Error::Config(format!("{name} is not set")))
        };
        Self::parse(
            &var("ALPHACOMPUTE_KMS_CA_SPKI_SHA256")?,
            &var("ALPHACOMPUTE_KMS_REVISIONS")?,
            &var("ALPHACOMPUTE_KMS_ENDPOINTS")?,
            std::env::var("ALPHACOMPUTE_SECRETS").ok().as_deref(),
            std::env::var("ALPHACOMPUTE_TLS_UPSTREAM").ok().as_deref(),
        )
    }

    pub fn parse(
        ca_spki_sha256: &str,
        revisions: &str,
        endpoints: &str,
        secrets: Option<&str>,
        tls_upstream: Option<&str>,
    ) -> Result<Self, Error> {
        let kms_ca_spki_sha256 = ca_spki_sha256
            .trim()
            .strip_prefix("sha256:")
            .and_then(alpha_core::hex_bytes::<32>)
            .ok_or_else(|| {
                Error::Config("ALPHACOMPUTE_KMS_CA_SPKI_SHA256 is not sha256:<64 hex>".into())
            })?;
        let kms_revisions = list(revisions)
            .map(|s| {
                s.parse().map_err(|_| {
                    Error::Config(format!(
                        "ALPHACOMPUTE_KMS_REVISIONS: {s:?} is not sha256:<64 hex>"
                    ))
                })
            })
            .collect::<Result<Vec<ComposeHash>, _>>()?;
        if kms_revisions.is_empty() {
            return Err(Error::Config("ALPHACOMPUTE_KMS_REVISIONS is empty".into()));
        }
        let kms_endpoints: Vec<String> = list(endpoints)
            .map(|s| s.trim_end_matches('/').to_owned())
            .collect();
        if kms_endpoints.is_empty() {
            return Err(Error::Config("ALPHACOMPUTE_KMS_ENDPOINTS is empty".into()));
        }
        let secrets = parse_secrets(secrets)?;
        let tls_upstream = parse_upstream(tls_upstream)?;
        Ok(Self {
            kms_ca_spki_sha256,
            kms_revisions,
            kms_endpoints,
            secrets,
            tls_upstream,
        })
    }

    fn pin(&self) -> Pin {
        Pin::CaSpkiAndRevisions(self.kms_ca_spki_sha256, self.kms_revisions.clone())
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

/// A quote over `report_data` and the event log behind it; the guest agent in `main`, a capture in tests.
pub type EvidenceSource = Arc<dyn Fn(&[u8; 64]) -> Result<Evidence, String> + Send + Sync>;

pub fn tsm_evidence() -> EvidenceSource {
    Arc::new(|report_data| {
        Ok(Evidence {
            format: EVIDENCE_FORMAT.into(),
            quote: alpha_tsm::quote(report_data).map_err(|e| e.to_string())?,
            event_log: alpha_tsm::event_log().map_err(|e| e.to_string())?,
        })
    })
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
    /// The guest agent's; served to the tenant's services only once a leaf names its hash.
    app_compose: String,
    kms: Client,
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
        app_compose: String,
    ) -> Result<Arc<Self>, Error> {
        let key_error = |e: p256::pkcs8::Error| Error::Key(e.to_string());
        let spki = key
            .verifying_key()
            .to_public_key_der()
            .map_err(|e| key_error(e.into()))?
            .into_vec();
        let pkcs8 = Zeroizing::new(key.to_pkcs8_der().map_err(key_error)?.to_bytes().to_vec());
        let kms = Client::configured(
            config.kms_endpoints.clone(),
            config.pin(),
            None,
            time.clone(),
        )?;
        Ok(Arc::new(Self {
            config,
            pkcs8,
            spki,
            clock,
            time,
            evidence,
            app_compose,
            kms,
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
        let attested = self.attest_inner().await.map_err(|e| self.note(e))?;
        *self.attested.write() = Some(attested.clone());
        Ok(attested)
    }

    async fn attest_inner(&self) -> Result<Arc<Attested>, Error> {
        let nonce = self.kms.attest_nonce().await?;
        let nonce: [u8; 32] = alpha_client::decode("nonce", &nonce.nonce)?
            .try_into()
            .map_err(|_| alpha_client::Error::Invalid("nonce is not 32 bytes".into()))?;
        let report_data = alpha_attest::report_data(&self.spki, &nonce, None);
        let evidence = (self.evidence)(&report_data).map_err(Error::Evidence)?;
        let reply = self
            .kms
            .attest(&AttestRequest {
                runtime_pubkey: BASE64_URL_SAFE_NO_PAD.encode(&self.spki),
                nonce: BASE64_URL_SAFE_NO_PAD.encode(nonce),
                evidence,
            })
            .await?;
        self.accept(reply)
    }

    /// The reply's chain is ours only if the leaf carries our key and the root the pinned one;
    /// the ids come from the leaf's SANs, never from the reply's text.
    fn accept(&self, reply: AttestReply) -> Result<Arc<Attested>, Error> {
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
        if alpha_core::compose_hash(&self.app_compose) != identity.compose_hash {
            return Err(Error::Certificate(
                "the guest agent's app_compose is not the leaf's Revision".into(),
            ));
        }
        let certified =
            tls::certified(chain.iter().cloned().map(Into::into).collect(), &self.pkcs8)?;
        let not_after = chrono::DateTime::parse_from_rfc3339(&reply.not_after)
            .map_err(|e| Error::Certificate(format!("not_after: {e}")))?
            .into();
        let client = Client::configured(
            self.config.kms_endpoints.clone(),
            self.config.pin(),
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
            eprintln!("alpha-runtime: secrets: {}", Error::NotAttested);
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
                        eprintln!("alpha-runtime: secret {name}: {e}");
                    }
                    incomplete.push(name.clone());
                    continue;
                }
            };
            let Ok(value) = BASE64_URL_SAFE_NO_PAD
                .decode(&secret.value)
                .map(Zeroizing::new)
            else {
                eprintln!("alpha-runtime: secret {name}: value is not base64url");
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
                    eprintln!("alpha-runtime: secret {name} for {service}: {e}");
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
                        eprintln!("alpha-runtime: waiting for secrets: {}", names.join(", "));
                        waiting = names;
                    }
                    tokio::time::sleep(retry).await;
                    retry = retry.saturating_mul(2).min(SECRETS_POLL);
                }
            }
        }
    }

    async fn renew_forever(&self) {
        loop {
            let delay = match self.last() {
                Some(a) => renewal_delay(a.not_after, self.now()),
                None => Duration::ZERO,
            };
            tokio::time::sleep(delay).await;
            match self.attest().await {
                Ok(a) => eprintln!(
                    "alpha-runtime: renewed until {}",
                    chrono::DateTime::<chrono::Utc>::from(a.not_after).to_rfc3339()
                ),
                Err(e) if e.revoked() => return,
                Err(e) => {
                    eprintln!("alpha-runtime: renewal failed: {e}");
                    tokio::time::sleep(RETRY_AFTER).await;
                }
            }
        }
    }

    /// Serves the socket, renews the leaf, keeps the declared Secret files under
    /// `secrets_root` current and, given `tls` and an upstream, proxies the Endpoint until
    /// `shutdown` resolves or the Revision is revoked. Socket connections drain either way;
    /// proxied ones drain on shutdown and are cut on revocation.
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
        let (stop_proxy, proxy_stopped) = tokio::sync::oneshot::channel::<proxy::Stop>();
        let proxy = tls.map(|endpoint| {
            tokio::spawn(
                endpoint.serve(async move { proxy_stopped.await.unwrap_or(proxy::Stop::Now) }),
            )
        });
        let mut revoked = self.revoked.subscribe();
        let exit = tokio::select! {
            () = shutdown => Exit::Drained,
            _ = revoked.wait_for(|r| *r) => Exit::Revoked,
            () = self.renew_forever() => Exit::Revoked,
        };
        delivery.abort();
        let _ = stop.send(());
        let _ = stop_proxy.send(match exit {
            Exit::Drained => proxy::Stop::Drain,
            Exit::Revoked => proxy::Stop::Now,
        });
        let proxied = async {
            if let Some(proxy) = proxy {
                let _ = proxy.await;
            }
        };
        let _ = tokio::join!(server, proxied);
        exit
    }
}

#[cfg(test)]
mod tests {
    use std::time::UNIX_EPOCH;

    use super::*;

    const HASH: &str = "sha256:ee097e09c4824eb6424202fe20ed882d19a33a563f3b3dd5988f3ff8ee1b8335";

    #[test]
    fn config_parses_the_three_variables_and_refuses_empty_or_malformed_ones() {
        let c = Config::parse(
            &format!(" {HASH} "),
            &format!("{HASH}, {HASH},"),
            "https://a:8443/,, https://b:8443",
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            c.kms_ca_spki_sha256,
            alpha_core::hex_bytes(&HASH[7..]).unwrap()
        );
        assert_eq!(c.kms_revisions.len(), 2);
        assert_eq!(c.kms_endpoints, ["https://a:8443", "https://b:8443"]);
        assert!(
            matches!(c.pin(), Pin::CaSpkiAndRevisions(spki, r) if spki == c.kms_ca_spki_sha256 && r.len() == 2)
        );

        let refused = |a: &str, b: &str, c: &str| {
            let Err(Error::Config(m)) = Config::parse(a, b, c, None, None) else {
                panic!("{a} {b} {c} was accepted");
            };
            m
        };
        assert!(refused(&HASH[7..], HASH, "x").contains("CA_SPKI"));
        assert!(refused(HASH, "", "x").contains("REVISIONS is empty"));
        assert!(refused(HASH, "sha256:zz", "x").contains("REVISIONS"));
        assert!(refused(HASH, HASH, " , ").contains("ENDPOINTS"));
        assert!(refused("", HASH, "x").contains("CA_SPKI"));
        assert!(c.secrets.is_empty());
        assert!(c.tls_upstream.is_none());
    }

    #[test]
    fn secrets_parse_the_wraps_variable() {
        let wrap = r#"{"db":["db_password"],"web":["db_password","session_key"]}"#;
        let c = Config::parse(HASH, HASH, "https://a", Some(wrap), None).unwrap();
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
            let Err(Error::Config(m)) = Config::parse(HASH, HASH, "https://a", Some(bad), None)
            else {
                panic!("{bad} was accepted by Config::parse");
            };
            assert!(m.contains("ALPHACOMPUTE_SECRETS"), "{bad}: {m}");
        }
    }

    #[test]
    fn the_tls_upstream_is_a_lowercase_service_and_a_port() {
        assert_eq!(parse_upstream(None).unwrap(), None);
        let c = Config::parse(HASH, HASH, "https://a", None, Some("web:80")).unwrap();
        assert_eq!(
            c.tls_upstream,
            Some(Upstream {
                host: "web".into(),
                port: 80
            })
        );
        let max = parse_upstream(Some("localhost:65535")).unwrap().unwrap();
        assert_eq!(max.to_string(), "localhost:65535");
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
        ] {
            let Err(Error::Config(m)) = Config::parse(HASH, HASH, "https://a", None, Some(bad))
            else {
                panic!("{bad} was accepted");
            };
            assert!(m.starts_with("ALPHACOMPUTE_TLS_UPSTREAM:"), "{bad}: {m}");
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
