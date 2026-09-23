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

pub mod socket;

use std::collections::HashMap;
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
use tokio::net::UnixListener;
use tokio::sync::watch;
use zeroize::Zeroizing;

pub use alpha_client::runtime::SOCKET_PATH;

pub const RENEW_BEFORE: Duration = Duration::from_secs(600);
const RETRY_AFTER: Duration = Duration::from_secs(30);

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

/// The three environment variables, nothing else.
#[derive(Clone, Debug)]
pub struct Config {
    pub kms_ca_spki_sha256: [u8; 32],
    pub kms_revisions: Vec<ComposeHash>,
    pub kms_endpoints: Vec<String>,
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
        )
    }

    pub fn parse(ca_spki_sha256: &str, revisions: &str, endpoints: &str) -> Result<Self, Error> {
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
        Ok(Self {
            kms_ca_spki_sha256,
            kms_revisions,
            kms_endpoints,
        })
    }

    fn pin(&self) -> Pin {
        Pin::CaSpkiAndRevisions(self.kms_ca_spki_sha256, self.kms_revisions.clone())
    }
}

fn list(text: &str) -> impl Iterator<Item = &str> {
    text.split(',').map(str::trim).filter(|s| !s.is_empty())
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
            kms,
            attested: RwLock::new(None),
            revoked: watch::Sender::new(false),
        }))
    }

    pub fn now(&self) -> SystemTime {
        (self.clock)()
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
        if tls::spki_of(leaf)? != self.spki {
            return Err(Error::Certificate(
                "leaf is not over the runtime key".into(),
            ));
        }
        if tls::spki_sha256(ca) != Some(self.config.kms_ca_spki_sha256) {
            return Err(Error::Certificate(
                "chain does not end at the pinned ca".into(),
            ));
        }
        let identity = tls::parse_instance_sans(&tls::uri_sans(leaf)?)?;
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

    /// Serves the socket and renews the leaf until `shutdown` resolves or the Revision is
    /// revoked; open connections drain either way.
    pub async fn run(
        self: Arc<Self>,
        listener: UnixListener,
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
        let mut revoked = self.revoked.subscribe();
        let exit = tokio::select! {
            () = shutdown => Exit::Drained,
            _ = revoked.wait_for(|r| *r) => Exit::Revoked,
            () = self.renew_forever() => Exit::Revoked,
        };
        let _ = stop.send(());
        let _ = server.await;
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
            let Err(Error::Config(m)) = Config::parse(a, b, c) else {
                panic!("{a} {b} {c} was accepted");
            };
            m
        };
        assert!(refused(&HASH[7..], HASH, "x").contains("CA_SPKI"));
        assert!(refused(HASH, "", "x").contains("REVISIONS is empty"));
        assert!(refused(HASH, "sha256:zz", "x").contains("REVISIONS"));
        assert!(refused(HASH, HASH, " , ").contains("ENDPOINTS"));
        assert!(refused("", HASH, "x").contains("CA_SPKI"));
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
