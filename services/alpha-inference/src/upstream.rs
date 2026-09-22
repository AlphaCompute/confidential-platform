//! Recipe A: before any request for a model is forwarded, fetch RedPill's attestation report
//! for it over an unpinned connection, verify the TDX quote with `alpha_attest::verify_quote`
//! and that its `report_data` binds the fresh nonce to the signing address RedPill returned
//! and the SPKI our own connection observed, then pin all forwarding for that model to that
//! SPKI for 60 seconds. Every failure — network, shape, collateral, quote or policy — leaves
//! the model unverified; nothing is ever forwarded on a failure.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use alpha_attest::{Collateral, Policy};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

use crate::{Config, Error};

/// A verification is trusted for one minute; older than that, recipe A runs again.
const VERIFIED_TTL: Duration = Duration::from_secs(60);
const REPORT_TIMEOUT: Duration = Duration::from_secs(10);

pub type Clock = Arc<dyn Fn() -> SystemTime + Send + Sync>;

/// Why a model failed recipe A. Logged by code and model only — never the report body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    /// The report endpoint could not be reached at all (refused, timed out, or the OS RNG
    /// that mints the nonce is unavailable — no request can be sent without one).
    Fetch,
    /// The report endpoint answered, but not with 2xx.
    Status,
    /// The answer was not the report this code expects: not JSON, or missing a field.
    Shape,
    /// DCAP collateral for the quote could not be fetched from the PCCS.
    Collateral,
    /// The quote itself does not verify (tampered, or does not appraise against the PCCS).
    Quote,
    /// The quote verifies, but its TCB status or advisories are outside the measured policy.
    Policy,
    /// The quote verifies and passes policy, but its `report_data` does not bind this nonce
    /// and this connection's SPKI.
    Binding,
}

impl Reason {
    pub fn code(self) -> &'static str {
        match self {
            Reason::Fetch => "fetch",
            Reason::Status => "status",
            Reason::Shape => "shape",
            Reason::Collateral => "collateral",
            Reason::Quote => "quote",
            Reason::Policy => "policy",
            Reason::Binding => "binding",
        }
    }
}

/// What `Upstream::verified` can refuse with.
#[derive(Clone, Copy, Debug)]
pub enum VerifyOutcome {
    Unverified(Reason),
    /// Defensive: `model` is not one of the slots built at startup. The router only ever
    /// calls `verified` after `Config::allows`, so this should not be reachable.
    UnknownModel,
}

/// The two fields recipe A reads from RedPill's `GET /v1/attestation/report?version=2` body.
#[derive(Debug, Deserialize)]
struct Report {
    signing_address: String,
    intel_quote: String,
}

/// A model's last recipe-A check: when, and what it found — a client that will only ever
/// complete a handshake against the attested SPKI, or why it refused to trust one. Caching the
/// failure too (not just the success) is what makes the per-model lock a true single flight:
/// two callers racing a cold model share the one fetch's outcome, not just its happy path.
struct Checked {
    at: SystemTime,
    outcome: Result<reqwest::Client, Reason>,
}

/// Recipe A over the allowlisted models. One `Mutex` per model, built once at startup —
/// nothing is inserted at runtime, so the mutex is the single flight for that model's check.
pub struct Upstream {
    upstream_url: String,
    pccs_url: String,
    policy: Policy,
    slots: HashMap<String, Mutex<Option<Checked>>>,
    /// Never pinned, never given the provider key: it only reads the report that says which
    /// key to pin to next.
    report_client: reqwest::Client,
    now: Clock,
}

fn unpinned_client(timeout: Duration) -> Result<reqwest::Client, Error> {
    let tls = alpha_client::tls::client_config(None, None, alpha_client::system_time_provider())
        .map_err(|e| Error::internal(format!("report client tls: {e}")))?;
    reqwest::Client::builder()
        .tls_backend_preconfigured(tls)
        .tls_info(true)
        .timeout(timeout)
        .build()
        .map_err(|e| Error::internal(format!("report client: {e}")))
}

fn pinned_client(spki: &[u8]) -> Result<reqwest::Client, Error> {
    let tls = alpha_client::tls::client_config(
        Some(alpha_client::tls::Pin::Spki(spki.to_vec())),
        None,
        alpha_client::system_time_provider(),
    )
    .map_err(|e| Error::internal(format!("forwarding client tls: {e}")))?;
    reqwest::Client::builder()
        .tls_backend_preconfigured(tls)
        .build()
        .map_err(|e| Error::internal(format!("forwarding client: {e}")))
}

/// `report_data`'s first half binds the signing address and the connection's SPKI; the second
/// half is the nonce. Never sliced — `split_first_chunk` and `try_into` on a mismatched length
/// simply fail the comparison rather than panic.
fn binding_matches(
    report_data: &[u8; 64],
    signing_address: &[u8],
    spki: &[u8],
    nonce: &[u8; 32],
) -> bool {
    let Some((address_spki_hash, rest)): Option<(&[u8; 32], &[u8])> =
        report_data.split_first_chunk()
    else {
        return false;
    };
    let Ok(bound_nonce) = <&[u8; 32]>::try_from(rest) else {
        return false;
    };
    let expected = Sha256::new()
        .chain_update(signing_address)
        .chain_update(Sha256::digest(spki))
        .finalize();
    address_spki_hash.as_slice() == expected.as_slice() && bound_nonce == nonce
}

/// Pure: DCAP-verifies `report`'s quote against `collateral` and `policy`, then checks that
/// its `report_data` binds `nonce` to `spki` — the connection's observed key, not anything the
/// report claims about itself.
fn check_report(
    report: &Report,
    spki: &[u8],
    nonce: &[u8; 32],
    collateral: &Collateral,
    policy: &Policy,
    now: SystemTime,
) -> Result<(), Reason> {
    let quote = hex::decode(&report.intel_quote).map_err(|_| Reason::Shape)?;
    let signing_address = report
        .signing_address
        .strip_prefix("0x")
        .and_then(alpha_core::hex_bytes::<20>)
        .ok_or(Reason::Shape)?;

    let verified =
        alpha_attest::verify_quote(&quote, collateral, policy, now).map_err(|e| match e {
            alpha_attest::AppraisalError::PolicyDenied(_) => Reason::Policy,
            alpha_attest::AppraisalError::Failed(_) | alpha_attest::AppraisalError::Unknown(_) => {
                Reason::Quote
            }
        })?;

    if binding_matches(&verified.report_data, &signing_address, spki, nonce) {
        Ok(())
    } else {
        Err(Reason::Binding)
    }
}

impl Upstream {
    pub fn new(config: &Config) -> Result<Self, Error> {
        Self::build(config, Arc::new(SystemTime::now), REPORT_TIMEOUT)
    }

    /// `now` and `report_timeout` are injected so tests never wait out a real clock or a real
    /// network timeout.
    pub fn build(config: &Config, now: Clock, report_timeout: Duration) -> Result<Self, Error> {
        let slots = config
            .models
            .iter()
            .map(|model| (model.clone(), Mutex::new(None)))
            .collect();
        Ok(Self {
            upstream_url: config.upstream_url.clone(),
            pccs_url: config.pccs_url.clone(),
            policy: config.upstream_policy.clone(),
            slots,
            report_client: unpinned_client(report_timeout)?,
            now,
        })
    }

    /// A client pinned to `model`'s attested key, checked within the last minute — refetching
    /// recipe A first if the last check is older than that, or there was none yet. Whatever
    /// that fetch finds — success or failure — is what every caller waiting on the same
    /// model's lock gets back; nothing here starts a second fetch while one is in flight.
    pub async fn verified(&self, model: &str) -> Result<reqwest::Client, VerifyOutcome> {
        let Some(slot) = self.slots.get(model) else {
            return Err(VerifyOutcome::UnknownModel);
        };
        let mut guard = slot.lock().await;
        let now = (self.now)();
        if let Some(checked) = guard.as_ref()
            && now.duration_since(checked.at).unwrap_or(Duration::MAX) < VERIFIED_TTL
        {
            return checked.outcome.clone().map_err(VerifyOutcome::Unverified);
        }
        let outcome = self.check(model, now).await;
        if let Err(reason) = &outcome {
            eprintln!(
                "alpha-inference: verification failed for {model}: {}",
                reason.code()
            );
        }
        // Replaces whatever was cached before, good or bad — a fresh failure past the TTL
        // must not go on serving a stale-but-formerly-good client.
        *guard = Some(Checked {
            at: now,
            outcome: outcome.clone(),
        });
        outcome.map_err(VerifyOutcome::Unverified)
    }

    /// The pinned connection for `model` failed after a passing check; the next call to
    /// `verified` runs recipe A again instead of reusing a client that just proved stale.
    pub async fn forget(&self, model: &str) {
        if let Some(slot) = self.slots.get(model) {
            *slot.lock().await = None;
        }
    }

    async fn check(&self, model: &str, now: SystemTime) -> Result<reqwest::Client, Reason> {
        let mut nonce = [0u8; 32];
        getrandom::fill(&mut nonce).map_err(|_| Reason::Fetch)?;

        let response = self
            .report_client
            .get(format!("{}/attestation/report", self.upstream_url))
            .query(&[
                ("model", model),
                ("nonce", hex::encode(nonce).as_str()),
                ("signing_algo", "ecdsa"),
                ("version", "2"),
            ])
            .send()
            .await
            .map_err(|_| Reason::Fetch)?;

        // The connection's leaf is read now (extensions borrow the response) but not required
        // yet — a failing status or an unparseable body must classify as Status/Shape even
        // over a fake that never terminates TLS at all, not as a generic Fetch.
        let leaf = response
            .extensions()
            .get::<reqwest::tls::TlsInfo>()
            .and_then(|info| info.peer_certificate().map(<[u8]>::to_vec));

        let status = response.status();
        let bytes = response.bytes().await.map_err(|_| Reason::Fetch)?;
        if !status.is_success() {
            return Err(Reason::Status);
        }
        let report: Report = serde_json::from_slice(&bytes).map_err(|_| Reason::Shape)?;
        let quote = hex::decode(&report.intel_quote).map_err(|_| Reason::Shape)?;
        let spki =
            alpha_client::tls::spki_of(&leaf.ok_or(Reason::Shape)?).map_err(|_| Reason::Shape)?;

        // ponytail: one PCCS round trip per check (at most once a minute per model, the
        // `VERIFIED_TTL` bound) rather than a cache keyed on the quote's FMSPC. Add the cache
        // if PCCS latency or rate limits become a problem.
        let collateral = alpha_attest::fetch_collateral(&self.pccs_url, &quote)
            .await
            .map_err(|_| Reason::Collateral)?;

        check_report(&report, &spki, &nonce, &collateral, &self.policy, now)?;

        pinned_client(&spki).map_err(|_| Reason::Binding)
    }

    /// RedPill's public model listing, over the report client, without the provider key — it
    /// carries no conversation. Any failure is treated as an empty listing.
    pub async fn list_models(&self) -> serde_json::Value {
        let fetch = async {
            let response = self
                .report_client
                .get(format!("{}/models", self.upstream_url))
                .send()
                .await
                .ok()?;
            response.error_for_status().ok()?.json().await.ok()
        };
        fetch.await.unwrap_or(serde_json::Value::Null)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::UNIX_EPOCH;

    use axum::http::StatusCode;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    use super::*;

    fn root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/redpill")
    }

    fn read(name: &str) -> String {
        std::fs::read_to_string(root().join(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
    }

    fn spki_of_pem(pem: &str) -> Vec<u8> {
        let cert = alpha_client::tls::cert_from_pem(pem).unwrap();
        alpha_client::tls::spki_of(cert.as_ref()).unwrap()
    }

    #[test]
    fn check_report_accepts_the_redpill_capture() {
        let report: Report = serde_json::from_str(&read("report.json")).unwrap();
        let nonce: [u8; 32] = alpha_core::hex_bytes(read("nonce.hex").trim()).unwrap();
        let spki = spki_of_pem(&read("api.redpill.ai.pem"));
        let collateral: Collateral = serde_json::from_str(&read("collateral.json")).unwrap();
        let policy = Policy {
            tcb_statuses: vec!["UpToDate".into()],
            tolerated_advisories: vec![],
        };
        let secs = chrono::DateTime::parse_from_rfc2822(read("captured_at.txt").trim())
            .unwrap()
            .timestamp();
        let now = UNIX_EPOCH + Duration::from_secs(secs.try_into().unwrap());

        assert_eq!(
            check_report(&report, &spki, &nonce, &collateral, &policy, now),
            Ok(())
        );
    }

    /// The real capture's report, nonce, SPKI, collateral, policy and clock — a baseline every
    /// negative golden test mutates exactly one field of.
    fn golden_inputs() -> (Report, [u8; 32], Vec<u8>, Collateral, Policy, SystemTime) {
        let report: Report = serde_json::from_str(&read("report.json")).unwrap();
        let nonce: [u8; 32] = alpha_core::hex_bytes(read("nonce.hex").trim()).unwrap();
        let spki = spki_of_pem(&read("api.redpill.ai.pem"));
        let collateral: Collateral = serde_json::from_str(&read("collateral.json")).unwrap();
        let policy = Policy {
            tcb_statuses: vec!["UpToDate".into()],
            tolerated_advisories: vec![],
        };
        let secs = chrono::DateTime::parse_from_rfc2822(read("captured_at.txt").trim())
            .unwrap()
            .timestamp();
        let now = UNIX_EPOCH + Duration::from_secs(secs.try_into().unwrap());
        (report, nonce, spki, collateral, policy, now)
    }

    #[test]
    fn check_report_fails_with_a_different_nonce() {
        let (report, mut nonce, spki, collateral, policy, now) = golden_inputs();
        nonce[0] ^= 0xff;
        assert_eq!(
            check_report(&report, &spki, &nonce, &collateral, &policy, now),
            Err(Reason::Binding)
        );
    }

    #[test]
    fn check_report_fails_with_the_spki_of_a_different_host() {
        let (report, nonce, _spki, collateral, policy, now) = golden_inputs();
        let wrong_spki = spki_of_pem(&read("tee.redpill.ai.pem"));
        assert_eq!(
            check_report(&report, &wrong_spki, &nonce, &collateral, &policy, now),
            Err(Reason::Binding)
        );
    }

    #[test]
    fn check_report_fails_with_one_byte_of_the_quote_altered() {
        let (mut report, nonce, spki, collateral, policy, now) = golden_inputs();
        // Byte 50 sits inside the TD report body (past the ~48-byte quote header), squarely
        // within the region the quote's own ECDSA signature covers — any TDX-quote byte here
        // breaks that signature, unlike bytes deep in the trailing PCK certificate data.
        let mut chars: Vec<char> = report.intel_quote.chars().collect();
        let index = 100;
        let Some(c) = chars.get_mut(index) else {
            panic!("quote.hex has no byte at {index}");
        };
        *c = if *c == '0' { '1' } else { '0' };
        report.intel_quote = chars.into_iter().collect();
        assert_eq!(
            check_report(&report, &spki, &nonce, &collateral, &policy, now),
            Err(Reason::Quote)
        );
    }

    #[test]
    fn check_report_fails_when_the_policy_tolerates_no_status_the_report_has() {
        let (report, nonce, spki, collateral, _policy, now) = golden_inputs();
        let policy = Policy {
            tcb_statuses: vec!["OutOfDate".into()],
            tolerated_advisories: vec![],
        };
        assert_eq!(
            check_report(&report, &spki, &nonce, &collateral, &policy, now),
            Err(Reason::Policy)
        );
    }

    #[test]
    fn check_report_fails_once_the_collateral_has_expired() {
        let (report, nonce, spki, collateral, policy, now) = golden_inputs();
        let ten_years = Duration::from_secs(10 * 365 * 86400);
        assert_eq!(
            check_report(
                &report,
                &spki,
                &nonce,
                &collateral,
                &policy,
                now + ten_years
            ),
            Err(Reason::Quote)
        );
    }

    fn test_config(upstream_url: &str, models: &[&str]) -> crate::Config {
        crate::Config {
            upstream_url: upstream_url.to_string(),
            models: models.iter().map(|s| (*s).to_string()).collect(),
            pccs_url: "https://pccs.example".to_string(),
            upstream_policy: Policy {
                tcb_statuses: vec!["UpToDate".into()],
                tolerated_advisories: vec![],
            },
        }
    }

    async fn build_upstream(
        upstream_url: &str,
        models: &[&str],
        report_timeout: Duration,
        now: SystemTime,
    ) -> Upstream {
        let clock: Clock = Arc::new(move || now);
        Upstream::build(&test_config(upstream_url, models), clock, report_timeout).unwrap()
    }

    use crate::test_support::{ReportBehavior, spawn_fake_upstream as spawn_report_server};

    #[tokio::test]
    async fn verified_fails_with_fetch_when_the_report_endpoint_refuses_the_connection() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let upstream = build_upstream(
            &format!("http://{addr}"),
            &["m1"],
            Duration::from_secs(5),
            SystemTime::now(),
        )
        .await;
        assert!(matches!(
            upstream.verified("m1").await.unwrap_err(),
            VerifyOutcome::Unverified(Reason::Fetch)
        ));
    }

    #[tokio::test]
    async fn verified_fails_with_status_when_the_report_endpoint_answers_500() {
        let (base, hits, completions) = spawn_report_server(ReportBehavior {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            body: String::new(),
            delay: None,
        })
        .await;
        let upstream =
            build_upstream(&base, &["m1"], Duration::from_secs(5), SystemTime::now()).await;
        assert!(matches!(
            upstream.verified("m1").await.unwrap_err(),
            VerifyOutcome::Unverified(Reason::Status)
        ));
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert_eq!(completions.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn verified_fails_with_fetch_when_the_report_endpoint_exceeds_the_timeout() {
        let (base, _hits, _completions) = spawn_report_server(ReportBehavior {
            status: StatusCode::OK,
            body: "{}".into(),
            delay: Some(Duration::from_millis(300)),
        })
        .await;
        let upstream =
            build_upstream(&base, &["m1"], Duration::from_millis(50), SystemTime::now()).await;
        assert!(matches!(
            upstream.verified("m1").await.unwrap_err(),
            VerifyOutcome::Unverified(Reason::Fetch)
        ));
    }

    #[tokio::test]
    async fn verified_fails_with_shape_when_the_report_is_not_json() {
        let (base, _hits, _completions) = spawn_report_server(ReportBehavior {
            status: StatusCode::OK,
            body: "not json".into(),
            delay: None,
        })
        .await;
        let upstream =
            build_upstream(&base, &["m1"], Duration::from_secs(5), SystemTime::now()).await;
        assert!(matches!(
            upstream.verified("m1").await.unwrap_err(),
            VerifyOutcome::Unverified(Reason::Shape)
        ));
    }

    #[tokio::test]
    async fn verified_fails_with_shape_when_the_report_omits_a_field() {
        for body in [r#"{"signing_address":"0x00"}"#, r#"{"intel_quote":"00"}"#] {
            let (base, _hits, _completions) = spawn_report_server(ReportBehavior {
                status: StatusCode::OK,
                body: body.into(),
                delay: None,
            })
            .await;
            let upstream =
                build_upstream(&base, &["m1"], Duration::from_secs(5), SystemTime::now()).await;
            assert!(
                matches!(
                    upstream.verified("m1").await.unwrap_err(),
                    VerifyOutcome::Unverified(Reason::Shape)
                ),
                "{body}"
            );
        }
    }

    #[tokio::test]
    async fn a_verification_younger_than_the_ttl_is_reused_without_a_fetch_and_a_failed_refetch_clears_a_good_slot()
     {
        let (base, hits, _completions) = spawn_report_server(ReportBehavior {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            body: String::new(),
            delay: None,
        })
        .await;
        let start = UNIX_EPOCH + Duration::from_secs(1_000_000);
        let clock_cell = Arc::new(parking_lot::Mutex::new(start));
        let clock: Clock = {
            let cell = clock_cell.clone();
            Arc::new(move || *cell.lock())
        };
        let upstream =
            Upstream::build(&test_config(&base, &["m1"]), clock, Duration::from_secs(5)).unwrap();
        *upstream.slots.get("m1").unwrap().lock().await = Some(Checked {
            at: start,
            outcome: Ok(pinned_client(&[7u8; 32]).unwrap()),
        });

        assert!(upstream.verified("m1").await.is_ok());
        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "a fresh slot must not refetch"
        );

        *clock_cell.lock() = start + VERIFIED_TTL + Duration::from_secs(1);
        assert!(matches!(
            upstream.verified("m1").await.unwrap_err(),
            VerifyOutcome::Unverified(Reason::Status)
        ));
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "an expired slot must refetch once"
        );
    }

    #[tokio::test]
    async fn two_concurrent_checks_on_a_cold_model_make_one_report_fetch_and_share_its_result() {
        let (base, hits, _completions) = spawn_report_server(ReportBehavior {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            body: String::new(),
            delay: Some(Duration::from_millis(50)),
        })
        .await;
        let upstream = Arc::new(
            build_upstream(&base, &["m1"], Duration::from_secs(5), SystemTime::now()).await,
        );
        let (a, b) = tokio::join!(
            {
                let upstream = upstream.clone();
                async move { upstream.verified("m1").await }
            },
            {
                let upstream = upstream.clone();
                async move { upstream.verified("m1").await }
            }
        );
        assert!(matches!(
            a.unwrap_err(),
            VerifyOutcome::Unverified(Reason::Status)
        ));
        assert!(matches!(
            b.unwrap_err(),
            VerifyOutcome::Unverified(Reason::Status)
        ));
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    fn self_signed_leaf() -> (
        CertificateDer<'static>,
        PrivatePkcs8KeyDer<'static>,
        Vec<u8>,
    ) {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let cert = params.self_signed(&key).unwrap();
        let der = CertificateDer::from(cert.der().to_vec());
        let spki = alpha_client::tls::spki_of(&der).unwrap();
        (der, PrivatePkcs8KeyDer::from(key.serialize_der()), spki)
    }

    /// A bare TLS server (no HTTP framework needed beyond one hyper service_fn) that records
    /// every request it actually receives — a failed handshake never reaches it.
    async fn spawn_tls_fake(
        cert: CertificateDer<'static>,
        key: PrivatePkcs8KeyDer<'static>,
    ) -> (
        String,
        Arc<AtomicUsize>,
        Arc<parking_lot::Mutex<Option<String>>>,
    ) {
        let server_config =
            rustls::ServerConfig::builder_with_provider(alpha_client::tls::provider())
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![cert], PrivateKeyDer::Pkcs8(key))
                .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let last_auth: Arc<parking_lot::Mutex<Option<String>>> =
            Arc::new(parking_lot::Mutex::new(None));
        {
            let hits = hits.clone();
            let last_auth = last_auth.clone();
            tokio::spawn(async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        return;
                    };
                    let acceptor = acceptor.clone();
                    let hits = hits.clone();
                    let last_auth = last_auth.clone();
                    tokio::spawn(async move {
                        let Ok(tls) = acceptor.accept(stream).await else {
                            return;
                        };
                        let hits = hits.clone();
                        let last_auth = last_auth.clone();
                        let service = hyper::service::service_fn(
                            move |req: hyper::Request<hyper::body::Incoming>| {
                                hits.fetch_add(1, Ordering::SeqCst);
                                *last_auth.lock() = req
                                    .headers()
                                    .get(hyper::header::AUTHORIZATION)
                                    .and_then(|v| v.to_str().ok())
                                    .map(String::from);
                                async move {
                                    Ok::<_, std::convert::Infallible>(hyper::Response::new(
                                        http_body_util::Full::new(hyper::body::Bytes::new()),
                                    ))
                                }
                            },
                        );
                        let _ = hyper_util::server::conn::auto::Builder::new(
                            hyper_util::rt::TokioExecutor::new(),
                        )
                        .serve_connection(hyper_util::rt::TokioIo::new(tls), service)
                        .await;
                    });
                }
            });
        }
        (format!("https://{addr}"), hits, last_auth)
    }

    #[tokio::test]
    async fn a_pinned_client_reaches_its_own_spki_and_carries_the_bearer_it_was_given() {
        let (cert, key, spki) = self_signed_leaf();
        let (base, hits, last_auth) = spawn_tls_fake(cert, key).await;
        let client = pinned_client(&spki).unwrap();
        let response = client
            .post(format!("{base}/chat/completions"))
            .bearer_auth("provider-key")
            .send()
            .await
            .unwrap();
        assert!(response.status().is_success());
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert_eq!(last_auth.lock().as_deref(), Some("Bearer provider-key"));
    }

    #[tokio::test]
    async fn a_pinned_client_fails_the_handshake_against_a_different_key_and_the_fake_sees_no_request()
     {
        let (cert_a, key_a, _spki_a) = self_signed_leaf();
        let (_cert_b, _key_b, spki_b) = self_signed_leaf();
        let (base_a, hits_a, _last_auth) = spawn_tls_fake(cert_a, key_a).await;
        let client = pinned_client(&spki_b).unwrap();
        let result = client
            .post(format!("{base_a}/chat/completions"))
            .send()
            .await;
        assert!(result.is_err());
        assert_eq!(hits_a.load(Ordering::SeqCst), 0);
    }

    /// The full round trip through the router: a caller's own bearer authenticates the
    /// request, but only the provider key ever reaches the (attested-key-pinned) upstream.
    #[tokio::test]
    async fn chat_completions_forwards_the_provider_key_never_the_callers_bearer() {
        let (cert, key, spki) = self_signed_leaf();
        let (base, hits, last_auth) = spawn_tls_fake(cert, key).await;

        let config = test_config(&base, &["m1"]);
        let upstream =
            Upstream::build(&config, Arc::new(SystemTime::now), Duration::from_secs(5)).unwrap();
        *upstream.slots.get("m1").unwrap().lock().await = Some(Checked {
            at: SystemTime::now(),
            outcome: Ok(pinned_client(&spki).unwrap()),
        });
        let state = Arc::new(crate::AppState {
            config,
            secrets: parking_lot::RwLock::new(crate::Secrets {
                provider_key: zeroize::Zeroizing::new("the-provider-key".to_string()),
                caller_bearer: zeroize::Zeroizing::new(b"the-callers-bearer".to_vec()),
            }),
            upstream,
        });
        let app = crate::router(state);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let http = reqwest::Client::new();
        let response = http
            .post(format!("http://{addr}/v1/chat/completions"))
            .header(reqwest::header::AUTHORIZATION, "Bearer the-callers-bearer")
            .json(&serde_json::json!({ "model": "m1" }))
            .send()
            .await
            .unwrap();
        assert!(response.status().is_success());
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert_eq!(last_auth.lock().as_deref(), Some("Bearer the-provider-key"));
    }

    fn live_config() -> crate::Config {
        crate::Config::build(|name| match name {
            "UPSTREAM_URL" => Some("https://api.redpill.ai/v1".to_string()),
            "MODELS" => Some(
                "nvidia/nemotron-3.5-lightning,qwen/qwen3.8-27b,meta/muse-glimmer-30b".to_string(),
            ),
            "PCCS_URL" => Some("https://pccs.phala.network".to_string()),
            "UPSTREAM_POLICY" => {
                Some(r#"{"tcb_statuses":["UpToDate"],"tolerated_advisories":[]}"#.to_string())
            }
            _ => None,
        })
        .unwrap()
    }

    /// Proves the whole front end to end against the live RedPill gateway: a caller with its
    /// bearer only gets an answer after recipe A verified RedPill's gateway for real.
    #[tokio::test]
    #[ignore = "hits the live RedPill API; run with REDPILL_API_KEY set, via --include-ignored"]
    async fn a_caller_with_its_bearer_gets_a_streamed_answer_after_live_verification() {
        let provider_key =
            std::env::var("REDPILL_API_KEY").expect("REDPILL_API_KEY is not set for the live test");
        let bearer = b"test-bearer".to_vec();

        let config = live_config();
        let upstream = Upstream::new(&config).unwrap();
        let state = Arc::new(crate::AppState {
            config,
            secrets: parking_lot::RwLock::new(crate::Secrets {
                provider_key: zeroize::Zeroizing::new(provider_key),
                caller_bearer: zeroize::Zeroizing::new(bearer.clone()),
            }),
            upstream,
        });
        let app = crate::router(state);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let http = reqwest::Client::new();
        let auth = format!("Bearer {}", String::from_utf8(bearer).unwrap());

        let model_response = http
            .get(format!(
                "http://{addr}/v1/models/nvidia/nemotron-3.5-lightning"
            ))
            .header(reqwest::header::AUTHORIZATION, &auth)
            .send()
            .await
            .unwrap();
        let model_status = model_response.status();
        assert_eq!(
            model_status,
            200,
            "{}",
            model_response.text().await.unwrap_or_default()
        );

        let completion_response = http
            .post(format!("http://{addr}/v1/chat/completions"))
            .header(reqwest::header::AUTHORIZATION, &auth)
            .json(&serde_json::json!({
                "model": "nvidia/nemotron-3.5-lightning",
                "stream": true,
                "messages": [{"role": "user", "content": "Reply with the single word: ok"}],
            }))
            .send()
            .await
            .unwrap();
        let completion_status = completion_response.status();
        let body = completion_response.text().await.unwrap_or_default();
        assert_eq!(completion_status, 200, "{body}");
        assert!(body.lines().any(|l| l.starts_with("data:")), "{body}");
        assert!(body.trim_end().ends_with("data: [DONE]"), "{body}");
    }
}
