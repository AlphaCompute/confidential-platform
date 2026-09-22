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

/// A model's last passing check: when, and a client that will only ever complete a handshake
/// against the exact SPKI that check's report bound.
struct Verified {
    checked_at: SystemTime,
    client: reqwest::Client,
}

/// Recipe A over the allowlisted models. One `Mutex` per model, built once at startup —
/// nothing is inserted at runtime, so the mutex is the single flight for that model's check.
pub struct Upstream {
    upstream_url: String,
    pccs_url: String,
    policy: Policy,
    slots: HashMap<String, Mutex<Option<Verified>>>,
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

    /// A client pinned to `model`'s attested key, verified within the last minute — refetching
    /// recipe A first if the last check is older than that, or there was none yet.
    pub async fn verified(&self, model: &str) -> Result<reqwest::Client, VerifyOutcome> {
        let Some(slot) = self.slots.get(model) else {
            return Err(VerifyOutcome::UnknownModel);
        };
        let mut guard = slot.lock().await;
        let now = (self.now)();
        if let Some(verified) = guard.as_ref()
            && now
                .duration_since(verified.checked_at)
                .unwrap_or(Duration::MAX)
                < VERIFIED_TTL
        {
            return Ok(verified.client.clone());
        }
        match self.check(model, now).await {
            Ok(verified) => {
                let client = verified.client.clone();
                *guard = Some(verified);
                Ok(client)
            }
            Err(reason) => {
                // A failed refetch is final, even if the slot held a good result a moment ago.
                *guard = None;
                eprintln!(
                    "alpha-inference: verification failed for {model}: {}",
                    reason.code()
                );
                Err(VerifyOutcome::Unverified(reason))
            }
        }
    }

    /// The pinned connection for `model` failed after a passing check; the next call to
    /// `verified` runs recipe A again instead of reusing a client that just proved stale.
    pub async fn forget(&self, model: &str) {
        if let Some(slot) = self.slots.get(model) {
            *slot.lock().await = None;
        }
    }

    async fn check(&self, model: &str, now: SystemTime) -> Result<Verified, Reason> {
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

        let leaf = response
            .extensions()
            .get::<reqwest::tls::TlsInfo>()
            .and_then(|info| info.peer_certificate().map(<[u8]>::to_vec))
            .ok_or(Reason::Fetch)?;
        let spki = alpha_client::tls::spki_of(&leaf).map_err(|_| Reason::Fetch)?;

        let status = response.status();
        let bytes = response.bytes().await.map_err(|_| Reason::Fetch)?;
        if !status.is_success() {
            return Err(Reason::Status);
        }
        let report: Report = serde_json::from_slice(&bytes).map_err(|_| Reason::Shape)?;
        let quote = hex::decode(&report.intel_quote).map_err(|_| Reason::Shape)?;

        let collateral = alpha_attest::fetch_collateral(&self.pccs_url, &quote)
            .await
            .map_err(|_| Reason::Collateral)?;

        check_report(&report, &spki, &nonce, &collateral, &self.policy, now)?;

        Ok(Verified {
            client: pinned_client(&spki).map_err(|_| Reason::Binding)?,
            checked_at: now,
        })
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
    use std::time::UNIX_EPOCH;

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
