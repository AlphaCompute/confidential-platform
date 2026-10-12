//! The `local` [`GpuVerifier`]: the RIM cache read at start, an optional online OCSP query to the
//! one endpoint the release-signed `gpu_policy` names, and [`super::appraise::appraise`].

use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use sha2::{Digest, Sha256};
use x509_cert::Certificate;

use super::appraise::{appraise, missing_statuses};
use super::cache::RimCache;
use super::{ocsp, policy};
use crate::AppraisalError;
use crate::gpu::{GpuEvidence, GpuFuture, GpuPolicy, GpuVerifier, GpuVerifierKind};

/// Each online OCSP query's limit, and the whole appraisal's budget for them.
pub const OCSP_QUERY_TIMEOUT: Duration = Duration::from_secs(5);
pub const OCSP_BUDGET: Duration = Duration::from_secs(20);
/// Responses fetched online that are kept for later appraisals, at most.
const MAX_FETCHED: usize = 1024;

/// The local GPU verifier.
pub struct Local {
    cache: RimCache,
    http: reqwest::Client,
    clock: fn() -> SystemTime,
    /// Good responses fetched online, reused until they reach the policy's maximum age.
    fetched: Mutex<Vec<ocsp::Response>>,
}

impl Local {
    pub fn new(cache: RimCache) -> Result<Self, AppraisalError> {
        let http = reqwest::Client::builder()
            .timeout(OCSP_QUERY_TIMEOUT)
            .build()
            .map_err(|e| AppraisalError::Failed(format!("local ocsp client: {e}")))?;
        Ok(Self {
            cache,
            http,
            clock: SystemTime::now,
            fetched: Mutex::new(Vec::new()),
        })
    }

    /// For tests: a fixed clock.
    pub fn with_clock(mut self, clock: fn() -> SystemTime) -> Self {
        self.clock = clock;
        self
    }

    /// How many RIMs and OCSP responses the cache holds, for the KMS's start-up log.
    pub fn cache_size(&self) -> (usize, usize) {
        (self.cache.rims.len(), self.cache.ocsp.len())
    }

    fn fetched(&self) -> Vec<ocsp::Response> {
        self.fetched.lock().map(|f| f.clone()).unwrap_or_default()
    }

    /// Queries `url` for every status the decision needs that neither the cache nor an earlier
    /// query gives. A response must echo the nonce sent, which is fresh per appraisal (derived
    /// from the GPU nonce), so a replayed answer is useless. Errors are not returned: a status
    /// still missing refuses in the appraisal, naming the certificate.
    async fn query(
        &self,
        url: &str,
        pairs: Vec<(Certificate, Certificate)>,
        nonce: &[u8; 32],
        pinned: &policy::Pinned,
        now: SystemTime,
    ) -> Vec<ocsp::Response> {
        let since_epoch = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default();
        let deadline = tokio::time::Instant::now().checked_add(OCSP_BUDGET);
        let mut out = Vec::new();
        for (cert, issuer) in pairs {
            if deadline.is_some_and(|d| tokio::time::Instant::now() >= d) {
                break;
            }
            let ocsp_nonce: [u8; 16] = Sha256::new()
                .chain_update(b"alphacompute/gpu-local/ocsp-nonce/v1")
                .chain_update(nonce)
                .chain_update(cert.tbs_certificate.serial_number.as_bytes())
                .finalize()
                .get(..16)
                .and_then(|s| <[u8; 16]>::try_from(s).ok())
                .unwrap_or_default();
            let Ok(request) = ocsp::request(&cert, &issuer, &ocsp_nonce) else {
                continue;
            };
            let Ok(response) = self
                .http
                .post(url)
                .header("content-type", "application/ocsp-request")
                .body(request)
                .send()
                .await
            else {
                continue;
            };
            if !response.status().is_success()
                || response
                    .content_length()
                    .is_some_and(|n| n > ocsp::MAX_RESPONSE_DER as u64)
            {
                continue;
            }
            let Ok(body) = response.bytes().await else {
                continue;
            };
            let Ok(parsed) = ocsp::parse(&body) else {
                continue;
            };
            // Kept only if it is about this certificate, echoes our nonce and is reliable.
            if parsed.nonce().as_deref() == Some(&ocsp_nonce[..])
                && parsed
                    .status(&cert, &issuer, since_epoch, pinned.ocsp)
                    .is_ok()
            {
                out.push(parsed);
            }
        }
        if let Ok(mut kept) = self.fetched.lock() {
            kept.retain(|r| r.age(since_epoch) <= pinned.ocsp.max_age);
            kept.extend(out.iter().cloned());
            let excess = kept.len().saturating_sub(MAX_FETCHED);
            kept.drain(..excess);
        }
        out
    }
}

impl GpuVerifier for Local {
    fn kind(&self) -> GpuVerifierKind {
        GpuVerifierKind::Local
    }

    fn verify<'a>(
        &'a self,
        gpus: &'a [GpuEvidence],
        nonce: &'a [u8; 32],
        policy: &'a GpuPolicy,
    ) -> GpuFuture<'a> {
        Box::pin(async move {
            // Before anything is parsed or fetched: with nothing pinned, nothing could pass.
            let pinned = policy::pinned(policy.local.as_ref())?;
            let now = (self.clock)();
            let mut extra = self.fetched();
            if let Some(url) = &pinned.ocsp_url {
                let pairs = missing_statuses(gpus, &pinned, &self.cache, &extra, now);
                if !pairs.is_empty() {
                    extra.extend(self.query(url, pairs, nonce, &pinned, now).await);
                }
            }
            appraise(gpus, nonce, policy, &self.cache, &extra, now)
        })
    }
}
