//! The NVIDIA Remote Attestation Service backend. NRAS verifies each GPU's SPDM report, its
//! certificate chain and revocation, and the driver and VBIOS RIMs, and answers with an overall
//! EAT plus one EAT per GPU, all ES384 JWTs. This backend checks those signatures under the NRAS
//! keys the release-signed `gpu_policy` pins by `kid` (never under a key fetched at run time),
//! binds the per-GPU tokens to the overall one through its `submods` digests, checks the nonce and
//! every per-GPU result claim, and reduces each GPU to [`VerifiedGpu`].
//!
//! Development uses NRAS free of charge; a paid service needs NVIDIA's licence (L1, F9).
//! Results are accepted for one attestation, i.e. the life of one leaf (Q12). A call NRAS does
//! not answer is retried with backoff inside one bounded budget ([`Retry`]), then refused.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::prelude::{BASE64_STANDARD, BASE64_URL_SAFE_NO_PAD};
use p384::ecdsa::signature::Verifier;
use p384::ecdsa::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use super::{
    GpuEvidence, GpuFuture, GpuPolicy, GpuVerdict, GpuVerifier, GpuVerifierKind, VerifiedGpu,
};
use crate::AppraisalError;

pub const DEFAULT_URL: &str = "https://nras.attestation.nvidia.com";
const ATTEST_PATH: &str = "/v3/attest/gpu";
const CLOCK_SKEW: Duration = Duration::from_secs(60);

/// How the call to NRAS is retried (Q12, risk R4): only when NRAS gave no answer (no connection,
/// a timeout, `429`, `408` or a `5xx`), with a doubling backoff plus jitter, and everything inside
/// one `budget`, after which the attestation fails closed. An answer NRAS gave (a `4xx`, a body
/// that is not JSON, or any reply the checks refuse) is a verdict and is never retried.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Retry {
    /// Calls at most, the first included.
    pub attempts: u32,
    /// Each call's own limit.
    pub per_attempt: Duration,
    /// The wait before the second call, doubled before each later one; a jitter of up to half of
    /// it, drawn from the GPU nonce, keeps a fleet of renewals from retrying in step.
    pub backoff: Duration,
    /// Calls and waits together end within this.
    pub budget: Duration,
}

impl Default for Retry {
    /// Three calls of at most 15 s, 1 s then 2 s apart, all within 40 s: inside a renewal's
    /// window, and the KMS caller may pass a tighter one ([`Nras::with_retry`]).
    fn default() -> Self {
        Self {
            attempts: 3,
            per_attempt: Duration::from_secs(15),
            backoff: Duration::from_secs(1),
            budget: Duration::from_secs(40),
        }
    }
}

/// Why one call to NRAS did not return a reply.
enum Attempt {
    /// NRAS gave no answer; worth another call.
    Transient(String),
    /// NRAS answered; final.
    Final(AppraisalError),
}

/// Up to half of `wait`, from the nonce byte for this attempt.
fn jitter(nonce: &[u8; 32], attempt: u32, wait: Duration) -> Duration {
    let byte = usize::try_from(attempt)
        .ok()
        .and_then(|i| i.checked_rem(nonce.len()))
        .and_then(|i| nonce.get(i))
        .copied()
        .unwrap_or(0);
    let ms = u64::try_from(wait.as_millis()).unwrap_or(u64::MAX);
    Duration::from_millis(
        ms.saturating_mul(u64::from(byte))
            .checked_div(510)
            .unwrap_or(0),
    )
}

/// The claims this backend requires, named as NVIDIA's GPU claims version 3.0 lists them (4.0
/// only adds to 3.0). Every per-GPU requirement is a JSON pointer into that GPU's EAT claims.
// ponytail: G0 — `g0_nras_reply_has_every_claim_this_backend_requires` (docs/kata-attestation.md,
// "G0 check") runs these against a captured B300 reply before M-B. A missing claim refuses.
pub mod claims {
    pub const OVERALL_RESULT: &str = "x-nvidia-overall-att-result";
    pub const NONCE: &str = "eat_nonce";
    pub const SUBMODS: &str = "submods";
    pub const HWMODEL: &str = "hwmodel";
    pub const UEID: &str = "ueid";
    pub const DRIVER: &str = "x-nvidia-gpu-driver-version";
    pub const VBIOS: &str = "x-nvidia-gpu-vbios-version";
    /// Per-GPU text claims that must be present; read into [`super::VerifiedGpu`].
    pub const TEXT: [&str; 4] = [HWMODEL, UEID, DRIVER, VBIOS];

    /// What a required per-GPU claim must hold.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Expect {
        True,
        Text(&'static str),
        /// Must be true when NRAS sends it; older replies may leave it out.
        TrueIfPresent,
    }

    use Expect::*;

    /// The report, its certificate chain and revocation (OCSP), the driver and VBIOS RIMs with
    /// their certificate chains and revocation, the measurements, secure boot and debug.
    pub const REQUIRED: [(&str, Expect); 26] = [
        ("/measres", Text("success")),
        ("/secboot", True),
        ("/dbgstat", Text("disabled")),
        ("/x-nvidia-gpu-arch-check", True),
        ("/x-nvidia-gpu-attestation-report-parsed", True),
        ("/x-nvidia-gpu-attestation-report-signature-verified", True),
        ("/x-nvidia-gpu-attestation-report-nonce-match", True),
        (
            "/x-nvidia-gpu-attestation-report-cert-chain-fwid-match",
            True,
        ),
        (
            "/x-nvidia-gpu-attestation-report-cert-chain/x-nvidia-cert-status",
            Text("valid"),
        ),
        (
            "/x-nvidia-gpu-attestation-report-cert-chain/x-nvidia-cert-ocsp-status",
            Text("good"),
        ),
        (
            "/x-nvidia-gpu-attestation-report-cert-chain/x-nvidia-cert-ocsp-nonce-matches",
            TrueIfPresent,
        ),
        (
            "/x-nvidia-gpu-attestation-report-cert-chain/x-nvidia-cert-ocsp-response-valid",
            TrueIfPresent,
        ),
        ("/x-nvidia-gpu-driver-rim-signature-verified", True),
        ("/x-nvidia-gpu-driver-rim-version-match", True),
        (
            "/x-nvidia-gpu-driver-rim-cert-chain/x-nvidia-cert-status",
            Text("valid"),
        ),
        (
            "/x-nvidia-gpu-driver-rim-cert-chain/x-nvidia-cert-ocsp-status",
            Text("good"),
        ),
        (
            "/x-nvidia-gpu-driver-rim-cert-chain/x-nvidia-cert-ocsp-nonce-matches",
            TrueIfPresent,
        ),
        (
            "/x-nvidia-gpu-driver-rim-cert-chain/x-nvidia-cert-ocsp-response-valid",
            TrueIfPresent,
        ),
        ("/x-nvidia-gpu-vbios-rim-signature-verified", True),
        ("/x-nvidia-gpu-vbios-rim-version-match", True),
        (
            "/x-nvidia-gpu-vbios-rim-cert-chain/x-nvidia-cert-status",
            Text("valid"),
        ),
        (
            "/x-nvidia-gpu-vbios-rim-cert-chain/x-nvidia-cert-ocsp-status",
            Text("good"),
        ),
        (
            "/x-nvidia-gpu-vbios-rim-cert-chain/x-nvidia-cert-ocsp-nonce-matches",
            TrueIfPresent,
        ),
        (
            "/x-nvidia-gpu-vbios-rim-cert-chain/x-nvidia-cert-ocsp-response-valid",
            TrueIfPresent,
        ),
        ("/x-nvidia-gpu-vbios-index-no-conflict", True),
        ("/x-nvidia-gpu-driver-rim-measurements-available", True),
    ];
}

/// The per-GPU claim that shows the GPU is in confidential-computing mode, and the value it must
/// hold, as the release-signed `gpu_policy.nras_cc_mode` names it. NVIDIA's published GPU claims
/// (version 3.0) have no claim of that name, so it is not compiled in: it is confirmed on a B300
/// reply at G0 (docs/kata-attestation.md, "G0 check") and signed into the policy. Until then the
/// `nras` backend refuses every GPU.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NrasClaim {
    /// RFC 6901 JSON pointer into the per-GPU EAT claims, e.g. `/x-nvidia-attester-claims/<name>`.
    pub pointer: String,
    /// The JSON value that means CC mode is on.
    pub equals: Value,
}

fn expect_failure(claims: &Value, pointer: &str, expect: claims::Expect) -> Option<String> {
    use claims::Expect::*;
    let found = claims.pointer(pointer);
    let holds = match (expect, found) {
        (TrueIfPresent, None) => true,
        (True | TrueIfPresent, Some(v)) => v.as_bool() == Some(true),
        (Text(want), Some(v)) => v.as_str() == Some(want),
        (_, None) => false,
    };
    if holds {
        return None;
    }
    let want = match expect {
        True | TrueIfPresent => "true".to_owned(),
        Text(want) => format!("{want:?}"),
    };
    Some(match found {
        None => format!("claim {pointer} is missing"),
        Some(v) => format!("claim {pointer} is {v}, not {want}"),
    })
}

/// Whether the GPU is in CC mode by the policy's claim; `Err` when the policy names none or the
/// GPU's claims lack it (fail closed: a GPU is never reported in CC mode on a guess).
fn cc_mode(claims: &Value, policy: &GpuPolicy) -> Result<bool, String> {
    let claim = policy
        .nras_cc_mode
        .as_ref()
        .ok_or_else(|| "gpu_policy.nras_cc_mode names no CC-mode claim (G0 check)".to_owned())?;
    claims
        .pointer(&claim.pointer)
        .map(|v| *v == claim.equals)
        .ok_or_else(|| format!("CC-mode claim {} is missing", claim.pointer))
}

/// Every requirement this backend has of one GPU's EAT claims, checked without stopping at the
/// first failure: one line per claim that is missing or does not hold, and an empty list when
/// the claims would pass. Signatures, the nonce and the `submods` binding are not checked here.
/// The G0 check runs it over a captured B300 reply; [`parse_reply`] refuses on the first line.
pub fn claim_report(claims: &Value, policy: &GpuPolicy) -> Vec<String> {
    let mut out: Vec<String> = claims::REQUIRED
        .iter()
        .filter_map(|(pointer, expect)| expect_failure(claims, pointer, *expect))
        .collect();
    for name in claims::TEXT {
        if claims.get(name).and_then(Value::as_str).is_none() {
            out.push(format!("claim /{name} is missing"));
        }
    }
    if let Some(hwmodel) = claims.get(claims::HWMODEL).and_then(Value::as_str)
        && !policy.hwmodels.contains_key(hwmodel)
    {
        out.push(format!("hwmodel {hwmodel:?} is not in gpu_policy.hwmodels"));
    }
    match cc_mode(claims, policy) {
        Ok(true) => {}
        Ok(false) => {
            if let Some(claim) = &policy.nras_cc_mode {
                out.push(format!(
                    "CC-mode claim {} is {}, not {}",
                    claim.pointer,
                    claims.pointer(&claim.pointer).unwrap_or(&Value::Null),
                    claim.equals
                ));
            }
        }
        Err(e) => out.push(e),
    }
    out
}

/// NRAS over HTTPS; the URL comes from the release-signed `gpu_policy`, NVIDIA's by default.
pub struct Nras {
    http: reqwest::Client,
    clock: fn() -> SystemTime,
    retry: Retry,
}

impl Nras {
    pub fn new() -> Result<Self, AppraisalError> {
        Self::with_retry(Retry::default())
    }

    pub fn with_retry(retry: Retry) -> Result<Self, AppraisalError> {
        // Each attempt is bounded by `retry.per_attempt` and the budget in `call`.
        let http = reqwest::Client::builder()
            .build()
            .map_err(|e| AppraisalError::Failed(format!("nras client: {e}")))?;
        Ok(Self {
            http,
            clock: SystemTime::now,
            retry,
        })
    }

    async fn call(
        &self,
        base: &str,
        gpus: &[GpuEvidence],
        nonce: &[u8; 32],
    ) -> Result<Value, AppraisalError> {
        let arch = gpus
            .first()
            .map(|g| g.arch.clone())
            .ok_or_else(|| AppraisalError::Failed("no GPU evidence".into()))?;
        if gpus.iter().any(|g| g.arch != arch) {
            return Err(AppraisalError::Failed(
                "GPUs of more than one architecture".into(),
            ));
        }
        let body = json!({
            "nonce": hex::encode(nonce),
            "arch": arch,
            "evidence_list": gpus.iter().map(|g| json!({
                "evidence": BASE64_STANDARD.encode(&g.evidence),
                "certificate": BASE64_STANDARD.encode(&g.certificate),
            })).collect::<Vec<_>>(),
        });
        let url = format!("{base}{ATTEST_PATH}");
        let Retry {
            attempts,
            per_attempt,
            backoff,
            budget,
        } = self.retry;
        let start = tokio::time::Instant::now();
        let deadline = start.checked_add(budget).unwrap_or(start);
        let mut wait = backoff;
        let mut last = "no call made".to_owned();
        let mut made = 0u32;
        for attempt in 0..attempts {
            if attempt > 0 {
                let pause = wait.saturating_add(jitter(nonce, attempt, wait));
                let resume = tokio::time::Instant::now().checked_add(pause);
                if resume.is_none_or(|at| at >= deadline) {
                    break;
                }
                tokio::time::sleep(pause).await;
                wait = wait.saturating_mul(2);
            }
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            if left.is_zero() {
                break;
            }
            made = made.saturating_add(1);
            match tokio::time::timeout(left.min(per_attempt), self.attempt(&url, &body)).await {
                Ok(Ok(reply)) => return Ok(reply),
                Ok(Err(Attempt::Final(e))) => return Err(e),
                Ok(Err(Attempt::Transient(e))) => last = e,
                Err(_) => last = format!("no reply within {:?}", left.min(per_attempt)),
            }
        }
        Err(AppraisalError::Failed(format!(
            "nras attest: {last} ({made} attempts within {budget:?})"
        )))
    }

    async fn attempt(&self, url: &str, body: &Value) -> Result<Value, Attempt> {
        let response = self
            .http
            .post(url)
            .json(body)
            .send()
            .await
            .map_err(|e| Attempt::Transient(e.to_string()))?;
        let status = response.status();
        if status.is_server_error()
            || status == reqwest::StatusCode::TOO_MANY_REQUESTS
            || status == reqwest::StatusCode::REQUEST_TIMEOUT
        {
            return Err(Attempt::Transient(format!("status {status}")));
        }
        if !status.is_success() {
            return Err(Attempt::Final(AppraisalError::Failed(format!(
                "nras attest: status {status}"
            ))));
        }
        response
            .json()
            .await
            .map_err(|e| Attempt::Final(AppraisalError::Failed(format!("nras attest reply: {e}"))))
    }
}

impl GpuVerifier for Nras {
    fn kind(&self) -> GpuVerifierKind {
        GpuVerifierKind::Nras
    }

    fn verify<'a>(
        &'a self,
        gpus: &'a [GpuEvidence],
        nonce: &'a [u8; 32],
        policy: &'a GpuPolicy,
    ) -> GpuFuture<'a> {
        Box::pin(async move {
            // Checked before any call: with no pinned key nothing NRAS answers could be trusted,
            // and with no CC-mode claim no GPU could pass.
            if policy.nras_keys.is_empty() {
                return Err(AppraisalError::Unknown(
                    "gpu_policy.nras_keys pins no NRAS signing key".into(),
                ));
            }
            if policy.nras_cc_mode.is_none() {
                return Err(AppraisalError::Unknown(
                    "gpu_policy.nras_cc_mode names no CC-mode claim (G0 check)".into(),
                ));
            }
            let base = policy
                .nras_url
                .as_deref()
                .unwrap_or(DEFAULT_URL)
                .trim_end_matches('/');
            let reply = self.call(base, gpus, nonce).await?;
            parse_reply(&reply, base, gpus.len(), nonce, policy, (self.clock)())
        })
    }
}

/// One NRAS signing key as `gpu_policy.nras_keys` pins it under its `kid`: the EC P-384 public
/// key exactly as NRAS's JWKS publishes it (`x` and `y` base64url). Copied into the platform
/// document from NVIDIA's JWKS when the document is prepared and release-signed with it; NRAS
/// rotating a key therefore means a new platform document, never a key fetched at run time.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NrasKey {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
}

impl NrasKey {
    fn verifying_key(&self, kid: &str) -> Result<VerifyingKey, AppraisalError> {
        let bad = |m: &str| AppraisalError::Failed(format!("gpu_policy.nras_keys {kid:?}: {m}"));
        if self.kty != "EC" || self.crv != "P-384" {
            return Err(bad("key is not EC P-384"));
        }
        let coord = |c: &str| -> Result<[u8; 48], AppraisalError> {
            BASE64_URL_SAFE_NO_PAD
                .decode(c)
                .ok()
                .and_then(|b| <[u8; 48]>::try_from(b).ok())
                .ok_or_else(|| bad("coordinate is not 48 bytes base64url"))
        };
        let point = p384::EncodedPoint::from_affine_coordinates(
            &coord(&self.x)?.into(),
            &coord(&self.y)?.into(),
            false,
        );
        VerifyingKey::from_encoded_point(&point).map_err(|_| bad("not a P-384 point"))
    }
}

/// An ES384 JWT's claims after its signature (under the key pinned for its `kid`) and lifetime
/// are checked. A token with no `kid`, or one whose `kid` is not pinned, is refused.
fn verify_jwt(
    token: &str,
    keys: &BTreeMap<String, NrasKey>,
    issuer: &str,
    now: SystemTime,
) -> Result<Map<String, Value>, AppraisalError> {
    let bad = |m: String| AppraisalError::Failed(format!("nras token: {m}"));
    let mut parts = token.split('.');
    let (Some(h), Some(p), Some(s), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(bad("not a compact JWS".into()));
    };
    let decode = |what: &str, part: &str| {
        BASE64_URL_SAFE_NO_PAD
            .decode(part)
            .map_err(|_| bad(format!("{what} is not base64url")))
    };
    let header: Value =
        serde_json::from_slice(&decode("header", h)?).map_err(|e| bad(format!("header: {e}")))?;
    if header.get("alg").and_then(Value::as_str) != Some("ES384") {
        return Err(bad("alg is not ES384".into()));
    }
    let kid = header
        .get("kid")
        .and_then(Value::as_str)
        .ok_or_else(|| bad("names no kid".into()))?;
    let key = keys
        .get(kid)
        .ok_or_else(|| bad(format!("kid {kid:?} is not pinned in gpu_policy.nras_keys")))?
        .verifying_key(kid)?;
    let signature =
        Signature::from_slice(&decode("signature", s)?).map_err(|_| bad("signature".into()))?;
    key.verify(format!("{h}.{p}").as_bytes(), &signature)
        .map_err(|_| bad("signature does not verify".into()))?;
    let claims: Map<String, Value> =
        serde_json::from_slice(&decode("payload", p)?).map_err(|e| bad(format!("payload: {e}")))?;

    if claims.get("iss").and_then(Value::as_str) != Some(issuer) {
        return Err(bad(format!("issuer is not {issuer}")));
    }
    let now = now.duration_since(UNIX_EPOCH).unwrap_or_default();
    let at = |name: &str| {
        claims
            .get(name)
            .and_then(Value::as_u64)
            .map(Duration::from_secs)
    };
    let exp = at("exp").ok_or_else(|| bad("no exp".into()))?;
    if now > exp.saturating_add(CLOCK_SKEW) {
        return Err(bad("expired".into()));
    }
    if let Some(nbf) = at("nbf").or_else(|| at("iat"))
        && nbf > now.saturating_add(CLOCK_SKEW)
    {
        return Err(bad("not yet valid".into()));
    }
    Ok(claims)
}

/// The pure half of the backend, over NRAS's reply, with the keys `policy.nras_keys` pins. The
/// verdict's digest is over the overall EAT, which binds every per-GPU token through its
/// `submods`.
pub fn parse_reply(
    reply: &Value,
    issuer: &str,
    count: usize,
    nonce: &[u8; 32],
    policy: &GpuPolicy,
    now: SystemTime,
) -> Result<GpuVerdict, AppraisalError> {
    use AppraisalError::Failed;
    let bad = |m: String| Failed(format!("nras: {m}"));

    // [["JWT", "<overall>"], {"GPU-0": "<token>", …}]
    let items = reply
        .as_array()
        .ok_or_else(|| bad("reply is not an array".into()))?;
    let overall = items
        .first()
        .and_then(Value::as_array)
        .and_then(|pair| match pair.as_slice() {
            [kind, token] if kind.as_str() == Some("JWT") => token.as_str(),
            _ => None,
        })
        .ok_or_else(|| bad("no overall token".into()))?;
    let per_gpu = items
        .get(1)
        .and_then(Value::as_object)
        .ok_or_else(|| bad("no per-GPU tokens".into()))?;

    let token_sha256: [u8; 32] = Sha256::digest(overall.as_bytes()).into();
    let overall = verify_jwt(overall, &policy.nras_keys, issuer, now)?;
    if overall.get(claims::OVERALL_RESULT).and_then(Value::as_bool) != Some(true) {
        return Err(bad("overall attestation result is not true".into()));
    }
    let nonce_hex = hex::encode(nonce);
    if overall.get(claims::NONCE).and_then(Value::as_str) != Some(nonce_hex.as_str()) {
        return Err(bad("overall token is not over this nonce".into()));
    }
    let submods = overall
        .get(claims::SUBMODS)
        .and_then(Value::as_object)
        .ok_or_else(|| bad("overall token has no submods".into()))?;
    if per_gpu.len() != count || submods.len() != count {
        return Err(bad(format!(
            "{} GPU tokens and {} submods for {count} GPUs",
            per_gpu.len(),
            submods.len()
        )));
    }

    let mut out = Vec::with_capacity(count);
    for index in 0..count {
        let name = format!("GPU-{index}");
        let token = per_gpu
            .get(&name)
            .and_then(Value::as_str)
            .ok_or_else(|| bad(format!("no token for {name}")))?;
        // ["DIGEST", ["SHA256", "<hex>"]] ties this token to the signed overall result.
        let digest = submods
            .get(&name)
            .and_then(|d| d.pointer("/1/1"))
            .and_then(Value::as_str)
            .ok_or_else(|| bad(format!("no submod digest for {name}")))?;
        if hex::encode(Sha256::digest(token.as_bytes())) != digest.to_ascii_lowercase() {
            return Err(bad(format!(
                "{name} token is not the one the overall result names"
            )));
        }
        let c = Value::Object(verify_jwt(token, &policy.nras_keys, issuer, now)?);
        let text = |claim: &str| -> Result<String, AppraisalError> {
            c.get(claim)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| bad(format!("{name}: claim /{claim} is missing")))
        };
        if c.get(claims::NONCE).and_then(Value::as_str) != Some(nonce_hex.as_str()) {
            return Err(bad(format!("{name}: token is not over this nonce")));
        }
        if let Some(failure) = claims::REQUIRED
            .iter()
            .find_map(|(pointer, expect)| expect_failure(&c, pointer, *expect))
        {
            return Err(bad(format!("{name}: {failure}")));
        }
        let cc_mode = cc_mode(&c, policy).map_err(|e| bad(format!("{name}: {e}")))?;
        let hwmodel = text(claims::HWMODEL)?;
        let model = policy.hwmodels.get(&hwmodel).cloned().ok_or_else(|| {
            bad(format!(
                "{name}: hwmodel {hwmodel:?} is not in gpu_policy.hwmodels"
            ))
        })?;
        out.push(VerifiedGpu {
            index: u32::try_from(index).map_err(|_| bad("index".into()))?,
            device_id: text(claims::UEID)?,
            model,
            driver_version: text(claims::DRIVER)?,
            vbios_version: text(claims::VBIOS)?,
            cc_mode,
            nonce: *nonce,
        });
    }
    Ok(GpuVerdict {
        gpus: out,
        token_sha256,
    })
}

#[cfg(test)]
mod tests {
    use p384::ecdsa::SigningKey;
    use p384::ecdsa::signature::Signer;

    use super::*;

    const ISS: &str = "https://nras.example";
    const NONCE: [u8; 32] = [9; 32];

    fn key() -> SigningKey {
        SigningKey::from_slice(&[0x42; 48]).unwrap()
    }

    fn pinned(key: &SigningKey) -> NrasKey {
        let point = key.verifying_key().to_encoded_point(false);
        NrasKey {
            kty: "EC".into(),
            crv: "P-384".into(),
            x: BASE64_URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            y: BASE64_URL_SAFE_NO_PAD.encode(point.y().unwrap()),
        }
    }

    fn signed(header: &str, claims: &Value, key: &SigningKey) -> String {
        let h = BASE64_URL_SAFE_NO_PAD.encode(header);
        let p = BASE64_URL_SAFE_NO_PAD.encode(claims.to_string());
        let sig: Signature = key.sign(format!("{h}.{p}").as_bytes());
        format!("{h}.{p}.{}", BASE64_URL_SAFE_NO_PAD.encode(sig.to_bytes()))
    }

    fn jwt(claims: &Value) -> String {
        signed(r#"{"alg":"ES384","kid":"k1"}"#, claims, &key())
    }

    fn now() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_800_000_000)
    }

    /// The CC-mode claim the tests' policy names; a stand-in, not a claim NRAS is known to send.
    const CC_CLAIM: &str = "/x-test-cc-mode";

    /// Sets the claim at a two-level JSON pointer, creating the object it sits in.
    fn set(c: &mut Value, pointer: &str, value: Value) {
        let mut parts = pointer.trim_start_matches('/').split('/');
        let (first, second) = (parts.next().unwrap(), parts.next());
        match second {
            None => c[first] = value,
            Some(second) => {
                if c.get(first).is_none() {
                    c[first] = json!({});
                }
                c[first][second] = value;
            }
        }
    }

    fn gpu_claims() -> Value {
        let mut c = json!({
            "iss": ISS, "exp": 1_800_000_600u64, "iat": 1_800_000_000u64,
            "eat_nonce": hex::encode(NONCE), "ueid": "ueid-0",
            "hwmodel": "GB110 A01 GSP BROM", "x-nvidia-gpu-driver-version": "575.51.03",
            "x-nvidia-gpu-vbios-version": "97.00.9A.00.01", "x-test-cc-mode": "ON",
        });
        for (pointer, expect) in claims::REQUIRED {
            match expect {
                claims::Expect::True | claims::Expect::TrueIfPresent => {
                    set(&mut c, pointer, json!(true))
                }
                claims::Expect::Text(want) => set(&mut c, pointer, json!(want)),
            }
        }
        c
    }

    fn reply(gpus: &[Value]) -> Value {
        let tokens: Vec<String> = gpus.iter().map(jwt).collect();
        let submods: Map<String, Value> = tokens
            .iter()
            .enumerate()
            .map(|(i, t)| {
                (
                    format!("GPU-{i}"),
                    json!(["DIGEST", ["SHA256", hex::encode(Sha256::digest(t))]]),
                )
            })
            .collect();
        let overall = json!({
            "iss": ISS, "exp": 1_800_000_600u64, "eat_nonce": hex::encode(NONCE),
            "x-nvidia-overall-att-result": true, "submods": submods,
        });
        let per: Map<String, Value> = tokens
            .into_iter()
            .enumerate()
            .map(|(i, t)| (format!("GPU-{i}"), json!(t)))
            .collect();
        json!([["JWT", jwt(&overall)], per])
    }

    fn policy() -> GpuPolicy {
        GpuPolicy {
            allowed_models: vec!["B300".into()],
            min_driver_version: None,
            min_vbios_version: None,
            verifiers: vec![GpuVerifierKind::Nras],
            nras_url: Some(ISS.into()),
            hwmodels: [("GB110 A01 GSP BROM".to_owned(), "B300".to_owned())].into(),
            nras_keys: [("k1".to_owned(), pinned(&key()))].into(),
            nras_cc_mode: Some(NrasClaim {
                pointer: CC_CLAIM.into(),
                equals: json!("ON"),
            }),
        }
    }

    fn parse(reply: &Value, count: usize) -> Result<Vec<VerifiedGpu>, AppraisalError> {
        parse_reply(reply, ISS, count, &NONCE, &policy(), now()).map(|v| v.gpus)
    }

    #[test]
    fn eight_signed_gpu_tokens_reduce_to_verified_gpus() {
        let r = reply(&vec![gpu_claims(); 8]);
        let verdict = parse_reply(&r, ISS, 8, &NONCE, &policy(), now()).unwrap();
        let overall = r[0][1].as_str().unwrap();
        assert_eq!(
            verdict.token_sha256,
            <[u8; 32]>::from(Sha256::digest(overall.as_bytes()))
        );
        assert_eq!(verdict.gpus[3].device_id, "ueid-0");
        let out = parse(&r, 8).unwrap();
        assert_eq!(out.len(), 8);
        assert!(
            out.iter()
                .all(|g| g.model == "B300" && g.cc_mode && g.nonce == NONCE)
        );
        assert_eq!(out[7].index, 7);
        assert_eq!(out[0].vbios_version, "97.00.9A.00.01");
    }

    #[test]
    fn refuses_what_nras_did_not_vouch_for() {
        let with = |pointer: &str, value: Value| {
            let mut c = gpu_claims();
            set(&mut c, pointer, value);
            reply(&[c])
        };
        let without = |pointer: &str| {
            let mut c = gpu_claims();
            let (parent, last) = pointer.rsplit_once('/').unwrap();
            let parent = if parent.is_empty() {
                &mut c
            } else {
                c.pointer_mut(parent).unwrap()
            };
            parent.as_object_mut().unwrap().remove(last);
            reply(&[c])
        };
        for (case, r, reason) in [
            ("measurements", with("/measres", json!("fail")), "/measres"),
            (
                "nonce",
                with("/eat_nonce", json!(hex::encode([1u8; 32]))),
                "nonce",
            ),
            ("debug", with("/dbgstat", json!("enabled")), "/dbgstat"),
            (
                "rim",
                with("/x-nvidia-gpu-driver-rim-signature-verified", json!(false)),
                "driver-rim-signature-verified",
            ),
            (
                "revoked report certificate",
                with(
                    "/x-nvidia-gpu-attestation-report-cert-chain/x-nvidia-cert-status",
                    json!("revoked"),
                ),
                "attestation-report-cert-chain/x-nvidia-cert-status is \"revoked\"",
            ),
            (
                "report certificate OCSP unknown",
                with(
                    "/x-nvidia-gpu-attestation-report-cert-chain/x-nvidia-cert-ocsp-status",
                    json!("unknown"),
                ),
                "x-nvidia-cert-ocsp-status",
            ),
            (
                "revoked VBIOS RIM certificate",
                with(
                    "/x-nvidia-gpu-vbios-rim-cert-chain/x-nvidia-cert-ocsp-status",
                    json!("revoked"),
                ),
                "vbios-rim-cert-chain",
            ),
            (
                "invalid OCSP response",
                with(
                    "/x-nvidia-gpu-driver-rim-cert-chain/x-nvidia-cert-ocsp-response-valid",
                    json!(false),
                ),
                "ocsp-response-valid",
            ),
            (
                "no driver RIM certificate chain",
                without("/x-nvidia-gpu-driver-rim-cert-chain"),
                "driver-rim-cert-chain/x-nvidia-cert-status is missing",
            ),
            (
                "no FWID match",
                without("/x-nvidia-gpu-attestation-report-cert-chain-fwid-match"),
                "fwid-match is missing",
            ),
            ("no device identity", without("/ueid"), "/ueid is missing"),
            (
                "model",
                with("/hwmodel", json!("GH100 A01 GSP BROM")),
                "hwmodels",
            ),
            ("expired", with("/exp", json!(1_700_000_000u64)), "expired"),
            (
                "issuer",
                with("/iss", json!("https://evil.example")),
                "issuer",
            ),
            (
                "no CC-mode claim",
                without(CC_CLAIM),
                "CC-mode claim /x-test-cc-mode is missing",
            ),
        ] {
            let error = parse(&r, 1).unwrap_err().to_string();
            assert!(error.contains(reason), "{case}: {error}");
        }
        // The optional OCSP claims may be absent.
        assert!(
            parse(
                &without("/x-nvidia-gpu-vbios-rim-cert-chain/x-nvidia-cert-ocsp-nonce-matches"),
                1
            )
            .is_ok()
        );
        // CC mode off, or DevTools mode, is reported as not in CC mode, and check_gpus refuses it.
        for mode in ["OFF", "DEVTOOLS"] {
            let out = parse(&with(CC_CLAIM, json!(mode)), 1).unwrap();
            assert!(!out[0].cc_mode, "{mode}");
        }
        // A policy that names no CC-mode claim refuses every GPU.
        let mut unset = policy();
        unset.nras_cc_mode = None;
        let error = parse_reply(&reply(&[gpu_claims()]), ISS, 1, &NONCE, &unset, now())
            .unwrap_err()
            .to_string();
        assert!(error.contains("nras_cc_mode"), "{error}");
    }

    #[test]
    fn claim_report_lists_every_claim_a_reply_lacks() {
        assert!(claim_report(&gpu_claims(), &policy()).is_empty());
        // A reply in the claims 2.0 shape: booleans where 3.0 has certificate-chain objects.
        let mut old = gpu_claims();
        for chain in ["attestation-report", "driver-rim", "vbios-rim"] {
            old.as_object_mut()
                .unwrap()
                .remove(&format!("x-nvidia-gpu-{chain}-cert-chain"));
        }
        old.as_object_mut().unwrap().remove("x-test-cc-mode");
        old["hwmodel"] = json!("GB999 unknown");
        let report = claim_report(&old, &policy());
        assert_eq!(report.len(), 8, "{report:#?}");
        assert!(report.iter().any(|l| l.contains("GB999")));
        assert!(report.iter().any(|l| l.contains("CC-mode claim")));
        let mut unset = policy();
        unset.nras_cc_mode = None;
        assert_eq!(
            claim_report(&gpu_claims(), &unset),
            ["gpu_policy.nras_cc_mode names no CC-mode claim (G0 check)"]
        );
    }

    /// The G0 check (docs/kata-attestation.md): run against a reply NRAS gave for a B300 pod's
    /// GPUs. `ALPHA_NRAS_REPLY` is the reply's path; `ALPHA_GPU_POLICY` optionally the candidate
    /// `gpu_policy` (JSON) whose `hwmodels` and `nras_cc_mode` are to be confirmed. Signatures are
    /// not checked here, only that every claim this backend requires is present and holds.
    #[test]
    #[ignore = "G0: needs a captured B300 NRAS reply (ALPHA_NRAS_REPLY)"]
    fn g0_nras_reply_has_every_claim_this_backend_requires() {
        let read = |var: &str| {
            std::env::var(var)
                .ok()
                .map(|path| std::fs::read(&path).unwrap_or_else(|e| panic!("{var}={path}: {e}")))
        };
        let reply: Value = serde_json::from_slice(
            &read("ALPHA_NRAS_REPLY").expect("set ALPHA_NRAS_REPLY to a captured NRAS reply"),
        )
        .unwrap();
        let policy: GpuPolicy = read("ALPHA_GPU_POLICY")
            .map(|b| serde_json::from_slice(&b).unwrap())
            .unwrap_or_else(|| GpuPolicy {
                nras_cc_mode: None,
                hwmodels: Default::default(),
                ..policy()
            });
        let payload = |token: &str| -> Value {
            let p = token.split('.').nth(1).unwrap();
            serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(p).unwrap()).unwrap()
        };
        let overall = payload(reply[0][1].as_str().unwrap());
        println!("overall claims: {overall:#}");
        let mut failures = Vec::new();
        for (name, token) in reply[1].as_object().unwrap() {
            let claims = payload(token.as_str().unwrap());
            println!("{name} claims: {claims:#}");
            failures.extend(
                claim_report(&claims, &policy)
                    .into_iter()
                    .map(|l| format!("{name}: {l}")),
            );
        }
        assert!(failures.is_empty(), "{failures:#?}");
    }

    #[test]
    fn refuses_unbound_or_forged_tokens_and_wrong_counts() {
        let good = reply(&[gpu_claims()]);
        assert!(
            parse(&good, 2)
                .unwrap_err()
                .to_string()
                .contains("for 2 GPUs")
        );

        // A per-GPU token swapped for another validly signed one breaks the submods digest.
        let mut swapped = good.clone();
        let mut other = gpu_claims();
        other["x-nvidia-gpu-driver-version"] = json!("1.0");
        swapped[1]["GPU-0"] = json!(jwt(&other));
        assert!(
            parse(&swapped, 1)
                .unwrap_err()
                .to_string()
                .contains("overall result names")
        );

        // A token signed by another key does not verify.
        let mut forged = good.clone();
        let token = forged[0][1].as_str().unwrap().to_owned();
        let (head, _) = token.rsplit_once('.').unwrap();
        let other_key = SigningKey::from_slice(&[0x43; 48]).unwrap();
        let sig: Signature = other_key.sign(head.as_bytes());
        forged[0][1] = json!(format!(
            "{head}.{}",
            BASE64_URL_SAFE_NO_PAD.encode(sig.to_bytes())
        ));
        assert!(
            parse(&forged, 1)
                .unwrap_err()
                .to_string()
                .contains("does not verify")
        );

        let mut failed_overall = good;
        let mut overall = json!({"iss": ISS, "exp": 1_800_000_600u64, "eat_nonce": hex::encode(NONCE),
            "x-nvidia-overall-att-result": false, "submods": {}});
        failed_overall[0][1] = json!(jwt(&overall));
        assert!(
            parse(&failed_overall, 1)
                .unwrap_err()
                .to_string()
                .contains("overall")
        );
        overall["alg"] = json!(null);
        assert!(parse(&json!({}), 1).is_err());
    }

    #[test]
    fn only_keys_pinned_in_the_policy_are_trusted() {
        let good = reply(&[gpu_claims()]);
        // A validly formed token from a key NRAS might publish, but the policy does not pin.
        let rogue = SigningKey::from_slice(&[0x44; 48]).unwrap();
        let mut unknown_kid = good.clone();
        unknown_kid[0][1] = json!(signed(
            r#"{"alg":"ES384","kid":"k2"}"#,
            &json!({"iss": ISS, "exp": 1_800_000_600u64}),
            &rogue
        ));
        let error = parse(&unknown_kid, 1).unwrap_err().to_string();
        assert!(error.contains("\"k2\" is not pinned"), "{error}");
        let mut no_kid = good.clone();
        no_kid[0][1] = json!(signed(
            r#"{"alg":"ES384"}"#,
            &json!({"iss": ISS, "exp": 1_800_000_600u64}),
            &key()
        ));
        let error = parse(&no_kid, 1).unwrap_err().to_string();
        assert!(error.contains("no kid"), "{error}");
        // The rogue key pinned under the kid the token names is still not the key it signed with
        // when the policy pins another key there.
        let mut policy = policy();
        policy.nras_keys.insert("k1".into(), pinned(&rogue));
        let error = parse_reply(&good, ISS, 1, &NONCE, &policy, now())
            .unwrap_err()
            .to_string();
        assert!(error.contains("does not verify"), "{error}");
        policy.nras_keys.insert(
            "k1".into(),
            NrasKey {
                kty: "RSA".into(),
                ..pinned(&key())
            },
        );
        let error = parse_reply(&good, ISS, 1, &NONCE, &policy, now())
            .unwrap_err()
            .to_string();
        assert!(error.contains("not EC P-384"), "{error}");
    }

    /// A stand-in NRAS that answers each connection with the next status in `script` (the last
    /// one repeating) and `[]` as the body of a 200; `None` holds the connection without
    /// answering. Returns its base URL and the number of calls it took.
    fn stand_in(
        script: Vec<Option<u16>>,
    ) -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        use std::io::{BufRead, BufReader, Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = calls.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let n = counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let step = script.get(n).or(script.last()).copied().flatten();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut length = 0usize;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                    if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        length = v.trim().parse().unwrap();
                    }
                }
                let mut body = vec![0; length];
                let _ = reader.read_exact(&mut body);
                match step {
                    None => {
                        std::thread::sleep(Duration::from_secs(5));
                    }
                    Some(status) => {
                        let body = if status == 200 { "[]" } else { "" };
                        let _ = write!(
                            stream,
                            "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                    }
                }
            }
        });
        (base, calls)
    }

    fn quick(attempts: u32, budget: Duration) -> Nras {
        Nras::with_retry(Retry {
            attempts,
            per_attempt: Duration::from_millis(300),
            backoff: Duration::from_millis(20),
            budget,
        })
        .unwrap()
    }

    fn evidence() -> [GpuEvidence; 1] {
        [GpuEvidence {
            arch: "BLACKWELL".into(),
            evidence: vec![1],
            certificate: vec![2],
        }]
    }

    #[tokio::test]
    async fn nras_is_retried_only_when_it_gave_no_answer() {
        let long = Duration::from_secs(10);
        // Two unavailable answers, then a reply.
        let (base, calls) = stand_in(vec![Some(503), Some(502), Some(200)]);
        let reply = quick(3, long)
            .call(&base, &evidence(), &NONCE)
            .await
            .unwrap();
        assert_eq!(reply, json!([]));
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 3);

        // An answer NRAS gave is final.
        let (base, calls) = stand_in(vec![Some(400)]);
        let error = quick(3, long)
            .call(&base, &evidence(), &NONCE)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("400"), "{error}");
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);

        // Unavailable every time: refused after the last attempt, fail closed.
        let (base, calls) = stand_in(vec![Some(503)]);
        let error = quick(3, long)
            .call(&base, &evidence(), &NONCE)
            .await
            .unwrap_err();
        assert_eq!(error.code(), "attestation_failed");
        assert!(error.to_string().contains("3 attempts"), "{error}");
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn retries_end_within_the_budget() {
        // NRAS accepts the connection and never answers; ten attempts would take 3 s, the budget
        // is 700 ms.
        let (base, calls) = stand_in(vec![None]);
        let started = std::time::Instant::now();
        let error = quick(10, Duration::from_millis(700))
            .call(&base, &evidence(), &NONCE)
            .await
            .unwrap_err();
        assert!(started.elapsed() < Duration::from_millis(1500));
        assert!(error.to_string().contains("no reply within"), "{error}");
        assert!(calls.load(std::sync::atomic::Ordering::SeqCst) < 10);
    }

    #[test]
    fn jitter_is_at_most_half_the_wait() {
        let wait = Duration::from_secs(2);
        assert_eq!(jitter(&[0; 32], 1, wait), Duration::ZERO);
        assert_eq!(jitter(&[255; 32], 1, wait), Duration::from_secs(1));
        let mut nonce = [0; 32];
        nonce[2] = 51;
        assert_eq!(jitter(&nonce, 2, wait), Duration::from_millis(200));
        assert_eq!(jitter(&nonce, 34, wait), Duration::from_millis(200));
    }

    #[tokio::test]
    async fn no_pinned_key_refuses_before_calling_nras() {
        let mut policy = policy();
        policy.nras_keys.clear();
        // Nothing listens there; the refusal must come before any connection is tried.
        policy.nras_url = Some("http://127.0.0.1:9".into());
        let gpus = [GpuEvidence {
            arch: "BLACKWELL".into(),
            evidence: vec![1],
            certificate: vec![2],
        }];
        let error = Nras::new()
            .unwrap()
            .verify(&gpus, &NONCE, &policy)
            .await
            .unwrap_err();
        assert_eq!(error.code(), "attestation_unknown");
        assert!(error.to_string().contains("nras_keys"), "{error}");
    }
}
