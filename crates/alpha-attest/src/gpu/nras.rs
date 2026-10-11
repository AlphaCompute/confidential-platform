//! The NVIDIA Remote Attestation Service backend. NRAS verifies each GPU's SPDM report, its
//! certificate chain and revocation, and the driver and VBIOS RIMs, and answers with an overall
//! EAT plus one EAT per GPU, all ES384 JWTs under NVIDIA's JWKS. This backend checks those
//! signatures, binds the per-GPU tokens to the overall one through its `submods` digests, checks
//! the nonce and every per-GPU result claim, and reduces each GPU to [`VerifiedGpu`].
//!
//! Development uses NRAS free of charge; a paid service needs NVIDIA's licence (L1, F9).
//! Results are accepted for one attestation, i.e. the life of one leaf (Q12).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::prelude::{BASE64_STANDARD, BASE64_URL_SAFE_NO_PAD};
use p384::ecdsa::signature::Verifier;
use p384::ecdsa::{Signature, VerifyingKey};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use super::{
    GpuEvidence, GpuFuture, GpuPolicy, GpuVerdict, GpuVerifier, GpuVerifierKind, VerifiedGpu,
};
use crate::AppraisalError;

pub const DEFAULT_URL: &str = "https://nras.attestation.nvidia.com";
const ATTEST_PATH: &str = "/v3/attest/gpu";
const JWKS_PATH: &str = "/.well-known/jwks.json";
const CLOCK_SKEW: Duration = Duration::from_secs(60);
const TIMEOUT: Duration = Duration::from_secs(20);

/// The per-GPU claims this backend requires, named as NRAS emits them.
// ponytail: confirm every name against an NRAS reply for a B300 at M-B; `CC_MODE` especially, whose
// name is not in NVIDIA's published claim list we have. A missing claim refuses (fail closed).
mod claims {
    pub const OVERALL_RESULT: &str = "x-nvidia-overall-att-result";
    pub const NONCE: &str = "eat_nonce";
    pub const SUBMODS: &str = "submods";
    pub const MEASUREMENTS: &str = "measres";
    pub const MEASUREMENTS_OK: &str = "success";
    pub const REQUIRED_TRUE: [&str; 6] = [
        "x-nvidia-gpu-arch-check",
        "x-nvidia-gpu-attestation-report-signature-verified",
        "x-nvidia-gpu-attestation-report-nonce-match",
        "x-nvidia-gpu-driver-rim-signature-verified",
        "x-nvidia-gpu-vbios-rim-signature-verified",
        "secboot",
    ];
    pub const DEBUG: &str = "dbgstat";
    pub const DEBUG_OFF: &str = "disabled";
    pub const HWMODEL: &str = "hwmodel";
    pub const UEID: &str = "ueid";
    pub const DRIVER: &str = "x-nvidia-gpu-driver-version";
    pub const VBIOS: &str = "x-nvidia-gpu-vbios-version";
    pub const CC_MODE: &str = "x-nvidia-cc-mode";
    pub const CC_MODE_ON: &str = "ON";
}

/// NRAS over HTTPS; the URL comes from the release-signed `gpu_policy`, NVIDIA's by default.
pub struct Nras {
    http: reqwest::Client,
    clock: fn() -> SystemTime,
}

impl Nras {
    pub fn new() -> Result<Self, AppraisalError> {
        let http = reqwest::Client::builder()
            .timeout(TIMEOUT)
            .build()
            .map_err(|e| AppraisalError::Failed(format!("nras client: {e}")))?;
        Ok(Self {
            http,
            clock: SystemTime::now,
        })
    }

    async fn call(
        &self,
        base: &str,
        gpus: &[GpuEvidence],
        nonce: &[u8; 32],
    ) -> Result<(Value, Jwks), AppraisalError> {
        let failed =
            |what: &str, e: reqwest::Error| AppraisalError::Failed(format!("nras {what}: {e}"));
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
        let reply: Value = self
            .http
            .post(format!("{base}{ATTEST_PATH}"))
            .json(&body)
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .map_err(|e| failed("attest", e))?
            .json()
            .await
            .map_err(|e| failed("attest reply", e))?;
        let jwks: Jwks = self
            .http
            .get(format!("{base}{JWKS_PATH}"))
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .map_err(|e| failed("jwks", e))?
            .json()
            .await
            .map_err(|e| failed("jwks reply", e))?;
        Ok((reply, jwks))
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
            let base = policy
                .nras_url
                .as_deref()
                .unwrap_or(DEFAULT_URL)
                .trim_end_matches('/');
            let (reply, jwks) = self.call(base, gpus, nonce).await?;
            parse_reply(
                &reply,
                &jwks,
                base,
                gpus.len(),
                nonce,
                policy,
                (self.clock)(),
            )
        })
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Jwk {
    #[serde(default)]
    pub kid: Option<String>,
    pub kty: String,
    #[serde(default)]
    pub crv: Option<String>,
    #[serde(default)]
    pub x: Option<String>,
    #[serde(default)]
    pub y: Option<String>,
}

impl Jwks {
    fn key(&self, kid: Option<&str>) -> Result<VerifyingKey, AppraisalError> {
        let bad = |m: &str| AppraisalError::Failed(format!("nras jwks: {m}"));
        let jwk = self
            .keys
            .iter()
            .find(|k| kid.is_none() || k.kid.as_deref() == kid)
            .ok_or_else(|| bad("no key for the token's kid"))?;
        if jwk.kty != "EC" || jwk.crv.as_deref() != Some("P-384") {
            return Err(bad("key is not EC P-384"));
        }
        let coord = |c: &Option<String>| -> Result<[u8; 48], AppraisalError> {
            c.as_deref()
                .and_then(|c| BASE64_URL_SAFE_NO_PAD.decode(c).ok())
                .and_then(|b| <[u8; 48]>::try_from(b).ok())
                .ok_or_else(|| bad("coordinate is not 48 bytes base64url"))
        };
        let point = p384::EncodedPoint::from_affine_coordinates(
            &coord(&jwk.x)?.into(),
            &coord(&jwk.y)?.into(),
            false,
        );
        VerifyingKey::from_encoded_point(&point).map_err(|_| bad("not a P-384 point"))
    }
}

/// An ES384 JWT's claims after its signature and lifetime are checked.
fn verify_jwt(
    token: &str,
    jwks: &Jwks,
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
    let key = jwks.key(header.get("kid").and_then(Value::as_str))?;
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

/// The pure half of the backend, over NRAS's reply and JWKS. The verdict's digest is over the
/// overall EAT, which binds every per-GPU token through its `submods`.
pub fn parse_reply(
    reply: &Value,
    jwks: &Jwks,
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
    let overall = verify_jwt(overall, jwks, issuer, now)?;
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
        let c = verify_jwt(token, jwks, issuer, now)?;
        let text = |claim: &str| -> Result<String, AppraisalError> {
            c.get(claim)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| bad(format!("{name}: no {claim}")))
        };
        if c.get(claims::NONCE).and_then(Value::as_str) != Some(nonce_hex.as_str()) {
            return Err(bad(format!("{name}: token is not over this nonce")));
        }
        if text(claims::MEASUREMENTS)? != claims::MEASUREMENTS_OK {
            return Err(bad(format!("{name}: measurements do not match the RIMs")));
        }
        if let Some(claim) = claims::REQUIRED_TRUE
            .iter()
            .find(|claim| c.get(**claim).and_then(Value::as_bool) != Some(true))
        {
            return Err(bad(format!("{name}: {claim} is not true")));
        }
        if text(claims::DEBUG)? != claims::DEBUG_OFF {
            return Err(bad(format!("{name}: debug is not disabled")));
        }
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
            cc_mode: c
                .get(claims::CC_MODE)
                .and_then(Value::as_str)
                .is_some_and(|m| m.eq_ignore_ascii_case(claims::CC_MODE_ON)),
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

    fn jwks() -> Jwks {
        let point = key().verifying_key().to_encoded_point(false);
        Jwks {
            keys: vec![Jwk {
                kid: Some("k1".into()),
                kty: "EC".into(),
                crv: Some("P-384".into()),
                x: Some(BASE64_URL_SAFE_NO_PAD.encode(point.x().unwrap())),
                y: Some(BASE64_URL_SAFE_NO_PAD.encode(point.y().unwrap())),
            }],
        }
    }

    fn jwt(claims: &Value) -> String {
        let h = BASE64_URL_SAFE_NO_PAD.encode(br#"{"alg":"ES384","kid":"k1"}"#);
        let p = BASE64_URL_SAFE_NO_PAD.encode(claims.to_string());
        let sig: Signature = key().sign(format!("{h}.{p}").as_bytes());
        format!("{h}.{p}.{}", BASE64_URL_SAFE_NO_PAD.encode(sig.to_bytes()))
    }

    fn now() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_800_000_000)
    }

    fn gpu_claims() -> Value {
        let mut c = json!({
            "iss": ISS, "exp": 1_800_000_600u64, "iat": 1_800_000_000u64,
            "eat_nonce": hex::encode(NONCE), "measres": "success", "dbgstat": "disabled",
            "ueid": "ueid-0",
            "hwmodel": "GB110 A01 GSP BROM", "x-nvidia-gpu-driver-version": "575.51.03",
            "x-nvidia-gpu-vbios-version": "97.00.9A.00.01", "x-nvidia-cc-mode": "ON",
        });
        for claim in claims::REQUIRED_TRUE {
            c[claim] = json!(true);
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
        }
    }

    fn parse(reply: &Value, count: usize) -> Result<Vec<VerifiedGpu>, AppraisalError> {
        parse_reply(reply, &jwks(), ISS, count, &NONCE, &policy(), now()).map(|v| v.gpus)
    }

    #[test]
    fn eight_signed_gpu_tokens_reduce_to_verified_gpus() {
        let r = reply(&vec![gpu_claims(); 8]);
        let verdict = parse_reply(&r, &jwks(), ISS, 8, &NONCE, &policy(), now()).unwrap();
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
        let with = |claim: &str, value: Value| {
            let mut c = gpu_claims();
            c[claim] = value;
            reply(&[c])
        };
        for (case, r, reason) in [
            ("measurements", with("measres", json!("fail")), "RIMs"),
            (
                "nonce",
                with("eat_nonce", json!(hex::encode([1u8; 32]))),
                "nonce",
            ),
            ("debug", with("dbgstat", json!("enabled")), "debug"),
            (
                "rim",
                with("x-nvidia-gpu-driver-rim-signature-verified", json!(false)),
                "rim",
            ),
            (
                "model",
                with("hwmodel", json!("GH100 A01 GSP BROM")),
                "hwmodels",
            ),
            ("expired", with("exp", json!(1_700_000_000u64)), "expired"),
            (
                "issuer",
                with("iss", json!("https://evil.example")),
                "issuer",
            ),
        ] {
            let error = parse(&r, 1).unwrap_err().to_string();
            assert!(error.contains(reason), "{case}: {error}");
        }
        // CC mode off is reported, and check_gpus refuses it.
        let out = parse(&with("x-nvidia-cc-mode", json!("OFF")), 1).unwrap();
        assert!(!out[0].cc_mode);
        let mut no_cc = gpu_claims();
        no_cc.as_object_mut().unwrap().remove("x-nvidia-cc-mode");
        assert!(!parse(&reply(&[no_cc]), 1).unwrap()[0].cc_mode);
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
}
