//! What a Trustee attestation token says about a pod.
//!
//! Trustee v0.21.0's Attestation Service answers a KBS attestation with an EAR, an ES256 JWT
//! (`attestation-service/src/ear_token/broker.rs`). It has one submodule per device, `cpu0` for
//! the TD and `gpu<i>` for each GPU, each with an `ear.status` and the claims its verifier
//! produced under `ear.veraison.annotated-evidence`. For the TD these are `tdx` (the parsed quote,
//! `tcb_status`, `advisory_ids`, `td_attributes`; `deps/verifier/src/tdx/claims.rs`), `init_data`
//! (MRCONFIGID in hex, which the verifier checked against the init-data the pod sent) and
//! `runtime_data_claims`. For a GPU they are `nvidia`, NRAS's per-GPU claims
//! (`deps/verifier/src/nvidia/nras_response.rs`).
//!
//! The KMS reads a token its own Trustee pod's KBS issued and the pod's feed handed it from inside
//! the same TD. It does not check the token's signature, which the KBS does; it checks what the
//! claims say against its own platform document and Revisions.

use alpha_attest::Measurement;
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// The EAR status every submodule must have.
pub const AFFIRMING: &str = "affirming";
const STATUS: &str = "ear.status";
const ANNOTATED: &str = "ear.veraison.annotated-evidence";
/// A TDX quote's `tee_type`, as Trustee writes it (little-endian `0x81`).
pub const TDX_TEE_TYPE: &str = "81000000";

/// The JSON payload of a JWT, unverified.
pub fn token_payload(token: &str) -> Result<Value, String> {
    let mut parts = token.split('.');
    let (Some(_), Some(payload), Some(_), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err("token is not a JWT".into());
    };
    let bytes = BASE64_URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| "token payload is not base64url".to_owned())?;
    serde_json::from_slice(&bytes).map_err(|e| format!("token payload: {e}"))
}

/// The digest a token is known by between the feed and the KMS.
pub fn token_sha256(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

/// A pod as its EAR describes it.
#[derive(Clone, Debug, PartialEq)]
pub struct PodClaims {
    /// The token's `exp`, in seconds since the epoch.
    pub expires: u64,
    pub mrtd: Measurement,
    pub rtmr0: Measurement,
    pub rtmr1: Measurement,
    pub rtmr2: Measurement,
    pub rtmr3: Measurement,
    pub mrconfigid: Measurement,
    pub tcb_status: String,
    pub advisories: Vec<String>,
    pub debug: bool,
    /// Each GPU's NRAS claims, `gpu0` first.
    pub gpus: Vec<Value>,
}

fn object<'a>(value: &'a Value, what: &str) -> Result<&'a Map<String, Value>, String> {
    value
        .as_object()
        .ok_or_else(|| format!("token: {what} is not an object"))
}

fn text<'a>(value: &'a Value, pointer: &str) -> Result<&'a str, String> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("token: claim {pointer} is missing"))
}

fn measurement(value: &Value, pointer: &str) -> Result<Measurement, String> {
    let hex = text(value, pointer)?;
    let mut out = [0u8; 48];
    hex::decode_to_slice(hex, &mut out)
        .map_err(|_| format!("token: claim {pointer} is not 48 bytes of hex"))?;
    Ok(Measurement(out))
}

/// The index of a submodule named `<class><index>`, e.g. `gpu3`.
fn index_of(name: &str, class: &str) -> Option<usize> {
    let digits = name.strip_prefix(class)?;
    if digits.is_empty() || (digits.len() > 1 && digits.starts_with('0')) {
        return None;
    }
    digits.parse().ok()
}

impl PodClaims {
    /// Every submodule affirming, one TD, GPUs `gpu0` to `gpu<n-1>` with NRAS claims each.
    pub fn from_payload(payload: &Value) -> Result<Self, String> {
        let submods = object(
            payload
                .get("submods")
                .ok_or("token: no submods".to_owned())?,
            "submods",
        )?;
        if let Some((name, _)) = submods
            .iter()
            .find(|(_, s)| s.get(STATUS).and_then(Value::as_str) != Some(AFFIRMING))
        {
            return Err(format!("token: submodule {name} is not {AFFIRMING}"));
        }
        if submods.keys().any(|k| k.starts_with("cpu") && k != "cpu0") {
            return Err("token: more than one TD submodule".into());
        }
        let cpu = submods
            .get("cpu0")
            .and_then(|s| s.get(ANNOTATED))
            .ok_or("token: no cpu0 claims".to_owned())?;
        let tdx = cpu
            .get("tdx")
            .ok_or("token: cpu0 is not a TDX TD".to_owned())?;
        if text(tdx, "/quote/header/tee_type")? != TDX_TEE_TYPE {
            return Err("token: cpu0's quote is not a TDX quote".into());
        }
        let mrconfigid = measurement(tdx, "/quote/body/mr_config_id")?;
        let init_data = measurement(cpu, "/init_data")?;
        if init_data != mrconfigid {
            return Err("token: init_data is not the quote's MRCONFIGID".into());
        }
        let advisories = tdx
            .get("advisory_ids")
            .and_then(Value::as_array)
            .ok_or("token: claim /advisory_ids is missing".to_owned())?
            .iter()
            .map(|a| a.as_str().map(str::to_owned))
            .collect::<Option<Vec<_>>>()
            .ok_or("token: an advisory id is not text".to_owned())?;
        let debug = tdx
            .pointer("/td_attributes/debug")
            .and_then(Value::as_bool)
            .ok_or("token: claim /td_attributes/debug is missing".to_owned())?;

        let mut gpus: Vec<(usize, &Value)> = Vec::new();
        for (name, submod) in submods {
            if !name.starts_with("gpu") {
                continue;
            }
            let index = index_of(name, "gpu")
                .ok_or_else(|| format!("token: submodule {name} is not gpu<index>"))?;
            let claims = submod
                .get(ANNOTATED)
                .and_then(|a| a.get("nvidia"))
                .filter(|c| c.is_object())
                .ok_or_else(|| format!("token: {name} has no NVIDIA claims"))?;
            gpus.push((index, claims));
        }
        gpus.sort_by_key(|(i, _)| *i);
        if gpus.iter().enumerate().any(|(want, (got, _))| want != *got) {
            return Err("token: GPU submodules are not gpu0 to gpu<n-1>".into());
        }

        Ok(Self {
            expires: payload
                .get("exp")
                .and_then(Value::as_u64)
                .ok_or("token: no exp".to_owned())?,
            mrtd: measurement(tdx, "/quote/body/mr_td")?,
            rtmr0: measurement(tdx, "/quote/body/rtmr_0")?,
            rtmr1: measurement(tdx, "/quote/body/rtmr_1")?,
            rtmr2: measurement(tdx, "/quote/body/rtmr_2")?,
            rtmr3: measurement(tdx, "/quote/body/rtmr_3")?,
            mrconfigid,
            tcb_status: text(tdx, "/tcb_status")?.to_owned(),
            advisories,
            debug,
            gpus: gpus.into_iter().map(|(_, c)| c.clone()).collect(),
        })
    }
}

/// An EAR payload as Trustee v0.21.0's Attestation Service writes one, for tests here and in the
/// KMS and the feed.
pub mod sample {
    use serde_json::{Value, json};

    pub fn hex48(byte: u8) -> String {
        hex::encode([byte; 48])
    }

    /// One TD with these registers and MRCONFIGID, and one NVIDIA submodule per entry of `gpus`.
    pub fn payload(registers: [&str; 5], mrconfigid: &str, gpus: &[Value], exp: u64) -> Value {
        let [mr_td, rtmr_0, rtmr_1, rtmr_2, rtmr_3] = registers;
        let affirming = |annotated: Value| {
            json!({
                "ear.status": "affirming",
                "ear.trustworthiness-vector": { "configuration": 2, "executables": 3, "hardware": 2 },
                "ear.appraisal-policy-id": "default",
                "ear.veraison.annotated-evidence": annotated,
            })
        };
        let mut submods = serde_json::Map::new();
        submods.insert(
            "cpu0".into(),
            affirming(json!({
                "tdx": {
                    "quote": {
                        "header": { "version": "0400", "tee_type": super::TDX_TEE_TYPE,
                                    "vendor_id": "939a7233f79c4ca9940a0db3957f0607" },
                        "body": { "mr_td": mr_td, "rtmr_0": rtmr_0, "rtmr_1": rtmr_1,
                                  "rtmr_2": rtmr_2, "rtmr_3": rtmr_3, "mr_config_id": mrconfigid,
                                  "report_data": "00".repeat(64) },
                    },
                    "td_attributes": { "debug": false, "septve_disable": true },
                    "tcb_status": "UpToDate",
                    "collateral_expiration_status": "0",
                    "advisory_ids": [],
                },
                "init_data": mrconfigid,
                "init_data_claims": { "alpha.json": "{}" },
                "report_data": "00".repeat(64),
                "runtime_data_claims": { "tee-pubkey": { "kty": "EC", "crv": "P-256" }, "nonce": "n" },
            })),
        );
        for (i, gpu) in gpus.iter().enumerate() {
            submods.insert(format!("gpu{i}"), affirming(json!({ "nvidia": gpu })));
        }
        json!({
            "eat_profile": "tag:github.com,2024:confidential-containers/Trustee",
            "iat": exp.saturating_sub(300),
            "exp": exp,
            "ear.verifier-id": { "build": "attestation-service 0.21.0", "developer": "https://confidentialcontainers.org" },
            "submods": submods,
        })
    }

    /// `payload` as the unsigned JWT the feed would pass on (the signature is the KBS's business).
    pub fn token(payload: &Value) -> String {
        use base64::Engine;
        use base64::prelude::BASE64_URL_SAFE_NO_PAD;
        format!(
            "{}.{}.c2ln",
            BASE64_URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256","typ":"JWT"}"#),
            BASE64_URL_SAFE_NO_PAD.encode(payload.to_string())
        )
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::sample::{hex48, payload, token};
    use super::*;

    fn registers() -> [String; 5] {
        [hex48(1), hex48(2), hex48(3), hex48(4), hex48(5)]
    }

    fn sample(gpus: &[Value]) -> Value {
        let r = registers();
        payload(
            [&r[0], &r[1], &r[2], &r[3], &r[4]],
            &hex48(9),
            gpus,
            1_800_000_000,
        )
    }

    #[test]
    fn a_tds_registers_and_its_gpus_claims_are_read_from_the_token() {
        let gpus = [
            json!({ "hwmodel": "GB100", "ueid": "1" }),
            json!({ "hwmodel": "GB100", "ueid": "2" }),
        ];
        let t = token(&sample(&gpus));
        let claims = PodClaims::from_payload(&token_payload(&t).unwrap()).unwrap();
        assert_eq!(claims.expires, 1_800_000_000);
        assert_eq!(claims.mrtd, Measurement([1; 48]));
        assert_eq!(claims.rtmr2, Measurement([4; 48]));
        assert_eq!(claims.mrconfigid, Measurement([9; 48]));
        assert_eq!(claims.tcb_status, "UpToDate");
        assert!(!claims.debug);
        assert_eq!(claims.gpus, gpus);
        assert_eq!(
            token_sha256(&t),
            <[u8; 32]>::from(Sha256::digest(t.as_bytes()))
        );
    }

    #[test]
    fn anything_but_one_affirming_td_and_numbered_gpus_is_refused() {
        let gpu = json!({ "hwmodel": "GB100" });
        type Edit = Box<dyn Fn(&mut Value)>;
        let cases: Vec<(Edit, &str)> = vec![
            (
                Box::new(|p| p["submods"]["cpu0"]["ear.status"] = json!("warning")),
                "not affirming",
            ),
            (
                Box::new(|p| p["submods"]["gpu0"]["ear.status"] = json!("contraindicated")),
                "gpu0 is not affirming",
            ),
            (
                Box::new(|p| p["submods"]["cpu1"] = p["submods"]["cpu0"].clone()),
                "more than one TD",
            ),
            (
                Box::new(|p| {
                    p["submods"].as_object_mut().unwrap().remove("cpu0");
                }),
                "no cpu0",
            ),
            (
                Box::new(|p| {
                    p["submods"]["cpu0"]["ear.veraison.annotated-evidence"]["tdx"]["quote"]["header"]
                        ["tee_type"] = json!("00000000")
                }),
                "not a TDX quote",
            ),
            (
                Box::new(|p| {
                    p["submods"]["cpu0"]["ear.veraison.annotated-evidence"]["init_data"] =
                        json!(hex48(8))
                }),
                "not the quote's MRCONFIGID",
            ),
            (
                Box::new(|p| {
                    p["submods"]["cpu0"]["ear.veraison.annotated-evidence"]["tdx"]["quote"]["body"]
                        ["mr_td"] = json!("00")
                }),
                "48 bytes",
            ),
            (
                Box::new(|p| {
                    p["submods"]["cpu0"]["ear.veraison.annotated-evidence"]["tdx"]
                        .as_object_mut()
                        .unwrap()
                        .remove("advisory_ids");
                }),
                "advisory_ids",
            ),
            (
                Box::new(|p| {
                    p["submods"]["cpu0"]["ear.veraison.annotated-evidence"]["tdx"]["td_attributes"]
                        .as_object_mut()
                        .unwrap()
                        .remove("debug");
                }),
                "debug",
            ),
            (
                Box::new(|p| {
                    let g = p["submods"]["gpu0"].clone();
                    p["submods"]["gpu2"] = g;
                }),
                "gpu0 to gpu<n-1>",
            ),
            (
                Box::new(|p| {
                    let g = p["submods"]["gpu0"].clone();
                    p["submods"]["gpu01"] = g;
                }),
                "not gpu<index>",
            ),
            (
                Box::new(|p| p["submods"]["gpu0"]["ear.veraison.annotated-evidence"] = json!({})),
                "no NVIDIA claims",
            ),
            (
                Box::new(|p| {
                    p.as_object_mut().unwrap().remove("exp");
                }),
                "no exp",
            ),
        ];
        for (edit, reason) in cases {
            let mut p = sample(std::slice::from_ref(&gpu));
            edit(&mut p);
            let error = PodClaims::from_payload(&p).unwrap_err();
            assert!(error.contains(reason), "{reason}: {error}");
        }
        assert!(token_payload("a.b").is_err());
        assert!(token_payload("a.!!.c").is_err());
        assert!(token_payload("a.b.c.d").is_err());
    }
}
