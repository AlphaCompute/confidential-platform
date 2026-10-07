//! The release-signed platform document as its artifact URL serves it, and its verification:
//! the signature under the compiled-in release key and `issued_at` not in the future. Version
//! monotonicity is the caller's, against whatever it remembers.

use std::time::SystemTime;

use alpha_core::{CatalogKey, KmsRevision, Signer, context, signing_digest};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use chrono::DateTime;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{Error, NamedSignature, unix_seconds};

/// `{ document, signature: { algorithm: "ed25519", signature } }`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedDocument {
    pub document: Value,
    pub signature: NamedSignature,
}

/// The fields a channel client reads. Unknown fields are allowed so a document that grows a
/// field still verifies in a page built before it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlatformView {
    pub version: u64,
    pub issued_at: String,
    pub kms_ca_pem: String,
    pub kms_revisions: Vec<KmsRevision>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<Signer>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catalog_key: Option<CatalogKey>,
}

/// The release key's public half, the same file `alpha-kms` compiles in; replaced at the
/// ceremony, never in CI.
pub fn release_key() -> Result<VerifyingKey, Error> {
    alpha_core::hex_bytes::<32>(include_str!("../../../services/alpha-kms/release-key.pub").trim())
        .and_then(|b| VerifyingKey::from_bytes(&b).ok())
        .ok_or_else(|| Error::Malformed("release-key.pub is not an Ed25519 public key".into()))
}

pub fn sign(document: Value, key: &SigningKey) -> Result<SignedDocument, Error> {
    let digest = signing_digest(context::PLATFORM, &document).map_err(canonicalize)?;
    Ok(SignedDocument {
        document,
        signature: NamedSignature {
            algorithm: "ed25519".into(),
            signature: BASE64_URL_SAFE_NO_PAD.encode(key.sign(&digest).to_bytes()),
        },
    })
}

fn canonicalize(e: serde_json::Error) -> Error {
    Error::PlatformSignature(format!("platform document does not canonicalize: {e}"))
}

pub fn verify(
    signed: &SignedDocument,
    release_key: &VerifyingKey,
    now: SystemTime,
) -> Result<PlatformView, Error> {
    let refuse = |m: &str| Error::PlatformSignature(format!("platform document: {m}"));
    if signed.signature.algorithm != "ed25519" {
        return Err(refuse(&format!(
            "algorithm {:?}",
            signed.signature.algorithm
        )));
    }
    let signature = BASE64_URL_SAFE_NO_PAD
        .decode(&signed.signature.signature)
        .ok()
        .and_then(|b| Signature::from_slice(&b).ok())
        .ok_or_else(|| refuse("signature is not base64url Ed25519"))?;
    let digest = signing_digest(context::PLATFORM, &signed.document).map_err(canonicalize)?;
    release_key
        .verify_strict(&digest, &signature)
        .map_err(|_| refuse("release signature does not verify"))?;
    let view: PlatformView = serde_json::from_value(signed.document.clone())
        .map_err(|e| refuse(&format!("document: {e}")))?;
    let issued_at = DateTime::parse_from_rfc3339(&view.issued_at)
        .map_err(|e| refuse(&format!("issued_at: {e}")))?;
    if issued_at.timestamp() > unix_seconds(now)? {
        return Err(refuse("issued_at is in the future"));
    }
    Ok(view)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use serde_json::json;

    use super::*;

    fn document(version: u64, issued_at: &str) -> Value {
        json!({
            "version": version, "issued_at": issued_at,
            "policy": { "tcb_statuses": ["UpToDate"], "tolerated_advisories": [] },
            "reference_values": [], "kms_ca_pem": "", "kms_revisions": []
        })
    }

    #[wasm_bindgen_test::wasm_bindgen_test(unsupported = test)]
    fn verify_checks_signature_key_and_issued_at() {
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let signed = sign(document(3, "2026-09-14T00:00:00Z"), &key).unwrap();
        assert_eq!(
            verify(&signed, &key.verifying_key(), now).unwrap().version,
            3
        );
        let other = SigningKey::from_bytes(&[6u8; 32]);
        assert!(verify(&signed, &other.verifying_key(), now).is_err());
        let mut tampered = signed.clone();
        tampered.document["version"] = json!(4);
        assert!(verify(&tampered, &key.verifying_key(), now).is_err());
        let future = sign(document(3, "2100-01-01T00:00:00Z"), &key).unwrap();
        assert!(
            verify(&future, &key.verifying_key(), now)
                .unwrap_err()
                .to_string()
                .contains("future")
        );
        let mut alg = signed.clone();
        alg.signature.algorithm = "ml-dsa".into();
        assert_eq!(
            verify(&alg, &key.verifying_key(), now).unwrap_err().code(),
            "platform_signature"
        );
    }

    fn document_with_signer_and_catalog_key() -> Value {
        let mut d = document(3, "2026-09-14T00:00:00Z");
        d["kms_revisions"] = json!([{
            "compose_hash": alpha_core::compose_hash("{}"), "build": "b", "source_url": "u"
        }]);
        d["signer"] = json!({
            "origins": ["https://sign.example", "https://a.sign.example"],
            "rp_id": "sign.example",
            "bundle_sha256": format!("sha256:{}", "0".repeat(64)),
            "api_origin": "https://api.example"
        });
        d["catalog_key"] = json!({
            "algorithm": "ed25519",
            "public_key": BASE64_URL_SAFE_NO_PAD.encode([7u8; 32])
        });
        d
    }

    #[wasm_bindgen_test::wasm_bindgen_test(unsupported = test)]
    fn a_document_with_signer_and_catalog_key_exposes_them_in_the_view() {
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let mut d = document_with_signer_and_catalog_key();
        let signed = sign(d.clone(), &key).unwrap();
        let view = verify(&signed, &key.verifying_key(), now).unwrap();
        let signer = view.signer.as_ref().unwrap();
        assert_eq!(
            signer.origins,
            ["https://sign.example", "https://a.sign.example"]
        );
        assert_eq!(signer.rp_id, "sign.example");
        assert_eq!(signer.api_origin, "https://api.example");
        let catalog_key = view.catalog_key.as_ref().unwrap();
        assert_eq!(catalog_key.algorithm, "ed25519");
        assert_eq!(
            catalog_key.public_key,
            BASE64_URL_SAFE_NO_PAD.encode([7u8; 32])
        );
        assert_eq!(view.kms_revisions.len(), 1);
        assert_eq!(
            view.kms_revisions[0].compose_hash,
            alpha_core::compose_hash("{}")
        );
        let json = serde_json::to_value(&view).unwrap();
        for k in ["signer", "catalog_key", "kms_revisions"] {
            assert!(json.get(k).is_some(), "{k}");
        }

        d["signer"]["origins"][0] = json!("https://sign.example/");
        let bad = sign(d, &key).unwrap();
        assert_eq!(
            verify(&bad, &key.verifying_key(), now).unwrap_err().code(),
            "platform_signature"
        );
    }

    #[wasm_bindgen_test::wasm_bindgen_test(unsupported = test)]
    fn a_document_without_signer_or_catalog_key_has_neither_in_the_view() {
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let signed = sign(document(3, "2026-09-14T00:00:00Z"), &key).unwrap();
        let view = verify(&signed, &key.verifying_key(), now).unwrap();
        assert!(view.signer.is_none());
        assert!(view.catalog_key.is_none());
        let json = serde_json::to_value(&view).unwrap();
        assert!(json.get("kms_revisions").is_some());
        assert!(json.get("signer").is_none());
        assert!(json.get("catalog_key").is_none());
    }

    #[wasm_bindgen_test::wasm_bindgen_test(unsupported = test)]
    fn a_signer_or_catalog_key_breaking_a_rule_is_refused_as_platform_signature() {
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        for (section, field, bad) in [
            ("signer", "origins", json!([])),
            ("signer", "origins", json!(["https://sign.example/"])),
            ("signer", "origins", json!(["http://sign.example"])),
            ("signer", "origins", json!(["https://Sign.example"])),
            ("signer", "origins", json!(["https://sign.example:443"])),
            ("signer", "origins", json!(["https://sign.example:+8443"])),
            ("signer", "origins", json!(["https://evilsign.example"])),
            ("signer", "origins", json!(["https://u@sign.example"])),
            ("signer", "origins", json!(["https://sign.example?x"])),
            ("signer", "api_origin", json!("https://api.example/v1")),
            (
                "signer",
                "bundle_sha256",
                json!(format!("sha256:{}", "A".repeat(64))),
            ),
            ("catalog_key", "algorithm", json!("ml-dsa")),
            (
                "catalog_key",
                "public_key",
                json!(BASE64_URL_SAFE_NO_PAD.encode([7u8; 31])),
            ),
            (
                "catalog_key",
                "public_key",
                json!(base64::prelude::BASE64_URL_SAFE.encode([7u8; 32])),
            ),
        ] {
            let mut d = document_with_signer_and_catalog_key();
            d[section][field] = bad.clone();
            let signed = sign(d, &key).unwrap();
            assert_eq!(
                verify(&signed, &key.verifying_key(), now)
                    .unwrap_err()
                    .code(),
                "platform_signature",
                "{section}.{field} {bad}"
            );
        }
    }

    #[wasm_bindgen_test::wasm_bindgen_test(unsupported = test)]
    fn the_compiled_in_release_key_parses() {
        release_key().unwrap();
    }
}
