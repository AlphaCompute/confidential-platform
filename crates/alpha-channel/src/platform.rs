//! The release-signed platform document as its artifact URL serves it, and its verification:
//! the signature under the compiled-in release key and `issued_at` not in the future. Version
//! monotonicity is the caller's, against whatever it remembers.

use std::time::SystemTime;

use alpha_core::{context, signing_digest};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use chrono::DateTime;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{Error, unix_seconds};

/// `{ document, signature: { algorithm: "ed25519", signature } }`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedDocument {
    pub document: Value,
    pub signature: ReleaseSignature,
}

pub use crate::NamedSignature as ReleaseSignature;

/// The fields a channel client reads. Unknown fields are allowed so a document that grows a
/// field still verifies in a page built before it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlatformView {
    pub version: u64,
    pub issued_at: String,
    pub kms_ca_pem: String,
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
        signature: ReleaseSignature {
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

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
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

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn the_compiled_in_release_key_parses() {
        release_key().unwrap();
    }
}
