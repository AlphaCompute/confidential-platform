//! `alpha sign`: the release artifact of a platform document, and `--check`, which verifies
//! one under the compiled-in key and prints the pins a tenant puts in its compose.

use std::time::SystemTime;

use alpha_attest::PlatformDocument;
use alpha_client::platform::{self, SignedDocument};
use alpha_core::ComposeHash;
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::Serialize;
use serde_json::Value;

/// Signing garbage is refused: the document must already be a platform document.
pub fn sign(document: Value, key: &SigningKey) -> Result<SignedDocument, String> {
    serde_json::from_value::<PlatformDocument>(document.clone())
        .map_err(|e| format!("document: {e}"))?;
    Ok(platform::sign(document, key))
}

/// `ALPHACOMPUTE_KMS_CA_SPKI_SHA256` and `ALPHACOMPUTE_KMS_REVISIONS`, from a verified artifact.
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct Summary {
    pub version: u64,
    pub kms_ca_spki_sha256: Option<String>,
    pub kms_revisions: Vec<ComposeHash>,
}

pub fn check(
    artifact: &SignedDocument,
    release_key: &VerifyingKey,
    now: SystemTime,
) -> Result<Summary, String> {
    let document = platform::verify(artifact, release_key, now).map_err(|e| e.to_string())?;
    Ok(Summary {
        version: document.version,
        kms_ca_spki_sha256: ca_spki_sha256(&document.kms_ca_pem)?,
        kms_revisions: document
            .kms_revisions
            .iter()
            .map(|r| r.compose_hash)
            .collect(),
    })
}

/// `None` for the day-0 document that has no CA yet.
pub fn ca_spki_sha256(kms_ca_pem: &str) -> Result<Option<String>, String> {
    if kms_ca_pem.trim().is_empty() {
        return Ok(None);
    }
    let der = alpha_client::tls::ca_from_pem(kms_ca_pem).map_err(|e| e.to_string())?;
    let spki = alpha_client::tls::spki_of(&der).map_err(|e| e.to_string())?;
    Ok(Some(crate::sha256_prefixed(&spki)))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn sign_then_check_prints_the_pins() {
        let key = SigningKey::from_bytes(&[8u8; 32]);
        let hash = alpha_core::compose_hash("{}");
        let document = json!({
            "version": 4, "issued_at": "2026-09-14T00:00:00Z",
            "policy": { "tcb_statuses": ["UpToDate"], "tolerated_advisories": [] },
            "reference_values": [], "kms_ca_pem": "",
            "kms_revisions": [{ "compose_hash": hash, "build": "b", "source_url": "u" }]
        });
        assert!(sign(json!({"version": 1}), &key).is_err());
        let artifact = sign(document, &key).unwrap();
        let summary = check(&artifact, &key.verifying_key(), SystemTime::now()).unwrap();
        assert_eq!(
            summary,
            Summary {
                version: 4,
                kms_ca_spki_sha256: None,
                kms_revisions: vec![hash]
            }
        );
        let other = SigningKey::from_bytes(&[9u8; 32]);
        assert!(check(&artifact, &other.verifying_key(), SystemTime::now()).is_err());
        assert!(ca_spki_sha256("not a pem").is_err());
    }
}
