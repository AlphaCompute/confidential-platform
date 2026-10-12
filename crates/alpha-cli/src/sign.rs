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
    let parsed = serde_json::from_value::<PlatformDocument>(document.clone())
        .map_err(|e| format!("document: {e}"))?;
    if let Some(expires_at) = &parsed.expires_at {
        let at = |t: &str| chrono::DateTime::parse_from_rfc3339(t).map_err(|e| format!("{t}: {e}"));
        if at(expires_at)? <= at(&parsed.issued_at)? {
            return Err(format!(
                "document: expires_at {expires_at} is not after issued_at {}",
                parsed.issued_at
            ));
        }
    }
    platform::sign(document, key).map_err(|e| e.to_string())
}

/// `ALPHACOMPUTE_KMS_CA_SPKI_SHA256` and `ALPHACOMPUTE_KMS_REVISIONS`, from a verified artifact,
/// and the PCCS it names.
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct Summary {
    pub version: u64,
    pub kms_ca_spki_sha256: Option<String>,
    pub kms_revisions: Vec<ComposeHash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pccs_url: Option<String>,
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
        pccs_url: document.pccs_url,
    })
}

/// `None` for the day-0 document that has no CA yet.
pub fn ca_spki_sha256(kms_ca_pem: &str) -> Result<Option<String>, String> {
    if kms_ca_pem.trim().is_empty() {
        return Ok(None);
    }
    let der = alpha_client::tls::cert_from_pem(kms_ca_pem).map_err(|e| e.to_string())?;
    let spki = alpha_client::tls::spki_of(&der).map_err(|e| e.to_string())?;
    Ok(Some(alpha_channel::sha256_label(&spki)))
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
                kms_revisions: vec![hash],
                pccs_url: None,
            }
        );
        let other = SigningKey::from_bytes(&[9u8; 32]);
        assert!(check(&artifact, &other.verifying_key(), SystemTime::now()).is_err());
        assert!(ca_spki_sha256("not a pem").is_err());
    }

    #[test]
    fn sign_refuses_a_document_whose_signer_breaks_a_rule() {
        let key = SigningKey::from_bytes(&[8u8; 32]);
        let mut document = json!({
            "version": 4, "issued_at": "2026-09-14T00:00:00Z",
            "policy": { "tcb_statuses": ["UpToDate"], "tolerated_advisories": [] },
            "reference_values": [], "kms_ca_pem": "",
            "kms_revisions": [{
                "compose_hash": alpha_core::compose_hash("{}"), "build": "b", "source_url": "u"
            }],
            "signer": {
                "origins": ["https://sign.example"],
                "rp_id": "sign.example",
                "bundle_sha256": format!("sha256:{}", "0".repeat(64)),
                "api_origin": "https://api.example"
            }
        });
        assert!(sign(document.clone(), &key).is_ok());
        document["signer"]["origins"][0] = json!("https://sign.example/path");
        assert!(sign(document, &key).is_err());
    }

    #[test]
    fn a_document_expires_after_it_is_issued() {
        let key = SigningKey::from_bytes(&[8u8; 32]);
        let mut document = json!({
            "version": 5, "issued_at": "2026-10-12T00:00:00Z",
            "policy": { "tcb_statuses": ["UpToDate"], "tolerated_advisories": [] },
            "reference_values": [], "kms_ca_pem": "", "kms_revisions": [],
            "expires_at": "2026-11-12T00:00:00Z"
        });
        assert!(sign(document.clone(), &key).is_ok());
        for bad in ["2026-10-12T00:00:00Z", "2026-10-11T00:00:00Z", "next month"] {
            document["expires_at"] = json!(bad);
            let e = sign(document.clone(), &key).unwrap_err();
            assert!(e.contains("expires_at"), "{bad}: {e}");
        }
    }

    /// alpha-infra's draft generator writes `pccs_url`; it used to be refused as an unknown field.
    #[test]
    fn a_document_names_its_pccs_and_check_prints_it() {
        let key = SigningKey::from_bytes(&[8u8; 32]);
        let site = "https://pccs.site1.alphacompute.internal:8081/sgx/certification/v4/";
        let mut document = json!({
            "version": 5, "issued_at": "2026-10-12T00:00:00Z",
            "policy": { "tcb_statuses": ["UpToDate"], "tolerated_advisories": [] },
            "reference_values": [], "kms_ca_pem": "", "kms_revisions": [],
            "pccs_url": site
        });
        let artifact = sign(document.clone(), &key).unwrap();
        let summary = check(&artifact, &key.verifying_key(), SystemTime::now()).unwrap();
        assert_eq!(summary.pccs_url.as_deref(), Some(site));
        for bad in ["http://pccs.example/", "https://pccs.example/?a", ""] {
            document["pccs_url"] = json!(bad);
            let e = sign(document.clone(), &key).unwrap_err();
            assert!(e.contains("pccs_url"), "{bad}: {e}");
        }
    }
}
