//! `alpha sign`: the release artifact of a platform document, and `--check`, which verifies
//! one under the compiled-in key and prints the pins a tenant puts in its compose.

use std::time::SystemTime;

use alpha_attest::PlatformDocument;
use alpha_client::platform::{self, SignedDocument};
use alpha_core::{ComposeHash, InitData};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::Serialize;
use serde_json::Value;

/// Signing garbage is refused: the document must already be a platform document. Every
/// `kms_revisions` entry must be one of the supplied node Revisions, a dstack compose or a Kata
/// init-data; the KMS sees only a Kata node's digest, so its init-data must pass the document's
/// own `kata_policy` here, as a tenant's does at registration.
pub fn sign(
    document: Value,
    key: &SigningKey,
    composes: &[String],
    init_data: &[String],
) -> Result<SignedDocument, String> {
    let doc = serde_json::from_value::<PlatformDocument>(document.clone())
        .map_err(|e| format!("document: {e}"))?;
    let mut supplied = Vec::new();
    for compose in composes {
        // An init-data is TOML, so it cannot pass as a compose and skip the policy check.
        alpha_core::parse(compose.as_bytes()).map_err(|e| format!("compose: {e}"))?;
        supplied.push(alpha_core::compose_hash(compose));
    }
    for toml in init_data {
        let init_data = InitData::parse(toml.clone()).map_err(|e| e.to_string())?;
        let digest = init_data.digest();
        let pinned = doc
            .kata_policy
            .as_ref()
            .ok_or("the document pins no kata_policy for an init-data")?;
        init_data
            .check_policy(pinned)
            .map_err(|e| format!("init-data {digest}: {e}"))?;
        supplied.push(digest);
    }
    let listed: Vec<ComposeHash> = doc.kms_revisions.iter().map(|r| r.compose_hash).collect();
    if let Some(extra) = supplied.iter().find(|d| !listed.contains(d)) {
        return Err(format!("{extra} is not in kms_revisions"));
    }
    if let Some(missing) = listed.iter().find(|d| !supplied.contains(d)) {
        return Err(format!(
            "kms_revisions {missing}: no compose or init-data supplied"
        ));
    }
    platform::sign(document, key).map_err(|e| e.to_string())
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
        let compose = ["{}".to_owned()];
        assert!(sign(json!({"version": 1}), &key, &compose, &[]).is_err());
        let artifact = sign(document, &key, &compose, &[]).unwrap();
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
        let compose = ["{}".to_owned()];
        assert!(sign(document.clone(), &key, &compose, &[]).is_ok());
        document["signer"]["origins"][0] = json!("https://sign.example/path");
        assert!(sign(document, &key, &compose, &[]).is_err());
    }

    #[test]
    fn sign_checks_a_kata_node_init_data_against_the_document() {
        let key = SigningKey::from_bytes(&[8u8; 32]);
        let k3 = include_str!("../../../testdata/attest/b300-kata-4.0.0/k3-app.toml");
        let mut document: Value = serde_json::from_str(include_str!(
            "../../../testdata/attest/b300-kata-4.0.0/platform-document.json"
        ))
        .unwrap();
        document["kms_revisions"] = json!([{
            "compose_hash": alpha_core::compose_hash(k3), "build": "b", "source_url": "u"
        }]);
        let init_data = [k3.to_owned()];
        assert!(sign(document.clone(), &key, &[], &init_data).is_ok());

        let err = sign(document.clone(), &key, &[], &[]).unwrap_err();
        assert!(err.contains("no compose or init-data"), "{err}");
        let err = sign(document.clone(), &key, &init_data, &[]).unwrap_err();
        assert!(err.starts_with("compose:"), "{err}");

        document["kata_policy"]["rules_sha256"] = json!(format!("sha256:{}", "0".repeat(64)));
        let err = sign(document, &key, &[], &init_data).unwrap_err();
        assert!(err.contains("not the pinned rules"), "{err}");
    }
}
