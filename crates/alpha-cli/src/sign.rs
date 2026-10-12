//! `alpha sign`: the release artifact of a platform document, and `--check`, which verifies
//! one under the compiled-in key and prints the pins a tenant puts in its compose.

use std::time::SystemTime;

use alpha_attest::PlatformDocument;
use alpha_client::platform::{self, NamedSignature, SignedDocument};
use alpha_core::{ComposeHash, context, signing_digest};
use alpha_dsm::{OwnDsm, OwnDsmConfig};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Signing garbage is refused: the document must already be a platform document.
pub fn sign(document: Value, key: &SigningKey) -> Result<SignedDocument, String> {
    serde_json::from_value::<PlatformDocument>(document.clone())
        .map_err(|e| format!("document: {e}"))?;
    platform::sign(document, key).map_err(|e| e.to_string())
}

/// `alpha sign --release-key-dsm F` (PRD-06 I3): the release key is held in our on-prem DSM and
/// never leaves it. `F` names the DSM, its CA and the key, and the key's public half.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseDsm {
    pub dsm: OwnDsmConfig,
    /// The release key's Ed25519 public key, base64url: the DSM's signature must verify under it
    /// before anything is written.
    pub public_key: String,
}

impl ReleaseDsm {
    pub fn parse(text: &str) -> Result<Self, String> {
        let value = alpha_core::parse(text.as_bytes()).map_err(|e| format!("release DSM: {e}"))?;
        let config: Self =
            serde_json::from_value(value).map_err(|e| format!("release DSM: {e}"))?;
        config
            .dsm
            .check()
            .map_err(|e| format!("release DSM: {e}"))?;
        config.verifying_key()?;
        Ok(config)
    }

    pub fn verifying_key(&self) -> Result<VerifyingKey, String> {
        BASE64_URL_SAFE_NO_PAD
            .decode(&self.public_key)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .and_then(|b| VerifyingKey::from_bytes(&b).ok())
            .filter(|k| !k.is_weak())
            .ok_or_else(|| "release DSM: public_key is not an Ed25519 key in base64url".into())
    }
}

/// As [`sign`], with the release key in DSM. The signature is checked under the expected public
/// key, then the artifact is verified as every reader verifies it, so a DSM that signed with
/// another key, another algorithm or another request shape yields nothing.
pub async fn sign_with_dsm(
    document: Value,
    dsm: &OwnDsm,
    public_key: &VerifyingKey,
    now: SystemTime,
) -> Result<SignedDocument, String> {
    serde_json::from_value::<PlatformDocument>(document.clone())
        .map_err(|e| format!("document: {e}"))?;
    let digest = signing_digest(context::PLATFORM, &document)
        .map_err(|e| format!("document does not canonicalize: {e}"))?;
    let signature = dsm
        .sign(&digest)
        .await
        .map_err(|e| format!("release DSM: {e}"))?;
    let signature = Signature::from_slice(&signature)
        .map_err(|_| "release DSM: the signature is not 64 bytes of Ed25519".to_owned())?;
    public_key
        .verify_strict(&digest, &signature)
        .map_err(|_| "release DSM: the signature does not verify under public_key".to_owned())?;
    let artifact = SignedDocument {
        document,
        signature: NamedSignature {
            algorithm: "ed25519".into(),
            signature: BASE64_URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        },
    };
    platform::verify(&artifact, public_key, now).map_err(|e| e.to_string())?;
    Ok(artifact)
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

    fn document() -> Value {
        json!({
            "version": 4, "issued_at": "2026-09-14T00:00:00Z",
            "policy": { "tcb_statuses": ["UpToDate"], "tolerated_advisories": [] },
            "reference_values": [], "kms_ca_pem": "",
            "kms_revisions": [{
                "compose_hash": alpha_core::compose_hash("{}"), "build": "b", "source_url": "u"
            }]
        })
    }

    #[tokio::test]
    async fn the_release_key_in_dsm_signs_what_a_local_key_would_and_nothing_unverified() {
        use std::sync::atomic::Ordering;

        use alpha_dsm::stand_in::{API_KEY, SIGNING_KEY, StandIn};
        use zeroize::Zeroizing;

        let stand_in = StandIn::new();
        let (endpoint, ca) = stand_in.serve().await;
        let config = json!({
            "dsm": StandIn::config(&endpoint, &ca, SIGNING_KEY),
            "public_key": BASE64_URL_SAFE_NO_PAD.encode(stand_in.verifying_key().to_bytes()),
        });
        let release = ReleaseDsm::parse(&config.to_string()).unwrap();
        let dsm = OwnDsm::new(&release.dsm, Zeroizing::new(API_KEY.into())).unwrap();
        let key = release.verifying_key().unwrap();
        let now = SystemTime::now();

        let artifact = sign_with_dsm(document(), &dsm, &key, now).await.unwrap();
        // The same bytes a local key signs (Ed25519 is deterministic), and `--check` reads them.
        let local = platform::sign(document(), &SigningKey::from_bytes(&[0x17; 32])).unwrap();
        assert_eq!(artifact.signature.signature, local.signature.signature);
        assert_eq!(check(&artifact, &key, now).unwrap().version, 4);

        // Garbage is refused before DSM is asked.
        let calls = stand_in.calls.load(Ordering::SeqCst);
        assert!(
            sign_with_dsm(json!({"version": 1}), &dsm, &key, now)
                .await
                .is_err()
        );
        assert_eq!(stand_in.calls.load(Ordering::SeqCst), calls);

        // A DSM that signs with another key yields nothing.
        stand_in.wrong_signer.store(true, Ordering::SeqCst);
        let error = sign_with_dsm(document(), &dsm, &key, now)
            .await
            .unwrap_err();
        assert!(
            error.contains("does not verify under public_key"),
            "{error}"
        );
        stand_in.wrong_signer.store(false, Ordering::SeqCst);

        // So does a DSM that refuses, and a public key that is not the DSM key's.
        stand_in.disabled.store(true, Ordering::SeqCst);
        assert!(sign_with_dsm(document(), &dsm, &key, now).await.is_err());
        stand_in.disabled.store(false, Ordering::SeqCst);
        let other = SigningKey::from_bytes(&[9; 32]).verifying_key();
        assert!(sign_with_dsm(document(), &dsm, &other, now).await.is_err());

        let mut bad = config.clone();
        bad["public_key"] = json!("AAAA");
        assert!(ReleaseDsm::parse(&bad.to_string()).is_err());
        bad = config;
        bad["api_key"] = json!("never in this file");
        assert!(ReleaseDsm::parse(&bad.to_string()).is_err());
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
}
