//! The release-signed platform document as its artifact URL serves it, and its verification:
//! the signature under the compiled-in release key and `issued_at` not in the future. Version
//! monotonicity is the caller's, against whatever it remembers.

use std::time::SystemTime;

use alpha_attest::PlatformDocument;
pub use alpha_channel::NamedSignature;
pub use alpha_channel::platform::{SignedDocument, sign};
use alpha_core::ComposeHash;
use ed25519_dalek::VerifyingKey;

use crate::Error;
use crate::tls::{ListedRevisions, Pin};

/// The signature and `issued_at` checks are `alpha_channel`'s; this adds the full document shape
/// that the KMS and the CLI read.
pub fn verify(
    signed: &SignedDocument,
    release_key: &VerifyingKey,
    now: SystemTime,
) -> Result<PlatformDocument, Error> {
    alpha_channel::platform::verify(signed, release_key, now)?;
    serde_json::from_value(signed.document.clone())
        .map_err(|e| Error::Invalid(format!("platform document: document: {e}")))
}

/// The URL is untrusted; the signature is what makes the document the reference.
pub async fn fetch(
    url: &str,
    release_key: &VerifyingKey,
    now: SystemTime,
) -> Result<PlatformDocument, Error> {
    verify(&fetch_signed(url).await?, release_key, now)
}

/// The compiled-in release key (`services/alpha-kms/release-key.pub`).
pub fn release_key() -> Result<VerifyingKey, Error> {
    Ok(alpha_channel::platform::release_key()?)
}

fn unix_seconds(now: SystemTime) -> Result<u64, Error> {
    now.duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| Error::Invalid("the clock is before 1970".into()))
}

async fn fetch_signed(url: &str) -> Result<SignedDocument, Error> {
    reqwest::get(url)
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|e| Error::Connect(format!("platform document fetch: {e}")))?
        .json()
        .await
        .map_err(|e| Error::Invalid(format!("platform document body: {e}")))
}

/// D6's opt-in pin: the KMS by its CA plus whichever KMS Revisions the current release-signed
/// platform document lists, so a KMS upgrade no longer changes the Revision of every App that
/// pins it. The release key then vouches for the KMS's identity where the tenant's approval
/// used to. The CA stays pinned by the tenant: a document naming another CA is refused.
///
/// A KMS build is revoked by dropping it from `kms_revisions`. Only an older document could let it
/// back in, and none is accepted that is below `min_version` (pinned with the App's Revision),
/// below a version this process has already accepted, or past its `expires_at` (required here,
/// because a fresh process remembers nothing). The listed Revisions match nothing once the
/// document they came from expires.
pub struct PlatformPin {
    url: String,
    release_key: VerifyingKey,
    min_version: u64,
    ca_spki_sha256: [u8; 32],
    listed: ListedRevisions,
    accepted: parking_lot::Mutex<u64>,
}

impl PlatformPin {
    pub fn new(
        url: String,
        release_key: VerifyingKey,
        min_version: u64,
        ca_spki_sha256: [u8; 32],
    ) -> Self {
        Self {
            url,
            release_key,
            min_version,
            ca_spki_sha256,
            listed: ListedRevisions::default(),
            accepted: parking_lot::Mutex::new(0),
        }
    }

    /// The TLS pin, which follows every document [`PlatformPin::apply`] accepts.
    pub fn pin(&self) -> Pin {
        Pin::CaSpkiAndListedRevisions(self.ca_spki_sha256, self.listed.clone())
    }

    /// The Revisions a KMS leaf may name at `now`: the current document's, or none.
    pub fn revisions(&self, now: SystemTime) -> Vec<ComposeHash> {
        self.listed.get(unix_seconds(now).unwrap_or(u64::MAX))
    }

    /// Verifies `signed` and pins its `kms_revisions`; the version now pinned. A refused
    /// document leaves the previous one in place until it expires.
    pub fn apply(&self, signed: &SignedDocument, now: SystemTime) -> Result<u64, Error> {
        let refuse = |m: String| Error::Invalid(format!("platform pin: {m}"));
        let doc = verify(signed, &self.release_key, now)?;
        if doc.version < self.min_version {
            return Err(refuse(format!(
                "document version {} is below the pinned minimum {}",
                doc.version, self.min_version
            )));
        }
        let mut accepted = self.accepted.lock();
        if doc.version < *accepted {
            return Err(refuse(format!(
                "document version {} is below version {} already accepted",
                doc.version, *accepted
            )));
        }
        let expires_at = doc
            .expires_at
            .as_deref()
            .ok_or_else(|| refuse("the document has no expires_at".into()))?;
        let expires = chrono::DateTime::parse_from_rfc3339(expires_at)
            .ok()
            .and_then(|t| u64::try_from(t.timestamp()).ok())
            .ok_or_else(|| refuse(format!("expires_at {expires_at:?}")))?;
        if unix_seconds(now)? >= expires {
            return Err(refuse(format!("the document expired at {expires_at}")));
        }
        let ca = crate::tls::cert_from_pem(&doc.kms_ca_pem)?;
        if crate::tls::spki_sha256(&ca) != Some(self.ca_spki_sha256) {
            return Err(refuse(
                "the document's kms_ca_pem is not the pinned KMS CA".into(),
            ));
        }
        if doc.kms_revisions.is_empty() {
            return Err(refuse("the document lists no KMS Revision".into()));
        }
        self.listed.set(
            doc.kms_revisions.iter().map(|r| r.compose_hash).collect(),
            expires,
        );
        *accepted = doc.version;
        Ok(doc.version)
    }

    /// Fetches the document from its URL (untrusted: the signature is what counts) and applies it.
    pub async fn refresh(&self, now: SystemTime) -> Result<u64, Error> {
        self.apply(&fetch_signed(&self.url).await?, now)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use base64::Engine;
    use base64::prelude::BASE64_URL_SAFE_NO_PAD;
    use ed25519_dalek::SigningKey;
    use serde_json::json;

    use super::*;

    #[test]
    fn verify_parses_the_full_document_after_the_signature() {
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let document = json!({
            "version": 3, "issued_at": "2026-09-14T00:00:00Z",
            "policy": { "tcb_statuses": ["UpToDate"], "tolerated_advisories": [] },
            "reference_values": [], "kms_ca_pem": "", "kms_revisions": []
        });
        let signed = sign(document.clone(), &key).unwrap();
        assert_eq!(
            verify(&signed, &key.verifying_key(), now).unwrap().version,
            3
        );
        let mut partial = document;
        partial.as_object_mut().unwrap().remove("policy");
        let signed = sign(partial, &key).unwrap();
        assert!(
            verify(&signed, &key.verifying_key(), now)
                .unwrap_err()
                .to_string()
                .contains("policy")
        );
        let other = SigningKey::from_bytes(&[6u8; 32]);
        assert!(verify(&signed, &other.verifying_key(), now).is_err());
    }

    #[test]
    fn verify_carries_signer_and_catalog_key_into_the_full_document() {
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let mut document = json!({
            "version": 3, "issued_at": "2026-09-14T00:00:00Z",
            "policy": { "tcb_statuses": ["UpToDate"], "tolerated_advisories": [] },
            "reference_values": [], "kms_ca_pem": "", "kms_revisions": [],
            "signer": {
                "origins": ["https://sign.example"],
                "rp_id": "sign.example",
                "bundle_sha256": format!("sha256:{}", "0".repeat(64)),
                "api_origin": "https://api.example"
            },
            "catalog_key": {
                "algorithm": "ed25519",
                "public_key": BASE64_URL_SAFE_NO_PAD.encode(
                    SigningKey::from_bytes(&[7u8; 32]).verifying_key().to_bytes()
                )
            }
        });
        let signed = sign(document.clone(), &key).unwrap();
        let full = verify(&signed, &key.verifying_key(), now).unwrap();
        assert_eq!(full.signer.unwrap().rp_id, "sign.example");
        assert!(full.catalog_key.is_some());

        document["signer"]["origins"][0] = json!("http://sign.example");
        let signed = sign(document, &key).unwrap();
        assert!(
            verify(&signed, &key.verifying_key(), now)
                .unwrap_err()
                .to_string()
                .contains("signer.origins \"http://sign.example\"")
        );
    }
}
