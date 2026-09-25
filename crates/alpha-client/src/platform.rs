//! The release-signed platform document as its artifact URL serves it, and its verification:
//! the signature under the compiled-in release key and `issued_at` not in the future. Version
//! monotonicity is the caller's, against whatever it remembers.

use std::time::SystemTime;

use alpha_attest::PlatformDocument;
pub use alpha_channel::platform::{ReleaseSignature, SignedDocument, sign};
use ed25519_dalek::VerifyingKey;

use crate::Error;

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
    let signed: SignedDocument = reqwest::get(url)
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|e| Error::Connect(format!("platform document fetch: {e}")))?
        .json()
        .await
        .map_err(|e| Error::Invalid(format!("platform document body: {e}")))?;
    verify(&signed, release_key, now)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

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
}
