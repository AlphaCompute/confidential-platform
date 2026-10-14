//! The release-signed platform document as its artifact URL serves it, and its verification:
//! the threshold of release signatures and `issued_at` not in the future. Version
//! monotonicity is the caller's, against whatever it remembers.

use std::time::SystemTime;

use alpha_attest::PlatformDocument;

pub use alpha_channel::platform::{ReleaseKeys, SignedDocument, count_signatures, sign};

use crate::Error;

/// The signature and `issued_at` checks are `alpha_channel`'s; this adds the full document shape
/// that the KMS and the CLI read.
pub fn verify(
    signed: &SignedDocument,
    keys: &ReleaseKeys,
    now: SystemTime,
) -> Result<PlatformDocument, Error> {
    alpha_channel::platform::verify(signed, keys, now)?;
    serde_json::from_value(signed.document.clone())
        .map_err(|e| Error::Invalid(format!("platform document: document: {e}")))
}

/// The document is a few kilobytes and grows by one entry per machine shape.
const DOCUMENT_CAP: usize = 1 << 20;

/// The URL is untrusted; the signature is what makes the document the reference.
pub async fn fetch(
    url: &str,
    keys: &ReleaseKeys,
    now: SystemTime,
) -> Result<PlatformDocument, Error> {
    verify(&fetch_signed(url).await?, keys, now)
}

/// Unverified: the caller verifies. Redirects are followed, as a release artifact host may
/// redirect; the signature, not the host, is what is trusted.
pub async fn fetch_signed(url: &str) -> Result<SignedDocument, Error> {
    let fetch_failed = |e: String| Error::Connect(format!("platform document fetch: {e}"));
    let http = crate::http()
        .build()
        .map_err(|e| Error::Invalid(format!("http client: {e}")))?;
    let response = http
        .get(url)
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|e| fetch_failed(e.to_string()))?;
    let body = crate::read_capped(response, DOCUMENT_CAP)
        .await
        .map_err(fetch_failed)?;
    serde_json::from_slice(&body)
        .map_err(|e| Error::Invalid(format!("platform document body: {e}")))
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
            verify(&signed, &key.verifying_key().into(), now)
                .unwrap()
                .version,
            3
        );
        let mut partial = document;
        partial.as_object_mut().unwrap().remove("policy");
        let signed = sign(partial, &key).unwrap();
        assert!(
            verify(&signed, &key.verifying_key().into(), now)
                .unwrap_err()
                .to_string()
                .contains("policy")
        );
        let other = SigningKey::from_bytes(&[6u8; 32]);
        assert!(verify(&signed, &other.verifying_key().into(), now).is_err());
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
        let full = verify(&signed, &key.verifying_key().into(), now).unwrap();
        assert_eq!(full.signer.unwrap().rp_id, "sign.example");
        assert!(full.catalog_key.is_some());

        document["signer"]["origins"][0] = json!("http://sign.example");
        let signed = sign(document, &key).unwrap();
        assert!(
            verify(&signed, &key.verifying_key().into(), now)
                .unwrap_err()
                .to_string()
                .contains("signer.origins \"http://sign.example\"")
        );
    }

    #[tokio::test]
    async fn a_document_over_the_cap_is_refused_without_a_declared_length() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/platform.json", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let _ = socket.read(&mut [0u8; 1024]).await;
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nconnection: close\r\n\r\n")
                .await
                .unwrap();
            let _ = socket.write_all(&vec![b' '; DOCUMENT_CAP + 1]).await;
        });
        let error = fetch_signed(&url).await.unwrap_err().to_string();
        assert!(error.contains("reply over"), "{error}");
    }
}
