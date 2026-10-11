//! The release-signed platform document as its artifact URL serves it, and its verification:
//! the signature under the compiled-in release key and `issued_at` not in the future. Version
//! monotonicity is the caller's, against whatever it remembers.

use std::time::{Duration, SystemTime};

use alpha_attest::PlatformDocument;
pub use alpha_channel::NamedSignature;
pub use alpha_channel::platform::{SignedDocument, sign};
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

/// The whole fetch, from connecting to the end of the body: a server that accepts the connection
/// and never answers must not hold the caller, such as the stand's `alpha probe`, past it.
const FETCH_TIMEOUT: Duration = Duration::from_secs(30);

/// Redirects followed: an artifact URL may redirect to its storage. The signature, not the
/// server, makes the document the reference, so where it is fetched from is not trusted anyway.
const FETCH_REDIRECTS: usize = 5;

/// The URL is untrusted; the signature is what makes the document the reference.
pub async fn fetch(
    url: &str,
    release_key: &VerifyingKey,
    now: SystemTime,
) -> Result<PlatformDocument, Error> {
    fetch_within(url, release_key, now, FETCH_TIMEOUT).await
}

async fn fetch_within(
    url: &str,
    release_key: &VerifyingKey,
    now: SystemTime,
    timeout: Duration,
) -> Result<PlatformDocument, Error> {
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::limited(FETCH_REDIRECTS))
        .timeout(timeout)
        .build()
        .map_err(|e| Error::Invalid(format!("http client: {e}")))?;
    let signed: SignedDocument = http
        .get(url)
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|e| {
            Error::Connect(format!(
                "platform document fetch: {}",
                crate::error_chain(&e)
            ))
        })?
        .json()
        .await
        .map_err(|e| {
            Error::Invalid(format!(
                "platform document body: {}",
                crate::error_chain(&e)
            ))
        })?;
    verify(&signed, release_key, now)
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};

    use base64::Engine;
    use base64::prelude::BASE64_URL_SAFE_NO_PAD;
    use ed25519_dalek::SigningKey;
    use serde_json::json;

    use super::*;

    /// A server on 127.0.0.1 that accepts one connection, reads the request, writes `reply` and
    /// then holds the connection open without another byte.
    fn stalling_server(reply: &'static [u8]) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/platform.json", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 4096];
            let _ = stream.read(&mut request);
            stream.write_all(reply).unwrap();
            std::thread::sleep(Duration::from_secs(600));
            drop(stream);
        });
        url
    }

    #[tokio::test]
    async fn a_server_that_never_answers_fails_the_fetch_within_its_bound() {
        let url = stalling_server(b"");
        let key = SigningKey::from_bytes(&[5u8; 32]).verifying_key();
        let fetch = fetch_within(&url, &key, SystemTime::now(), Duration::from_millis(300));
        let error = tokio::time::timeout(Duration::from_secs(10), fetch)
            .await
            .expect("the fetch outlived its bound")
            .unwrap_err();
        let text = error.to_string();
        assert!(text.contains("platform document fetch"), "{text}");
        assert!(text.contains("timed out"), "{text}");
    }

    #[tokio::test]
    async fn a_body_that_never_ends_fails_the_fetch_within_its_bound() {
        let url = stalling_server(
            b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 1000\r\n\r\n{",
        );
        let key = SigningKey::from_bytes(&[5u8; 32]).verifying_key();
        let fetch = fetch_within(&url, &key, SystemTime::now(), Duration::from_millis(300));
        let error = tokio::time::timeout(Duration::from_secs(10), fetch)
            .await
            .expect("the fetch outlived its bound")
            .unwrap_err();
        let text = error.to_string();
        assert!(text.contains("platform document body"), "{text}");
        assert!(text.contains("timed out"), "{text}");
    }

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
