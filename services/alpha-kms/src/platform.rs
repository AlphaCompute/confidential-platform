//! The platform document, the one release-signed input. Fetched on start and every five minutes, verified
//! here and nowhere else, kept in `platform_document` and in memory.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use alpha_attest::PlatformDocument;
use alpha_core::{context, signing_digest};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::error::ApiError;
use crate::{Node, audit, certs};

pub const RELOAD_EVERY: Duration = Duration::from_secs(300);

/// What the release artifact URL serves: the document as signed and the signature over
/// `signing_digest("alphacompute/platform/v1", document)`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedDocument {
    pub document: Value,
    pub signature: ReleaseSignature,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseSignature {
    pub algorithm: String,
    pub signature: String,
}

#[derive(Debug)]
pub struct Verified {
    pub document: PlatformDocument,
    pub raw: Value,
    pub signature: Vec<u8>,
}

/// Signature, `issued_at` not in the future, and a well-formed document.
pub fn verify(
    signed: &SignedDocument,
    release_key: &VerifyingKey,
    now: SystemTime,
) -> Result<Verified, String> {
    if signed.signature.algorithm != "ed25519" {
        return Err(format!("algorithm {:?}", signed.signature.algorithm));
    }
    let signature = BASE64_URL_SAFE_NO_PAD
        .decode(&signed.signature.signature)
        .ok()
        .and_then(|b| Signature::from_slice(&b).ok())
        .ok_or("signature is not base64url Ed25519")?;
    let digest = signing_digest(context::PLATFORM, &signed.document);
    release_key
        .verify_strict(&digest, &signature)
        .map_err(|_| "release signature does not verify")?;
    let document: PlatformDocument =
        serde_json::from_value(signed.document.clone()).map_err(|e| format!("document: {e}"))?;
    let issued_at = DateTime::parse_from_rfc3339(&document.issued_at)
        .map_err(|e| format!("issued_at: {e}"))?
        .with_timezone(&Utc);
    if issued_at > DateTime::<Utc>::from(now) {
        return Err("issued_at is in the future".into());
    }
    Ok(Verified {
        document,
        raw: signed.document.clone(),
        signature: signature.to_bytes().to_vec(),
    })
}

/// The stored row, re-verified: a swapped row must not become the reference values.
pub async fn load_stored(node: &Node) -> Result<Option<Verified>, ApiError> {
    let row = sqlx::query!("select document, signature from platform_document")
        .fetch_optional(&node.pool)
        .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let signed = SignedDocument {
        document: row.document,
        signature: ReleaseSignature {
            algorithm: "ed25519".into(),
            signature: BASE64_URL_SAFE_NO_PAD.encode(row.signature),
        },
    };
    verify(&signed, &node.release_key, node.now())
        .map(Some)
        .map_err(|e| ApiError::internal(format!("stored platform document: {e}")))
}

/// Applies a verified document: the row moves only to a higher version (with a
/// `platform.reload` audit row), memory follows the row.
pub async fn apply(node: &Node, verified: Verified) -> Result<(), ApiError> {
    let version = i32::try_from(verified.document.version)
        .map_err(|_| ApiError::internal("platform document version overflows"))?;
    let mut tx = node.pool.begin().await?;
    let stored = sqlx::query_scalar!("select version from platform_document for update")
        .fetch_optional(&mut *tx)
        .await?;
    match stored {
        Some(stored) if stored > version => {
            return Err(ApiError::internal(format!(
                "platform document version {version} is below the stored {stored}"
            )));
        }
        Some(stored) if stored == version => {}
        _ => {
            sqlx::query!(
                "insert into platform_document (one, version, document, signature) values (1, $1, $2, $3)
                 on conflict (one) do update set version = $1, document = $2, signature = $3, verified_at = now()",
                version,
                verified.raw,
                verified.signature,
            )
            .execute(&mut *tx)
            .await?;
            audit::node(
                "platform.reload",
                "ok",
                json!({ "version": version, "previous": stored }),
            )
            .insert(&mut *tx)
            .await?;
        }
    }
    tx.commit().await?;
    let current = node.platform.read().unwrap().as_ref().map(|d| d.version);
    if current.is_none_or(|v| v <= verified.document.version) {
        *node.platform.write().unwrap() = Some(Arc::new(verified.document));
    }
    Ok(())
}

pub async fn fetch(node: &Node) -> Result<Verified, ApiError> {
    let signed: SignedDocument = reqwest::get(&node.config.platform_document_url)
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|e| ApiError::internal(format!("platform document fetch: {e}")))?
        .json()
        .await
        .map_err(|e| ApiError::internal(format!("platform document body: {e}")))?;
    verify(&signed, &node.release_key, node.now())
        .map_err(|e| ApiError::internal(format!("platform document: {e}")))
}

pub async fn reload(node: &Node) -> Result<(), ApiError> {
    let verified = fetch(node).await?;
    apply(node, verified).await
}

/// Start: the stored row, then the URL; afterwards one tick every five minutes.
pub async fn start(node: &Node) {
    match load_stored(node).await {
        Ok(Some(stored)) => *node.platform.write().unwrap() = Some(Arc::new(stored.document)),
        Ok(None) => {}
        Err(e) => eprintln!("{}", e.message),
    }
    if let Err(e) = reload(node).await {
        eprintln!("platform document: {}", e.message);
    }
}

pub async fn run(node: Arc<Node>) {
    loop {
        tokio::time::sleep(RELOAD_EVERY).await;
        if let Err(e) = reload(&node).await {
            eprintln!("platform document: {}", e.message);
        }
        renew_leaf(&node);
    }
}

/// The node's own leaf is renewed on the timer once a third of its hour is left.
fn renew_leaf(node: &Node) {
    let Ok(keys) = node.intermediates() else {
        return;
    };
    let current = node.server_cert.current();
    let Some(leaf) = current.cert.first() else {
        return;
    };
    use x509_parser::prelude::{FromDer, X509Certificate};
    let Ok((_, cert)) = X509Certificate::from_der(leaf) else {
        return;
    };
    let not_after = SystemTime::UNIX_EPOCH
        + Duration::from_secs(cert.validity().not_after.timestamp().max(0) as u64);
    if not_after > node.now() + certs::LEAF_TTL / 3 {
        return;
    }
    if let Ok(leaf) = certs::issue_leaf(
        &keys.ca_key(),
        &keys.ca_cert_der,
        &node.runtime_spki,
        certs::node_sans(node.compose_hash),
        node.now(),
    ) {
        node.server_cert
            .serve(&node.runtime_pkcs8(), leaf, keys.ca_cert_der.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    pub fn sign(document: &Value, key: &SigningKey) -> SignedDocument {
        let digest = signing_digest(context::PLATFORM, document);
        SignedDocument {
            document: document.clone(),
            signature: ReleaseSignature {
                algorithm: "ed25519".into(),
                signature: BASE64_URL_SAFE_NO_PAD.encode(key.sign(&digest).to_bytes()),
            },
        }
    }

    fn document(version: u64, issued_at: &str) -> Value {
        json!({
            "version": version, "issued_at": issued_at,
            "policy": { "tcb_statuses": ["UpToDate"], "tolerated_advisories": [] },
            "reference_values": [], "kms_ca_pem": "", "kms_revisions": []
        })
    }

    #[test]
    fn verify_checks_signature_key_and_issued_at() {
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let signed = sign(&document(3, "2026-09-14T00:00:00Z"), &key);
        assert_eq!(
            verify(&signed, &key.verifying_key(), now)
                .unwrap()
                .document
                .version,
            3
        );
        let other = SigningKey::from_bytes(&[6u8; 32]);
        assert!(verify(&signed, &other.verifying_key(), now).is_err());
        let mut tampered = signed.clone();
        tampered.document["version"] = json!(4);
        assert!(verify(&tampered, &key.verifying_key(), now).is_err());
        let future = sign(&document(3, "2100-01-01T00:00:00Z"), &key);
        assert!(
            verify(&future, &key.verifying_key(), now)
                .unwrap_err()
                .contains("future")
        );
        let mut alg = signed.clone();
        alg.signature.algorithm = "ml-dsa".into();
        assert!(verify(&alg, &key.verifying_key(), now).is_err());
    }
}
