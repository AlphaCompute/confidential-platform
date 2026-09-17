//! `org_key` and `anchor_check`, the two AES-256-GCM shapes, Ed25519 signature
//! objects, and the chain walk from a key to its organization's anchor.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use alpha_core::{OrgId, signing_digest};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use ed25519_dalek::pkcs8::DecodePublicKey;
use ed25519_dalek::{Signature, VerifyingKey};
use hkdf::Hkdf;
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::PgExecutor;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::ApiError;

pub type Key32 = Zeroizing<[u8; 32]>;

fn derive(ikm: &[u8; 32], salt: &[u8], org: OrgId, anchor_spki: &[u8]) -> Result<Key32, ApiError> {
    let info = [org.as_bytes().as_slice(), &Sha256::digest(anchor_spki)].concat();
    let mut out = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(&info, out.as_mut())
        .map_err(|e| ApiError::internal(format!("hkdf: {e}")))?;
    Ok(out)
}

pub fn org_key(
    tenant_kek_root: &[u8; 32],
    org: OrgId,
    anchor_spki: &[u8],
) -> Result<Key32, ApiError> {
    derive(
        tenant_kek_root,
        b"alphacompute-kms/org-key/v1",
        org,
        anchor_spki,
    )
}

pub fn anchor_check(
    tenant_kek_root: &[u8; 32],
    org: OrgId,
    anchor_spki: &[u8],
) -> Result<Key32, ApiError> {
    derive(
        tenant_kek_root,
        b"alphacompute-kms/anchor-check/v1",
        org,
        anchor_spki,
    )
}

/// `nonce(12) ‖ AES-256-GCM(key, plaintext, aad)`.
pub fn aead_seal(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, ApiError> {
    let nonce = crate::random::<12>()?;
    let ct = Aes256Gcm::new(key.into())
        .encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| ApiError::internal("aead: encryption failed"))?;
    Ok([nonce.as_slice(), &ct].concat())
}

pub fn aead_open(key: &[u8; 32], aad: &[u8], blob: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let (nonce, ct) = blob.split_at_checked(12)?;
    Aes256Gcm::new(key.into())
        .decrypt(&Nonce::try_from(nonce).ok()?, Payload { msg: ct, aad })
        .ok()
        .map(Zeroizing::new)
}

pub use alpha_client::SignatureObject;

pub fn verify_ed25519(spki_der: &[u8], digest: &[u8; 32], signature_b64: &str) -> bool {
    let Ok(key) = VerifyingKey::from_public_key_der(spki_der) else {
        return false;
    };
    let Some(signature) = BASE64_URL_SAFE_NO_PAD
        .decode(signature_b64)
        .ok()
        .and_then(|b| Signature::from_slice(&b).ok())
    else {
        return false;
    };
    key.verify_strict(digest, &signature).is_ok()
}

/// A `principal_keys` row as the chain walk needs it.
#[derive(Clone)]
pub struct KeyRow {
    pub id: Uuid,
    pub org_id: Uuid,
    pub public_key: Vec<u8>,
    pub document: Value,
    pub signature: Value,
    pub registered_by_key: Option<Uuid>,
    pub anchor_check: Option<Vec<u8>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revocation_reason: Option<String>,
}

pub async fn load_key(exec: impl PgExecutor<'_>, id: Uuid) -> Result<Option<KeyRow>, ApiError> {
    Ok(sqlx::query_as!(
        KeyRow,
        r#"select id, org_id, public_key, document, signature, registered_by_key, anchor_check, revoked_at,
                  revocation_reason::text as "revocation_reason"
           from principal_keys where id = $1"#,
        id
    )
    .fetch_optional(exec)
    .await?)
}

/// The organization's anchor SPKI, for `org_key`.
pub struct Chain {
    pub key: KeyRow,
    pub anchor_spki: Vec<u8>,
}

/// Walks `key_id` → `registered_by_key` → … → the anchor, without a cache, and recomputes
/// the anchor's `anchor_check`. Each delegated link's registration document must carry its
/// own SPKI and verify under its parent's key, so a row edited in the database no longer
/// chains. A link is good while unrevoked, or retired after the moment the thing it signed
/// was signed; `compromised` anywhere fails the chain. Each hop moves `signed_at` back to
/// the moment the link itself was registered.
pub async fn walk_chain(
    exec: impl PgExecutor<'_> + Copy,
    tenant_kek_root: &[u8; 32],
    key_id: Uuid,
    mut signed_at: DateTime<Utc>,
) -> Result<Chain, ApiError> {
    let invalid = |m: &str| ApiError::signature_invalid(m.to_owned());
    let first = load_key(exec, key_id)
        .await?
        .ok_or_else(|| invalid("unknown key"))?;
    let mut current = Some(first.clone());
    let mut child: Option<KeyRow> = None;
    let mut hops = 0;
    while let Some(link) = current {
        if link.org_id != first.org_id {
            return Err(invalid("the chain crosses organizations"));
        }
        if let Some(child) = &child {
            verify_registration(child, &link)?;
        }
        if let Some(revoked_at) = link.revoked_at {
            let retired = link.revocation_reason.as_deref() == Some("retired");
            if !retired || signed_at >= revoked_at {
                return Err(invalid("a key in the chain is revoked"));
            }
        }
        match link.registered_by_key {
            None => {
                let expected =
                    anchor_check(tenant_kek_root, OrgId::from(link.org_id), &link.public_key)?;
                if link.anchor_check.as_deref() != Some(expected.as_slice()) {
                    return Err(invalid(
                        "the chain does not end at the organization's anchor",
                    ));
                }
                verify_self_registration(&link)?;
                return Ok(Chain {
                    key: first,
                    anchor_spki: link.public_key,
                });
            }
            Some(parent) => {
                signed_at = link
                    .document
                    .get("issued_at")
                    .and_then(Value::as_str)
                    .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                    .map(|t| t.with_timezone(&Utc))
                    .ok_or_else(|| invalid("a key in the chain has no issued_at"))?;
                hops = u32::saturating_add(hops, 1);
                if hops > 64 {
                    return Err(invalid("the chain does not end"));
                }
                current = load_key(exec, parent).await?;
                child = Some(link);
            }
        }
    }
    Err(invalid("the chain is broken"))
}

/// The child's registration document names the child's own SPKI and is signed by the parent.
fn verify_registration(child: &KeyRow, parent: &KeyRow) -> Result<(), ApiError> {
    let invalid = |m: &str| ApiError::signature_invalid(m.to_owned());
    let signature = registration_signature(child)?;
    if signature.key_id.map(Uuid::from) != Some(parent.id) || signature.algorithm != "ed25519" {
        return Err(invalid(
            "a key in the chain was not registered by its parent",
        ));
    }
    verify_document_spki(child)?;
    let digest = signing_digest(alpha_core::context::PRINCIPAL_KEY, &child.document)
        .map_err(|e| invalid(&format!("registration document: {e}")))?;
    if !verify_ed25519(&parent.public_key, &digest, &signature.signature) {
        return Err(invalid(
            "a key in the chain has a bad registration signature",
        ));
    }
    Ok(())
}

/// The root key's registration is signed by the key it carries, under its own context and with
/// no `key_id`. It proves nothing on its own — a forged one verifies against itself — but it is
/// what binds `org_id` to the key, and `anchor_check` above is what a forger cannot recompute.
fn verify_self_registration(root: &KeyRow) -> Result<(), ApiError> {
    let invalid = |m: &str| ApiError::signature_invalid(m.to_owned());
    let signature = registration_signature(root)?;
    if signature.key_id.is_some() || signature.algorithm != "ed25519" {
        return Err(invalid("the root key's registration names a signer"));
    }
    verify_document_spki(root)?;
    if root.document.get("org_id").and_then(Value::as_str) != Some(root.org_id.to_string().as_str())
    {
        return Err(invalid(
            "the root key is registered to another organization",
        ));
    }
    let digest = signing_digest(alpha_core::context::ORG_ROOT_KEY, &root.document)
        .map_err(|e| invalid(&format!("registration document: {e}")))?;
    if !verify_ed25519(&root.public_key, &digest, &signature.signature) {
        return Err(invalid("the root key has a bad registration signature"));
    }
    Ok(())
}

fn registration_signature(row: &KeyRow) -> Result<SignatureObject, ApiError> {
    serde_json::from_value(row.signature.clone()).map_err(|_| {
        ApiError::signature_invalid("a key in the chain has no registration signature")
    })
}

fn verify_document_spki(row: &KeyRow) -> Result<(), ApiError> {
    let registered = row
        .document
        .get("public_key")
        .and_then(Value::as_str)
        .and_then(|s| BASE64_URL_SAFE_NO_PAD.decode(s).ok());
    if registered.as_deref() != Some(row.public_key.as_slice()) {
        return Err(ApiError::signature_invalid(
            "a key in the chain differs from its registration document",
        ));
    }
    Ok(())
}

/// Verifies a signature object over `document` under `context` and walks the signer's chain.
pub async fn verify_signed(
    exec: impl PgExecutor<'_> + Copy,
    tenant_kek_root: &[u8; 32],
    signature: &SignatureObject,
    context: &str,
    document: &Value,
    signed_at: DateTime<Utc>,
) -> Result<Chain, ApiError> {
    if signature.algorithm != "ed25519" {
        return Err(ApiError::signature_invalid("unsupported algorithm"));
    }
    let key_id = signature
        .key_id
        .ok_or_else(|| ApiError::malformed("signature: key_id is required"))?;
    let chain = walk_chain(exec, tenant_kek_root, key_id.into(), signed_at).await?;
    let digest = signing_digest(context, document)
        .map_err(|e| ApiError::malformed(format!("payload: {e}")))?;
    if !verify_ed25519(&chain.key.public_key, &digest, &signature.signature) {
        return Err(ApiError::signature_invalid("signature does not verify"));
    }
    Ok(chain)
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivations_separate_salts_orgs_and_anchors() {
        let root = [1u8; 32];
        let org = OrgId::mint();
        let a = org_key(&root, org, b"anchor").unwrap();
        assert_ne!(*a, *anchor_check(&root, org, b"anchor").unwrap());
        assert_ne!(*a, *org_key(&root, OrgId::mint(), b"anchor").unwrap());
        assert_ne!(*a, *org_key(&root, org, b"other").unwrap());
        assert_eq!(*a, *org_key(&root, org, b"anchor").unwrap());
    }

    #[test]
    fn aead_round_trip_binds_aad() {
        let key = [9u8; 32];
        let blob = aead_seal(&key, b"aad", b"value").unwrap();
        assert_eq!(aead_open(&key, b"aad", &blob).unwrap().as_slice(), b"value");
        assert!(aead_open(&key, b"other", &blob).is_none());
        assert!(aead_open(&[0; 32], b"aad", &blob).is_none());
        assert!(aead_open(&key, b"aad", &blob[..5]).is_none());
    }

    #[test]
    fn ed25519_over_the_digest() {
        use ed25519_dalek::SigningKey;
        use ed25519_dalek::pkcs8::EncodePublicKey;
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let spki = sk.verifying_key().to_public_key_der().unwrap();
        let digest = signing_digest("ctx", &serde_json::json!({"a": 1})).unwrap();
        let sig =
            BASE64_URL_SAFE_NO_PAD.encode(ed25519_dalek::Signer::sign(&sk, &digest).to_bytes());
        assert!(verify_ed25519(spki.as_bytes(), &digest, &sig));
        assert!(!verify_ed25519(spki.as_bytes(), &[0; 32], &sig));
        assert!(!verify_ed25519(b"nope", &digest, &sig));
        assert!(!verify_ed25519(spki.as_bytes(), &digest, "AAAA"));
    }
}
