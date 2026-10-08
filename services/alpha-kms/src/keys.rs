//! `org_key`, `anchor_check` and `app_key`, the two AES-256-GCM shapes, signature objects
//! (Ed25519 and passkey), and the chain walk from a key to its organization's anchor.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use alpha_core::{AppId, OrgId, Signer, signing_digest};
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
use crate::webauthn;

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

/// A key only Instances of `app` receive. The Revision is not an input, so a new Revision of
/// the App opens what an earlier one sealed; the purpose goes last in `info` because the App
/// id before it has a fixed length.
pub fn app_key(org_key: &[u8; 32], app: AppId, purpose: &str) -> Result<Key32, ApiError> {
    let info = [app.as_bytes().as_slice(), purpose.as_bytes()].concat();
    let mut out = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(b"alphacompute-kms/app-key/v1"), org_key)
        .expand(&info, out.as_mut())
        .map_err(|e| ApiError::internal(format!("hkdf: {e}")))?;
    Ok(out)
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

/// The algorithm the object names must be the one its key's SPKI parses as: each branch parses
/// only its own key type, so no column records a key's kind.
pub fn verify_signature(
    spki: &[u8],
    digest: &[u8; 32],
    signature: &SignatureObject,
    signer: Option<&Signer>,
) -> Result<(), ApiError> {
    match signature.algorithm.as_str() {
        "ed25519" => {
            if signature.authenticator_data.is_some() || signature.client_data_json.is_some() {
                return Err(ApiError::signature_invalid(
                    "ed25519: authenticator_data and client_data_json are not part of an ed25519 signature",
                ));
            }
            if !verify_ed25519(spki, digest, &signature.signature) {
                return Err(ApiError::signature_invalid("signature does not verify"));
            }
            Ok(())
        }
        webauthn::ALGORITHM => webauthn::verify(spki, digest, signature, signer),
        _ => Err(ApiError::signature_invalid("unsupported algorithm")),
    }
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
    signer: Option<&Signer>,
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
            verify_registration(child, &link, signer)?;
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
                verify_self_registration(&link, signer)?;
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
fn verify_registration(
    child: &KeyRow,
    parent: &KeyRow,
    signer: Option<&Signer>,
) -> Result<(), ApiError> {
    let invalid = |m: &str| ApiError::signature_invalid(m.to_owned());
    let signature = registration_signature(child)?;
    if signature.key_id.map(Uuid::from) != Some(parent.id) {
        return Err(invalid(
            "a key in the chain was not registered by its parent",
        ));
    }
    verify_document_spki(child)?;
    let digest = signing_digest(alpha_core::context::PRINCIPAL_KEY, &child.document)
        .map_err(|e| invalid(&format!("registration document: {e}")))?;
    verify_signature(&parent.public_key, &digest, &signature, signer).map_err(|e| {
        invalid(&format!(
            "a key in the chain has a bad registration signature: {}",
            e.message
        ))
    })
}

/// The root key's registration is signed by the key it carries, under its own context and with
/// no `key_id`. It proves nothing on its own — a forged one verifies against itself — but it is
/// what binds `org_id` to the key, and `anchor_check` above is what a forger cannot recompute.
fn verify_self_registration(root: &KeyRow, signer: Option<&Signer>) -> Result<(), ApiError> {
    let invalid = |m: &str| ApiError::signature_invalid(m.to_owned());
    let signature = registration_signature(root)?;
    if signature.key_id.is_some() {
        return Err(invalid("the root key's registration names a signer"));
    }
    verify_document_spki(root)?;
    let claimed = root
        .document
        .get("org_id")
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok());
    if claimed != Some(root.org_id) {
        return Err(invalid(
            "the root key is registered to another organization",
        ));
    }
    let digest = signing_digest(alpha_core::context::ORG_ROOT_KEY, &root.document)
        .map_err(|e| invalid(&format!("registration document: {e}")))?;
    verify_signature(&root.public_key, &digest, &signature, signer).map_err(|e| {
        invalid(&format!(
            "the root key has a bad registration signature: {}",
            e.message
        ))
    })
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

/// A request body's signature object has the fields of its algorithm, and a wrong shape is the
/// caller's malformed body. A stored row is never judged by shape: anything wrong there is an
/// invalid signature.
pub fn check_shape(signature: &SignatureObject) -> Result<(), ApiError> {
    let webauthn_fields = (
        signature.authenticator_data.is_some(),
        signature.client_data_json.is_some(),
    );
    match signature.algorithm.as_str() {
        "ed25519" if webauthn_fields != (false, false) => Err(ApiError::malformed(
            "signature: authenticator_data and client_data_json are not allowed with ed25519",
        )),
        "ed25519" => Ok(()),
        webauthn::ALGORITHM if webauthn_fields != (true, true) => Err(ApiError::malformed(
            "signature: webauthn-es256 needs authenticator_data and client_data_json",
        )),
        webauthn::ALGORITHM => Ok(()),
        _ => Err(ApiError::signature_invalid("unsupported algorithm")),
    }
}

/// Verifies a signature object over `document` under `context` and walks the signer's chain.
pub async fn verify_signed(
    exec: impl PgExecutor<'_> + Copy,
    tenant_kek_root: &[u8; 32],
    signature: &SignatureObject,
    context: &str,
    document: &Value,
    signed_at: DateTime<Utc>,
    signer: Option<&Signer>,
) -> Result<Chain, ApiError> {
    let key_id = signature
        .key_id
        .ok_or_else(|| ApiError::malformed("signature: key_id is required"))?;
    let chain = walk_chain(exec, tenant_kek_root, key_id.into(), signed_at, signer).await?;
    let digest = signing_digest(context, document)
        .map_err(|e| ApiError::malformed(format!("payload: {e}")))?;
    verify_signature(&chain.key.public_key, &digest, signature, signer)?;
    Ok(chain)
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_shape_refuses_other_algorithms_and_misplaced_webauthn_fields() {
        let plain = SignatureObject {
            key_id: None,
            algorithm: "ed25519".into(),
            signature: String::new(),
            authenticator_data: None,
            client_data_json: None,
        };
        assert!(check_shape(&plain).is_ok());
        let other = SignatureObject {
            algorithm: "ml-dsa".into(),
            ..plain.clone()
        };
        assert_eq!(check_shape(&other).unwrap_err().code, "signature_invalid");
        for (authenticator_data, client_data_json) in [
            (Some("AAAA".to_owned()), None),
            (None, Some("e30".to_owned())),
            (Some("AAAA".to_owned()), Some("e30".to_owned())),
        ] {
            let webauthn = SignatureObject {
                authenticator_data,
                client_data_json,
                ..plain.clone()
            };
            assert_eq!(check_shape(&webauthn).unwrap_err().code, "malformed");
        }
    }

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
    fn app_key_matches_an_independent_rfc5869_computation() {
        let app = AppId::from(Uuid::parse_str("01920000-0000-7000-8000-000000000001").unwrap());
        assert_eq!(
            hex::encode(*app_key(&[7; 32], app, "connectors").unwrap()),
            "503b90f56c674229db2bf6427a36675c6f25271025d31d67768c65f71b14690d"
        );
    }

    #[test]
    fn app_key_changes_with_the_app_the_purpose_and_the_org_key() {
        let (org_key, app) = ([7u8; 32], AppId::mint());
        let a = app_key(&org_key, app, "connectors").unwrap();
        assert_eq!(*a, *app_key(&org_key, app, "connectors").unwrap());
        assert_ne!(*a, *app_key(&org_key, AppId::mint(), "connectors").unwrap());
        assert_ne!(*a, *app_key(&org_key, app, "connector").unwrap());
        assert_ne!(*a, *app_key(&[8; 32], app, "connectors").unwrap());
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
