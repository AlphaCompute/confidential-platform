//! KBS protocol 0.4.0 for one resource: the registry credential a Revision's `cdh.toml` names,
//! released to the guest's data hub so that the credential never sits on the host. `attest` is
//! the Kata appraisal of `/v1/attest` over the protocol's `report_data`; `resource` repeats the
//! checks of `GET /v1/secrets/{name}` and encrypts the value to the TEE key the quote bound.
//! Nonces and tokens are keyed from `tenant-kek-root`, so each request may reach either node.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use aes_gcm::aead::AeadInOut;
use aes_gcm::{Aes256Gcm, KeyInit};
use aes_kw::KwAes256;
use alpha_attest::PlatformDocument;
use alpha_core::{AppId, ComposeHash, OrgId};
use axum::Json;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::prelude::{BASE64_STANDARD, BASE64_URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256, Sha384};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::audit::Audit;
use crate::body::Body;
use crate::error::ApiError;
use crate::instance::{
    appraise_revision, check_nonce, collateral, decode32, load_revision, mint_nonce, unix,
};
use crate::keys::{Key32, hkdf, sha256_hex};
use crate::{Node, later};

const TOKEN_TTL: Duration = Duration::from_secs(300);
const NONCE_LABEL: &[u8] = b"alphacompute-kms/kbs-nonce/v1";
const TOKEN_LABEL: &[u8] = b"alphacompute-kms/kbs-token/v1";
/// `{"alg":"HS256","typ":"JWT"}`
const TOKEN_HEADER: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
const KEY_WRAP: &str = "ECDH-ES+A256KW";

/// An [`ApiError`] in the protocol's `ErrorInformation` form: the guest reads that body on a 401
/// to fetch a new token, and fails on any other.
pub struct KbsError(ApiError);

impl From<ApiError> for KbsError {
    fn from(e: ApiError) -> Self {
        Self(e)
    }
}

impl IntoResponse for KbsError {
    fn into_response(self) -> Response {
        let body = json!({ "type": self.0.code, "detail": self.0.message });
        (self.0.status(), Json(body)).into_response()
    }
}

fn nonce_key(tenant_kek_root: &[u8; 32]) -> Result<Key32, ApiError> {
    hkdf(tenant_kek_root, NONCE_LABEL, b"")
}

#[derive(Deserialize)]
pub struct AuthRequest {
    version: String,
    tee: String,
}

pub async fn auth(
    State(node): State<Arc<Node>>,
    Body(request, _): Body<AuthRequest>,
) -> Result<Json<Value>, KbsError> {
    if request.version != "0.4.0" || request.tee != "tdx" {
        return Err(ApiError::malformed("only KBS protocol 0.4.0 with tee tdx").into());
    }
    let key = nonce_key(&node.intermediates()?.tenant_kek_root)?;
    let nonce = mint_nonce(&key, node.now())?;
    Ok(Json(json!({
        "nonce": BASE64_URL_SAFE_NO_PAD.encode(nonce),
        "extra-params": { "selected-hash-algorithm": "sha384" },
    })))
}

/// A P-256 key as kbs-types writes it, the only kind the guest's default key wraps to.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TeeKey {
    kty: String,
    crv: String,
    alg: String,
    x: String,
    y: String,
}

impl TeeKey {
    fn public_key(&self) -> Result<p256::PublicKey, ApiError> {
        let coordinate = |c: &str| {
            BASE64_URL_SAFE_NO_PAD
                .decode(c)
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
        };
        match (coordinate(&self.x), coordinate(&self.y)) {
            (Some(x), Some(y))
                if (&*self.kty, &*self.crv, &*self.alg) == ("EC", "P-256", KEY_WRAP) =>
            {
                p256::PublicKey::from_sec1_bytes(&[&[4u8][..], &x, &y].concat())
                    .map_err(|_| ApiError::malformed("tee-pubkey: not a point on P-256"))
            }
            _ => Err(ApiError::malformed(
                "tee-pubkey: not an ECDH-ES+A256KW P-256 key",
            )),
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Attestation {
    runtime_data: RuntimeData,
    tee_evidence: TeeEvidence,
}

#[derive(Deserialize)]
pub struct RuntimeData {
    nonce: String,
    #[serde(rename = "tee-pubkey")]
    tee_pubkey: Value,
}

#[derive(Deserialize)]
pub struct TeeEvidence {
    primary_evidence: TdxEvidence,
    additional_evidence: String,
}

#[derive(Deserialize)]
pub struct TdxEvidence {
    quote: String,
}

/// What the guest's attestation agent binds into the quote: SHA-384 of the JCS of the nonce, the
/// TEE key and the additional (device) evidence, zero-padded.
fn report_data(
    nonce: &str,
    tee_pubkey: &Value,
    additional_evidence: &str,
) -> Result<[u8; 64], ApiError> {
    let bound = json!({
        "additional-evidence": additional_evidence,
        "nonce": nonce,
        "tee-pubkey": tee_pubkey,
    });
    let jcs =
        alpha_core::jcs(&bound).map_err(|e| ApiError::malformed(format!("runtime-data: {e}")))?;
    let mut out = [0u8; 64];
    for (dst, src) in out.iter_mut().zip(Sha384::digest(jcs)) {
        *dst = src;
    }
    Ok(out)
}

#[derive(Deserialize, Serialize)]
pub struct Claims {
    exp: u64,
    org_id: OrgId,
    revision: ComposeHash,
    #[serde(rename = "tee-pubkey")]
    tee_pubkey: TeeKey,
}

fn tee_key_hash(tee_pubkey: &Value) -> String {
    alpha_core::jcs(tee_pubkey)
        .map(|k| sha256_hex(&k))
        .unwrap_or_default()
}

fn token_mac(tenant_kek_root: &[u8; 32], signed: &str) -> Result<Hmac<Sha256>, ApiError> {
    let key = hkdf(tenant_kek_root, TOKEN_LABEL, b"")?;
    let mut mac = Hmac::<Sha256>::new_from_slice(&*key)
        .map_err(|e| ApiError::internal(format!("hmac: {e}")))?;
    mac.update(signed.as_bytes());
    Ok(mac)
}

pub fn issue_token(tenant_kek_root: &[u8; 32], claims: &Claims) -> Result<String, ApiError> {
    let payload = serde_json::to_vec(claims).map_err(|e| ApiError::internal(e.to_string()))?;
    let signed = format!("{TOKEN_HEADER}.{}", BASE64_URL_SAFE_NO_PAD.encode(payload));
    let tag = token_mac(tenant_kek_root, &signed)?.finalize();
    Ok(format!(
        "{signed}.{}",
        BASE64_URL_SAFE_NO_PAD.encode(tag.into_bytes())
    ))
}

fn verify_token(
    tenant_kek_root: &[u8; 32],
    token: &str,
    now: SystemTime,
) -> Result<Claims, ApiError> {
    let invalid = |why: &str| ApiError::new("token_invalid", format!("token: {why}"));
    let (signed, tag) = token.rsplit_once('.').ok_or_else(|| invalid("not a JWT"))?;
    let tag = BASE64_URL_SAFE_NO_PAD
        .decode(tag)
        .map_err(|_| invalid("not a JWT"))?;
    token_mac(tenant_kek_root, signed)?
        .verify_slice(&tag)
        .map_err(|_| invalid("does not verify"))?;
    let payload = signed
        .strip_prefix(TOKEN_HEADER)
        .and_then(|p| p.strip_prefix('.'))
        .and_then(|p| BASE64_URL_SAFE_NO_PAD.decode(p).ok())
        .ok_or_else(|| invalid("not ours"))?;
    let claims: Claims = serde_json::from_slice(&payload).map_err(|_| invalid("not ours"))?;
    if unix(now) >= claims.exp {
        return Err(invalid("expired"));
    }
    Ok(claims)
}

/// The Revision `revision`, checked again as `/v1/attest` checks it, and the
/// registry credential its init-data names.
async fn registry_credential(
    node: &Node,
    tenant_kek_root: &[u8; 32],
    doc: &PlatformDocument,
    revision: ComposeHash,
) -> Result<(OrgId, AppId, String), ApiError> {
    let unknown = || ApiError::new("attestation_unknown", format!("no revision {revision}"));
    let row = load_revision(&node.pool, revision)
        .await?
        .ok_or_else(unknown)?;
    let init_data = appraise_revision(&node.pool, tenant_kek_root, revision, &row, doc)
        .await?
        .ok_or_else(unknown)?;
    let name = init_data.registry_credential().ok_or_else(|| {
        ApiError::new("policy_denied", "the revision names no registry credential")
    })?;
    Ok((row.org_id.into(), row.app_id.into(), name))
}

pub async fn attest(
    State(node): State<Arc<Node>>,
    Body(request, _): Body<Attestation>,
) -> Result<Json<Value>, KbsError> {
    let quote = BASE64_STANDARD.decode(&request.tee_evidence.primary_evidence.quote);
    let evidence_sha256 = quote.as_ref().ok().map(|q| Sha256::digest(q).to_vec());
    let actor = tee_key_hash(&request.runtime_data.tee_pubkey);
    let result = attest_inner(&node, &request, quote).await;
    let (outcome, details, org_id, object) = match &result {
        Ok((claims, _)) => (
            "ok",
            json!({}),
            Some(Uuid::from(claims.org_id)),
            Some(format!("revision:{}", claims.revision)),
        ),
        Err(e) => (e.outcome(), e.details(), None, None),
    };
    Audit {
        actor_kind: "instance",
        actor: &actor,
        action: "kbs.attest",
        org_id,
        object,
        outcome,
        details,
        evidence_sha256,
    }
    .insert(&node.pool)
    .await
    .map_err(ApiError::from)?;
    let (_, token) = result?;
    Ok(Json(json!({ "token": token })))
}

async fn attest_inner(
    node: &Node,
    request: &Attestation,
    quote: Result<Vec<u8>, base64::DecodeError>,
) -> Result<(Claims, String), ApiError> {
    let runtime = &request.runtime_data;
    let keys = node.intermediates()?;
    let now = node.now();
    let nonce = decode32("nonce", &runtime.nonce)?;
    check_nonce(&*nonce_key(&keys.tenant_kek_root)?, &nonce, now)?;
    let tee_pubkey = TeeKey::deserialize(&runtime.tee_pubkey)
        .map_err(|e| ApiError::malformed(format!("tee-pubkey: {e}")))?;
    tee_pubkey.public_key()?;
    let expected = report_data(
        &runtime.nonce,
        &runtime.tee_pubkey,
        &request.tee_evidence.additional_evidence,
    )?;
    let quote = quote.map_err(|_| ApiError::malformed("primary_evidence.quote: not base64"))?;
    let doc = node
        .platform_document()
        .ok_or_else(|| ApiError::new("attestation_unknown", "no platform document"))?;
    let collateral = collateral(node, &quote).await?;
    let appraised = alpha_attest::appraise_kata(&quote, &expected, &doc, &collateral, now)?;
    let (org_id, _, _) =
        registry_credential(node, &keys.tenant_kek_root, &doc, appraised.init_data).await?;
    let claims = Claims {
        exp: unix(later(now, TOKEN_TTL)?),
        org_id,
        revision: appraised.init_data,
        tee_pubkey,
    };
    let token = issue_token(&keys.tenant_kek_root, &claims)?;
    Ok((claims, token))
}

pub async fn resource(
    State(node): State<Arc<Node>>,
    Path((repository, kind, name)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Result<Json<Value>, KbsError> {
    let keys = node.intermediates()?;
    let claims = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| ApiError::new("token_invalid", "no bearer token"))
        .and_then(|token| verify_token(&keys.tenant_kek_root, token, node.now()))?;
    let actor = tee_key_hash(&json!(claims.tee_pubkey));
    let result = resource_inner(
        &node,
        &keys.tenant_kek_root,
        &claims,
        (&repository, &kind, &name),
    )
    .await;
    let (outcome, details) = match &result {
        Ok(_) => ("ok", json!({})),
        Err(e) => (e.outcome(), e.details()),
    };
    // A refused path is unbounded text from the peer; only a Secret name is recorded.
    let object = alpha_core::is_secret_name(&name).then(|| format!("secret:{name}"));
    Audit {
        actor_kind: "instance",
        actor: &actor,
        action: "kbs.resource",
        org_id: Some(claims.org_id.into()),
        object,
        outcome,
        details,
        evidence_sha256: None,
    }
    .insert(&node.pool)
    .await
    .map_err(ApiError::from)?;
    Ok(Json(result?))
}

async fn resource_inner(
    node: &Node,
    tenant_kek_root: &[u8; 32],
    claims: &Claims,
    (repository, kind, name): (&str, &str, &str),
) -> Result<Value, ApiError> {
    let doc = node
        .platform_document()
        .ok_or_else(|| ApiError::new("attestation_unknown", "no platform document"))?;
    let (org_id, app_id, credential) =
        registry_credential(node, tenant_kek_root, &doc, claims.revision).await?;
    // The data hub serves any resource to every container of the pod, so the Revision's one
    // credential is all this route releases.
    if (repository, kind, name) != ("alpha", "secret", credential.as_str()) {
        return Err(ApiError::not_found("the revision names no such resource"));
    }
    let released = crate::instance::release_secret(
        node,
        tenant_kek_root,
        doc.signer.as_ref(),
        org_id,
        app_id,
        name,
    )
    .await?;
    let tee = claims.tee_pubkey.public_key()?;
    seal(
        &tee,
        &released.value,
        &crate::random()?,
        &Zeroizing::new(crate::random()?),
        &crate::random()?,
    )
}

/// The JWE kbs-types reads: `ECDH-ES+A256KW` on P-256 (Concat KDF over SHA-256, RFC 7518 §4.6)
/// wraps a fresh A256GCM key, and the protected header in base64url is the AAD.
fn seal(
    tee: &p256::PublicKey,
    plaintext: &[u8],
    ephemeral: &[u8; 32],
    cek: &[u8; 32],
    iv: &[u8; 12],
) -> Result<Value, ApiError> {
    let ephemeral = p256::SecretKey::from_bytes(&(*ephemeral).into())
        .map_err(|_| ApiError::internal("ephemeral key"))?;
    let shared = p256::ecdh::diffie_hellman(ephemeral.to_nonzero_scalar(), tee.as_affine());
    let mut kdf = Sha256::new();
    kdf.update(1u32.to_be_bytes());
    kdf.update(shared.raw_secret_bytes());
    kdf.update((KEY_WRAP.len() as u32).to_be_bytes());
    kdf.update(KEY_WRAP.as_bytes());
    kdf.update([0; 8]);
    kdf.update(256u32.to_be_bytes());
    let kek = Zeroizing::new(<[u8; 32]>::from(kdf.finalize()));
    let mut wrapped = [0u8; 40];
    KwAes256::new(&(*kek).into())
        .wrap_key(cek, &mut wrapped)
        .map_err(|e| ApiError::internal(format!("key wrap: {e}")))?;
    let point = ephemeral.public_key().to_sec1_bytes();
    let Some((x, y)) = point.get(1..).and_then(|xy| xy.split_first_chunk::<32>()) else {
        return Err(ApiError::internal("ephemeral key"));
    };
    // Keys in sorted order: the guest re-serializes the header to rebuild the AAD.
    let protected = BASE64_URL_SAFE_NO_PAD.encode(format!(
        r#"{{"alg":"{KEY_WRAP}","enc":"A256GCM","epk":{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}}}"#,
        BASE64_URL_SAFE_NO_PAD.encode(x),
        BASE64_URL_SAFE_NO_PAD.encode(y),
    ));
    let mut ciphertext = Zeroizing::new(plaintext.to_vec());
    let tag = Aes256Gcm::new(cek.into())
        .encrypt_inout_detached(
            iv.into(),
            protected.as_bytes(),
            ciphertext.as_mut_slice().into(),
        )
        .map_err(|_| ApiError::internal("aes-gcm"))?;
    Ok(json!({
        "protected": protected,
        "encrypted_key": BASE64_URL_SAFE_NO_PAD.encode(wrapped),
        "iv": BASE64_URL_SAFE_NO_PAD.encode(iv),
        "ciphertext": BASE64_URL_SAFE_NO_PAD.encode(&*ciphertext),
        "tag": BASE64_URL_SAFE_NO_PAD.encode(tag),
    }))
}

#[cfg(test)]
mod tests {
    use std::time::UNIX_EPOCH;

    use super::*;

    fn hex<const N: usize>(v: &Value) -> [u8; N] {
        alpha_core::hex_bytes(v.as_str().unwrap()).unwrap()
    }

    #[test]
    fn the_jwe_is_the_one_the_guest_opened() {
        let vector: Value =
            serde_json::from_str(include_str!("../../../testdata/crypto/kbs-jwe-p256.json"))
                .unwrap();
        let tee = p256::SecretKey::from_bytes(&hex(&vector["tee_secret_hex"]).into()).unwrap();
        let jwe = seal(
            &tee.public_key(),
            vector["plaintext"].as_str().unwrap().as_bytes(),
            &hex(&vector["ephemeral_secret_hex"]),
            &hex(&vector["cek_hex"]),
            &hex(&vector["iv_hex"]),
        )
        .unwrap();
        assert_eq!(jwe, vector["jwe"]);
    }

    #[test]
    fn report_data_hashes_the_additional_evidence_too() {
        let key = json!({ "kty": "EC", "crv": "P-256", "alg": KEY_WRAP, "x": "eA", "y": "eQ" });
        let bound = report_data("bm9uY2U", &key, "").unwrap();
        assert_eq!(
            hex::encode(&bound[..48]),
            "00d18df38713faa9d511a60382526f2a7956859de14efec2266a2d0a3d5e74a765281f8f44da2635f0aa3fd790a8b5ee"
        );
        assert_eq!(bound[48..], [0; 16]);
        assert_ne!(report_data("bm9uY2U", &key, "{}").unwrap(), bound);
    }

    #[test]
    fn a_token_verifies_under_its_root_until_it_expires() {
        let root = [1u8; 32];
        let t0 = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let tee_pubkey: TeeKey = serde_json::from_value(
            json!({ "kty": "EC", "crv": "P-256", "alg": KEY_WRAP, "x": "eA", "y": "eQ" }),
        )
        .unwrap();
        let claims = Claims {
            exp: unix(t0 + TOKEN_TTL),
            org_id: OrgId::mint(),
            revision: alpha_core::compose_hash("init-data"),
            tee_pubkey,
        };
        let token = issue_token(&root, &claims).unwrap();
        assert_eq!(token.split('.').count(), 3);
        let read = verify_token(&root, &token, t0 + TOKEN_TTL - Duration::from_secs(1)).unwrap();
        assert_eq!(
            (read.org_id, read.revision),
            (claims.org_id, claims.revision)
        );

        let (signed, tag) = token.rsplit_once('.').unwrap();
        let other_claims = BASE64_URL_SAFE_NO_PAD.encode(br#"{"exp":1}"#);
        let refusals = [
            verify_token(&root, &token, t0 + TOKEN_TTL),
            verify_token(&[2u8; 32], &token, t0),
            verify_token(&root, &format!("{signed}.AAAA"), t0),
            verify_token(&root, &format!("{TOKEN_HEADER}.{other_claims}.{tag}"), t0),
            verify_token(&root, "not a token", t0),
        ];
        for refused in refusals {
            assert_eq!(refused.err().map(|e| e.code), Some("token_invalid"));
        }
    }
}
