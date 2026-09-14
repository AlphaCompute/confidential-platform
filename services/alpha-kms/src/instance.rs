//! The Instance API: the stateless nonce, attestation into a one-hour leaf, and secrets over mTLS.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alpha_attest::{AttestationResult, Evidence, RESULT_FORMAT, Revision, Verdict, appraise};
use alpha_core::{ComposeHash, context};
use axum::Json;
use axum::extract::{Extension, Path, State};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use hmac::{Hmac, KeyInit, Mac};
use p256::pkcs8::DecodePublicKey;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::audit::Audit;
use crate::body::Body;
use crate::error::ApiError;
use crate::keys::{self, SignatureObject};
use crate::tls::PeerCerts;
use crate::{CollateralSource, Node, certs};

pub const NONCE_MAX_AGE: Duration = Duration::from_secs(300);

fn unix(now: SystemTime) -> u64 {
    now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

/// `ts(8, BE) ‖ HMAC-SHA256(node_nonce_key, ts)[0..24]`.
pub fn mint_nonce(key: &[u8; 32], now: SystemTime) -> [u8; 32] {
    let ts = unix(now).to_be_bytes();
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("any key length");
    mac.update(&ts);
    let tag = mac.finalize().into_bytes();
    let mut nonce = [0u8; 32];
    nonce[..8].copy_from_slice(&ts);
    nonce[8..].copy_from_slice(&tag[..24]);
    nonce
}

pub fn check_nonce(key: &[u8; 32], nonce: &[u8; 32], now: SystemTime) -> Result<(), ApiError> {
    let ts = u64::from_be_bytes(nonce[..8].try_into().unwrap());
    let expected = mint_nonce(key, UNIX_EPOCH + Duration::from_secs(ts));
    if expected != *nonce {
        return Err(ApiError::new("nonce_invalid", "nonce does not verify"));
    }
    let age = unix(now).saturating_sub(ts);
    if ts > unix(now) || age > NONCE_MAX_AGE.as_secs() {
        return Err(ApiError::new("nonce_invalid", "nonce is too old"));
    }
    Ok(())
}

pub async fn nonce(State(node): State<Arc<Node>>) -> Json<Value> {
    let now = node.now();
    let nonce = mint_nonce(&node.nonce_key, now);
    let expires: DateTime<Utc> = (now + NONCE_MAX_AGE).into();
    Json(json!({
        "nonce": BASE64_URL_SAFE_NO_PAD.encode(nonce),
        "expires_at": expires.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestRequest {
    pub runtime_pubkey: String,
    pub nonce: String,
    pub evidence: Evidence,
}

pub fn decode32(field: &str, text: &str) -> Result<[u8; 32], ApiError> {
    BASE64_URL_SAFE_NO_PAD
        .decode(text)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| ApiError::malformed(format!("{field}: expected 32 bytes base64url")))
}

pub async fn collateral(node: &Node, quote: &[u8]) -> Result<alpha_attest::Collateral, ApiError> {
    Ok(match &node.collateral {
        CollateralSource::Pccs(url) => alpha_attest::fetch_collateral(url, quote).await?,
        CollateralSource::Fixed(c) => (**c).clone(),
    })
}

/// A `revisions` row with what the checks need.
pub struct RevisionRow {
    pub app_id: Uuid,
    pub org_id: Uuid,
    pub compose: String,
    pub created_by_key: Uuid,
    pub signature: Value,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

pub async fn load_revision(
    exec: impl sqlx::PgExecutor<'_>,
    compose_hash: ComposeHash,
) -> Result<Option<RevisionRow>, ApiError> {
    Ok(sqlx::query_as!(
        RevisionRow,
        "select app_id, org_id, compose, created_by_key, signature, created_at, revoked_at
         from revisions where compose_hash = $1",
        compose_hash.as_bytes().as_slice()
    )
    .fetch_optional(exec)
    .await?)
}

/// The last appraisal step, on every attestation and every Instance call: the Revision's signature and
/// the signer's chain, from the row as it is now.
pub async fn verify_revision(
    exec: impl sqlx::PgExecutor<'_> + Copy,
    tenant_kek_root: &[u8; 32],
    compose_hash: ComposeHash,
    revision: &RevisionRow,
) -> Result<keys::Chain, ApiError> {
    if alpha_core::compose_hash(&revision.compose) != compose_hash {
        return Err(ApiError::signature_invalid(
            "revision bytes do not hash to their key",
        ));
    }
    let signature: SignatureObject = serde_json::from_value(revision.signature.clone())
        .map_err(|_| ApiError::signature_invalid("revision signature object"))?;
    if Uuid::from(signature.key_id) != revision.created_by_key {
        return Err(ApiError::signature_invalid(
            "revision signer does not match",
        ));
    }
    let document = json!({ "app_id": revision.app_id, "compose": revision.compose });
    let chain = keys::verify_signed(
        exec,
        tenant_kek_root,
        &signature,
        context::REVISION,
        &document,
        revision.created_at,
    )
    .await?;
    if chain.key.org_id != revision.org_id {
        return Err(ApiError::signature_invalid(
            "revision signer is not of its organization",
        ));
    }
    Ok(chain)
}

pub async fn attest(
    State(node): State<Arc<Node>>,
    Body(request): Body<AttestRequest>,
) -> Result<Json<Value>, ApiError> {
    let spki = BASE64_URL_SAFE_NO_PAD
        .decode(&request.runtime_pubkey)
        .map_err(|_| ApiError::malformed("runtime_pubkey: not base64url"))?;
    p256::PublicKey::from_public_key_der(&spki)
        .map_err(|_| ApiError::malformed("runtime_pubkey: not a P-256 SPKI"))?;
    let actor = keys::sha256_hex(&spki);
    let evidence_sha256 = Sha256::digest(alpha_core::jcs(&json!(request.evidence))).to_vec();
    let result = attest_inner(&node, &spki, &request).await;
    let (outcome, details, org_id) = match &result {
        Ok(ok) => (
            "ok",
            json!(ok.result),
            Some(Uuid::from(ok.result.revision.org_id)),
        ),
        Err(e) => (e.outcome(), e.details(), None),
    };
    Audit {
        actor_kind: "instance",
        actor: &actor,
        action: "attest",
        org_id,
        object: result
            .as_ref()
            .ok()
            .map(|ok| format!("revision:{}", ok.result.revision.compose_hash)),
        outcome,
        details,
        evidence_sha256: Some(evidence_sha256),
    }
    .insert(&node.pool)
    .await?;
    let ok = result?;
    Ok(Json(json!({
        "certificate_chain": [certs::pem(&ok.leaf_der), ok.ca_pem],
        "not_after": ok.not_after.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "attestation_result": ok.result,
    })))
}

struct Attested {
    leaf_der: Vec<u8>,
    ca_pem: String,
    not_after: DateTime<Utc>,
    result: AttestationResult,
}

async fn attest_inner(
    node: &Node,
    spki: &[u8],
    request: &AttestRequest,
) -> Result<Attested, ApiError> {
    let now = node.now();
    let nonce = decode32("nonce", &request.nonce)?;
    check_nonce(&node.nonce_key, &nonce, now)?;
    let doc = node
        .platform_document()
        .ok_or_else(|| ApiError::new("attestation_unknown", "no platform document"))?;
    let collateral = collateral(node, &request.evidence.quote).await?;
    let appraised = appraise(
        &request.evidence,
        &nonce,
        spki,
        None,
        &doc,
        &collateral,
        now,
    )?;
    let keys = node.intermediates()?;
    let revision = load_revision(&node.pool, appraised.compose_hash)
        .await?
        .ok_or_else(|| {
            ApiError::new(
                "attestation_unknown",
                format!("no revision {}", appraised.compose_hash),
            )
        })?;
    if revision.revoked_at.is_some() {
        return Err(ApiError::new("revision_revoked", "revision is revoked"));
    }
    verify_revision(
        &node.pool,
        &keys.tenant_kek_root,
        appraised.compose_hash,
        &revision,
    )
    .await?;
    let runtime_sha_hex = appraised
        .runtime_pubkey_sha256
        .trim_start_matches("sha256:")
        .to_owned();
    let leaf_der = certs::issue_leaf(
        &keys.ca_key(),
        &keys.ca_cert_der,
        spki,
        certs::instance_sans(
            revision.org_id.into(),
            revision.app_id.into(),
            &runtime_sha_hex,
            appraised.compose_hash,
        ),
        now,
    )?;
    let result = AttestationResult {
        format: RESULT_FORMAT.into(),
        verdict: Verdict::Verified,
        measured: appraised.measured,
        tcb_status: appraised.tcb_status,
        advisories: appraised.advisories,
        os_image: appraised.os_image,
        revision: Revision {
            compose_hash: appraised.compose_hash,
            app_id: revision.app_id.into(),
            org_id: revision.org_id.into(),
        },
        runtime_pubkey_sha256: appraised.runtime_pubkey_sha256,
        evidence_sha256: appraised.evidence_sha256,
        verified_at: DateTime::<Utc>::from(now).to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        policy_version: appraised.policy_version,
    };
    Ok(Attested {
        leaf_der,
        ca_pem: keys.ca_pem(),
        not_after: (now + certs::LEAF_TTL).into(),
        result,
    })
}

pub async fn get_secret(
    State(node): State<Arc<Node>>,
    Path(name): Path<String>,
    Extension(peer): Extension<PeerCerts>,
) -> Result<Json<Value>, ApiError> {
    let keys = node.intermediates()?;
    let verifier = certs::ca_verifier(&keys.ca_cert_der);
    let sans = certs::verify_to_ca(verifier.as_ref(), &peer.0, node.now())?;
    let identity = certs::parse_instance_sans(&sans)?;
    let result = get_secret_inner(&node, &keys.tenant_kek_root, &identity, &name).await;
    let (outcome, details) = match &result {
        Ok(_) => ("ok", json!({})),
        Err(e) => (e.outcome(), e.details()),
    };
    Audit {
        actor_kind: "instance",
        actor: &identity.runtime_pubkey_sha256_hex,
        action: "secret.get",
        org_id: Some(identity.org_id.into()),
        object: Some(format!("secret:{name}")),
        outcome,
        details,
        evidence_sha256: None,
    }
    .insert(&node.pool)
    .await?;
    result.map(Json)
}

async fn get_secret_inner(
    node: &Node,
    tenant_kek_root: &[u8; 32],
    identity: &certs::InstanceIdentity,
    name: &str,
) -> Result<Value, ApiError> {
    let revision = load_revision(&node.pool, identity.compose_hash)
        .await?
        .filter(|r| {
            r.org_id == Uuid::from(identity.org_id) && r.app_id == Uuid::from(identity.app_id)
        })
        .ok_or_else(|| ApiError::not_found("no such revision"))?;
    if revision.revoked_at.is_some() {
        return Err(ApiError::new("revision_revoked", "revision is revoked"));
    }
    verify_revision(
        &node.pool,
        tenant_kek_root,
        identity.compose_hash,
        &revision,
    )
    .await?;
    let secret = sqlx::query!(
        "select id, ciphertext, content_sha256, document, signed_by_key, signature, issued_at
         from secrets where org_id = $1 and name = $2 and $3 = any(app_ids)",
        Uuid::from(identity.org_id),
        name,
        Uuid::from(identity.app_id),
    )
    .fetch_optional(&node.pool)
    .await?
    .ok_or_else(|| ApiError::not_found("no such secret for this app"))?;
    let signature: SignatureObject = serde_json::from_value(secret.signature)
        .map_err(|_| ApiError::signature_invalid("secret signature object"))?;
    if Uuid::from(signature.key_id) != secret.signed_by_key {
        return Err(ApiError::signature_invalid("secret signer does not match"));
    }
    let chain = keys::verify_signed(
        &node.pool,
        tenant_kek_root,
        &signature,
        context::SECRET,
        &secret.document,
        secret.issued_at,
    )
    .await?;
    if chain.key.org_id != Uuid::from(identity.org_id) {
        return Err(ApiError::signature_invalid(
            "secret signer is not of its organization",
        ));
    }
    let org_key = keys::org_key(tenant_kek_root, identity.org_id, &chain.anchor_spki);
    let value = keys::aead_open(&org_key, secret.id.as_bytes(), &secret.ciphertext)
        .ok_or_else(|| ApiError::internal("secret does not decrypt under org_key"))?;
    Ok(json!({
        "value": BASE64_URL_SAFE_NO_PAD.encode(&*value),
        "content_sha256": format!("sha256:{}", hex::encode(secret.content_sha256)),
        "issued_at": secret.issued_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_is_hmac_bound_and_expires() {
        let key = [4u8; 32];
        let t0 = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let nonce = mint_nonce(&key, t0);
        assert!(check_nonce(&key, &nonce, t0).is_ok());
        assert!(check_nonce(&key, &nonce, t0 + Duration::from_secs(299)).is_ok());
        assert_eq!(
            check_nonce(&key, &nonce, t0 + Duration::from_secs(301))
                .unwrap_err()
                .code,
            "nonce_invalid"
        );
        assert!(check_nonce(&key, &nonce, t0 - Duration::from_secs(1)).is_err());
        assert!(check_nonce(&[5u8; 32], &nonce, t0).is_err());
        let mut flipped = nonce;
        flipped[31] ^= 1;
        assert!(check_nonce(&key, &flipped, t0).is_err());
        assert_ne!(
            mint_nonce(&key, t0),
            mint_nonce(&key, t0 + Duration::from_secs(1))
        );
    }
}
