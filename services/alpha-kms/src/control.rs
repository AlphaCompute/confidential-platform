//! The Control API: five mutations, each `{payload, signature}`, the organization taken from the key,
//! idempotent as the table says, one transaction with its audit row.

use std::sync::Arc;

use alpha_core::{AppId, ComposeHash, KeyId, PrincipalId, SecretId, context};
use axum::Json;
use axum::extract::{Path, State};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::pkcs8::DecodePublicKey;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::PgTransaction;
use uuid::Uuid;

use crate::audit::Audit;
use crate::body::Body;
use crate::error::ApiError;
use crate::instance::load_revision;
use crate::keys::{self, Chain, SignatureObject};
use crate::{Intermediates, Node};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signed {
    pub payload: Value,
    pub signature: SignatureObject,
    #[serde(default)]
    pub value: Option<String>,
}

const ISSUED_AT_WINDOW: Duration = Duration::minutes(5);

fn within_window(at: DateTime<Utc>, now: DateTime<Utc>) -> Result<DateTime<Utc>, ApiError> {
    if (at - now).abs() > ISSUED_AT_WINDOW {
        return Err(ApiError::malformed("issued_at is outside ±5 minutes"));
    }
    Ok(at)
}

fn payload<T: serde::de::DeserializeOwned>(value: &Value) -> Result<T, ApiError> {
    serde_json::from_value(value.clone()).map_err(|e| ApiError::malformed(format!("payload: {e}")))
}

/// The signer must be active with a chain to the anchor; the signature covers `payload`.
async fn authorize(
    node: &Node,
    keys: &Intermediates,
    ctx: &str,
    body: &Signed,
    signed_at: DateTime<Utc>,
) -> Result<Chain, ApiError> {
    let chain = keys::verify_signed(
        &node.pool,
        &keys.tenant_kek_root,
        &body.signature,
        ctx,
        &body.payload,
        signed_at,
    )
    .await?;
    if chain.key.revoked_at.is_some() {
        return Err(ApiError::signature_invalid("signing key is revoked"));
    }
    Ok(chain)
}

async fn audited(
    tx: &mut PgTransaction<'_>,
    chain: &Chain,
    action: &str,
    object: String,
    details: Value,
) -> Result<(), ApiError> {
    Audit {
        actor_kind: "principal",
        actor: &chain.key.id.to_string(),
        action,
        org_id: Some(chain.key.org_id),
        object: Some(object),
        outcome: "ok",
        details,
        evidence_sha256: None,
    }
    .insert(&mut **tx)
    .await?;
    Ok(())
}

async fn denied(node: &Node, key_id: KeyId, action: &str, error: &ApiError) {
    let _ = Audit {
        actor_kind: "principal",
        actor: &key_id.to_string(),
        action,
        org_id: None,
        object: None,
        outcome: error.outcome(),
        details: error.details(),
        evidence_sha256: None,
    }
    .insert(&node.pool)
    .await;
}

fn rfc3339(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

macro_rules! audited_route {
    ($node:expr, $body:expr, $action:literal, $inner:expr) => {{
        let result = $inner.await;
        if let Err(e) = &result {
            denied(&$node, $body.signature.key_id, $action, e).await;
        }
        result.map(Json)
    }};
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RevisionPayload {
    app_id: AppId,
    compose: String,
}

pub async fn register_revision(
    State(node): State<Arc<Node>>,
    Body(body): Body<Signed>,
) -> Result<Json<Value>, ApiError> {
    audited_route!(node, body, "revision.register", async {
        if body.value.is_some() {
            return Err(ApiError::malformed("unexpected field value"));
        }
        let keys = node.intermediates()?;
        let p: RevisionPayload = payload(&body.payload)?;
        let compose_hash = alpha_core::check_registration(&p.compose, p.app_id)?;
        let chain = authorize(&node, &keys, context::REVISION, &body, node.now_utc()).await?;
        let org_id = chain.key.org_id;
        let mut tx = node.pool.begin().await?;
        if let Some(existing) = load_revision(&mut *tx, compose_hash).await? {
            if existing.org_id != org_id {
                return Err(ApiError::not_found("no such revision"));
            }
            return Ok(revision_json(
                compose_hash,
                existing.app_id,
                org_id,
                existing.created_at,
            ));
        }
        let other_org = sqlx::query_scalar!(
            "select exists(select 1 from revisions where app_id = $1 and org_id <> $2)",
            Uuid::from(p.app_id),
            org_id
        )
        .fetch_one(&mut *tx)
        .await?;
        if other_org.unwrap_or(false) {
            return Err(ApiError::not_found("app belongs to another organization"));
        }
        let created_at = sqlx::query_scalar!(
            "insert into revisions (compose_hash, app_id, org_id, compose, created_by_key, signature)
             values ($1, $2, $3, $4, $5, $6) returning created_at",
            compose_hash.as_bytes().as_slice(),
            Uuid::from(p.app_id),
            org_id,
            p.compose,
            chain.key.id,
            json!(body.signature),
        )
        .fetch_one(&mut *tx)
        .await?;
        audited(
            &mut tx,
            &chain,
            "revision.register",
            format!("revision:{compose_hash}"),
            json!({ "app_id": p.app_id }),
        )
        .await?;
        tx.commit().await?;
        Ok(revision_json(
            compose_hash,
            p.app_id.into(),
            org_id,
            created_at,
        ))
    })
}

fn revision_json(
    hash: ComposeHash,
    app_id: Uuid,
    org_id: Uuid,
    created_at: DateTime<Utc>,
) -> Value {
    json!({
        "compose_hash": hash,
        "app_id": app_id,
        "org_id": org_id,
        "created_at": rfc3339(created_at),
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RevokeRevisionPayload {
    compose_hash: ComposeHash,
    issued_at: DateTime<Utc>,
}

pub async fn revoke_revision(
    State(node): State<Arc<Node>>,
    Path(path_hash): Path<String>,
    Body(body): Body<Signed>,
) -> Result<Json<Value>, ApiError> {
    audited_route!(node, body, "revision.revoke", async {
        if body.value.is_some() {
            return Err(ApiError::malformed("unexpected field value"));
        }
        let keys = node.intermediates()?;
        let p: RevokeRevisionPayload = payload(&body.payload)?;
        if path_hash != p.compose_hash.to_string() {
            return Err(ApiError::malformed("path and payload compose_hash differ"));
        }
        let at = within_window(p.issued_at, node.now_utc())?;
        let chain = authorize(&node, &keys, context::CONTROL, &body, at).await?;
        let mut tx = node.pool.begin().await?;
        let revision = load_revision(&mut *tx, p.compose_hash)
            .await?
            .filter(|r| r.org_id == chain.key.org_id)
            .ok_or_else(|| ApiError::not_found("no such revision"))?;
        let revoked_at = match revision.revoked_at {
            Some(t) => t,
            None => {
                let t = sqlx::query_scalar!(
                    "update revisions set revoked_at = now() where compose_hash = $1 returning revoked_at",
                    p.compose_hash.as_bytes().as_slice()
                )
                .fetch_one(&mut *tx)
                .await?
                .expect("just set");
                audited(
                    &mut tx,
                    &chain,
                    "revision.revoke",
                    format!("revision:{}", p.compose_hash),
                    json!({}),
                )
                .await?;
                t
            }
        };
        tx.commit().await?;
        Ok(json!({ "compose_hash": p.compose_hash, "revoked_at": rfc3339(revoked_at) }))
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretPayload {
    name: String,
    app_ids: Vec<AppId>,
    content_sha256: String,
    issued_at: DateTime<Utc>,
}

pub async fn put_secret(
    State(node): State<Arc<Node>>,
    Path(name): Path<String>,
    Body(body): Body<Signed>,
) -> Result<Json<Value>, ApiError> {
    audited_route!(node, body, "secret.put", async {
        let keys = node.intermediates()?;
        let p: SecretPayload = payload(&body.payload)?;
        if p.name != name {
            return Err(ApiError::malformed("path and payload name differ"));
        }
        if p.app_ids.is_empty() {
            return Err(ApiError::malformed("app_ids is empty"));
        }
        let value = body
            .value
            .as_deref()
            .and_then(|v| BASE64_URL_SAFE_NO_PAD.decode(v).ok())
            .ok_or_else(|| ApiError::malformed("value: expected base64url"))?;
        let content_sha256: [u8; 32] = p
            .content_sha256
            .strip_prefix("sha256:")
            .and_then(alpha_core::hex_bytes)
            .ok_or_else(|| ApiError::malformed("content_sha256: expected sha256:<hex>"))?;
        if Sha256::digest(&value).as_slice() != content_sha256 {
            return Err(ApiError::malformed("content_sha256 does not match value"));
        }
        let at = within_window(p.issued_at, node.now_utc())?;
        let chain = authorize(&node, &keys, context::SECRET, &body, at).await?;
        let org_id = chain.key.org_id;
        let app_ids: Vec<Uuid> = p.app_ids.iter().map(|a| Uuid::from(*a)).collect();
        let mut tx = node.pool.begin().await?;
        let foreign = sqlx::query_scalar!(
            "select exists(select 1 from revisions where app_id = any($1) and org_id <> $2)",
            &app_ids,
            org_id
        )
        .fetch_one(&mut *tx)
        .await?;
        if foreign.unwrap_or(false) {
            return Err(ApiError::not_found(
                "an app belongs to another organization",
            ));
        }
        let existing = sqlx::query!(
            "select id, issued_at from secrets where org_id = $1 and name = $2 for update",
            org_id,
            name
        )
        .fetch_optional(&mut *tx)
        .await?;
        let id = match &existing {
            Some(row) if row.issued_at >= at => {
                return Err(ApiError::new(
                    "already_exists",
                    "a put with a later issued_at is stored",
                ));
            }
            Some(row) => row.id,
            None => SecretId::mint().into(),
        };
        let org_key = keys::org_key(&keys.tenant_kek_root, org_id.into(), &chain.anchor_spki);
        let ciphertext = keys::aead_seal(&org_key, id.as_bytes(), &value);
        sqlx::query!(
            "insert into secrets (id, org_id, name, app_ids, ciphertext, content_sha256, document, signed_by_key, signature, issued_at)
             values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
             on conflict (org_id, name) do update set app_ids = $4, ciphertext = $5, content_sha256 = $6,
               document = $7, signed_by_key = $8, signature = $9, issued_at = $10",
            id,
            org_id,
            name,
            &app_ids,
            ciphertext,
            content_sha256.as_slice(),
            body.payload,
            chain.key.id,
            json!(body.signature),
            at,
        )
        .execute(&mut *tx)
        .await?;
        audited(
            &mut tx,
            &chain,
            "secret.put",
            format!("secret:{name}"),
            json!({ "app_ids": app_ids }),
        )
        .await?;
        tx.commit().await?;
        Ok(json!({
            "id": id, "name": name, "app_ids": app_ids,
            "content_sha256": p.content_sha256, "issued_at": rfc3339(at),
        }))
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyPayload {
    principal_id: PrincipalId,
    public_key: String,
    #[allow(dead_code)]
    label: String,
    issued_at: DateTime<Utc>,
}

pub async fn register_key(
    State(node): State<Arc<Node>>,
    Body(body): Body<Signed>,
) -> Result<Json<Value>, ApiError> {
    audited_route!(node, body, "key.register", async {
        if body.value.is_some() {
            return Err(ApiError::malformed("unexpected field value"));
        }
        let keys = node.intermediates()?;
        let p: KeyPayload = payload(&body.payload)?;
        let spki = BASE64_URL_SAFE_NO_PAD
            .decode(&p.public_key)
            .map_err(|_| ApiError::malformed("public_key: not base64url"))?;
        ed25519_dalek::VerifyingKey::from_public_key_der(&spki)
            .map_err(|_| ApiError::malformed("public_key: not an Ed25519 SPKI"))?;
        let at = within_window(p.issued_at, node.now_utc())?;
        let chain = authorize(&node, &keys, context::PRINCIPAL_KEY, &body, at).await?;
        let id: Uuid = KeyId::mint().into();
        let mut tx = node.pool.begin().await?;
        let inserted = sqlx::query_scalar!(
            "insert into principal_keys (id, org_id, principal_id, public_key, document, registered_by_key, signature)
             values ($1, $2, $3, $4, $5, $6, $7) returning created_at",
            id,
            chain.key.org_id,
            Uuid::from(p.principal_id),
            spki,
            body.payload,
            chain.key.id,
            json!(body.signature),
        )
        .fetch_one(&mut *tx)
        .await;
        let created_at = match inserted {
            Ok(t) => t,
            Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
                return Err(ApiError::new(
                    "already_exists",
                    "public_key is already registered",
                ));
            }
            Err(e) => return Err(e.into()),
        };
        audited(
            &mut tx,
            &chain,
            "key.register",
            format!("key:{id}"),
            json!({ "principal_id": p.principal_id }),
        )
        .await?;
        tx.commit().await?;
        Ok(json!({
            "id": id, "principal_id": p.principal_id, "org_id": chain.key.org_id,
            "created_at": rfc3339(created_at),
        }))
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RevokeKeyPayload {
    key_id: KeyId,
    reason: String,
    issued_at: DateTime<Utc>,
}

pub async fn revoke_key(
    State(node): State<Arc<Node>>,
    Path(path_id): Path<String>,
    Body(body): Body<Signed>,
) -> Result<Json<Value>, ApiError> {
    audited_route!(node, body, "key.revoke", async {
        if body.value.is_some() {
            return Err(ApiError::malformed("unexpected field value"));
        }
        let keys = node.intermediates()?;
        let p: RevokeKeyPayload = payload(&body.payload)?;
        if path_id != p.key_id.to_string() {
            return Err(ApiError::malformed("path and payload key_id differ"));
        }
        if !matches!(p.reason.as_str(), "retired" | "compromised") {
            return Err(ApiError::malformed(
                "reason: expected retired or compromised",
            ));
        }
        let at = within_window(p.issued_at, node.now_utc())?;
        let chain = authorize(&node, &keys, context::CONTROL, &body, at).await?;
        let mut tx = node.pool.begin().await?;
        let target = keys::load_key(&mut *tx, p.key_id.into())
            .await?
            .filter(|k| k.org_id == chain.key.org_id)
            .ok_or_else(|| ApiError::not_found("no such key"))?;
        let (revoked_at, reason) = match (target.revoked_at, target.revocation_reason) {
            (Some(t), Some(reason)) => (t, reason),
            _ => {
                let t = sqlx::query_scalar!(
                    "update principal_keys set revoked_at = now(), revocation_reason = $2::principal_key_revocation
                     where id = $1 returning revoked_at",
                    target.id,
                    p.reason as _,
                )
                .fetch_one(&mut *tx)
                .await?
                .expect("just set");
                audited(
                    &mut tx,
                    &chain,
                    "key.revoke",
                    format!("key:{}", target.id),
                    json!({ "reason": p.reason }),
                )
                .await?;
                (t, p.reason.clone())
            }
        };
        tx.commit().await?;
        Ok(json!({ "key_id": target.id, "revoked_at": rfc3339(revoked_at), "reason": reason }))
    })
}
