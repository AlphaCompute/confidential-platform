//! PRD-06 P1 "Evidence to the customer", the Alpha side (draft): an organization reads the KMS's
//! own decisions about its Instances — every attestation, Secret release and key derivation the
//! KMS recorded for it, granted or refused — directly, under its own signing key, with the node's
//! receipt over the whole answer.
//!
//! `POST /v1/decisions/export`, body `{payload, signature}` signed under
//! [`context::DECISIONS_EXPORT`] by any active key of the organization. Payload
//! `{after_seq, limit, issued_at}`: the rows after audit sequence number `after_seq`, at most
//! `limit` (1 to [`MAX_ROWS`]), in sequence order. The answer echoes the request, so the receipt
//! alone lets an auditor check it offline (`alpha_client::decisions::verify`).
//!
//! The Fortanix side (CCM attestation records, DSM key-release logs) is the customer's own
//! account and is read there, not through here: `docs/customer-evidence.md`.
//!
//! What the export cannot prove yet:
//! - TODO(draft): completeness. The receipt proves the KMS returned these rows, not that it
//!   returned every row; that needs the hash-chained audit log (confidential-platform #95) and a
//!   chain head in the receipt. QUESTION(PRD-06 Q89).
//! - TODO(draft): refusals the KMS could not attribute. A failed attestation, or a refused
//!   Control call, is recorded with no organization (the KMS never learned whose it was), so it is
//!   not in any organization's export. QUESTION(PRD-06 Q89).

use std::sync::Arc;

use alpha_core::context;
use axum::Json;
use axum::extract::State;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::audit::Audit;
use crate::body::Body;
use crate::control::{Signed, authorize, denied, payload, receipted, within_window};
use crate::error::ApiError;
use crate::{Node, rfc3339};

pub const FORMAT: &str = "alphacompute-kms-decisions/1";
pub const MAX_ROWS: i64 = 500;
/// The audit action of an export, and its receipt's route.
pub const ACTION: &str = alpha_channel::receipt::DECISIONS_EXPORT_ROUTE;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportPayload {
    after_seq: i64,
    limit: i64,
    issued_at: DateTime<Utc>,
}

pub async fn export(
    State(node): State<Arc<Node>>,
    Body(body, request): Body<Signed>,
) -> Result<Json<Value>, ApiError> {
    let result = export_inner(&node, &body, &request).await;
    if let Err(e) = &result {
        denied(&node, body.signature.key_id, ACTION, e).await;
    }
    result
        .and_then(|response| receipted(&node, ACTION, &request, response))
        .map(Json)
}

async fn export_inner(node: &Node, body: &Signed, request: &Value) -> Result<Value, ApiError> {
    let keys = node.intermediates()?;
    let p: ExportPayload = payload(&body.payload)?;
    if p.after_seq < 0 {
        return Err(ApiError::malformed("after_seq: must be 0 or more"));
    }
    if !(1..=MAX_ROWS).contains(&p.limit) {
        return Err(ApiError::malformed(format!("limit: 1 to {MAX_ROWS}")));
    }
    let at = within_window(p.issued_at, node.now_utc())?;
    // QUESTION(PRD-06 Q88): any active key of the organization may read its decisions. A
    // read-only auditor key kind (so a customer's auditor holds no key that can register a
    // Revision or put a Secret) is not built.
    let chain = authorize(node, &keys, context::DECISIONS_EXPORT, body, at).await?;
    let org_id: Uuid = chain.key.org_id;
    let fetch = p
        .limit
        .checked_add(1)
        .ok_or_else(|| ApiError::malformed("limit"))?;
    // QUESTION(PRD-06 Q87): which actions are "decisions". Today: the Instance API's three, and
    // earlier exports. The organization's own Control calls are in the audit log too and could
    // be added.
    let rows = sqlx::query!(
        "select seq, ts, actor_kind, actor, action, object, outcome, details, evidence_sha256
         from audit_log
         where org_id = $1 and seq > $2
           and action in ('attest', 'secret.get', 'key.derive', 'decisions.export')
         order by seq
         limit $3",
        org_id,
        p.after_seq,
        fetch,
    )
    .fetch_all(&node.pool)
    .await?;
    let limit = usize::try_from(p.limit).map_err(|_| ApiError::malformed("limit"))?;
    let more = rows.len() > limit;
    let rows: Vec<Value> = rows
        .into_iter()
        .take(limit)
        .map(|r| {
            json!({
                "seq": r.seq,
                "ts": rfc3339(r.ts),
                "actor_kind": r.actor_kind,
                "actor": r.actor,
                "action": r.action,
                "object": r.object,
                "outcome": r.outcome,
                "details": r.details,
                "evidence_sha256": r.evidence_sha256.map(|h| format!("sha256:{}", hex::encode(h))),
            })
        })
        .collect();
    let next_after_seq = rows
        .last()
        .and_then(|r| r.get("seq"))
        .and_then(Value::as_i64)
        .unwrap_or(p.after_seq);
    // Reading the record is itself recorded, so the organization sees every export of it.
    Audit {
        actor_kind: "principal",
        actor: &chain.key.id.to_string(),
        action: ACTION,
        org_id: Some(org_id),
        object: None,
        outcome: "ok",
        details: json!({ "after_seq": p.after_seq, "rows": rows.len() }),
        evidence_sha256: None,
    }
    .insert(&node.pool)
    .await?;
    Ok(json!({
        "format": FORMAT,
        "org_id": org_id,
        "request": request,
        "rows": rows,
        "next_after_seq": next_after_seq,
        "more": more,
    }))
}
