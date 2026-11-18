//! `POST /v1/tickets/{ticket}/kms/{op}`: carries a body a roster key signed to the KMS and back.
//! The relay can drop a body, never change one, and it records a step only after the KMS receipt
//! for exactly that body verifies under the platform document's KMS CA. A ticket drives each
//! state-changing op once, and only while it is open.

use std::sync::Arc;

use alpha_attest::PlatformDocument;
use alpha_channel::receipt::{self, Expected};
use alpha_client::{Client, Pin, Signed};
use alpha_core::ComposeHash;
use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use data_encoding::BASE64URL_NOPAD;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::tickets;
use crate::{AppState, Error, platform, stale};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyBody {
    credential_id: String,
    registration: Value,
}

/// A `claim` ticket's `root` makes the owner's passkey the Organization's first key; its `key`
/// adds one that a key already in the roster signed.
pub async fn relay(
    State(state): State<Arc<AppState>>,
    Path((ticket, op)): Path<(String, String)>,
    headers: HeaderMap,
    body: Result<Json<KeyBody>, JsonRejection>,
) -> Result<Json<Value>, Error> {
    let Json(KeyBody {
        credential_id,
        registration,
    }) = body?;
    // Refused cheaply before the platform document is fetched: anyone can reach this route.
    if !matches!(op.as_str(), "root" | "key") {
        return Err(Error::Forbidden);
    }
    let early = tickets::usable(&mut state.pool.begin().await?, &ticket).await?;
    if early.kind != "claim" || early.disabled {
        return Err(Error::Forbidden);
    }
    // Fetched before the transaction, so a relay never holds one pool connection while it waits
    // for another.
    let (version, document) = platform(&state).await?;
    // ponytail: the ticket and Organization rows stay locked across the KMS call, up to 60 s per
    // endpoint, so a step and a disable of one Organization wait for each other that long. The
    // upgrade is a ticket state `sending` committed before the call and settled after it.
    // The row stays locked until the step is recorded, so two relays of one op cannot both run.
    let mut tx = state.pool.begin().await?;
    let found = tickets::usable(&mut tx, &ticket).await?;
    if found.disabled {
        return Err(Error::Forbidden);
    }
    if found.used.contains(&op) {
        return Err(Error::TicketClosed);
    }
    if found.kind != "claim" {
        return Err(Error::Forbidden);
    }
    if credential_id.is_empty()
        || credential_id.len() > 1024
        || BASE64URL_NOPAD.decode(credential_id.as_bytes()).is_err()
    {
        return Err(Error::Malformed("credential_id is not base64url".into()));
    }
    let signed = Signed::deserialize(&registration)
        .map_err(|e| Error::Malformed(format!("registration: {e}")))?;
    let org_id = found.org_id;
    let mut expected = Map::new();
    expected.insert("org_id".into(), json!(org_id));
    if op == "root" {
        // A ticket alone never roots: the owner's sign-in must stand behind this very request.
        let presented = headers
            .get("alpha-claim-session")
            .map(|v| Sha256::digest(v.as_bytes()));
        let bound = matches!((presented, &found.session_sha256), (Some(p), Some(s))
            if alpha_client::bearer_matches(&p, s));
        if !bound || found.rooted {
            return Err(Error::SessionRefused);
        }
        if signed.signature.key_id.is_some()
            || signed.payload.get("org_id") != Some(&json!(org_id))
            || signed.payload.get("principal_id") != found.owner.map(|o| json!(o)).as_ref()
        {
            return Err(Error::Malformed(
                "a root registration is self-signed for this Organization and its owner".into(),
            ));
        }
        let public_key = signed
            .payload
            .get("public_key")
            .cloned()
            .unwrap_or_default();
        expected.insert("public_key".into(), public_key);
        // The KMS answers a repeated key with its stored row, which may name another holder.
        expected.insert("principal_id".into(), json!(found.owner));
    } else if signed.signature.key_id.is_none()
        || signed.payload.get("principal_id") != found.principal_id.map(|p| json!(p)).as_ref()
    {
        // Without a signer in the roster the KMS would take it as a root claim; and the key is
        // the one of the holder the ticket names.
        return Err(Error::Forbidden);
    }
    // The KMS answers a repeated root for the same key with its stored row and a new receipt,
    // so a root checks the version after the reply and a retry after `stale` still records it.
    // A repeated other key is `already_exists`, so a key checks the version before the call.
    if op == "key" {
        current(&mut tx, version).await?;
        // The version lock may have waited past the ticket's expiry.
        let open: bool = sqlx::query_scalar(
            "select expires_at > clock_timestamp() from tickets where ticket = $1",
        )
        .bind(&ticket)
        .fetch_one(&mut *tx)
        .await?;
        if !open {
            return Err(Error::TicketExpired);
        }
    }
    let reply = kms(&state, &document, "/v1/keys", &registration).await?;
    let response = confirm(&document, "key.register", &registration, expected, &reply)?;
    if op == "root" {
        current(&mut tx, version).await?;
    }
    let key_id: Uuid = response
        .get("id")
        .and_then(|id| Uuid::deserialize(id).ok())
        .filter(|id| reply.get("id") == Some(&json!(id)))
        .ok_or(Error::UpstreamInvalid)?;
    sqlx::query(
        "insert into credentials (key_id, org_id, credential_id) values ($1, $2, $3) \
         on conflict (key_id) do nothing",
    )
    .bind(key_id)
    .bind(org_id)
    .bind(&credential_id)
    .execute(&mut *tx)
    .await?;
    if op == "root" {
        sqlx::query("update organizations set rooted_at = now() where id = $1")
            .bind(org_id)
            .execute(&mut *tx)
            .await?;
        // The owner may add one more key on this ticket, as the holder it now names.
        sqlx::query("update tickets set principal_id = $1 where ticket = $2")
            .bind(found.owner)
            .bind(&ticket)
            .execute(&mut *tx)
            .await?;
    }
    // A claim ends with the key it adds; after a root the owner may still add one.
    sqlx::query(
        "update tickets set used = array_append(used, $1), \
         state = case when $1 = 'key' then 'done' else state end where ticket = $2",
    )
    .bind(&op)
    .bind(&ticket)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "insert into audit_log (actor, org_id, action, object) values ('ticket', $1, $2, $3)",
    )
    .bind(org_id)
    .bind(format!("relay.{op}"))
    .bind(key_id.to_string())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(reply))
}

/// Refuses a step checked under a document older than the accepted one. The share lock holds to
/// the commit, so no newer version is accepted before the step is recorded.
async fn current(tx: &mut Transaction<'_, Postgres>, version: i64) -> Result<(), Error> {
    let accepted: i64 =
        sqlx::query_scalar("select version from platform_version where one = 1 for share")
            .fetch_one(&mut **tx)
            .await?;
    if version < accepted {
        return Err(stale(version, accepted));
    }
    Ok(())
}

fn kms_revisions(document: &PlatformDocument) -> Vec<ComposeHash> {
    document
        .kms_revisions
        .iter()
        .map(|r| r.compose_hash)
        .collect()
}

/// One KMS call, pinned to the document's CA and KMS builds. A KMS refusal keeps its code.
async fn kms(
    state: &AppState,
    document: &PlatformDocument,
    path: &str,
    body: &Value,
) -> Result<Value, Error> {
    // The error text names the endpoint, so the caller gets a fixed message and the log the kind.
    let unavailable = |e: alpha_client::Error| {
        alpha_client::warn!("kms_unavailable", error = e.kind());
        Error::Unavailable("the KMS is unavailable".into())
    };
    let ca = alpha_client::tls::cert_from_pem(&document.kms_ca_pem).map_err(unavailable)?;
    let pin = Pin::CaAndRevisions(ca, kms_revisions(document));
    let client = Client::new(state.kms_endpoints.clone(), pin).map_err(unavailable)?;
    client
        .request(reqwest::Method::POST, path, Some(body))
        .await
        .map_err(|e| match &e {
            alpha_client::Error::Api(api) => Error::Kms {
                status: StatusCode::from_u16(api.status).unwrap_or(StatusCode::BAD_GATEWAY),
                code: e.kind(),
            },
            _ => unavailable(e),
        })
}

/// The response the receipt signs for `request` at `route`, if it carries every `expected` value.
fn confirm(
    document: &PlatformDocument,
    route: &str,
    request: &Value,
    expected: Map<String, Value>,
    reply: &Value,
) -> Result<Value, Error> {
    let receipt = reply.get("receipt").ok_or(Error::UpstreamInvalid)?;
    let expected = Expected {
        route: route.into(),
        request_sha256: receipt::request_sha256(request).map_err(|_| Error::UpstreamInvalid)?,
        response: expected,
    };
    let receipt = serde_json::to_vec(receipt).map_err(|_| Error::UpstreamInvalid)?;
    receipt::verify(
        &receipt,
        &document.kms_ca_pem,
        &kms_revisions(document),
        &expected,
    )
    .map_err(|_| Error::UpstreamInvalid)
}
