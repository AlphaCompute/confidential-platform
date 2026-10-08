//! A demonstration tenant: an App that proves to a caller it runs as an attested Instance holding
//! its App's key, derived by the KMS for purpose `hmac`, without ever disclosing the key.
//! `/healthz` names the Instance and says whether the key was obtained right now; `/v1/hmac` uses
//! it as an HMAC-SHA256 key. The key is read from the runtime socket on every request and never
//! kept, logged or returned.

#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )
)]

use std::sync::Arc;

use alpha_client::runtime::{RuntimeIdentity, RuntimeSocket};
use alpha_core::{AppId, ComposeHash, OrgId};
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use hmac::{Hmac, KeyInit, Mac};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::Sha256;
use zeroize::Zeroizing;

pub const KEY_PURPOSE: &str = "hmac";
const MAX_BODY_BYTES: usize = 64 * 1024;

pub struct AppState {
    runtime: RuntimeSocket,
    org_id: OrgId,
    app_id: AppId,
    compose_hash: ComposeHash,
}

impl AppState {
    pub fn new(runtime: RuntimeSocket, identity: &RuntimeIdentity) -> Self {
        Self {
            runtime,
            org_id: identity.org_id,
            app_id: identity.app_id,
            compose_hash: identity.compose_hash,
        }
    }

    /// Any failure is the same answer to the caller: the key is not available to this Instance
    /// now, whether the runtime is gone or the KMS refused.
    async fn key(&self) -> Result<Zeroizing<[u8; 32]>, StatusCode> {
        self.runtime
            .key(KEY_PURPOSE)
            .await
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
    }
}

#[derive(Deserialize)]
struct Challenge {
    challenge: Option<String>,
}

/// Echoes the caller's `challenge`, so an answer cannot be one recorded earlier. The three
/// constant fields are the contract a deploy orchestrator's readiness check reads: it judges
/// the body, not the status.
async fn health(
    State(state): State<Arc<AppState>>,
    Query(query): Query<Challenge>,
) -> Result<Json<Value>, StatusCode> {
    state.key().await?;
    Ok(Json(json!({
        "schema_version": 1,
        "ready": true,
        "secret_access": true,
        "org_id": state.org_id,
        "app_id": state.app_id,
        "compose_hash": state.compose_hash,
        "challenge": query.challenge,
    })))
}

async fn hmac_sha256(
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Result<Json<Value>, StatusCode> {
    let key = state.key().await?;
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_slice())
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    mac.update(&body);
    Ok(Json(
        json!({ "hmac_sha256": hex::encode(mac.finalize().into_bytes()) }),
    ))
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route("/v1/hmac", post(hmac_sha256))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}
