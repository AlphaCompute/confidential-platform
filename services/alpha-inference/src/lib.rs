//! The platform's inference front: an App of its own, whose provider is RedPill. Every
//! `/v1` route forwards to RedPill only after `upstream::Upstream::verified` has proven, in
//! this process's own measured code, that the connection it will forward over terminates
//! inside RedPill's attested gateway — never on a stale check, an error, or a caller without
//! its bearer.

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

pub mod upstream;

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, FromRequestParts, Path, State};
use axum::http::request::Parts;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub use upstream::Upstream;

const COMPLETIONS_BODY_LIMIT: usize = 16 * 1024 * 1024;

/// The four measured environment variables, read once at startup and never mutated.
#[derive(Clone, Debug)]
pub struct Config {
    /// RedPill's OpenAI-compatible base, `/v1` included, trailing slash trimmed.
    pub upstream_url: String,
    /// The allowlist, in order; the first is the default model.
    pub models: Vec<String>,
    pub pccs_url: String,
    pub upstream_policy: alpha_attest::Policy,
}

impl Config {
    pub fn from_env() -> Result<Self, Error> {
        Self::build(|name| std::env::var(name).ok())
    }

    /// Built from a lookup function rather than the process environment, so validation is
    /// testable without touching global state.
    pub fn build(get: impl Fn(&str) -> Option<String>) -> Result<Self, Error> {
        let upstream_url =
            get("UPSTREAM_URL").ok_or_else(|| Error::internal("UPSTREAM_URL is required"))?;
        if !upstream_url.starts_with("https://") {
            return Err(Error::internal("UPSTREAM_URL must be https"));
        }
        let models: Vec<String> = get("MODELS")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
        if models.is_empty() {
            return Err(Error::internal("MODELS names no model"));
        }
        let pccs_url = get("PCCS_URL").ok_or_else(|| Error::internal("PCCS_URL is required"))?;
        if !pccs_url.starts_with("https://") {
            return Err(Error::internal("PCCS_URL must be https"));
        }
        let policy_raw =
            get("UPSTREAM_POLICY").ok_or_else(|| Error::internal("UPSTREAM_POLICY is required"))?;
        let upstream_policy: alpha_attest::Policy = serde_json::from_str(&policy_raw)
            .map_err(|e| Error::internal(format!("UPSTREAM_POLICY: {e}")))?;
        if upstream_policy.tcb_statuses.is_empty() {
            return Err(Error::internal("UPSTREAM_POLICY names no tcb_status"));
        }
        Ok(Config {
            upstream_url: upstream_url.trim_end_matches('/').to_owned(),
            models,
            pccs_url: pccs_url.trim_end_matches('/').to_owned(),
            upstream_policy,
        })
    }

    pub fn default_model(&self) -> &str {
        self.models.first().map_or("", String::as_str)
    }

    pub fn allows(&self, model: &str) -> bool {
        self.models.iter().any(|m| m == model)
    }
}

/// Held only in zeroizing buffers; `Debug` never shows the bytes.
pub struct Secrets {
    pub provider_key: Zeroizing<String>,
    pub caller_bearer: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for Secrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Secrets")
            .field("provider_key", &"<redacted>")
            .field("caller_bearer", &"<redacted>")
            .finish()
    }
}

/// Everything the router and `main` share. `secrets` is behind a lock so a rotated bearer or
/// provider key takes effect without a restart.
pub struct AppState {
    pub config: Config,
    pub secrets: parking_lot::RwLock<Secrets>,
    pub upstream: Upstream,
}

/// Every error this service answers with, OpenAI-shaped on the wire. Messages never carry a
/// key or conversation text.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("missing or invalid bearer")]
    Unauthorized,
    #[error("model '{0}' is not available")]
    ModelNotFound(String),
    #[error("The model provider did not pass verification, so nothing was sent.")]
    UpstreamUnverified,
    #[error("the model provider could not be reached")]
    Upstream,
    #[error("{0}")]
    Internal(String),
}

impl Error {
    pub fn internal(message: impl Into<String>) -> Self {
        Error::Internal(message.into())
    }

    fn parts(&self) -> (StatusCode, &'static str, &'static str) {
        match self {
            Error::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "authentication_error",
                "unauthorized",
            ),
            Error::ModelNotFound(_) => (
                StatusCode::NOT_FOUND,
                "invalid_request_error",
                "model_not_found",
            ),
            Error::UpstreamUnverified => (
                StatusCode::BAD_GATEWAY,
                "upstream_error",
                "upstream_unverified",
            ),
            Error::Upstream => (StatusCode::BAD_GATEWAY, "upstream_error", "upstream"),
            Error::Internal(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "internal",
            ),
        }
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let (status, error_type, code) = self.parts();
        // Internal detail (paths, library error text) never reaches the wire; every other
        // variant's Display is wire-safe by construction.
        let message = match &self {
            Error::Internal(_) => "internal error".to_string(),
            other => other.to_string(),
        };
        let body = json!({ "error": { "message": message, "type": error_type, "code": code } });
        (status, Json(body)).into_response()
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn bearer_matches(presented: &[u8], expected: &[u8]) -> bool {
    constant_time_eq(
        Sha256::digest(presented).as_slice(),
        Sha256::digest(expected).as_slice(),
    )
}

/// Proof of the caller's bearer, extracted before any handler runs.
pub struct AuthedCaller;

impl FromRequestParts<Arc<AppState>> for AuthedCaller {
    type Rejection = Error;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let presented = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or(Error::Unauthorized)?;
        if bearer_matches(presented.as_bytes(), &state.secrets.read().caller_bearer) {
            Ok(AuthedCaller)
        } else {
            Err(Error::Unauthorized)
        }
    }
}

fn verify_error(outcome: upstream::VerifyOutcome, model: &str) -> Error {
    match outcome {
        upstream::VerifyOutcome::Unverified(_) => Error::UpstreamUnverified,
        upstream::VerifyOutcome::UnknownModel => {
            Error::internal(format!("{model} has no verification slot"))
        }
    }
}

async fn list_models(State(state): State<Arc<AppState>>, _: AuthedCaller) -> Json<Value> {
    let listed = state.upstream.list_models().await;
    let entries = listed
        .get("data")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let allowed: Vec<Value> = entries
        .into_iter()
        .filter(|m| {
            m.get("id")
                .and_then(Value::as_str)
                .is_some_and(|id| state.config.allows(id))
        })
        .collect();
    let data = if allowed.is_empty() {
        state
            .config
            .models
            .iter()
            .map(|id| json!({ "id": id, "object": "model" }))
            .collect()
    } else {
        allowed
    };
    Json(json!({ "object": "list", "data": data }))
}

async fn get_model(
    State(state): State<Arc<AppState>>,
    _: AuthedCaller,
    Path(model): Path<String>,
) -> Result<Json<Value>, Error> {
    if !state.config.allows(&model) {
        return Err(Error::ModelNotFound(model));
    }
    state
        .upstream
        .verified(&model)
        .await
        .map_err(|outcome| verify_error(outcome, &model))?;
    Ok(Json(
        json!({ "id": model, "object": "model", "owned_by": "redpill" }),
    ))
}

async fn chat_completions(
    State(state): State<Arc<AppState>>,
    _: AuthedCaller,
    body: Bytes,
) -> Result<Response, Error> {
    let parsed: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let model = parsed
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    if !state.config.allows(&model) {
        return Err(Error::ModelNotFound(model));
    }
    let client = state
        .upstream
        .verified(&model)
        .await
        .map_err(|outcome| verify_error(outcome, &model))?;

    let provider_key = state.secrets.read().provider_key.clone();
    let sent = client
        .post(format!("{}/chat/completions", state.config.upstream_url))
        .bearer_auth(provider_key.as_str())
        .header(header::CONTENT_TYPE, "application/json")
        .body(body)
        .send()
        .await;
    let upstream_response = match sent {
        Ok(response) => response,
        Err(_) => {
            state.upstream.forget(&model).await;
            return Err(Error::Upstream);
        }
    };
    let status = StatusCode::from_u16(upstream_response.status().as_u16())
        .unwrap_or(StatusCode::BAD_GATEWAY);
    let content_type = upstream_response
        .headers()
        .get(header::CONTENT_TYPE)
        .cloned()
        .unwrap_or_else(|| header::HeaderValue::from_static("text/event-stream"));
    let stream = upstream_response.bytes_stream();
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .body(axum::body::Body::from_stream(stream))
        .map_err(|e| Error::internal(format!("response: {e}")))
}

async fn healthz() -> StatusCode {
    StatusCode::OK
}

async fn ready(State(state): State<Arc<AppState>>) -> StatusCode {
    match state.upstream.verified(state.config.default_model()).await {
        Ok(_) => StatusCode::OK,
        Err(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}

pub fn router(state: Arc<AppState>) -> Router {
    let completions = Router::new()
        .route("/v1/chat/completions", post(chat_completions))
        .layer(DefaultBodyLimit::max(COMPLETIONS_BODY_LIMIT));
    Router::new()
        .route("/v1/models", get(list_models))
        .route("/v1/models/{*model}", get(get_model))
        .merge(completions)
        .route("/healthz", get(healthz))
        .route("/ready", get(ready))
        .with_state(state)
}
