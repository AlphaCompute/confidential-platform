//! The platform's inference front: an App of its own with two kinds of upstream, chosen per
//! model by the measured environment. A model listed in `MODEL_SERVERS` is served by our own
//! `alpha-model-server` on a confidential GPU, reached only over TLS pinned to this Instance's KMS
//! CA and one of that model's Revisions (`own`). Every other allowlisted model goes to the
//! external provider, and only after `upstream::Upstream::verified` has proven, in this
//! process's own measured code, that the connection it will forward over terminates inside the
//! provider's attested gateway. Neither kind is ever used on a stale check, an error, or for a
//! caller without its bearer, and neither falls back to the other on its own.
//!
//! Whatever the model, a member's whole prompt is judged by `alpha-guard` before it reaches an
//! upstream and the completion is judged before it is released (`guard`); only the judge's own
//! calls, under their own bearer, are exempt.

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

pub mod guard;
pub mod own;
pub mod upstream;

#[cfg(test)]
mod test_support;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, FromRequestParts, Path, State};
use axum::http::request::Parts;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{Value, json};
use zeroize::Zeroizing;

pub use upstream::Upstream;

const COMPLETIONS_BODY_LIMIT: usize = 16 * 1024 * 1024;
/// A completion, from connecting to the last byte of its body, gets this long on either kind
/// of upstream; a stuck upstream then answers `502 upstream` instead of holding a task forever.
pub const COMPLETION_TIMEOUT: Duration = Duration::from_secs(600);
/// A completion is held whole while it is judged; one larger than this is not released.
const COMPLETION_HOLD_LIMIT: usize = 16 * 1024 * 1024;

/// The measured environment, read once at startup and never mutated.
#[derive(Clone, Debug)]
pub struct Config {
    /// The external provider's OpenAI-compatible base, `/v1` included, trailing slash trimmed.
    /// Empty when every allowlisted model is served by our own model servers.
    pub upstream_url: String,
    /// The allowlist, in order; the first is the default model.
    pub models: Vec<String>,
    /// Empty when there is no external model, as `upstream_url`.
    pub pccs_url: String,
    pub upstream_policy: alpha_attest::Policy,
    /// The allowlisted models served by our own model servers; the rest go to the external
    /// provider.
    pub model_servers: BTreeMap<String, own::ModelServer>,
    /// The judge every member's turn and completion goes through.
    pub guard: guard::GuardConfig,
}

impl Config {
    pub fn from_env() -> Result<Self, Error> {
        Self::build(|name| std::env::var(name).ok())
    }

    /// Built from a lookup function rather than the process environment, so validation is
    /// testable without touching global state.
    pub fn build(get: impl Fn(&str) -> Option<String>) -> Result<Self, Error> {
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
        let model_servers = match get("MODEL_SERVERS") {
            Some(raw) if !raw.trim().is_empty() => own::parse_servers(&raw)?,
            _ => BTreeMap::new(),
        };
        if let Some(stray) = model_servers.keys().find(|m| !models.contains(m)) {
            return Err(Error::internal(format!(
                "MODEL_SERVERS names {stray}, which is not in MODELS"
            )));
        }
        let any_external = models.iter().any(|m| !model_servers.contains_key(m));
        // The external provider's three variables are required exactly when some allowlisted
        // model is not ours; set anyway, they are still validated.
        let external = |name: &str| match get(name) {
            Some(value) => Ok(Some(value)),
            None if any_external => Err(Error::internal(format!("{name} is required"))),
            None => Ok(None),
        };
        let upstream_url = external("UPSTREAM_URL")?.unwrap_or_default();
        if (any_external || !upstream_url.is_empty()) && !upstream_url.starts_with("https://") {
            return Err(Error::internal("UPSTREAM_URL must be https"));
        }
        let pccs_url = external("PCCS_URL")?.unwrap_or_default();
        if (any_external || !pccs_url.is_empty()) && !pccs_url.starts_with("https://") {
            return Err(Error::internal("PCCS_URL must be https"));
        }
        let upstream_policy = match external("UPSTREAM_POLICY")? {
            Some(policy_raw) => {
                let policy: alpha_attest::Policy = serde_json::from_str(&policy_raw)
                    .map_err(|e| Error::internal(format!("UPSTREAM_POLICY: {e}")))?;
                if policy.tcb_statuses.is_empty() {
                    return Err(Error::internal("UPSTREAM_POLICY names no tcb_status"));
                }
                policy
            }
            None => alpha_attest::Policy {
                tcb_statuses: Vec::new(),
                tolerated_advisories: Vec::new(),
            },
        };
        let guard = guard::GuardConfig::build(&get, &models)?;
        Ok(Config {
            upstream_url: upstream_url.trim_end_matches('/').to_owned(),
            models,
            pccs_url: pccs_url.trim_end_matches('/').to_owned(),
            upstream_policy,
            model_servers,
            guard,
        })
    }

    /// The allowlisted models the external provider serves, in allowlist order.
    pub fn external_models(&self) -> Vec<String> {
        self.models
            .iter()
            .filter(|m| !self.model_servers.contains_key(*m))
            .cloned()
            .collect()
    }

    pub fn default_model(&self) -> &str {
        self.models.first().map_or("", String::as_str)
    }

    pub fn allows(&self, model: &str) -> bool {
        self.models.iter().any(|m| m == model)
    }
}

/// Held only in zeroizing buffers; `Debug` never shows the bytes. A key for an upstream kind
/// this Revision does not use is empty and never sent anywhere.
pub struct Secrets {
    pub provider_key: Zeroizing<String>,
    pub caller_bearer: Zeroizing<Vec<u8>>,
    /// The bearer our own model servers expect; sent only over their pinned connections.
    pub model_server_bearer: Zeroizing<String>,
    /// `alpha-guard`'s own bearer: its calls are not judged again, and may name only a model in
    /// `JUDGE_MODELS`. Never equal to `caller_bearer`, and never matched when empty.
    pub judge_bearer: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for Secrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Secrets")
            .field("provider_key", &"<redacted>")
            .field("caller_bearer", &"<redacted>")
            .field("model_server_bearer", &"<redacted>")
            .field("judge_bearer", &"<redacted>")
            .finish()
    }
}

/// Everything the router and `main` share. `secrets` is behind a lock so a rotated bearer or
/// provider key takes effect without a restart.
pub struct AppState {
    pub config: Config,
    pub secrets: parking_lot::RwLock<Secrets>,
    pub upstream: Upstream,
    /// Our own model servers, pinned by the KMS CA and each model's Revisions.
    pub own: own::Servers,
    pub guard: guard::Guard,
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
    #[error("The content was blocked by the moderation policy.")]
    ContentBlocked,
    #[error("Moderation is unavailable, so nothing was sent or released.")]
    ModerationUnavailable,
    #[error("The content is too large to be moderated.")]
    ContentTooLarge,
    #[error("The request has content the moderation policy cannot judge, so nothing was sent.")]
    ContentUnjudgeable,
    #[error("The model provider refused the request.")]
    UpstreamRefused(StatusCode),
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
            Error::ContentBlocked => (
                StatusCode::FORBIDDEN,
                "invalid_request_error",
                "content_blocked",
            ),
            Error::ModerationUnavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "upstream_error",
                "moderation_unavailable",
            ),
            Error::ContentTooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                "invalid_request_error",
                "content_too_large",
            ),
            Error::ContentUnjudgeable => (
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                "content_not_judgeable",
            ),
            // The upstream's own status, never its body: an error body is text nobody judged.
            Error::UpstreamRefused(status) => (
                if status.is_client_error() || status.is_server_error() {
                    *status
                } else {
                    StatusCode::BAD_GATEWAY
                },
                "upstream_error",
                "upstream_refused",
            ),
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

/// Proof of the caller's bearer, extracted before any handler runs: a member's (`caller-bearer`),
/// whose completions are judged, or the judge's own (`judge-bearer`), whose are not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthedCaller {
    Member,
    Judge,
}

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
        let secrets = state.secrets.read();
        if alpha_client::bearer_matches(presented.as_bytes(), &secrets.caller_bearer) {
            Ok(AuthedCaller::Member)
        } else if !secrets.judge_bearer.is_empty()
            && alpha_client::bearer_matches(presented.as_bytes(), &secrets.judge_bearer)
        {
            Ok(AuthedCaller::Judge)
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

/// Where a verified model's request goes.
enum Route {
    /// Our own model server, over its pinned client.
    Own,
    /// The external provider, over the client pinned to its attested gateway key.
    External(reqwest::Client),
}

/// The model's upstream, checked within the last minute; `model` must already be allowlisted.
async fn verified_route(state: &AppState, model: &str) -> Result<Route, Error> {
    if state.own.serves(model) {
        let bearer = state.secrets.read().model_server_bearer.clone();
        state
            .own
            .verified(model, bearer.as_str())
            .await
            .map_err(|_| Error::UpstreamUnverified)?;
        Ok(Route::Own)
    } else {
        state
            .upstream
            .verified(model)
            .await
            .map(Route::External)
            .map_err(|outcome| verify_error(outcome, model))
    }
}

/// The upstream's status, content type and body, relayed as they arrive.
fn relay(upstream_response: reqwest::Response) -> Result<Response, Error> {
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

async fn list_models(State(state): State<Arc<AppState>>, _: AuthedCaller) -> Json<Value> {
    let external = state.config.external_models();
    let mut data: Vec<Value> = Vec::new();
    if !external.is_empty() {
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
                    .is_some_and(|id| external.iter().any(|e| e == id))
            })
            .collect();
        if allowed.is_empty() {
            data.extend(
                external
                    .iter()
                    .map(|id| json!({ "id": id, "object": "model" })),
            );
        } else {
            data.extend(allowed);
        }
    }
    // Ours are listed from the measured configuration: the listing carries no conversation,
    // so, as for the external provider, no check runs for it.
    data.extend(
        state
            .config
            .model_servers
            .keys()
            .map(|id| json!({ "id": id, "object": "model", "owned_by": "alphacompute" })),
    );
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
    let owned_by = match verified_route(&state, &model).await? {
        Route::Own => "alphacompute",
        Route::External(_) => "redpill",
    };
    Ok(Json(
        json!({ "id": model, "object": "model", "owned_by": owned_by }),
    ))
}

async fn chat_completions(
    State(state): State<Arc<AppState>>,
    caller: AuthedCaller,
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
    match caller {
        // The judge's own call: a judge model only, and not judged again.
        AuthedCaller::Judge => {
            if !state.config.guard.judge_models.contains(&model) {
                return Err(Error::ModelNotFound(model));
            }
            relay(send(&state, &model, body).await?)
        }
        AuthedCaller::Member => {
            let input = state.guard.check_input(&model, &parsed).await?;
            let upstream_response = send(&state, &model, body).await?;
            let (status, content_type, held) = hold(upstream_response).await?;
            // An upstream refusal carries no completion, and its body is text nobody judged: the
            // member gets its status with a fixed error instead.
            if !status.is_success() {
                return Err(Error::UpstreamRefused(status));
            }
            state.guard.check_output(&model, &input, &held).await?;
            Response::builder()
                .status(status)
                .header(header::CONTENT_TYPE, content_type)
                .body(axum::body::Body::from(held))
                .map_err(|e| Error::internal(format!("response: {e}")))
        }
    }
}

/// The upstream's whole answer, held so it can be judged before any byte is released. Streams
/// are held too: within one completion there is no streaming under moderation.
async fn hold(
    upstream_response: reqwest::Response,
) -> Result<(StatusCode, header::HeaderValue, Bytes), Error> {
    let status = StatusCode::from_u16(upstream_response.status().as_u16())
        .unwrap_or(StatusCode::BAD_GATEWAY);
    let content_type = upstream_response
        .headers()
        .get(header::CONTENT_TYPE)
        .cloned()
        .unwrap_or_else(|| header::HeaderValue::from_static("text/event-stream"));
    let mut held: Vec<u8> = Vec::new();
    let mut upstream_response = upstream_response;
    while let Some(chunk) = upstream_response
        .chunk()
        .await
        .map_err(|_| Error::Upstream)?
    {
        if held.len().saturating_add(chunk.len()) > COMPLETION_HOLD_LIMIT {
            return Err(Error::ContentTooLarge);
        }
        held.extend_from_slice(&chunk);
    }
    Ok((status, content_type, Bytes::from(held)))
}

/// Forwards `body` for an allowlisted `model` over its verified upstream, the upstream's own
/// credential in place of the caller's bearer. A failed connection after a passing check
/// forgets the check, so the next request checks again.
async fn send(state: &AppState, model: &str, body: Bytes) -> Result<reqwest::Response, Error> {
    match verified_route(state, model).await? {
        Route::Own => {
            let bearer = state.secrets.read().model_server_bearer.clone();
            match state.own.complete(model, bearer.as_str(), body).await {
                Ok(response) => Ok(response),
                Err(e) => {
                    state.own.forget(model).await;
                    Err(e)
                }
            }
        }
        Route::External(client) => {
            let provider_key = state.secrets.read().provider_key.clone();
            let sent = client
                .post(format!("{}/chat/completions", state.config.upstream_url))
                .bearer_auth(provider_key.as_str())
                .header(header::CONTENT_TYPE, "application/json")
                .timeout(COMPLETION_TIMEOUT)
                .body(body)
                .send()
                .await;
            match sent {
                Ok(response) => Ok(response),
                Err(_) => {
                    state.upstream.forget(model).await;
                    Err(Error::Upstream)
                }
            }
        }
    }
}

async fn healthz() -> StatusCode {
    StatusCode::OK
}

async fn ready(State(state): State<Arc<AppState>>) -> StatusCode {
    match verified_route(&state, state.config.default_model()).await {
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

#[cfg(test)]
mod tests {
    use axum::body::{Body, to_bytes};
    use axum::http::Request;
    use std::sync::atomic::Ordering;
    use tower::ServiceExt;

    use super::*;
    use crate::test_support::{answering, spawn_fake_upstream, test_config, test_state};

    fn guard_env(name: &str) -> Option<String> {
        match name {
            "GUARD_URL" => Some("https://guard.example:8443".to_string()),
            "GUARD_REVISIONS" => Some(format!("sha256:{}", "3".repeat(64))),
            "GUARD_POLICY" => Some(r#"{"model":"m2","categories":["Violence"]}"#.to_string()),
            "JUDGE_MODELS" => Some("m2".to_string()),
            _ => None,
        }
    }

    fn valid_env(name: &str) -> Option<String> {
        match name {
            "GUARD_URL" | "GUARD_REVISIONS" | "GUARD_POLICY" | "JUDGE_MODELS" => guard_env(name),
            "UPSTREAM_URL" => Some("https://api.redpill.ai/v1".to_string()),
            "MODELS" => Some("m1,m2".to_string()),
            "PCCS_URL" => Some("https://pccs.example".to_string()),
            "UPSTREAM_POLICY" => {
                Some(r#"{"tcb_statuses":["UpToDate"],"tolerated_advisories":[]}"#.to_string())
            }
            _ => None,
        }
    }

    fn with_override(name: &'static str, value: &'static str) -> impl Fn(&str) -> Option<String> {
        move |n| {
            if n == name {
                Some(value.to_string())
            } else {
                valid_env(n)
            }
        }
    }

    #[test]
    fn config_build_accepts_the_valid_baseline() {
        assert!(Config::build(valid_env).is_ok());
    }

    #[test]
    fn config_build_refuses_an_http_upstream_url_naming_it() {
        let err =
            Config::build(with_override("UPSTREAM_URL", "http://api.redpill.ai/v1")).unwrap_err();
        assert!(err.to_string().contains("UPSTREAM_URL"), "{err}");
    }

    #[test]
    fn config_build_refuses_an_empty_models_naming_it() {
        let err = Config::build(with_override("MODELS", " , ,")).unwrap_err();
        assert!(err.to_string().contains("MODELS"), "{err}");
    }

    #[test]
    fn config_build_refuses_a_missing_pccs_url_naming_it() {
        let err = Config::build(|n| if n == "PCCS_URL" { None } else { valid_env(n) }).unwrap_err();
        assert!(err.to_string().contains("PCCS_URL"), "{err}");
    }

    #[test]
    fn config_build_refuses_an_upstream_policy_with_no_tcb_status_naming_it() {
        let err = Config::build(with_override(
            "UPSTREAM_POLICY",
            r#"{"tcb_statuses":[],"tolerated_advisories":[]}"#,
        ))
        .unwrap_err();
        assert!(err.to_string().contains("UPSTREAM_POLICY"), "{err}");
    }

    fn own_servers_json(models: &[&str]) -> String {
        let entries: Vec<String> = models
            .iter()
            .map(|m| {
                format!(
                    r#""{m}":{{"url":"https://ms.example:8443","revisions":["sha256:{}"]}}"#,
                    "1".repeat(64)
                )
            })
            .collect();
        format!("{{{}}}", entries.join(","))
    }

    #[test]
    fn config_build_needs_no_external_provider_when_every_model_is_ours() {
        let servers = own_servers_json(&["m1", "m2"]);
        let config = Config::build(|n| match n {
            "MODELS" => Some("m1,m2".to_string()),
            "MODEL_SERVERS" => Some(servers.clone()),
            other => guard_env(other),
        })
        .unwrap();
        assert!(config.external_models().is_empty());
        assert_eq!(config.model_servers.len(), 2);
    }

    #[test]
    fn config_build_still_needs_the_external_provider_for_a_model_that_is_not_ours() {
        let servers = own_servers_json(&["m1"]);
        let err = Config::build(|n| match n {
            "MODELS" => Some("m1,m2".to_string()),
            "MODEL_SERVERS" => Some(servers.clone()),
            other => guard_env(other),
        })
        .unwrap_err();
        assert!(err.to_string().contains("UPSTREAM_URL"), "{err}");

        let config = Config::build(|n| match n {
            "MODEL_SERVERS" => Some(servers.clone()),
            other => valid_env(other),
        })
        .unwrap();
        assert_eq!(config.external_models(), vec!["m2".to_string()]);
    }

    #[test]
    fn config_build_refuses_a_model_server_for_a_model_outside_models() {
        let servers = own_servers_json(&["m9"]);
        let err = Config::build(|n| match n {
            "MODEL_SERVERS" => Some(servers.clone()),
            other => valid_env(other),
        })
        .unwrap_err();
        assert!(err.to_string().contains("m9"), "{err}");
    }

    #[tokio::test]
    async fn an_own_model_that_fails_its_check_answers_upstream_unverified_and_never_reaches_the_external_provider()
     {
        let (base, report_hits, completions_hits) =
            spawn_fake_upstream(answering(StatusCode::OK, "{}")).await;
        let mut config = test_config(&base, &["m1", "ours"]);
        config.model_servers.insert(
            "ours".to_string(),
            own::ModelServer {
                // Nothing listens here: the pinned handshake can never complete.
                url: "https://127.0.0.1:1".to_string(),
                revisions: vec![alpha_core::compose_hash("model-server")],
            },
        );
        let ca = rcgen::CertificateParams::default()
            .self_signed(&rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap())
            .unwrap();
        let servers = own::Servers::new(
            &config.model_servers,
            &rustls::pki_types::CertificateDer::from(ca.der().to_vec()),
        )
        .unwrap();
        let state = test_state(config, b"right-bearer", "provider-key");
        let state = Arc::new(AppState {
            config: state.config.clone(),
            secrets: parking_lot::RwLock::new(Secrets {
                provider_key: Zeroizing::new("provider-key".into()),
                caller_bearer: Zeroizing::new(b"right-bearer".to_vec()),
                model_server_bearer: Zeroizing::new("ms-bearer".into()),
                judge_bearer: Zeroizing::new(b"judge-bearer".to_vec()),
            }),
            upstream: Upstream::new(&state.config).unwrap(),
            own: servers,
            guard: guard::Guard::fixed(Ok(()), Ok(())),
        });
        let app = router(state);

        let body =
            json!({ "model": "ours", "messages": [{"role": "user", "content": "hi"}] }).to_string();
        let request = Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header(header::AUTHORIZATION, "Bearer right-bearer")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let parsed: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed["error"]["code"], "upstream_unverified");
        assert_eq!(report_hits.load(Ordering::SeqCst), 0);
        assert_eq!(completions_hits.load(Ordering::SeqCst), 0);
    }

    /// `test_state` with `guard`, the judge's own bearer set, and the fake upstream at `base`
    /// answering completions for `m1` and the judge model `guard`.
    fn guarded_state(base: &str, guard: guard::Guard) -> Arc<AppState> {
        let config = test_config(base, &["m1", "guard"]);
        Arc::new(AppState {
            upstream: Upstream::new(&config).unwrap(),
            config,
            secrets: parking_lot::RwLock::new(Secrets {
                provider_key: Zeroizing::new("provider-key".into()),
                caller_bearer: Zeroizing::new(b"member-bearer".to_vec()),
                model_server_bearer: Zeroizing::new(String::new()),
                judge_bearer: Zeroizing::new(b"judge-bearer".to_vec()),
            }),
            own: own::Servers::none(),
            guard,
        })
    }

    fn completion_request(bearer: &str, model: &str) -> Request<Body> {
        let body = json!({ "model": model, "messages": [{"role": "user", "content": "hi"}] });
        Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    async fn error_code(response: Response) -> (StatusCode, Value) {
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let parsed: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, parsed["error"]["code"].clone())
    }

    #[tokio::test]
    async fn a_blocked_or_unjudged_turn_never_reaches_any_upstream() {
        for (refusal, status, code) in [
            (
                guard::Refusal::Blocked,
                StatusCode::FORBIDDEN,
                "content_blocked",
            ),
            (
                guard::Refusal::Unavailable,
                StatusCode::SERVICE_UNAVAILABLE,
                "moderation_unavailable",
            ),
        ] {
            let (base, report_hits, completions_hits) =
                spawn_fake_upstream(answering(StatusCode::OK, "{}")).await;
            let app = router(guarded_state(
                &base,
                guard::Guard::fixed(Err(refusal), Ok(())),
            ));
            let response = app
                .oneshot(completion_request("member-bearer", "m1"))
                .await
                .unwrap();
            assert_eq!(error_code(response).await, (status, json!(code)));
            assert_eq!(report_hits.load(Ordering::SeqCst), 0);
            assert_eq!(completions_hits.load(Ordering::SeqCst), 0);
        }
    }

    fn chat_request(bearer: &str, body: Value) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    #[tokio::test]
    async fn the_whole_prompt_with_its_history_reaches_the_judge_before_any_upstream() {
        let (base, report_hits, completions_hits) =
            spawn_fake_upstream(answering(StatusCode::OK, "{}")).await;
        let state = guarded_state(
            &base,
            guard::Guard::fixed(Err(guard::Refusal::Blocked), Ok(())),
        );
        let body = json!({ "model": "m1", "messages": [
            {"role": "system", "content": "the rules"},
            {"role": "user", "content": "earlier"},
            // Written by the caller, not the model: judged like everything else.
            {"role": "assistant", "content": "fabricated agreement"},
            {"role": "user", "content": "now"},
        ]});
        let response = router(state.clone())
            .oneshot(chat_request("member-bearer", body))
            .await
            .unwrap();
        assert_eq!(
            error_code(response).await,
            (StatusCode::FORBIDDEN, json!("content_blocked"))
        );
        let seen = state.guard.seen();
        let (judged, response) = seen.first().unwrap();
        assert_eq!(
            judged,
            "system: the rules\nuser: earlier\nassistant: fabricated agreement\nuser: now"
        );
        assert!(response.is_none());
        assert_eq!(report_hits.load(Ordering::SeqCst), 0);
        assert_eq!(completions_hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_request_the_judge_cannot_read_never_reaches_the_judge_or_any_upstream() {
        let (base, report_hits, completions_hits) =
            spawn_fake_upstream(answering(StatusCode::OK, "{}")).await;
        let state = guarded_state(&base, guard::Guard::fixed(Ok(()), Ok(())));
        for body in [
            json!({ "model": "m1", "messages": [
                {"role": "user", "content": "write it"},
                {"role": "assistant", "content": "Sure, step one:"},
            ]}),
            json!({ "model": "m1", "messages": [{"role": "user", "content": [
                {"type": "image_url", "image_url": {"url": "https://example.com/x.png"}},
            ]}]}),
            json!({ "model": "m1", "messages": [] }),
        ] {
            let response = router(state.clone())
                .oneshot(chat_request("member-bearer", body))
                .await
                .unwrap();
            assert_eq!(
                error_code(response).await,
                (StatusCode::BAD_REQUEST, json!("content_not_judgeable"))
            );
        }
        assert!(state.guard.seen().is_empty());
        assert_eq!(report_hits.load(Ordering::SeqCst), 0);
        assert_eq!(completions_hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn the_judges_own_bearer_may_name_only_a_judge_model() {
        let (base, report_hits, _completions_hits) =
            spawn_fake_upstream(answering(StatusCode::INTERNAL_SERVER_ERROR, "")).await;
        // A guard that blocks everything: the judge's call must not be judged at all.
        let app = router(guarded_state(
            &base,
            guard::Guard::fixed(Err(guard::Refusal::Blocked), Err(guard::Refusal::Blocked)),
        ));
        let response = app
            .clone()
            .oneshot(completion_request("judge-bearer", "m1"))
            .await
            .unwrap();
        assert_eq!(
            error_code(response).await,
            (StatusCode::NOT_FOUND, json!("model_not_found"))
        );
        assert_eq!(report_hits.load(Ordering::SeqCst), 0);

        // The judge model passes the guard untouched and goes on to the upstream's own check,
        // which this fake fails.
        let response = app
            .oneshot(completion_request("judge-bearer", "guard"))
            .await
            .unwrap();
        assert_eq!(
            error_code(response).await,
            (StatusCode::BAD_GATEWAY, json!("upstream_unverified"))
        );
        assert_eq!(report_hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn an_empty_judge_bearer_never_authenticates() {
        let state = test_state(
            test_config("https://example.invalid", &["m1"]),
            b"member-bearer",
            "key",
        );
        let request = Request::builder()
            .uri("/v1/models")
            .header(header::AUTHORIZATION, "Bearer ")
            .body(Body::empty())
            .unwrap();
        let response = router(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn every_v1_route_requires_the_bearer_before_any_upstream_contact() {
        let (base, report_hits, completions_hits) =
            spawn_fake_upstream(answering(StatusCode::INTERNAL_SERVER_ERROR, "")).await;
        let state = test_state(test_config(&base, &["m1"]), b"right-bearer", "provider-key");
        let app = router(state);

        let cases: [(&str, &str, Option<&str>); 4] = [
            ("GET", "/v1/models", None),
            ("GET", "/v1/models", Some("Bearer wrong")),
            ("GET", "/v1/models/m1", None),
            ("POST", "/v1/chat/completions", None),
        ];
        for (method, path, auth) in cases {
            let mut builder = Request::builder().method(method).uri(path);
            if let Some(value) = auth {
                builder = builder.header(header::AUTHORIZATION, value);
            }
            let request = builder.body(Body::empty()).unwrap();
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "{method} {path}"
            );
        }
        assert_eq!(report_hits.load(Ordering::SeqCst), 0);
        assert_eq!(completions_hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_model_outside_the_allowlist_answers_404_before_any_upstream_contact() {
        let (base, report_hits, _completions_hits) =
            spawn_fake_upstream(answering(StatusCode::OK, "{}")).await;
        let state = test_state(test_config(&base, &["m1"]), b"right-bearer", "provider-key");
        let app = router(state);

        let request = Request::builder()
            .method("GET")
            .uri("/v1/models/not-allowed")
            .header(header::AUTHORIZATION, "Bearer right-bearer")
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let body = json!({ "model": "not-allowed" }).to_string();
        let request = Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header(header::AUTHORIZATION, "Bearer right-bearer")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        assert_eq!(report_hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn healthz_needs_no_bearer() {
        let state = test_state(
            test_config("https://example.invalid", &["m1"]),
            b"bearer",
            "key",
        );
        let app = router(state);
        let request = Request::builder()
            .uri("/healthz")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn chat_completions_answers_upstream_unverified_and_never_reaches_the_fake_upstream() {
        let (base, _report_hits, completions_hits) =
            spawn_fake_upstream(answering(StatusCode::INTERNAL_SERVER_ERROR, "")).await;
        let state = test_state(test_config(&base, &["m1"]), b"right-bearer", "provider-key");
        let app = router(state);

        let body =
            json!({ "model": "m1", "messages": [{"role": "user", "content": "hi"}] }).to_string();
        let request = Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header(header::AUTHORIZATION, "Bearer right-bearer")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let parsed: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed["error"]["code"], "upstream_unverified");
        assert_eq!(
            parsed["error"]["message"],
            "The model provider did not pass verification, so nothing was sent."
        );
        assert_eq!(completions_hits.load(Ordering::SeqCst), 0);
    }
}
