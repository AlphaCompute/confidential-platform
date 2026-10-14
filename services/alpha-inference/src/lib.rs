//! The platform's inference front: an App of its own. A model in `MODEL_SERVERS` goes to our own
//! attested model server (`own`); every other allowlisted model goes to RedPill, and only after
//! `upstream::Upstream::verified` has proven, in this process's own measured code, that the
//! connection it will forward over terminates inside RedPill's attested gateway — never on a
//! stale check, an error, or a caller without its bearer.

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

/// A completion's whole exchange, the streamed answer included, ends after this. Far above any
/// caller's own deadline, so the front never cuts an answer a caller still waits for, yet it
/// bounds a connection held by a server that stopped sending.
pub const COMPLETION_TIMEOUT: Duration = Duration::from_secs(600);

/// The measured environment, read once at startup and never mutated.
#[derive(Clone, Debug)]
pub struct Config {
    /// The allowlist, in order; the first is the default model.
    pub models: Vec<String>,
    /// The allowlisted models our own model servers serve.
    pub own: BTreeMap<String, own::ModelServer>,
    /// The provider of every other allowlisted model; `None` when there is none.
    pub external: Option<External>,
}

#[derive(Clone, Debug)]
pub struct External {
    /// RedPill's OpenAI-compatible base, `/v1` included, trailing slash trimmed.
    pub upstream_url: String,
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
        let own = get("MODEL_SERVERS")
            .map(|raw| own::parse(&raw))
            .transpose()?
            .unwrap_or_default();
        if let Some(stray) = own.keys().find(|m| !models.contains(m)) {
            return Err(Error::internal(format!(
                "MODEL_SERVERS names {stray}, which is not in MODELS"
            )));
        }
        let external = if models.iter().all(|m| own.contains_key(m)) {
            None
        } else {
            Some(External::build(&get)?)
        };
        Ok(Config {
            models,
            own,
            external,
        })
    }

    pub fn default_model(&self) -> &str {
        self.models.first().map_or("", String::as_str)
    }

    pub fn allows(&self, model: &str) -> bool {
        self.models.iter().any(|m| m == model)
    }

    pub fn external_models(&self) -> impl Iterator<Item = &String> {
        self.models.iter().filter(|m| !self.own.contains_key(*m))
    }
}

impl External {
    fn build(get: &impl Fn(&str) -> Option<String>) -> Result<Self, Error> {
        let upstream_url =
            get("UPSTREAM_URL").ok_or_else(|| Error::internal("UPSTREAM_URL is required"))?;
        if !upstream_url.starts_with("https://") {
            return Err(Error::internal("UPSTREAM_URL must be https"));
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
        Ok(External {
            upstream_url: upstream_url.trim_end_matches('/').to_owned(),
            pccs_url: pccs_url.trim_end_matches('/').to_owned(),
            upstream_policy,
        })
    }
}

/// Held only in zeroizing buffers; `Debug` never shows the bytes.
pub struct Secrets {
    /// Read only when some model goes to the external provider.
    pub provider_key: Option<Zeroizing<String>>,
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
    pub upstream: Option<Upstream>,
    pub own: BTreeMap<String, own::Server>,
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
        if alpha_client::bearer_matches(presented.as_bytes(), &state.secrets.read().caller_bearer) {
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

async fn verified_external<'a>(
    state: &'a AppState,
    model: &str,
) -> Result<(&'a Upstream, reqwest::Client), Error> {
    let upstream = state
        .upstream
        .as_ref()
        .ok_or_else(|| Error::internal("no external provider is configured"))?;
    let client = upstream
        .verified(model)
        .await
        .map_err(|outcome| verify_error(outcome, model))?;
    Ok((upstream, client))
}

async fn list_models(State(state): State<Arc<AppState>>, _: AuthedCaller) -> Json<Value> {
    let mut data: Vec<Value> = state
        .config
        .own
        .keys()
        .map(|id| json!({ "id": id, "object": "model", "owned_by": "alphacompute" }))
        .collect();
    if let Some(upstream) = &state.upstream {
        let listed = upstream.list_models().await;
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
                    .is_some_and(|id| state.config.external_models().any(|e| e == id))
            })
            .collect();
        if allowed.is_empty() {
            data.extend(
                state
                    .config
                    .external_models()
                    .map(|id| json!({ "id": id, "object": "model" })),
            );
        } else {
            data.extend(allowed);
        }
    }
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
    let owned_by = match state.own.get(&model) {
        Some(server) if server.live(&model).await => "alphacompute",
        Some(_) => return Err(Error::Upstream),
        None => {
            verified_external(&state, &model).await?;
            "redpill"
        }
    };
    Ok(Json(
        json!({ "id": model, "object": "model", "owned_by": owned_by }),
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
    let upstream_response = if let Some(server) = state.own.get(&model) {
        server.complete(body).await.map_err(|_| Error::Upstream)?
    } else {
        let (upstream, client) = verified_external(&state, &model).await?;
        let provider_key = state
            .secrets
            .read()
            .provider_key
            .clone()
            .ok_or_else(|| Error::internal("no provider key was read"))?;
        let sent = client
            .post(format!("{}/chat/completions", upstream.url()))
            .bearer_auth(provider_key.as_str())
            .header(header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await;
        match sent {
            Ok(response) => response,
            Err(_) => {
                upstream.forget(&model).await;
                return Err(Error::Upstream);
            }
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
    let model = state.config.default_model();
    let ready = match state.own.get(model) {
        Some(server) => server.live(model).await,
        None => verified_external(&state, model).await.is_ok(),
    };
    if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
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

    fn valid_env(name: &str) -> Option<String> {
        match name {
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

    const OWN_M1: &str = r#"{"m1":{"url":"https://ms.example:8443","revisions":["sha256:1111111111111111111111111111111111111111111111111111111111111111"]}}"#;

    #[test]
    fn config_build_needs_no_provider_when_every_model_is_served_by_our_own() {
        let config = Config::build(|n| match n {
            "MODELS" => Some("m1".into()),
            "MODEL_SERVERS" => Some(OWN_M1.into()),
            _ => None,
        })
        .unwrap();
        assert!(config.external.is_none());
        assert_eq!(config.own["m1"].url, "https://ms.example:8443");
        let mixed = Config::build(with_override("MODEL_SERVERS", OWN_M1)).unwrap();
        assert!(mixed.external.is_some());
        assert_eq!(mixed.external_models().collect::<Vec<_>>(), ["m2"]);
    }

    #[test]
    fn config_build_refuses_a_bad_model_server_naming_it() {
        let rev = format!("sha256:{}", "1".repeat(64));
        for bad in [
            format!(r#"{{"m3":{{"url":"https://ms.example","revisions":["{rev}"]}}}}"#),
            format!(r#"{{"m1":{{"url":"http://ms.example","revisions":["{rev}"]}}}}"#),
            format!(r#"{{"m1":{{"url":"https://ms.example/v1","revisions":["{rev}"]}}}}"#),
            format!(r#"{{"m1":{{"url":"https://ms.example#f","revisions":["{rev}"]}}}}"#),
            r#"{"m1":{"url":"https://ms.example","revisions":[]}}"#.to_owned(),
        ] {
            let err = Config::build(|n| {
                if n == "MODEL_SERVERS" {
                    Some(bad.clone())
                } else {
                    valid_env(n)
                }
            })
            .unwrap_err();
            assert!(err.to_string().contains("MODEL_SERVERS"), "{bad}: {err}");
        }
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

        let body = json!({ "model": "m1" }).to_string();
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
