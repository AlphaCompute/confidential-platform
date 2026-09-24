//! The platform's content judge: an App of its own that an attested Instance of a listed App
//! calls with its own policy and a piece of conversation, and that answers allow or block. The
//! judging model is reached only through the inference front, pinned by the front's Revision, so
//! which provider serves the model is the front's business. The caller enforces the verdict;
//! this service never sees the rest of the caller's traffic and keeps nothing.

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

pub mod judge;

use std::sync::Arc;
use std::time::{Duration, Instant};

use alpha_client::tls::{PeerCerts, Pin};
use alpha_core::{AppId, ComposeHash};
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, FromRequestParts, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use rustls::pki_types::CertificateDer;
use serde::Deserialize;
use serde_json::{Value, json};
use zeroize::Zeroizing;

/// JSON escaping can double the text; the text itself is bounded by `judge::CONTENT_LIMIT`.
const BODY_LIMIT: usize = 4 * judge::CONTENT_LIMIT;
const JUDGE_TIMEOUT: Duration = Duration::from_secs(60);

/// The measured environment, read once at startup.
#[derive(Clone, Debug)]
pub struct Config {
    /// The front's origin, `https://host[:port]`, without a path.
    pub inference_url: String,
    pub inference_revisions: Vec<ComposeHash>,
    /// The Apps whose Instances may ask for a verdict.
    pub caller_apps: Vec<AppId>,
}

fn list<T: std::str::FromStr>(name: &str, raw: Option<String>) -> Result<Vec<T>, Error> {
    let items = raw
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse()
                .map_err(|_| Error::internal(format!("{name}: '{s}' is not valid")))
        })
        .collect::<Result<Vec<T>, Error>>()?;
    if items.is_empty() {
        return Err(Error::internal(format!("{name} names nothing")));
    }
    Ok(items)
}

impl Config {
    pub fn from_env() -> Result<Self, Error> {
        Self::build(|name| std::env::var(name).ok())
    }

    pub fn build(get: impl Fn(&str) -> Option<String>) -> Result<Self, Error> {
        let raw =
            get("INFERENCE_URL").ok_or_else(|| Error::internal("INFERENCE_URL is required"))?;
        let url = reqwest::Url::parse(&raw)
            .map_err(|e| Error::internal(format!("INFERENCE_URL: {e}")))?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || url.path() != "/"
            || url.query().is_some()
            || !url.username().is_empty()
        {
            return Err(Error::internal(
                "INFERENCE_URL must be an https origin without a path",
            ));
        }
        Ok(Config {
            inference_url: url.as_str().trim_end_matches('/').to_owned(),
            inference_revisions: list("INFERENCE_REVISIONS", get("INFERENCE_REVISIONS"))?,
            caller_apps: list("CALLER_APPS", get("CALLER_APPS"))?,
        })
    }
}

pub struct AppState {
    pub config: Config,
    /// The bearer the front expects; behind a lock so a rotated one takes effect without a
    /// restart.
    pub inference_bearer: parking_lot::RwLock<Zeroizing<String>>,
    /// Pinned to the front: the KMS CA and one of `inference_revisions`, inside the handshake.
    pub front: reqwest::Client,
}

pub fn front_client(
    kms_ca: CertificateDer<'static>,
    revisions: Vec<ComposeHash>,
) -> Result<reqwest::Client, Error> {
    let tls = alpha_client::tls::client_config(
        Some(Pin::CaAndInstanceRevisions(kms_ca, revisions)),
        None,
        alpha_client::system_time_provider(),
    )
    .map_err(|e| Error::internal(format!("front tls: {e}")))?;
    reqwest::Client::builder()
        .tls_backend_preconfigured(tls)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(JUDGE_TIMEOUT)
        .build()
        .map_err(|e| Error::internal(format!("front client: {e}")))
}

/// Every error this service answers with. No message ever carries the caller's text.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("a client certificate of an attested Instance is required")]
    CertInvalid,
    #[error("this App may not ask for a verdict")]
    NotAllowed,
    #[error("{0}")]
    Malformed(String),
    #[error("no verdict: the judge could not be reached or did not answer with a rating")]
    NoVerdict,
    #[error("{0}")]
    Internal(String),
}

impl Error {
    pub fn internal(message: impl Into<String>) -> Self {
        Error::Internal(message.into())
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            Error::CertInvalid => (StatusCode::UNAUTHORIZED, "cert_invalid"),
            Error::NotAllowed => (StatusCode::FORBIDDEN, "not_allowed"),
            Error::Malformed(_) => (StatusCode::BAD_REQUEST, "malformed"),
            Error::NoVerdict => (StatusCode::BAD_GATEWAY, "no_verdict"),
            Error::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
        };
        let message = match &self {
            Error::Internal(detail) => {
                eprintln!("alpha-guard: internal: {detail}");
                "internal error".to_string()
            }
            other => other.to_string(),
        };
        let body = json!({ "error": { "code": code, "message": message } });
        (status, Json(body)).into_response()
    }
}

/// An Instance's leaf, already chained to the KMS CA in the handshake, of an App in
/// `CALLER_APPS`. A KMS node's leaf chains to the same CA but does not carry an Instance's SANs.
pub struct AuthedCaller(pub AppId);

impl FromRequestParts<Arc<AppState>> for AuthedCaller {
    type Rejection = Error;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let leaf = parts
            .extensions
            .get::<PeerCerts>()
            .and_then(|peer| peer.0.first())
            .ok_or(Error::CertInvalid)?;
        let instance = alpha_client::tls::uri_sans(leaf)
            .and_then(|sans| alpha_client::tls::parse_instance_sans(&sans))
            .map_err(|_| Error::CertInvalid)?;
        if !state.config.caller_apps.contains(&instance.app_id) {
            return Err(Error::NotAllowed);
        }
        Ok(AuthedCaller(instance.app_id))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckRequest {
    policy: judge::Policy,
    user: String,
    /// Present when the caller asks about a model's answer to `user`.
    response: Option<String>,
}

async fn ask_judge(state: &AppState, request: &CheckRequest) -> Result<judge::Verdict, Error> {
    let prompt = judge::prompt(&request.policy, &request.user, request.response.as_deref());
    let bearer = state.inference_bearer.read().clone();
    let answer = state
        .front
        .post(format!(
            "{}/v1/chat/completions",
            state.config.inference_url
        ))
        .bearer_auth(bearer.as_str())
        .json(&judge::completion_request(&request.policy, &prompt))
        .send()
        .await
        .map_err(|_| Error::NoVerdict)?;
    if answer.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(Error::Malformed(
            "policy.model is not served by the inference front".into(),
        ));
    }
    if !answer.status().is_success() {
        return Err(Error::NoVerdict);
    }
    let completion: Value = answer.json().await.map_err(|_| Error::NoVerdict)?;
    judge::parse(&completion, &request.policy, request.response.is_some()).ok_or(Error::NoVerdict)
}

async fn check(
    State(state): State<Arc<AppState>>,
    AuthedCaller(caller): AuthedCaller,
    body: Bytes,
) -> Result<Json<Value>, Error> {
    let request: CheckRequest =
        serde_json::from_slice(&body).map_err(|e| Error::Malformed(format!("body: {e}")))?;
    request
        .policy
        .validate()
        .map_err(|m| Error::Malformed(m.into()))?;
    let length = request
        .user
        .len()
        .saturating_add(request.response.as_ref().map_or(0, String::len));
    if length > judge::CONTENT_LIMIT {
        return Err(Error::Malformed(
            "user and response together exceed 128 KiB".into(),
        ));
    }
    let digest = request
        .policy
        .digest()
        .map_err(|e| Error::internal(format!("policy digest: {e}")))?;

    let started = Instant::now();
    let verdict = ask_judge(&state, &request).await;
    let outcome = match &verdict {
        Ok(v) if v.block => "block",
        Ok(_) => "allow",
        Err(_) => "no_verdict",
    };
    // Fixed labels and digests only: never the text, the categories or the judge's answer.
    eprintln!(
        "alpha-guard: check caller={caller} phase={} outcome={outcome} policy={digest} elapsed_ms={}",
        if request.response.is_some() {
            "response"
        } else {
            "user"
        },
        started.elapsed().as_millis()
    );
    let verdict = verdict?;
    Ok(Json(json!({
        "verdict": if verdict.block { "block" } else { "allow" },
        "categories": verdict.categories,
        "policy_sha256": digest,
    })))
}

/// Ready when the front answers its own `/healthz` over the pinned connection.
async fn ready(State(state): State<Arc<AppState>>) -> StatusCode {
    match state
        .front
        .get(format!("{}/healthz", state.config.inference_url))
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => StatusCode::OK,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    }
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/check", post(check))
        .route("/healthz", get(|| async { StatusCode::OK }))
        .route("/ready", get(ready))
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
        .with_state(state)
}

#[cfg(test)]
mod tests;
