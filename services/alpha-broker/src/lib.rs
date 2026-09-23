//! The connectors broker: an App of its own that exchanges a provider's authorization code
//! with a PKCE verifier only it holds, and keeps the refresh token sealed under a key only
//! Instances of this App receive from the KMS. The tenant's backend starts and finishes a
//! connect with its bearer and relays an opaque code; it never sees a token.

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

pub mod connect;
pub mod oauth;
pub mod store;

use std::sync::Arc;

use axum::extract::{FromRequestParts, State};
use axum::http::request::Parts;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use zeroize::Zeroizing;

/// The measured environment, read once at startup.
#[derive(Clone, Debug)]
pub struct Config {
    pub google_client_id: String,
    pub google_redirect_uri: String,
}

impl Config {
    pub fn from_env() -> Result<Self, Error> {
        Self::build(|name| std::env::var(name).ok())
    }

    pub fn build(get: impl Fn(&str) -> Option<String>) -> Result<Self, Error> {
        let google_client_id = get("GOOGLE_CLIENT_ID")
            .map(|v| v.trim().to_owned())
            .filter(|v| !v.is_empty())
            .ok_or_else(|| Error::internal("GOOGLE_CLIENT_ID is required"))?;
        let google_redirect_uri = get("GOOGLE_REDIRECT_URI")
            .ok_or_else(|| Error::internal("GOOGLE_REDIRECT_URI is required"))?;
        if !google_redirect_uri.starts_with("https://") {
            return Err(Error::internal("GOOGLE_REDIRECT_URI must be https"));
        }
        Ok(Config {
            google_client_id,
            google_redirect_uri,
        })
    }
}

/// Held only in zeroizing buffers; `Debug` never shows the bytes.
pub struct Secrets {
    pub google_client_secret: Zeroizing<String>,
    pub connect_bearer: Zeroizing<Vec<u8>>,
    pub connectors_key: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for Secrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Secrets")
            .field("google_client_secret", &"<redacted>")
            .field("connect_bearer", &"<redacted>")
            .field("connectors_key", &"<redacted>")
            .finish()
    }
}

pub struct AppState {
    pub config: Config,
    pub secrets: parking_lot::RwLock<Secrets>,
    pub pool: PgPool,
    pub http: reqwest::Client,
}

/// Every error this service answers with. No message ever carries a token, code, verifier or
/// secret.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("missing or invalid bearer")]
    Unauthorized,
    #[error("{0}")]
    Malformed(String),
    #[error("not found")]
    NotFound,
    #[error("the connect state is unknown, expired or already used")]
    StateInvalid,
    #[error("the provider did not complete the connection")]
    ExchangeFailed,
    #[error("{0}")]
    Internal(String),
}

impl Error {
    pub fn internal(message: impl Into<String>) -> Self {
        Error::Internal(message.into())
    }

    fn parts(&self) -> (StatusCode, &'static str) {
        match self {
            Error::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Error::Malformed(_) => (StatusCode::BAD_REQUEST, "malformed"),
            Error::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            Error::StateInvalid => (StatusCode::BAD_REQUEST, "state_invalid"),
            Error::ExchangeFailed => (StatusCode::BAD_GATEWAY, "exchange_failed"),
            Error::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
        }
    }
}

impl From<sqlx::Error> for Error {
    fn from(e: sqlx::Error) -> Self {
        Error::internal(format!("database: {e}"))
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let (status, code) = self.parts();
        let message = match &self {
            Error::Internal(detail) => {
                eprintln!("alpha-broker: internal: {detail}");
                "internal error".to_string()
            }
            other => other.to_string(),
        };
        let body = json!({ "error": { "code": code, "message": message } });
        (status, Json(body)).into_response()
    }
}

pub fn random<const N: usize>() -> Result<[u8; N], Error> {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).map_err(|e| Error::internal(format!("rng: {e}")))?;
    Ok(out)
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

/// Proof of the tenant backend's connect bearer, extracted before any handler runs.
pub struct AuthedCorpus;

impl FromRequestParts<Arc<AppState>> for AuthedCorpus {
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
        if bearer_matches(presented.as_bytes(), &state.secrets.read().connect_bearer) {
            Ok(AuthedCorpus)
        } else {
            Err(Error::Unauthorized)
        }
    }
}

async fn healthz() -> Json<serde_json::Value> {
    Json(json!({ "ok": true }))
}

async fn ready(State(state): State<Arc<AppState>>) -> Response {
    match sqlx::query("select 1").execute(&state.pool).await {
        Ok(_) => Json(json!({ "ok": true })).into_response(),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "ok": false })),
        )
            .into_response(),
    }
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/connect/finish", post(connect::finish))
        .route("/connect/{provider}", post(connect::start))
        .route("/connections", get(connect::list))
        .route("/healthz", get(healthz))
        .route("/ready", get(ready))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_env(name: &str) -> Option<String> {
        match name {
            "GOOGLE_CLIENT_ID" => Some("client.apps.googleusercontent.com".into()),
            "GOOGLE_REDIRECT_URI" => Some("https://corpus.example/oauth/google/callback".into()),
            _ => None,
        }
    }

    #[test]
    fn config_build_accepts_the_valid_baseline() {
        let config = Config::build(valid_env).unwrap();
        assert_eq!(config.google_client_id, "client.apps.googleusercontent.com");
    }

    #[test]
    fn config_build_refuses_a_missing_or_blank_client_id_naming_it() {
        for value in [None, Some(" ")] {
            let err = Config::build(|n| {
                if n == "GOOGLE_CLIENT_ID" {
                    value.map(str::to_owned)
                } else {
                    valid_env(n)
                }
            })
            .unwrap_err();
            assert!(err.to_string().contains("GOOGLE_CLIENT_ID"), "{err}");
        }
    }

    #[test]
    fn config_build_refuses_an_http_redirect_uri_naming_it() {
        let err = Config::build(|n| {
            if n == "GOOGLE_REDIRECT_URI" {
                Some("http://corpus.example/oauth/google/callback".into())
            } else {
                valid_env(n)
            }
        })
        .unwrap_err();
        assert!(err.to_string().contains("GOOGLE_REDIRECT_URI"), "{err}");
    }
}
