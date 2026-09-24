//! The connectors broker: an App of its own that exchanges a provider's authorization code
//! with a PKCE verifier only it holds, and keeps the refresh token sealed under a key only
//! Instances of this App receive from the KMS. The tenant's backend starts and finishes a
//! connect with its bearer and relays an opaque code; it never sees a token. An attested
//! Instance holding the proxy bearer reads through `/proxy` inside its provider's read list, and
//! the tenant's backend writes an export through `/write` inside the write list, with the
//! member's access token attached here.

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
pub mod proxy;
pub mod store;

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, FromRequestParts, State};
use axum::http::request::Parts;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde_json::json;
use sqlx::PgPool;
use zeroize::Zeroizing;

use crate::oauth::Provider;

/// The measured environment, read once at startup: one `<NAME>_CLIENT_ID` per provider in the
/// table, and the base every provider's redirect URI hangs from.
#[derive(Clone, Debug)]
pub struct Config {
    client_ids: HashMap<&'static str, String>,
    redirect_base: String,
}

impl Config {
    pub fn from_env() -> Result<Self, Error> {
        Self::build(|name| std::env::var(name).ok())
    }

    pub fn build(get: impl Fn(&str) -> Option<String>) -> Result<Self, Error> {
        let mut client_ids = HashMap::new();
        for provider in oauth::PROVIDERS {
            let variable = format!("{}_CLIENT_ID", provider.name.to_ascii_uppercase());
            let client_id = get(&variable)
                .map(|v| v.trim().to_owned())
                .filter(|v| !v.is_empty())
                .ok_or_else(|| Error::internal(format!("{variable} is required")))?;
            client_ids.insert(provider.name, client_id);
        }
        let redirect_base = get("OAUTH_REDIRECT_BASE")
            .ok_or_else(|| Error::internal("OAUTH_REDIRECT_BASE is required"))?;
        if !redirect_base.starts_with("https://") {
            return Err(Error::internal("OAUTH_REDIRECT_BASE must be https"));
        }
        Ok(Config {
            client_ids,
            redirect_base: redirect_base.trim_end_matches('/').to_owned(),
        })
    }

    pub fn client_id(&self, provider: &Provider) -> Result<&str, Error> {
        self.client_ids
            .get(provider.name)
            .map(String::as_str)
            .ok_or_else(|| Error::internal(format!("no client id for {}", provider.name)))
    }

    pub fn redirect_uri(&self, provider: &Provider) -> String {
        format!("{}/{}/callback", self.redirect_base, provider.name)
    }
}

/// Held only in zeroizing buffers, and deliberately not `Debug`.
pub struct Secrets {
    /// The tenant's OAuth client secret per provider name.
    pub client_secrets: HashMap<&'static str, Zeroizing<String>>,
    pub connect_bearer: Zeroizing<Vec<u8>>,
    pub proxy_bearer: Zeroizing<Vec<u8>>,
    pub connectors_key: Zeroizing<[u8; 32]>,
}

pub struct AppState {
    pub config: Config,
    pub secrets: parking_lot::RwLock<Secrets>,
    pub pool: PgPool,
    pub http: reqwest::Client,
    pub tokens: proxy::TokenCache,
}

impl AppState {
    /// The provider's client id and a copy of its client secret.
    pub fn client(&self, provider: &Provider) -> Result<(&str, Zeroizing<String>), Error> {
        let secret = self
            .secrets
            .read()
            .client_secrets
            .get(provider.name)
            .cloned()
            .ok_or_else(|| Error::internal(format!("no client secret for {}", provider.name)))?;
        Ok((self.config.client_id(provider)?, secret))
    }
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
    #[error("a client certificate of an attested Instance is required")]
    CertInvalid,
    #[error("the request is outside what this route may send on this connection")]
    NotAllowed,
    #[error("the provider no longer accepts this connection; the member must reconnect")]
    ReconnectRequired,
    #[error("the provider could not be reached")]
    Upstream,
    #[error("the provider's response is larger than the broker relays")]
    TooLarge,
    #[error("{0}")]
    Internal(String),
}

impl Error {
    pub fn internal(message: impl Into<String>) -> Self {
        Error::Internal(message.into())
    }
}

impl From<sqlx::Error> for Error {
    fn from(e: sqlx::Error) -> Self {
        Error::internal(format!("database: {e}"))
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            Error::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Error::Malformed(_) => (StatusCode::BAD_REQUEST, "malformed"),
            Error::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            Error::StateInvalid => (StatusCode::BAD_REQUEST, "state_invalid"),
            Error::ExchangeFailed => (StatusCode::BAD_GATEWAY, "exchange_failed"),
            Error::CertInvalid => (StatusCode::UNAUTHORIZED, "cert_invalid"),
            Error::NotAllowed => (StatusCode::FORBIDDEN, "not_allowed"),
            Error::ReconnectRequired => (StatusCode::CONFLICT, "reconnect_required"),
            Error::Upstream => (StatusCode::BAD_GATEWAY, "upstream"),
            Error::TooLarge => (StatusCode::BAD_GATEWAY, "too_large"),
            Error::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
        };
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

fn bearer(parts: &Parts, expected: &[u8]) -> Result<(), Error> {
    let presented = parts
        .headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(Error::Unauthorized)?;
    if alpha_client::bearer_matches(presented.as_bytes(), expected) {
        Ok(())
    } else {
        Err(Error::Unauthorized)
    }
}

/// Proof of the tenant backend's connect bearer, extracted before any handler runs.
pub struct AuthedCorpus;

impl FromRequestParts<Arc<AppState>> for AuthedCorpus {
    type Rejection = Error;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        bearer(parts, &state.secrets.read().connect_bearer).map(|()| AuthedCorpus)
    }
}

/// An Instance's leaf, already chained to the KMS CA in the handshake, then the proxy bearer.
/// A KMS node's leaf chains to the same CA but does not carry an Instance's SANs.
pub struct AuthedInstance;

impl FromRequestParts<Arc<AppState>> for AuthedInstance {
    type Rejection = Error;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let leaf = parts
            .extensions
            .get::<alpha_client::tls::PeerCerts>()
            .and_then(|peer| peer.0.first())
            .ok_or(Error::CertInvalid)?;
        alpha_client::tls::uri_sans(leaf)
            .and_then(|sans| alpha_client::tls::parse_instance_sans(&sans))
            .map_err(|_| Error::CertInvalid)?;
        bearer(parts, &state.secrets.read().proxy_bearer).map(|()| AuthedInstance)
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
        .route("/connections/{id}", delete(connect::disconnect))
        .route("/proxy", post(proxy::proxy))
        .route(
            "/write",
            post(proxy::write).layer(DefaultBodyLimit::max(proxy::WRITE_BODY_LIMIT)),
        )
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
            "DROPBOX_CLIENT_ID" => Some("dropbox-app-key".into()),
            "OAUTH_REDIRECT_BASE" => Some("https://corpus.example/oauth/".into()),
            _ => None,
        }
    }

    #[test]
    fn config_build_accepts_the_valid_baseline() {
        let config = Config::build(valid_env).unwrap();
        assert_eq!(
            config.client_id(&oauth::GOOGLE).unwrap(),
            "client.apps.googleusercontent.com"
        );
        assert_eq!(
            config.client_id(&oauth::DROPBOX).unwrap(),
            "dropbox-app-key"
        );
        assert_eq!(
            config.redirect_uri(&oauth::DROPBOX),
            "https://corpus.example/oauth/dropbox/callback"
        );
    }

    #[test]
    fn config_build_refuses_a_missing_or_blank_client_id_naming_it() {
        for variable in ["GOOGLE_CLIENT_ID", "DROPBOX_CLIENT_ID"] {
            for value in [None, Some(" ")] {
                let err = Config::build(|n| {
                    if n == variable {
                        value.map(str::to_owned)
                    } else {
                        valid_env(n)
                    }
                })
                .unwrap_err();
                assert!(err.to_string().contains(variable), "{err}");
            }
        }
    }

    #[test]
    fn config_build_refuses_a_missing_or_http_redirect_base_naming_it() {
        for value in [None, Some("http://corpus.example/oauth")] {
            let err = Config::build(|n| {
                if n == "OAUTH_REDIRECT_BASE" {
                    value.map(str::to_owned)
                } else {
                    valid_env(n)
                }
            })
            .unwrap_err();
            assert!(err.to_string().contains("OAUTH_REDIRECT_BASE"), "{err}");
        }
    }
}
