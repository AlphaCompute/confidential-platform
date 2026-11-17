//! The control plane: Organizations, their operational API keys and their Apps. It holds no
//! roster key and no Secret value, so no bearer credential it accepts can sign, register,
//! enrol, revoke or seal anything; such an action needs a signature the KMS verifies.

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

mod apps;
mod orgs;

use std::sync::Arc;

use axum::extract::rejection::JsonRejection;
use axum::extract::{DefaultBodyLimit, FromRequestParts, State};
use axum::http::request::Parts;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;
use zeroize::Zeroizing;

pub async fn migrate(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    sqlx::migrate!("./migrations").run(pool).await
}

pub struct AppState {
    pub pool: PgPool,
    pub operator_token_sha256: [u8; 32],
}

/// The closed set of error codes; no message carries a token.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("missing or invalid bearer")]
    Unauthorized,
    #[error("this credential may not do that")]
    Forbidden,
    #[error("{0}")]
    Malformed(String),
    #[error("not found")]
    NotFound,
    #[error("{0}")]
    Conflict(&'static str),
    #[error("{0}")]
    Internal(String),
}

impl Error {
    pub fn internal(message: impl Into<String>) -> Self {
        Error::Internal(message.into())
    }

    pub fn code(&self) -> &'static str {
        self.parts().1
    }

    fn parts(&self) -> (StatusCode, &'static str) {
        match self {
            Error::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Error::Forbidden => (StatusCode::FORBIDDEN, "forbidden"),
            Error::Malformed(_) => (StatusCode::BAD_REQUEST, "malformed"),
            Error::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            Error::Conflict(_) => (StatusCode::CONFLICT, "conflict"),
            Error::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
        }
    }
}

impl From<sqlx::Error> for Error {
    fn from(e: sqlx::Error) -> Self {
        Error::internal(format!("database: {e}"))
    }
}

impl From<JsonRejection> for Error {
    fn from(e: JsonRejection) -> Self {
        Error::Malformed(e.body_text())
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let (status, code) = self.parts();
        let request_id = Uuid::now_v7();
        let message = match &self {
            Error::Internal(detail) => {
                alpha_client::error!(
                    "internal",
                    request_id = alpha_client::log::Field::text(&request_id.to_string()),
                    error = alpha_client::log::Field::text(detail.as_str()),
                );
                "internal error".to_owned()
            }
            other => other.to_string(),
        };
        let body =
            json!({ "error": { "code": code, "message": message, "request_id": request_id } });
        (status, Json(body)).into_response()
    }
}

pub const SCOPES: [&str; 5] = ["apps:read", "apps:write", "deploy", "org:admin", "onboard"];

/// A new operational API key `alpha_<base32>` and the SHA-256 its row keeps.
pub fn mint_token() -> Result<(String, [u8; 32]), Error> {
    let mut secret = Zeroizing::new([0u8; 32]);
    getrandom::fill(secret.as_mut_slice()).map_err(|e| Error::internal(format!("rng: {e}")))?;
    let token = format!(
        "alpha_{}",
        data_encoding::BASE32_NOPAD
            .encode(secret.as_slice())
            .to_ascii_lowercase()
    );
    let hash = Sha256::digest(token.as_bytes()).into();
    Ok((token, hash))
}

/// An operational API key's row.
#[derive(Debug, sqlx::FromRow)]
pub struct Key {
    pub id: Uuid,
    /// None for an onboarding key.
    pub org_id: Option<Uuid>,
    pub scopes: Vec<String>,
}

/// Who presented the bearer.
#[derive(Debug)]
pub enum Caller {
    Operator,
    Key(Key),
}

impl Caller {
    fn actor(&self) -> String {
        match self {
            Caller::Operator => "operator".to_owned(),
            Caller::Key(key) => format!("key:{}", key.id),
        }
    }

    pub fn has(&self, scope: &str) -> bool {
        matches!(self, Caller::Key(key) if key.scopes.iter().any(|s| s == scope))
    }

    /// The Organization of a key that holds `scope`; the operator never acts as one.
    pub fn org(&self, scope: &str) -> Result<Uuid, Error> {
        match self {
            Caller::Key(Key {
                org_id: Some(org), ..
            }) if self.has(scope) => Ok(*org),
            _ => Err(Error::Forbidden),
        }
    }
}

impl FromRequestParts<Arc<AppState>> for Caller {
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
        let hash: [u8; 32] = Sha256::digest(presented.as_bytes()).into();
        if hash == state.operator_token_sha256 {
            return Ok(Caller::Operator);
        }
        sqlx::query_as("select id, org_id, scopes from api_keys where token_sha256 = $1")
            .bind(hash.as_slice())
            .fetch_optional(&state.pool)
            .await?
            .map(Caller::Key)
            .ok_or(Error::Unauthorized)
    }
}

/// Every mutation writes its row in the mutation's own transaction.
pub async fn audit(
    tx: &mut Transaction<'_, Postgres>,
    caller: &Caller,
    org_id: Uuid,
    action: &str,
    object: &str,
    details: serde_json::Value,
) -> Result<(), Error> {
    sqlx::query(
        "insert into audit_log (actor, org_id, action, object, details) \
         values ($1, $2, $3, $4, $5)",
    )
    .bind(caller.actor())
    .bind(org_id)
    .bind(action)
    .bind(object)
    .bind(details)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn healthz() -> StatusCode {
    StatusCode::OK
}

async fn ready(State(state): State<Arc<AppState>>) -> Result<StatusCode, Error> {
    sqlx::query("select 1").execute(&state.pool).await?;
    Ok(StatusCode::OK)
}

/// `/healthz` and `/ready` alone, for the kubelet on a plain port: the API port serves no
/// certificate until the first ACME order, and the CA reaches the pod only once it is ready.
fn probe_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/ready", get(ready))
}

pub fn probes(state: Arc<AppState>) -> Router {
    probe_routes().with_state(state)
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/orgs", post(orgs::create))
        .route("/v1/apps/{slug}", put(apps::put))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .merge(probe_routes())
        .with_state(state)
}
