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
mod revisions;
mod tickets;

use std::sync::Arc;

use axum::extract::rejection::JsonRejection;
use axum::extract::{DefaultBodyLimit, FromRequestParts, State};
use axum::http::request::Parts;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
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
    pub platform_document_url: String,
    pub release_keys: alpha_client::platform::ReleaseKeys,
    /// Where the signer page lives, for example `https://sign.alphacompute.cc`.
    pub signer_url: String,
    pub oidc: Oidc,
    pub code_lookups: Limiter,
}

/// ponytail: one count per process, so it bounds the code lookups of the single replica; with
/// more replicas the count moves to Postgres or the edge.
#[derive(Default)]
pub struct Limiter(parking_lot::Mutex<(u64, u32)>);

/// A code has 40 bits, so a guess finds an open ticket only after billions of tries at this rate.
const CODE_LOOKUPS_PER_SECOND: u32 = 20;

impl Limiter {
    fn allow(&self) -> bool {
        let second = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |t| t.as_secs());
        let mut window = self.0.lock();
        if window.0 != second {
            *window = (second, 0);
        }
        window.1 = window.1.saturating_add(1);
        window.1 <= CODE_LOOKUPS_PER_SECOND
    }
}

/// The identity provider's public client that the signer page signs owners in with.
pub struct Oidc {
    pub issuer: String,
    pub token_endpoint: String,
    pub client_id: String,
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
    Unavailable(String),
    #[error("no such ticket")]
    TicketNotFound,
    #[error("the ticket has expired")]
    TicketExpired,
    #[error("the ticket is closed")]
    TicketClosed,
    #[error("the sign-in is not the Organization's owner")]
    SessionRefused,
    #[error("too many requests; retry in a second")]
    RateLimited,
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
            Error::Forbidden => (StatusCode::FORBIDDEN, "forbidden"),
            Error::Malformed(_) => (StatusCode::BAD_REQUEST, "malformed"),
            Error::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            Error::Conflict(_) => (StatusCode::CONFLICT, "conflict"),
            Error::Unavailable(_) => (StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
            Error::TicketNotFound => (StatusCode::NOT_FOUND, "ticket_not_found"),
            Error::TicketExpired => (StatusCode::GONE, "ticket_expired"),
            Error::TicketClosed => (StatusCode::CONFLICT, "ticket_closed"),
            Error::SessionRefused => (StatusCode::FORBIDDEN, "session_refused"),
            Error::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
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
        let mut response = (status, Json(body)).into_response();
        if matches!(self, Error::RateLimited) {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, header::HeaderValue::from_static("1"));
        }
        response
    }
}

pub const SCOPES: [&str; 5] = ["apps:read", "apps:write", "deploy", "org:admin", "onboard"];

fn fill(bytes: &mut [u8]) -> Result<(), Error> {
    getrandom::fill(bytes).map_err(|e| Error::internal(format!("rng: {e}")))
}

fn random<const N: usize>() -> Result<[u8; N], Error> {
    let mut bytes = [0u8; N];
    fill(&mut bytes)?;
    Ok(bytes)
}

/// A new operational API key `alpha_<base32>` and the SHA-256 its row keeps.
pub fn mint_token() -> Result<(String, [u8; 32]), Error> {
    let mut secret = Zeroizing::new([0u8; 32]);
    fill(secret.as_mut_slice())?;
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
    /// The only link issuer an onboarding key may claim.
    pub issuer: Option<String>,
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
        if alpha_client::bearer_matches(&hash, &state.operator_token_sha256) {
            return Ok(Caller::Operator);
        }
        sqlx::query_as(
            "select k.id, k.org_id, k.scopes, k.issuer from api_keys k \
             left join organizations o on o.id = k.org_id \
             where k.token_sha256 = $1 and k.revoked_at is null and o.disabled_at is null",
        )
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
        .route("/v1/orgs/{org}/disable", post(orgs::disable))
        .route("/v1/orgs/{org}/keys/{id}", delete(orgs::revoke_key))
        .route("/v1/orgs/{org}/tickets", post(tickets::claim))
        .route("/v1/apps/{slug}", put(apps::put))
        .route(
            "/v1/apps/{slug}/revisions",
            // A catalog file carries a whole init-data, up to 1 MiB.
            post(revisions::create).layer(DefaultBodyLimit::max(2 << 20)),
        )
        .route("/v1/apps/{slug}/revisions/{hash}", get(revisions::get))
        .route("/v1/tickets/{ticket}", get(tickets::read))
        .route("/v1/tickets/by-code/{code}", get(tickets::by_code))
        .route("/v1/tickets/{ticket}/session", post(tickets::session))
        .route("/v1/tickets/{ticket}/decline", post(tickets::decline))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .merge(probe_routes())
        .with_state(state)
}
