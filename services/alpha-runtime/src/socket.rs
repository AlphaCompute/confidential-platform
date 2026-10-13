//! The routes on the unix socket: HTTP/1.1, JSON, no authentication — access is the
//! right to the socket. KMS errors pass through in their own envelope with their status.

use std::sync::Arc;

use alpha_client::DerivedKey;
use alpha_core::RequestId;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use serde_json::{Value, json};

use crate::{Error, Runtime};

pub fn router(runtime: Arc<Runtime>) -> Router {
    Router::new()
        .route("/v1/identity", get(identity))
        .route("/v1/secrets/{name}", get(secret))
        .route("/v1/keys/{purpose}", get(key))
        .route("/v1/evidence-bundle", get(evidence_bundle))
        .route("/healthz", get(healthz))
        .fallback(|| async { envelope(StatusCode::NOT_FOUND, "not_found", "no such route") })
        .with_state(runtime)
}

pub fn rfc3339(t: std::time::SystemTime) -> String {
    chrono::DateTime::<chrono::Utc>::from(t).to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn envelope(status: StatusCode, code: &str, message: impl Into<String>) -> Response {
    let body = json!({ "error": {
        "code": code, "message": message.into(), "request_id": RequestId::mint(),
    }});
    (status, Json(body)).into_response()
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        match self {
            Error::Kms(alpha_client::Error::Api(e)) => (
                StatusCode::from_u16(e.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                Json(json!({ "error": {
                    "code": e.code, "message": e.message, "request_id": e.request_id,
                }})),
            )
                .into_response(),
            Error::NotAttested => envelope(
                StatusCode::SERVICE_UNAVAILABLE,
                "not_attested",
                self.to_string(),
            ),
            other => envelope(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                other.to_string(),
            ),
        }
    }
}

pub fn identity_json(runtime: &Runtime) -> Result<Value, Error> {
    let attested = runtime.attested().ok_or(Error::NotAttested)?;
    let mut identity = json!({
        "app_id": attested.identity.app_id,
        "org_id": attested.identity.org_id,
        "compose_hash": attested.identity.compose_hash,
        "certificate_chain": attested.chain_pem,
        "tls_private_key": BASE64_URL_SAFE_NO_PAD.encode(runtime.tls_private_key()),
        "attestation_result": attested.result,
        "app_compose": runtime.app_compose,
    });
    if let (Some(initdata), Some(fields)) = (runtime.initdata(), identity.as_object_mut()) {
        fields.insert(
            "initdata".into(),
            json!(BASE64_URL_SAFE_NO_PAD.encode(initdata)),
        );
    }
    Ok(identity)
}

async fn identity(State(runtime): State<Arc<Runtime>>) -> Result<Json<Value>, Error> {
    identity_json(&runtime).map(Json)
}

async fn secret(
    State(runtime): State<Arc<Runtime>>,
    Path(name): Path<String>,
) -> Result<Json<Value>, Error> {
    runtime.secret(&name).await.map(|s| Json(json!(s)))
}

async fn key(
    State(runtime): State<Arc<Runtime>>,
    Path(purpose): Path<String>,
) -> Result<Json<DerivedKey>, Error> {
    runtime.key(&purpose).await.map(Json)
}

/// The current leaf's evidence bundle (PRD-06 clear claims): the request, the leaf and the KMS's
/// receipt naming the verifiers that attested this workload. 404 from a KMS that sends no receipt.
async fn evidence_bundle(State(runtime): State<Arc<Runtime>>) -> Result<Response, Error> {
    let attested = runtime.attested().ok_or(Error::NotAttested)?;
    Ok(match &attested.bundle {
        Some(bundle) => Json(bundle).into_response(),
        None => envelope(
            StatusCode::NOT_FOUND,
            "not_found",
            "the KMS sent no attestation receipt",
        ),
    })
}

pub fn healthz_json(runtime: &Runtime) -> Value {
    json!({
        "attested": runtime.attested().is_some(),
        "cert_not_after": runtime.last().map(|a| rfc3339(a.not_after)),
    })
}

async fn healthz(State(runtime): State<Arc<Runtime>>) -> Json<Value> {
    Json(healthz_json(&runtime))
}
