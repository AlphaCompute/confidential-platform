use alpha_core::RequestId;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::json;

/// One of the wire error codes with its message; `request_id` is minted when the response is built.
#[derive(Debug)]
pub struct ApiError {
    pub code: &'static str,
    pub message: String,
}

impl ApiError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn malformed(message: impl Into<String>) -> Self {
        Self::new("malformed", message)
    }

    pub fn signature_invalid(message: impl Into<String>) -> Self {
        Self::new("signature_invalid", message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new("not_found", message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new("internal", message)
    }

    pub fn status(&self) -> StatusCode {
        match self.code {
            "signature_invalid" | "nonce_invalid" | "malformed" => StatusCode::BAD_REQUEST,
            "cert_invalid" => StatusCode::UNAUTHORIZED,
            "attestation_failed" | "attestation_unknown" | "policy_denied" => StatusCode::FORBIDDEN,
            "revision_revoked" | "already_exists" => StatusCode::CONFLICT,
            "not_found" => StatusCode::NOT_FOUND,
            "rate_limited" => StatusCode::TOO_MANY_REQUESTS,
            "sealed" => StatusCode::SERVICE_UNAVAILABLE,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// `ok` for a success, `denied` for a refusal the caller caused, `error` for our fault.
    pub fn outcome(&self) -> &'static str {
        if self.code == "internal" {
            "error"
        } else {
            "denied"
        }
    }

    pub fn details(&self) -> serde_json::Value {
        json!({ "code": self.code, "message": self.message })
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = json!({ "error": {
            "code": self.code,
            "message": self.message,
            "request_id": RequestId::mint(),
        }});
        let mut response = (self.status(), axum::Json(body)).into_response();
        let retry_after = match self.code {
            "rate_limited" => Some("1"),
            "sealed" => Some("30"),
            _ => None,
        };
        if let Some(seconds) = retry_after {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, seconds.parse().unwrap());
        }
        response
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        Self::internal(format!("database: {e}"))
    }
}

impl From<alpha_attest::AppraisalError> for ApiError {
    fn from(e: alpha_attest::AppraisalError) -> Self {
        Self::new(e.code(), e.to_string())
    }
}

impl From<alpha_core::RegistrationError> for ApiError {
    fn from(e: alpha_core::RegistrationError) -> Self {
        Self::new(e.code(), e.to_string())
    }
}
