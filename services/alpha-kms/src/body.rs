use axum::body::Bytes;
use axum::extract::{FromRequest, Request};
use serde::de::DeserializeOwned;

use crate::error::ApiError;

/// A JSON body, rejected as `malformed`; unknown fields are the type's business.
pub struct Body<T>(pub T);

impl<S: Send + Sync, T: DeserializeOwned> FromRequest<S> for Body<T> {
    type Rejection = ApiError;

    async fn from_request(request: Request, state: &S) -> Result<Self, ApiError> {
        let bytes = Bytes::from_request(request, state)
            .await
            .map_err(|e| ApiError::malformed(e.body_text()))?;
        serde_json::from_slice(&bytes)
            .map(Body)
            .map_err(|e| ApiError::malformed(format!("body: {e}")))
    }
}
