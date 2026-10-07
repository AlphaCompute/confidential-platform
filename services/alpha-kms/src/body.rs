use axum::body::Bytes;
use axum::extract::{FromRequest, Request};
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::error::ApiError;

/// A JSON body and the value it was parsed from; refused as `malformed` when it does not parse,
/// repeats a key at any depth, or does not fit `T`. Unknown fields are the type's business.
pub struct Body<T>(pub T, pub Value);

impl<S: Send + Sync, T: DeserializeOwned> FromRequest<S> for Body<T> {
    type Rejection = ApiError;

    async fn from_request(request: Request, state: &S) -> Result<Self, ApiError> {
        let bytes = Bytes::from_request(request, state)
            .await
            .map_err(|e| ApiError::malformed(e.body_text()))?;
        let value =
            alpha_core::parse(&bytes).map_err(|e| ApiError::malformed(format!("body: {e}")))?;
        let parsed =
            T::deserialize(&value).map_err(|e| ApiError::malformed(format!("body: {e}")))?;
        Ok(Body(parsed, value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn extract(bytes: &'static [u8]) -> Result<Body<Value>, ApiError> {
        let request = Request::new(axum::body::Body::from(bytes));
        Body::<Value>::from_request(request, &()).await
    }

    #[tokio::test]
    async fn a_repeated_key_anywhere_in_a_body_is_malformed() {
        for bytes in [
            &br#"{"payload":{},"payload":{}}"#[..],
            br#"{"payload":{},"payload":{}}"#,
            br#"{"payload":{"app_id":1,"app_id":2}}"#,
        ] {
            let Err(e) = extract(bytes).await else {
                panic!("accepted {}", String::from_utf8_lossy(bytes));
            };
            assert_eq!(e.code, "malformed");
        }
    }

    #[tokio::test]
    async fn a_body_hands_back_the_value_it_parsed() {
        let bytes = br#"{"payload":{"app_id":"x","n":[1,2.5]},"signature":null}"#;
        let Ok(Body(parsed, value)) = extract(bytes).await else {
            panic!("refused a valid body");
        };
        let expected = serde_json::from_slice::<Value>(bytes).unwrap();
        assert_eq!(parsed, expected);
        assert_eq!(value, expected);
    }
}
