//! `alpha instances`: an App's copies through shroud-go, under the organization's API key.

use std::time::Duration;

use alpha_core::{AppId, ComposeHash};
use reqwest::Method;
use serde_json::{Value, json};

use crate::deploy::{Shroud, wait_for_attestation};

/// One shroud-go route; a reply outside 2xx is an error carrying shroud-go's body.
pub async fn shroud_call(
    shroud: &Shroud,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> Result<Value, String> {
    let mut request = reqwest::Client::new()
        .request(
            method,
            format!("{}{path}", shroud.url.trim_end_matches('/')),
        )
        .bearer_auth(&shroud.api_key);
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request
        .send()
        .await
        .map_err(|e| format!("shroud-go: {e}"))?;
    let status = response.status();
    let body: Value = response.json().await.unwrap_or(Value::Null);
    if !status.is_success() {
        return Err(format!("shroud-go {path}: {status}: {body}"));
    }
    Ok(body)
}

pub async fn list(shroud: &Shroud, app: AppId) -> Result<Value, String> {
    shroud_call(
        shroud,
        Method::GET,
        &format!("/v1/apps/{app}/instances"),
        None,
    )
    .await
}

/// Adds a copy of the App's current Revision. With `wait`, returns only once the copy's
/// Endpoint presents a leaf from the KMS CA naming the Revision shroud-go says it runs.
pub async fn add(
    shroud: &Shroud,
    app: AppId,
    resources: Option<Value>,
    wait: Option<(Duration, &str)>,
) -> Result<Value, String> {
    let body = match resources {
        Some(resources) => json!({ "resources": resources }),
        None => json!({}),
    };
    let path = format!("/v1/apps/{app}/instances");
    let instance = shroud_call(shroud, Method::POST, &path, Some(body)).await?;
    let Some((deadline, kms_ca_pem)) = wait else {
        return Ok(instance);
    };
    let field = |name: &str| {
        instance
            .get(name)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("shroud-go {path}: no {name} to wait on in {instance}"))
    };
    let expected: ComposeHash = field("compose_hash")?
        .parse()
        .map_err(|e| format!("shroud-go {path}: compose_hash: {e}"))?;
    let attested = wait_for_attestation(field("url")?, kms_ca_pem, expected, deadline).await?;
    Ok(json!({ "instance": instance, "attested": attested }))
}
