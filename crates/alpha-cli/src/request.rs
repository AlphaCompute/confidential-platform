//! `alpha request`: one HTTP request to one or every live copy of an App, under a bearer the
//! App itself defines. shroud-go's list only says where to look; each copy must first prove,
//! by its KMS-issued leaf, that it is the App's own before the bearer is sent.

use std::time::Duration;

use alpha_client::{Pin, Probe, probe_instance, system_time_provider, tls};
use alpha_core::{AppId, ComposeHash};
use reqwest::Method;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::deploy::Shroud;
use crate::instances;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

pub struct Call<'a> {
    pub method: Method,
    pub path: &'a str,
    pub bearer: &'a str,
    pub body: Option<&'a Value>,
}

/// Probes `url` under the KMS CA, refuses a leaf of any App but `app`, then sends `call` over a
/// connection pinned to the Revision the probe saw: a Revision's compose names its App, so the
/// second connection cannot land on another App's Instance.
pub async fn send_to(
    url: &str,
    listed: ComposeHash,
    app: AppId,
    kms_ca_pem: &str,
    call: &Call<'_>,
) -> Result<Value, String> {
    // A copy mid-deploy may still serve the previous Revision; it is the App's own all the same.
    let sans = match probe_instance(url, kms_ca_pem, &listed, system_time_provider())
        .await
        .map_err(|e| format!("probe: {e}"))?
    {
        Probe::Attested(sans) | Probe::OtherRevision(sans) => sans,
        Probe::Silent(why) => return Err(format!("no Instance leaf from the KMS CA: {why}")),
    };
    if sans.app_id != app {
        return Err(format!(
            "the Endpoint presents App {}, not {app}",
            sans.app_id
        ));
    }
    let ca = tls::cert_from_pem(kms_ca_pem).map_err(|e| e.to_string())?;
    let pin = Pin::CaAndInstanceRevisions(ca, vec![sans.compose_hash]);
    let http = reqwest::Client::builder()
        .tls_backend_preconfigured(
            tls::client_config(Some(pin), None, system_time_provider())
                .map_err(|e| e.to_string())?,
        )
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(|e| format!("http client: {e}"))?;
    let mut request = http
        .request(
            call.method.clone(),
            format!("{}{}", url.trim_end_matches('/'), call.path),
        )
        .bearer_auth(call.bearer);
    if let Some(body) = call.body {
        request = request.json(body);
    }
    let response = request.send().await.map_err(|e| format!("{url}: {e}"))?;
    let status = response.status().as_u16();
    let text = response.text().await.map_err(|e| format!("{url}: {e}"))?;
    Ok(json!({
        "compose_hash": sans.compose_hash.to_string(),
        "status": status,
        "body": serde_json::from_str(&text).unwrap_or(Value::String(text)),
    }))
}

/// `instance`, or every copy shroud-go lists when `None`. One entry per copy in shroud-go's
/// order, each tagged by its `instance`; a copy that fails carries `error`, the others are
/// still served, and the flag says whether any failed.
pub async fn run(
    shroud: &Shroud,
    app: AppId,
    instance: Option<Uuid>,
    kms_ca_pem: &str,
    call: &Call<'_>,
) -> Result<(Value, bool), String> {
    let listed = instances::list(shroud, app).await?;
    let copies = listed
        .get("instances")
        .and_then(Value::as_array)
        .ok_or_else(|| format!("shroud-go listed no instances: {listed}"))?;
    let targets: Vec<&Value> = match instance {
        None => copies.iter().collect(),
        Some(iid) => {
            let iid = iid.to_string();
            let copy = copies
                .iter()
                .find(|c| c.get("id").and_then(Value::as_str) == Some(iid.as_str()))
                .ok_or_else(|| format!("{iid} is not a live copy of App {app}"))?;
            vec![copy]
        }
    };
    let (mut responses, mut failed) = (Vec::new(), false);
    for copy in targets {
        let instance = copy.get("id").cloned().unwrap_or(Value::Null);
        let reply = async {
            let field = |name: &str| {
                copy.get(name)
                    .and_then(Value::as_str)
                    .ok_or_else(|| format!("no {name} in {copy}"))
            };
            let hash: ComposeHash = field("compose_hash")?
                .parse()
                .map_err(|e| format!("compose_hash: {e}"))?;
            send_to(field("url")?, hash, app, kms_ca_pem, call).await
        }
        .await;
        responses.push(match reply {
            Ok(mut reply) => {
                if let Some(fields) = reply.as_object_mut() {
                    fields.insert("instance".into(), instance);
                }
                reply
            }
            Err(error) => {
                failed = true;
                json!({ "instance": instance, "error": error })
            }
        });
    }
    Ok((json!({ "responses": responses }), failed))
}
