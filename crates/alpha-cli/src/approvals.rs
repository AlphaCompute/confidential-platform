//! `alpha approvals prepare`: one shroud-go approval request per App for the re-approval
//! campaign (PRD-05 M3). Moving an App to a Kata pod changes its Revision (compose → Revision v2),
//! and only the App's organization can approve a Revision, with a passkey on the signer page.
//! This only asks: for each App's `alpha coco wrap` output it opens the request
//! (`POST /v1/apps/{id}/approval-requests`) and prints the signer link to send the organization.
//!
//! Idempotent: shroud-go keeps one live request per App and Revision and returns it on a repeat,
//! and answers 409 `approved` once the Revision is the App's latest; a link lives 30 minutes, so
//! a campaign reruns the same batch to refresh the links still pending. No secret passes through
//! here: the request carries Secret names, and the values are sealed on the signer page.

use std::path::{Path, PathBuf};

use alpha_core::coco::InitData;
use alpha_core::{AppId, ComposeHash};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::deploy::Shroud;

/// The batch file: one entry per App to move.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Batch {
    pub requests: Vec<Entry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    /// The JSON `alpha coco wrap` printed for the App, relative to the batch file.
    pub wrapped: PathBuf,
    /// The Rafay environment name shroud-go shows with the request.
    pub title: String,
    /// The machine shape token the offer runs the App on.
    pub machine: String,
}

/// What this reads of `alpha coco wrap`'s output; the pod spec is not sent.
#[derive(Debug, Deserialize)]
pub struct Wrapped {
    pub revision: String,
    pub revision_hash: ComposeHash,
    /// Standard base64 of the init-data TOML.
    pub initdata: String,
    #[serde(default)]
    pub secrets: Vec<String>,
}

/// One request, checked before anything is sent: the Revision hashes to `revision_hash` and is
/// exactly the Revision v2 the init-data stands for, so the signer page will show the pod's own
/// policy for what is approved.
#[derive(Debug, PartialEq, Eq)]
pub struct Prepared {
    pub app_id: AppId,
    pub title: String,
    pub compose_hash: ComposeHash,
    pub body: Value,
}

pub fn read_batch(path: &Path) -> Result<Vec<(PathBuf, Entry)>, String> {
    let text = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let batch: Batch =
        serde_json::from_slice(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    let dir = path.parent().unwrap_or(Path::new("."));
    Ok(batch
        .requests
        .into_iter()
        .map(|entry| (dir.join(&entry.wrapped), entry))
        .collect())
}

pub fn prepare(entry: &Entry, wrapped: &Wrapped) -> Result<Prepared, String> {
    if alpha_core::compose_hash(&wrapped.revision) != wrapped.revision_hash {
        return Err("revision does not hash to revision_hash".into());
    }
    let initdata = BASE64_STANDARD
        .decode(&wrapped.initdata)
        .map_err(|_| "initdata is not standard base64".to_owned())?;
    let revision = InitData::parse(&initdata)
        .and_then(|d| d.revision())
        .map_err(|e| format!("initdata: {e}"))?;
    if revision.canonical().map_err(|e| format!("initdata: {e}"))? != wrapped.revision {
        return Err("initdata does not stand for this revision".into());
    }
    Ok(Prepared {
        app_id: revision.app_id,
        title: entry.title.clone(),
        compose_hash: wrapped.revision_hash,
        body: json!({
            "compose_hash": wrapped.revision_hash,
            "title": entry.title,
            "compose": wrapped.revision,
            "machine": entry.machine,
            "secrets": wrapped.secrets,
            "initdata": wrapped.initdata,
        }),
    })
}

/// shroud-go's answer as a line of the report: the link of a live request (`created` says
/// whether this run opened it), `approved` with no link, or the error.
pub fn outcome(prepared: &Prepared, status: reqwest::StatusCode, body: &Value) -> Value {
    let mut line = json!({
        "app_id": prepared.app_id,
        "title": prepared.title,
        "compose_hash": prepared.compose_hash,
    });
    let field = |name: &str| body.get(name).cloned().unwrap_or(Value::Null);
    let state = body
        .get("error")
        .and_then(|e| e.get("details"))
        .and_then(|d| d.get("state"))
        .and_then(Value::as_str);
    let fields = match status.as_u16() {
        200 | 201 => json!({
            "state": field("state"),
            "created": status == reqwest::StatusCode::CREATED,
            "request_id": field("id"),
            "approval_url": field("approval_url"),
            "expires_at": field("expires_at"),
        }),
        409 if state == Some("approved") => json!({ "state": "approved" }),
        _ => json!({ "error": format!("shroud-go: {status}: {body}") }),
    };
    if let (Some(line), Some(fields)) = (line.as_object_mut(), fields.as_object()) {
        line.extend(fields.clone());
    }
    line
}

/// Opens or finds every request of the batch, in order, and reports each; `true` when any failed.
pub async fn prepare_all(shroud: &Shroud, batch: &Path) -> Result<(Value, bool), String> {
    let http = reqwest::Client::new();
    let mut lines = Vec::new();
    let mut failed = false;
    for (path, entry) in read_batch(batch)? {
        let prepared = std::fs::read(&path)
            .map_err(|e| format!("{}: {e}", path.display()))
            .and_then(|text| {
                serde_json::from_slice::<Wrapped>(&text)
                    .map_err(|e| format!("{}: {e}", path.display()))
            })
            .and_then(|wrapped| {
                prepare(&entry, &wrapped).map_err(|e| format!("{}: {e}", path.display()))
            });
        let prepared = match prepared {
            Ok(prepared) => prepared,
            Err(e) => {
                failed = true;
                lines.push(json!({ "wrapped": path, "title": entry.title, "error": e }));
                continue;
            }
        };
        let url = format!(
            "{}/v1/apps/{}/approval-requests",
            shroud.url.trim_end_matches('/'),
            prepared.app_id
        );
        let line = match http
            .post(url)
            .bearer_auth(&shroud.api_key)
            .json(&prepared.body)
            .send()
            .await
        {
            Ok(response) => {
                let status = response.status();
                let text = response.text().await.unwrap_or_default();
                let body = serde_json::from_str(&text).unwrap_or(Value::String(text));
                outcome(&prepared, status, &body)
            }
            Err(e) => outcome(
                &prepared,
                reqwest::StatusCode::BAD_GATEWAY,
                &Value::String(e.to_string()),
            ),
        };
        failed |= line.get("error").is_some();
        lines.push(line);
    }
    Ok((json!({ "requests": lines }), failed))
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use reqwest::StatusCode;

    use super::*;

    const APP: &str = "01994b3e-5c8a-7d3e-9a1b-2c3d4e5f6a7b";

    fn initdata(policy: &str) -> String {
        format!(
            "algorithm = \"sha384\"\nversion = \"0.1.0\"\n\n[data]\n\"policy.rego\" = '''\n{policy}'''\n\"alpha.json\" = '''{{\"app_id\":\"{APP}\",\"format\":\"alphacompute-initdata/1\",\"runtime_class\":\"kata-qemu-tdx\"}}'''\n"
        )
    }

    fn wrapped(policy: &str) -> Wrapped {
        let text = initdata(policy);
        let revision = InitData::parse(text.as_bytes())
            .unwrap()
            .revision()
            .unwrap()
            .canonical()
            .unwrap();
        Wrapped {
            revision_hash: alpha_core::compose_hash(&revision),
            revision,
            initdata: BASE64_STANDARD.encode(text),
            secrets: vec!["db-password".into()],
        }
    }

    fn entry() -> Entry {
        Entry {
            wrapped: "app.json".into(),
            title: "corpus-app".into(),
            machine: "cpu-4c-8g".into(),
        }
    }

    #[test]
    fn a_request_carries_the_revision_its_init_data_stands_for() {
        let w = wrapped("package agent_policy\n");
        let prepared = prepare(&entry(), &w).unwrap();
        assert_eq!(prepared.app_id.to_string(), APP);
        assert_eq!(
            prepared.body,
            json!({ "compose_hash": w.revision_hash, "title": "corpus-app",
                    "compose": w.revision, "machine": "cpu-4c-8g",
                    "secrets": ["db-password"], "initdata": w.initdata })
        );

        let mut other = wrapped("package agent_policy\n");
        other.initdata = wrapped("package other\n").initdata;
        assert!(
            prepare(&entry(), &other)
                .unwrap_err()
                .contains("does not stand for")
        );
        let mut tampered = wrapped("package agent_policy\n");
        tampered.revision_hash = alpha_core::compose_hash("x");
        assert!(
            prepare(&entry(), &tampered)
                .unwrap_err()
                .contains("does not hash")
        );
        let mut garbled = wrapped("package agent_policy\n");
        garbled.initdata = "!".into();
        assert!(prepare(&entry(), &garbled).unwrap_err().contains("base64"));
    }

    #[test]
    fn shroud_gos_answers_become_links_approved_or_errors() {
        let prepared = prepare(&entry(), &wrapped("package agent_policy\n")).unwrap();
        let live = json!({ "id": "r1", "approval_url": "https://sign.example/sign/approve#t",
                           "expires_at": "2026-11-20T00:30:00Z", "state": "pending" });
        let line = outcome(&prepared, StatusCode::CREATED, &live);
        assert_eq!(line["created"], true);
        assert_eq!(line["approval_url"], "https://sign.example/sign/approve#t");
        assert_eq!(line["app_id"], APP);
        assert_eq!(outcome(&prepared, StatusCode::OK, &live)["created"], false);
        let approved =
            json!({ "error": { "code": "SHROUD_CONFLICT", "details": { "state": "approved" } } });
        let line = outcome(&prepared, StatusCode::CONFLICT, &approved);
        assert_eq!(line["state"], "approved");
        assert!(line.get("approval_url").is_none() && line.get("error").is_none());
        let other =
            json!({ "error": { "code": "SHROUD_CONFLICT", "details": { "state": "declined" } } });
        assert!(outcome(&prepared, StatusCode::CONFLICT, &other)["error"].is_string());
        assert!(outcome(&prepared, StatusCode::BAD_REQUEST, &json!({}))["error"].is_string());
    }

    /// A stand-in for shroud-go's create route: the first create of a hash is 201, a repeat
    /// 200 with the same request, and the App whose Revision is approved gets 409.
    #[tokio::test]
    async fn a_batch_rerun_returns_the_same_links_and_reports_what_failed() {
        use axum::extract::{Path as UrlPath, State};
        use axum::http::{HeaderMap, StatusCode};
        use axum::routing::post;

        type Seen = Arc<Mutex<Vec<(String, Value)>>>;
        let seen: Seen = Arc::default();
        async fn create(
            State(seen): State<Seen>,
            UrlPath(app): UrlPath<String>,
            headers: HeaderMap,
            axum::Json(body): axum::Json<Value>,
        ) -> (StatusCode, axum::Json<Value>) {
            assert_eq!(headers["authorization"], "Bearer org-key");
            if body["title"] == "approved-app" {
                return (
                    StatusCode::CONFLICT,
                    axum::Json(json!({ "error": { "details": { "state": "approved" } } })),
                );
            }
            let mut seen = seen.lock().unwrap();
            let repeat = seen.iter().any(|(a, b)| *a == app && b == &body);
            seen.push((app, body));
            let status = if repeat {
                StatusCode::OK
            } else {
                StatusCode::CREATED
            };
            (
                status,
                axum::Json(json!({ "id": "r1", "state": "pending",
                    "approval_url": "https://sign.example/sign/approve#t",
                    "expires_at": "2026-11-20T00:30:00Z" })),
            )
        }
        let app = axum::Router::new()
            .route("/v1/apps/{id}/approval-requests", post(create))
            .with_state(seen.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let shroud = Shroud {
            url: format!("http://{}/", listener.local_addr().unwrap()),
            api_key: "org-key".into(),
        };
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let dir = std::env::temp_dir().join(format!("alpha-approvals-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let w = wrapped("package agent_policy\n");
        let file = |w: &Wrapped| {
            json!({ "revision": w.revision, "revision_hash": w.revision_hash,
                    "initdata": w.initdata, "secrets": w.secrets, "pod_spec": {} })
        };
        std::fs::write(dir.join("app.json"), file(&w).to_string()).unwrap();
        let mut broken = file(&w);
        broken["revision_hash"] = json!(alpha_core::compose_hash("x"));
        std::fs::write(dir.join("broken.json"), broken.to_string()).unwrap();
        let batch = dir.join("batch.json");
        std::fs::write(
            &batch,
            json!({ "requests": [
                { "wrapped": "app.json", "title": "corpus-app", "machine": "cpu-4c-8g" },
                { "wrapped": "app.json", "title": "approved-app", "machine": "cpu-4c-8g" },
                { "wrapped": "broken.json", "title": "broken", "machine": "cpu-4c-8g" },
                { "wrapped": "missing.json", "title": "missing", "machine": "cpu-4c-8g" }
            ] })
            .to_string(),
        )
        .unwrap();

        let (report, failed) = prepare_all(&shroud, &batch).await.unwrap();
        assert!(failed);
        let lines = report["requests"].as_array().unwrap();
        assert_eq!(lines[0]["created"], true);
        assert_eq!(
            lines[0]["approval_url"],
            "https://sign.example/sign/approve#t"
        );
        assert_eq!(lines[1]["state"], "approved");
        assert!(
            lines[2]["error"]
                .as_str()
                .unwrap()
                .contains("does not hash")
        );
        assert!(lines[3]["error"].as_str().unwrap().contains("missing.json"));
        // Only the two good entries reached shroud-go, at the Revision's own App.
        assert_eq!(seen.lock().unwrap().len(), 1);
        assert_eq!(seen.lock().unwrap()[0].0, APP);

        let (report, _) = prepare_all(&shroud, &batch).await.unwrap();
        assert_eq!(report["requests"][0]["created"], false);
        assert_eq!(
            report["requests"][0]["approval_url"],
            "https://sign.example/sign/approve#t"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
