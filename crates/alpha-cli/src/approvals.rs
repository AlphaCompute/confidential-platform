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
    /// The App's Endpoint URL, for `status` to probe for a leaf naming the Revision v2 (PRD-05
    /// Q66). `prepare` does not read it.
    #[serde(default)]
    pub endpoint: Option<String>,
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

/// One batch entry's wrap output, read and checked as [`prepare`] checks it.
fn load(path: &Path, entry: &Entry) -> Result<Prepared, String> {
    std::fs::read(path)
        .map_err(|e| format!("{}: {e}", path.display()))
        .and_then(|text| {
            serde_json::from_slice::<Wrapped>(&text).map_err(|e| format!("{}: {e}", path.display()))
        })
        .and_then(|wrapped| {
            prepare(entry, &wrapped).map_err(|e| format!("{}: {e}", path.display()))
        })
}

/// Opens or finds every request of the batch, in order, and reports each; `true` when any failed.
pub async fn prepare_all(shroud: &Shroud, batch: &Path) -> Result<(Value, bool), String> {
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("reqwest: {e}"))?;
    let mut lines = Vec::new();
    let mut failed = false;
    for (path, entry) in read_batch(batch)? {
        let prepared = match load(&path, &entry) {
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

// M3 status tracking (PRD-05): `alpha approvals status`.
//
// An organization's approval on the signer page ends in the Revision v2 being registered at the
// KMS, so the KMS is the source of truth for "re-approved" (`GET /v1/revisions/{hash}?app_id=`),
// not shroud-go's request list: a request can be approved in shroud-go and the registration still
// fail, and only a registered Revision ever attests.
//
// PRD-05 Q66: M-F's finish line is every tenant App re-approved *and running on CoCo*, so both are
// tracked. "Running" is an Instance leaf naming the Revision v2 that has not expired: the same
// KMS answer carries when the latest leaf it issued for the pair expires (`leaf_not_after`), and
// a batch entry that names the App's `endpoint` is also probed as `alpha instances add --wait`
// probes it (a handshake pinned to the KMS CA whose leaf names the Revision and the App). A
// Revision v2 attests only from a Kata pod booted with its init-data, so either proof is "running
// on CoCo".
//
// QUESTION(PRD-05 Q68): where does the campaign-wide list of tenant Apps come from? `prepare`
// takes one organization's batch (its shroud-go key); status needs no key, so one batch can list
// every App. Proposed: generate it from shroud-go's App registry and the Rafay offers at M-F,
// with each App's Endpoint.

/// QUESTION(PRD-05 Q64): the campaign deadline. Proposed: 2026-11-20 (M-D), which leaves the
/// re-approved Apps five days to redeploy on CoCo before M-G (Nov 25) and the prototype shutdown
/// (Dec 1). Not a default: `--deadline` is required, so nobody tracks against a guessed date.
pub const PROPOSED_DEADLINE: &str = "2026-11-20T00:00:00Z";
/// QUESTION(PRD-05 Q64): by when a re-approved App must be running on CoCo. Proposed: M-G
/// (2026-11-25). `--running-deadline` defaults to `--deadline`, the stricter reading.
pub const PROPOSED_RUNNING_DEADLINE: &str = "2026-11-25T00:00:00Z";
/// An App still pending this close to the deadline is `due-soon`.
pub const DEFAULT_DUE_WITHIN_DAYS: u32 = 7;

/// The calendar a status run judges against.
#[derive(Clone, Copy, Debug)]
pub struct Campaign {
    pub now: chrono::DateTime<chrono::Utc>,
    /// By when the KMS must hold every App's Revision v2.
    pub deadline: chrono::DateTime<chrono::Utc>,
    /// By when every re-approved App must be running on CoCo.
    pub running_deadline: chrono::DateTime<chrono::Utc>,
    /// A pending App this close to `deadline` is `due-soon`.
    pub due_within: chrono::Duration,
}

/// Where an App stands in the campaign.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Standing {
    /// Re-approved, and an Instance of the Revision v2 holds a live leaf: M-F's finish line.
    Running,
    /// The KMS holds the App's Revision v2, but no Instance of it holds a live leaf yet.
    ApprovedNotRunning,
    /// Re-approved, still not running, and the running deadline has passed.
    NotRunningOverdue,
    /// Not yet, and the deadline is more than `due_within` away.
    Pending,
    /// Not yet, and the deadline is within `due_within`.
    DueSoon,
    /// Not yet, and the deadline has passed.
    Overdue,
    /// Registered, then revoked by its organization: it will not attest.
    Revoked,
}

impl Standing {
    pub fn key(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::ApprovedNotRunning => "approved-not-running",
            Self::NotRunningOverdue => "not-running-overdue",
            Self::Pending => "pending",
            Self::DueSoon => "due-soon",
            Self::Overdue => "overdue",
            Self::Revoked => "revoked",
        }
    }

    /// What to do next; `None` once the App is running.
    pub fn action(self) -> Option<&'static str> {
        match self {
            Self::Running => None,
            Self::ApprovedNotRunning => Some(
                "re-approved: deploy the wrapped pod on CoCo and check that its Instance attests \
                 (`alpha instances add --wait`)",
            ),
            Self::NotRunningOverdue => Some(
                "re-approved but still not running on CoCo past the running deadline: escalate \
                 (QUESTION(PRD-05 Q67))",
            ),
            Self::Pending => Some(
                "rerun `alpha approvals prepare` for a fresh link and send it to the organization",
            ),
            Self::DueSoon => Some("send a fresh link now; the deadline is close"),
            Self::Overdue => Some("past the deadline: escalate (QUESTION(PRD-05 Q67))"),
            Self::Revoked => Some(
                "the organization revoked this Revision: ask why before the prototype shutdown",
            ),
        }
    }

    /// Fails the run: past a deadline, or revoked.
    pub fn fails(self) -> bool {
        matches!(
            self,
            Self::Overdue | Self::NotRunningOverdue | Self::Revoked
        )
    }
}

/// `running`: an Instance of the Revision v2 holds a live leaf.
pub fn standing(
    status: &alpha_client::RevisionStatus,
    running: bool,
    campaign: &Campaign,
) -> Standing {
    let now = campaign.now;
    match (status.registered, status.revoked) {
        (true, true) => Standing::Revoked,
        (true, false) if running => Standing::Running,
        (true, false) if now >= campaign.running_deadline => Standing::NotRunningOverdue,
        (true, false) => Standing::ApprovedNotRunning,
        (false, _) if now >= campaign.deadline => Standing::Overdue,
        (false, _) if campaign.deadline.signed_duration_since(now) <= campaign.due_within => {
            Standing::DueSoon
        }
        (false, _) => Standing::Pending,
    }
}

/// Whether the KMS's latest leaf for the pair is still live at `now`.
pub fn leaf_live(
    status: &alpha_client::RevisionStatus,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<bool, String> {
    status.leaf_not_after.as_deref().map_or(Ok(false), |t| {
        chrono::DateTime::parse_from_rfc3339(t)
            .map(|t| t.to_utc() > now)
            .map_err(|e| format!("the KMS's leaf_not_after {t}: {e}"))
    })
}

/// What one handshake with an App's Endpoint showed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Endpoint {
    /// A leaf from the KMS CA naming this Revision of this App.
    Attested,
    /// Anything else, and why: still the prototype's Revision, silent, or another App's leaf.
    Not(String),
}

/// One probe of `url`, as `alpha instances add --wait` makes it: the chain is pinned to the KMS
/// CA, and the leaf must name `expected` and `app`.
pub async fn probe_endpoint(
    url: &str,
    kms_ca_pem: &str,
    expected: ComposeHash,
    app: AppId,
) -> Result<Endpoint, String> {
    use alpha_client::Probe;
    match alpha_client::probe_instance(
        url,
        kms_ca_pem,
        &expected,
        alpha_client::system_time_provider(),
    )
    .await
    {
        Ok(Probe::Attested(sans)) if sans.app_id == app => Ok(Endpoint::Attested),
        Ok(Probe::Attested(sans)) => Ok(Endpoint::Not(format!(
            "the leaf names App {}, not {app}",
            sans.app_id
        ))),
        Ok(Probe::OtherRevision(sans)) => Ok(Endpoint::Not(format!(
            "another Revision is serving: {}",
            sans.compose_hash
        ))),
        Ok(Probe::Silent(why)) => Ok(Endpoint::Not(why)),
        Err(e) => Err(format!("probe {url}: {e}")),
    }
}

fn bump(counts: &mut std::collections::BTreeMap<&'static str, u64>, key: &'static str) {
    let n = counts.entry(key).or_default();
    *n = n.saturating_add(1);
}

/// One App's line once its wrap output checks: the KMS's answer, then the Endpoint's when the
/// entry names one and the KMS holds the Revision.
async fn status_line<F, Fut, P, PFut>(
    prepared: &Prepared,
    endpoint: Option<&str>,
    campaign: &Campaign,
    lookup: &mut F,
    probe: &mut P,
) -> Result<(Standing, Value), String>
where
    F: FnMut(ComposeHash, AppId) -> Fut,
    Fut: std::future::Future<Output = Result<alpha_client::RevisionStatus, String>>,
    P: FnMut(String, ComposeHash, AppId) -> PFut,
    PFut: std::future::Future<Output = Result<Endpoint, String>>,
{
    let status = lookup(prepared.compose_hash, prepared.app_id).await?;
    if status.compose_hash != prepared.compose_hash || status.app_id != prepared.app_id {
        return Err("the KMS answered about another Revision or App".into());
    }
    let mut running = leaf_live(&status, campaign.now)?;
    let mut line = json!({ "app_id": prepared.app_id, "title": prepared.title,
                           "compose_hash": prepared.compose_hash });
    let mut extra = serde_json::Map::new();
    if let Some(t) = &status.leaf_not_after {
        extra.insert("leaf_not_after".into(), json!(t));
    }
    if let (Some(url), true, false) = (endpoint, status.registered, status.revoked) {
        let seen = probe(url.to_owned(), prepared.compose_hash, prepared.app_id).await?;
        running |= seen == Endpoint::Attested;
        extra.insert(
            "endpoint".into(),
            match seen {
                Endpoint::Attested => json!({ "url": url, "attested": true }),
                Endpoint::Not(why) => json!({ "url": url, "attested": false, "detail": why }),
            },
        );
    }
    let standing = standing(&status, running, campaign);
    extra.insert("state".into(), json!(standing));
    if let Some(action) = standing.action() {
        extra.insert("action".into(), json!(action));
    }
    if let Some(fields) = line.as_object_mut() {
        fields.extend(extra);
    }
    Ok((standing, line))
}

/// The report for every entry of `batch`, each looked up through `lookup` (the KMS's revision
/// status, pinned like an admin call) and, for an entry naming its `endpoint`, `probe`
/// ([`probe_endpoint`]); `true` when any App is overdue (not re-approved, or re-approved but not
/// running, past its deadline) or revoked, or any entry failed.
///
/// QUESTION(PRD-05 Q65): nothing is sent to anyone. The report lists, per organization-facing
/// App, what to do next (`action`); which channel carries it (shroud-go email, the Rafay portal,
/// the account manager) is open.
pub async fn status_all<F, Fut, P, PFut>(
    batch: &Path,
    campaign: &Campaign,
    mut lookup: F,
    mut probe: P,
) -> Result<(Value, bool), String>
where
    F: FnMut(ComposeHash, AppId) -> Fut,
    Fut: std::future::Future<Output = Result<alpha_client::RevisionStatus, String>>,
    P: FnMut(String, ComposeHash, AppId) -> PFut,
    PFut: std::future::Future<Output = Result<Endpoint, String>>,
{
    let mut lines = Vec::new();
    let mut counts = std::collections::BTreeMap::<&'static str, u64>::new();
    let mut failed = false;
    for (path, entry) in read_batch(batch)? {
        let line = match load(&path, &entry) {
            Err(e) => Err(json!({ "wrapped": path, "title": entry.title, "error": e })),
            Ok(prepared) => status_line(
                &prepared,
                entry.endpoint.as_deref(),
                campaign,
                &mut lookup,
                &mut probe,
            )
            .await
            .map_err(|e| {
                json!({ "app_id": prepared.app_id, "title": prepared.title,
                        "compose_hash": prepared.compose_hash, "error": e })
            }),
        };
        lines.push(match line {
            Ok((standing, line)) => {
                failed |= standing.fails();
                bump(&mut counts, standing.key());
                line
            }
            Err(line) => {
                failed = true;
                bump(&mut counts, "error");
                line
            }
        });
    }
    let at =
        |t: chrono::DateTime<chrono::Utc>| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    Ok((
        json!({
            "now": at(campaign.now),
            "deadline": at(campaign.deadline),
            "running_deadline": at(campaign.running_deadline),
            "days_left": campaign.deadline.signed_duration_since(campaign.now).num_days(),
            "counts": counts,
            "total": lines.len(),
            "apps": lines,
        }),
        failed,
    ))
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
            endpoint: None,
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

    fn status(registered: bool, revoked: bool) -> alpha_client::RevisionStatus {
        let w = wrapped("package agent_policy\n");
        alpha_client::RevisionStatus {
            compose_hash: w.revision_hash,
            app_id: APP.parse().unwrap(),
            registered,
            revoked,
            leaf_not_after: None,
        }
    }

    fn at(s: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(s).unwrap().to_utc()
    }

    fn campaign(now: &str) -> Campaign {
        Campaign {
            now: at(now),
            deadline: at(PROPOSED_DEADLINE),
            running_deadline: at(PROPOSED_RUNNING_DEADLINE),
            due_within: chrono::Duration::days(7),
        }
    }

    #[test]
    fn standing_is_the_kms_registration_then_a_live_leaf_then_the_calendar() {
        let early = campaign("2026-11-01T00:00:00Z");
        let close = campaign("2026-11-15T00:00:00Z");
        let late = campaign("2026-11-20T00:00:00Z");
        let past_running = campaign("2026-11-25T00:00:00Z");
        for c in [&early, &late, &past_running] {
            assert_eq!(standing(&status(true, false), true, c), Standing::Running);
        }
        assert_eq!(
            standing(&status(true, false), false, &early),
            Standing::ApprovedNotRunning
        );
        // Past the approval deadline but not the running one: still time to deploy.
        assert_eq!(
            standing(&status(true, false), false, &late),
            Standing::ApprovedNotRunning
        );
        assert_eq!(
            standing(&status(true, false), false, &past_running),
            Standing::NotRunningOverdue
        );
        assert_eq!(
            standing(&status(true, true), true, &early),
            Standing::Revoked
        );
        assert_eq!(
            standing(&status(false, false), false, &early),
            Standing::Pending
        );
        assert_eq!(
            standing(&status(false, false), false, &close),
            Standing::DueSoon
        );
        assert_eq!(
            standing(&status(false, false), false, &late),
            Standing::Overdue
        );
        // Only the deadlines and a revocation fail the run, and only a running App has no action.
        let failing: Vec<_> = [
            Standing::Running,
            Standing::ApprovedNotRunning,
            Standing::NotRunningOverdue,
            Standing::Pending,
            Standing::DueSoon,
            Standing::Overdue,
            Standing::Revoked,
        ]
        .into_iter()
        .filter(|s| s.fails())
        .collect();
        assert_eq!(
            failing,
            [
                Standing::NotRunningOverdue,
                Standing::Overdue,
                Standing::Revoked
            ]
        );
        assert!(Standing::Running.action().is_none());
        assert!(
            Standing::ApprovedNotRunning
                .action()
                .unwrap()
                .contains("CoCo")
        );
    }

    #[test]
    fn a_leaf_is_live_until_its_not_after() {
        let now = at("2026-11-01T00:00:00Z");
        let mut s = status(true, false);
        assert!(!leaf_live(&s, now).unwrap(), "no leaf ever issued");
        s.leaf_not_after = Some("2026-11-01T00:30:00Z".into());
        assert!(leaf_live(&s, now).unwrap());
        s.leaf_not_after = Some("2026-11-01T00:00:00Z".into());
        assert!(!leaf_live(&s, now).unwrap(), "expired at now");
        s.leaf_not_after = Some("yesterday".into());
        assert!(leaf_live(&s, now).is_err());
    }

    #[tokio::test]
    async fn the_status_report_counts_each_app_and_fails_on_overdue_or_errors() {
        let dir =
            std::env::temp_dir().join(format!("alpha-approvals-status-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let running = wrapped("package agent_policy\n");
        let pending = wrapped("package agent_policy\n# v2\n");
        let deployed = wrapped("package agent_policy\n# v3\n");
        let probed = wrapped("package agent_policy\n# v4\n");
        let file = |w: &Wrapped| {
            json!({ "revision": w.revision, "revision_hash": w.revision_hash,
                    "initdata": w.initdata, "secrets": w.secrets, "pod_spec": {} })
            .to_string()
        };
        for (name, w) in [
            ("a.json", &running),
            ("b.json", &pending),
            ("c.json", &deployed),
            ("d.json", &probed),
        ] {
            std::fs::write(dir.join(name), file(w)).unwrap();
        }
        let write_batch = |name: &str, requests: Value| {
            let path = dir.join(name);
            std::fs::write(&path, json!({ "requests": requests }).to_string()).unwrap();
            path
        };
        let batch = write_batch(
            "batch.json",
            json!([
                { "wrapped": "a.json", "title": "running-app", "machine": "m" },
                { "wrapped": "b.json", "title": "pending-app", "machine": "m",
                  "endpoint": "https://b.example" },
                { "wrapped": "c.json", "title": "deployed-app", "machine": "m",
                  "endpoint": "https://c.example" },
                { "wrapped": "d.json", "title": "probed-app", "machine": "m",
                  "endpoint": "https://d.example" }
            ]),
        );
        // The KMS holds a, c and d; only a has a leaf, live until 2026-11-30.
        let (a, b) = (running.revision_hash, pending.revision_hash);
        let lookup = move |hash: ComposeHash, app: AppId| async move {
            Ok(alpha_client::RevisionStatus {
                compose_hash: hash,
                app_id: app,
                registered: hash != b,
                revoked: false,
                leaf_not_after: (hash == a).then(|| "2026-11-30T00:00:00Z".to_owned()),
            })
        };
        // c's Endpoint still serves the prototype's Revision; d's serves the Revision v2.
        let probes = Arc::new(Mutex::new(Vec::new()));
        let probe = {
            let probes = probes.clone();
            move |url: String, _: ComposeHash, _: AppId| {
                probes.lock().unwrap().push(url.clone());
                async move {
                    Ok(if url.starts_with("https://d.") {
                        Endpoint::Attested
                    } else {
                        Endpoint::Not("another Revision is serving: x".into())
                    })
                }
            }
        };

        let (report, failed) = status_all(
            &batch,
            &campaign("2026-11-01T00:00:00Z"),
            lookup,
            probe.clone(),
        )
        .await
        .unwrap();
        assert!(!failed, "{report}");
        let apps = &report["apps"];
        assert_eq!(apps[0]["state"], "running");
        assert_eq!(apps[0]["leaf_not_after"], "2026-11-30T00:00:00Z");
        assert!(apps[0].get("action").is_none());
        assert_eq!(apps[1]["state"], "pending");
        assert!(apps[1]["action"].as_str().unwrap().contains("prepare"));
        assert!(
            apps[1].get("endpoint").is_none(),
            "not probed: not approved"
        );
        assert_eq!(apps[2]["state"], "approved-not-running");
        assert_eq!(apps[2]["endpoint"]["attested"], false);
        assert!(
            apps[2]["endpoint"]["detail"]
                .as_str()
                .unwrap()
                .contains("another Revision")
        );
        assert!(apps[2]["action"].as_str().unwrap().contains("CoCo"));
        assert_eq!(apps[3]["state"], "running");
        assert_eq!(apps[3]["endpoint"]["attested"], true);
        assert_eq!(
            report["counts"],
            json!({ "running": 2, "pending": 1, "approved-not-running": 1 })
        );
        assert_eq!(report["days_left"], 19);
        assert_eq!(report["running_deadline"], PROPOSED_RUNNING_DEADLINE);
        assert_eq!(
            *probes.lock().unwrap(),
            ["https://c.example", "https://d.example"]
        );

        // Past the approval deadline: the pending App is overdue and fails the run; the deployed
        // one still has until the running deadline.
        let (report, failed) = status_all(
            &batch,
            &campaign("2026-11-21T00:00:00Z"),
            lookup,
            probe.clone(),
        )
        .await
        .unwrap();
        assert!(failed);
        assert_eq!(report["apps"][1]["state"], "overdue");
        assert_eq!(report["apps"][2]["state"], "approved-not-running");

        // Past the running deadline, approved but not running is overdue too, and alone fails
        // the run. a's leaf has not expired by then.
        let only_deployed = write_batch(
            "deployed.json",
            json!([
                { "wrapped": "a.json", "title": "running-app", "machine": "m" },
                { "wrapped": "c.json", "title": "deployed-app", "machine": "m",
                  "endpoint": "https://c.example" }
            ]),
        );
        let (report, failed) = status_all(
            &only_deployed,
            &campaign("2026-11-25T00:00:00Z"),
            lookup,
            probe.clone(),
        )
        .await
        .unwrap();
        assert!(failed, "{report}");
        assert_eq!(report["apps"][0]["state"], "running");
        assert_eq!(report["apps"][1]["state"], "not-running-overdue");
        assert!(
            report["apps"][1]["action"]
                .as_str()
                .unwrap()
                .contains("Q67")
        );
        assert_eq!(
            report["counts"],
            json!({ "running": 1, "not-running-overdue": 1 })
        );

        // A missing wrap file is an error that fails the run.
        let missing = write_batch(
            "missing.json",
            json!([
                { "wrapped": "a.json", "title": "running-app", "machine": "m" },
                { "wrapped": "gone.json", "title": "missing", "machine": "m" }
            ]),
        );
        let (report, failed) = status_all(
            &missing,
            &campaign("2026-11-01T00:00:00Z"),
            lookup,
            probe.clone(),
        )
        .await
        .unwrap();
        assert!(failed);
        assert!(
            report["apps"][1]["error"]
                .as_str()
                .unwrap()
                .contains("gone.json")
        );
        assert_eq!(report["counts"], json!({ "running": 1, "error": 1 }));

        // A KMS answer about another Revision is an error, never a standing.
        let (report, failed) = status_all(
            &batch,
            &campaign("2026-11-01T00:00:00Z"),
            |_, app| async move {
                Ok(alpha_client::RevisionStatus {
                    compose_hash: alpha_core::compose_hash("x"),
                    app_id: app,
                    registered: true,
                    revoked: false,
                    leaf_not_after: None,
                })
            },
            probe.clone(),
        )
        .await
        .unwrap();
        assert!(failed);
        assert!(
            report["apps"][0]["error"]
                .as_str()
                .unwrap()
                .contains("another Revision")
        );

        // A failed probe (not a silent Endpoint: the probe itself) is an error too.
        let (report, failed) = status_all(
            &only_deployed,
            &campaign("2026-11-01T00:00:00Z"),
            lookup,
            |url: String, _, _| async move { Err(format!("probe {url}: no certificate")) },
        )
        .await
        .unwrap();
        assert!(failed);
        assert!(
            report["apps"][1]["error"]
                .as_str()
                .unwrap()
                .contains("no certificate")
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
