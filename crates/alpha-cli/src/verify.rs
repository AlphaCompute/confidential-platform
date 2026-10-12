//! `alpha verify <url>`: what a relying party can establish about an App, or a KMS node, from its
//! Endpoint and the release-signed platform document, printed section by section (certificate,
//! Revision, CPU, GPU) with every check that decided it.
//!
//! The leaf is the KMS's verdict: it chains to the document's KMS CA only if the KMS appraised the
//! TD's evidence (and, on the GPU runtime class, every GPU) within the leaf's hour, and its SANs
//! name the Revision it appraised. An App's Endpoint serves nothing else, so what the leaf implies
//! is reported as the KMS's appraisal, and three inputs add what the leaf only names by digest:
//! the init-data or the registered document, which must hash to the leaf's Revision, and the
//! attestation result the KMS returned to the runtime (`attestation_result` of the runtime's
//! `/v1/identity`), which is not signed and is reported only where it agrees with the leaf. A KMS
//! node does serve its evidence, so its quote is appraised here again, over a fresh nonce.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use alpha_attest::{AttestationResult, Collateral, PlatformDocument, ReferenceKind, Verdict};
use alpha_channel::cert::{self, InstanceSans};
use alpha_channel::sha256_label;
use alpha_client::NodeEvidence;
use alpha_core::agent_policy::{self, PolicySummary};
use alpha_core::coco::{CocoRevision, InitData, RuntimeClass};
use alpha_core::{AppId, ComposeHash};
use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::rfc3339;

const TIMEOUT: Duration = Duration::from_secs(15);

#[derive(clap::Args)]
pub struct Args {
    /// The App's Endpoint (or a KMS node's), as `https://<host>[:port]`.
    pub url: String,
    /// The pod's init-data (TOML); it must stand for the Revision the leaf names, and its agent
    /// policy is summarised.
    #[arg(long, conflicts_with = "compose")]
    pub initdata: Option<PathBuf>,
    /// The registered document (an `app-compose.json` or a Revision v2), which must hash to the
    /// Revision the leaf names.
    #[arg(long)]
    pub compose: Option<PathBuf>,
    /// The `attestation_result` the KMS returned to the runtime; reported where it agrees with
    /// the leaf.
    #[arg(long)]
    pub attestation_result: Option<PathBuf>,
    /// Print the report as JSON.
    #[arg(long)]
    pub json: bool,
}

/// What the caller gave beside the URL.
#[derive(Default)]
pub struct Given {
    pub initdata: Option<InitData>,
    pub compose: Option<String>,
    pub attestation_result: Option<AttestationResult>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Check {
    pub name: &'static str,
    pub ok: bool,
    pub detail: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub url: String,
    pub verified: bool,
    pub platform_document: Value,
    pub certificate: Value,
    pub revision: Value,
    pub cpu: Value,
    pub gpu: Value,
    pub checks: Vec<Check>,
}

impl Report {
    fn new(url: &str) -> Self {
        Self {
            url: url.to_owned(),
            verified: false,
            platform_document: Value::Null,
            certificate: Value::Null,
            revision: Value::Null,
            cpu: Value::Null,
            gpu: Value::Null,
            checks: Vec::new(),
        }
    }

    fn check(&mut self, name: &'static str, result: Result<String, String>) -> bool {
        let ok = result.is_ok();
        let detail = result.unwrap_or_else(|e| e);
        self.checks.push(Check { name, ok, detail });
        ok
    }

    fn finish(mut self) -> Self {
        self.verified = !self.checks.is_empty() && self.checks.iter().all(|c| c.ok);
        self
    }
}

/// A KMS node's evidence as fetched over a fresh nonce, with the key its server proved.
pub struct NodeFetch {
    pub evidence: NodeEvidence,
    pub nonce: [u8; 32],
    pub server_spki: Vec<u8>,
    pub collateral: Collateral,
}

/// What the leaf's SANs say it is.
enum Subject {
    Instance(InstanceSans),
    Node(ComposeHash),
}

impl Subject {
    fn revision(&self) -> ComposeHash {
        match self {
            Self::Instance(sans) => sans.compose_hash,
            Self::Node(hash) => *hash,
        }
    }

    fn app_id(&self) -> Option<AppId> {
        match self {
            Self::Instance(sans) => Some(sans.app_id),
            Self::Node(_) => None,
        }
    }
}

/// The registered document behind the leaf's Revision, as far as it is known.
enum Document {
    Coco {
        revision: CocoRevision,
        policy: Option<Result<PolicySummary, String>>,
    },
    Compose,
    Unknown,
}

fn read(path: &Path) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|e| format!("{}: {e}", path.display()))
}

/// Reads the optional inputs; a file that does not parse is a usage error, not a finding.
pub fn given(args: &Args) -> Result<Given, String> {
    let initdata = args
        .initdata
        .as_deref()
        .map(|p| InitData::parse(&read(p)?).map_err(|e| format!("{}: {e}", p.display())))
        .transpose()?;
    let compose = args
        .compose
        .as_deref()
        .map(|p| String::from_utf8(read(p)?).map_err(|_| format!("{}: not UTF-8", p.display())))
        .transpose()?;
    let attestation_result = args
        .attestation_result
        .as_deref()
        .map(|p| serde_json::from_slice(&read(p)?).map_err(|e| format!("{}: {e}", p.display())))
        .transpose()?;
    Ok(Given {
        initdata,
        compose,
        attestation_result,
    })
}

/// The leaf the Endpoint serves, over TLS 1.3 with the post-quantum hybrid alone, the way
/// `probe_instance` reads one; the chain is judged afterwards, so a foreign one is reported
/// rather than lost in a handshake error.
pub async fn served_leaf(url: &str) -> Result<Vec<u8>, String> {
    let config = alpha_client::tls::client_config(None, None, alpha_client::system_time_provider())
        .map_err(|e| e.to_string())?;
    let http = reqwest::Client::builder()
        .tls_backend_preconfigured(config)
        .tls_info(true)
        .timeout(TIMEOUT)
        .build()
        .map_err(|e| format!("http client: {e}"))?;
    let response = http
        .get(url)
        .send()
        .await
        .map_err(|e| format!("{url}: {e}"))?;
    response
        .extensions()
        .get::<reqwest::tls::TlsInfo>()
        .and_then(|info| info.peer_certificate().map(<[u8]>::to_vec))
        .ok_or_else(|| format!("{url} served no certificate"))
}

/// Fetches a KMS node's evidence over a fresh nonce and the DCAP collateral for its quote.
pub async fn node_fetch(url: &str, pccs_url: &str) -> Result<NodeFetch, String> {
    let nonce = crate::random::<32>()?;
    let (evidence, server_spki) = alpha_client::fetch_node_evidence(url, &nonce)
        .await
        .map_err(|e| e.to_string())?;
    let quote = evidence.evidence().map_err(|e| e.to_string())?.quote;
    let collateral = alpha_attest::fetch_collateral(pccs_url, &quote)
        .await
        .map_err(|e| e.to_string())?;
    Ok(NodeFetch {
        evidence,
        nonce,
        server_spki,
        collateral,
    })
}

/// Whether a leaf names a KMS node, which serves evidence of its own.
pub fn is_node_leaf(leaf: &[u8]) -> bool {
    cert::uri_sans(leaf)
        .ok()
        .is_some_and(|sans| cert::parse_kms_sans(&sans).is_ok())
}

/// The whole report, pure over what was fetched: `leaf` is what the Endpoint served (or why it
/// served none), `node` the node evidence when the leaf is a KMS node's.
pub fn report(
    url: &str,
    doc: &PlatformDocument,
    leaf: Result<Vec<u8>, String>,
    node: Option<Result<NodeFetch, String>>,
    given: &Given,
    now: SystemTime,
) -> Report {
    let mut r = Report::new(url);
    r.platform_document = json!({ "version": doc.version, "issued_at": doc.issued_at });
    let leaf = match leaf {
        Ok(leaf) => {
            r.check(
                "tls",
                Ok("TLS 1.3 over X25519MLKEM768; the server proved the leaf's key".into()),
            );
            leaf
        }
        Err(e) => {
            r.check("tls", Err(e));
            return r.finish();
        }
    };
    let Some(subject) = certificate(&mut r, doc, &leaf, now) else {
        return r.finish();
    };
    let document = revision(&mut r, &subject, given);
    let reported = match (&subject, node) {
        (Subject::Node(_), Some(fetched)) => {
            node_cpu(&mut r, doc, &leaf, &subject, fetched, now);
            None
        }
        _ => kms_cpu(&mut r, doc, &leaf, &subject, &document, given),
    };
    gpu(&mut r, doc, &document, reported);
    r.finish()
}

fn certificate(
    r: &mut Report,
    doc: &PlatformDocument,
    leaf: &[u8],
    now: SystemTime,
) -> Option<Subject> {
    let validity = cert::pem_to_der(&doc.kms_ca_pem)
        .and_then(|ca| cert::verify_leaf(leaf, &ca, now))
        .map_err(|e| e.to_string());
    let checked = validity.and_then(|v| {
        cert::spki_of(leaf)
            .map(|spki| (v, spki))
            .map_err(|e| e.to_string())
    });
    let ((not_before, not_after), spki) = match checked {
        Ok(v) => v,
        Err(e) => {
            r.check("certificate", Err(e));
            return None;
        }
    };
    r.check(
        "certificate",
        Ok("signed by the KMS CA of the platform document, and valid now".into()),
    );
    let sans = cert::uri_sans(leaf).unwrap_or_default();
    let mut out = Map::new();
    out.insert("issued_at".into(), json!(rfc3339(not_before)));
    out.insert("not_after".into(), json!(rfc3339(not_after)));
    out.insert("runtime_pubkey_sha256".into(), json!(sha256_label(&spki)));
    let subject = if let Ok(hash) = cert::parse_kms_sans(&sans) {
        out.insert("kind".into(), json!("KMS node"));
        let listed = doc.kms_revisions.iter().any(|k| k.compose_hash == hash);
        r.check(
            "identity",
            if listed {
                Ok("a KMS node whose Revision the platform document lists".into())
            } else {
                Err(format!(
                    "the KMS node's Revision {hash} is not in kms_revisions"
                ))
            },
        );
        Subject::Node(hash)
    } else if let Ok(instance) = cert::parse_instance_sans(&sans) {
        out.insert("kind".into(), json!("App Instance"));
        out.insert("org_id".into(), json!(instance.org_id));
        out.insert("app_id".into(), json!(instance.app_id));
        let key = format!("sha256:{}", instance.runtime_pubkey_sha256_hex);
        r.check(
            "identity",
            if key == sha256_label(&spki) {
                Ok("an App Instance whose SAN names the key that served this connection".into())
            } else {
                Err(format!(
                    "the SAN names runtime key {key}, not the leaf's own key"
                ))
            },
        );
        Subject::Instance(instance)
    } else {
        r.check(
            "identity",
            Err(format!(
                "the leaf's SANs {sans:?} are neither an Instance's nor a KMS node's"
            )),
        );
        r.certificate = Value::Object(out);
        return None;
    };
    r.certificate = Value::Object(out);
    Some(subject)
}

fn revision(r: &mut Report, subject: &Subject, given: &Given) -> Document {
    let hash = subject.revision();
    let mut out = Map::new();
    out.insert("hash".into(), json!(hash));
    let document = if let Some(init) = &given.initdata {
        coco_from_initdata(r, subject, init)
    } else if let Some(text) = &given.compose {
        registered(r, subject, text)
    } else {
        out.insert(
            "document".into(),
            json!("not given: pass --initdata or --compose to see what this Revision is"),
        );
        Document::Unknown
    };
    match &document {
        Document::Coco { revision, policy } => {
            out.insert("format".into(), json!(revision.format));
            out.insert("runtime_class".into(), json!(revision.runtime_class));
            out.insert("initdata_sha256".into(), json!(revision.initdata_sha256));
            out.insert("policy_sha256".into(), json!(revision.policy_sha256));
            match policy {
                Some(Ok(summary)) => {
                    out.insert("exec".into(), json!(verdict_text(summary.exec)));
                    out.insert("logs".into(), json!(verdict_text(summary.logs)));
                    out.insert("images".into(), json!(summary.images));
                }
                Some(Err(e)) => {
                    out.insert("policy".into(), json!(format!("unreadable: {e}")));
                }
                None => {
                    out.insert(
                        "policy".into(),
                        json!("not shown: pass --initdata to read the agent policy"),
                    );
                }
            }
        }
        Document::Compose => {
            out.insert("format".into(), json!("app-compose (prototype CVM)"));
        }
        Document::Unknown => {}
    }
    r.revision = Value::Object(out);
    document
}

fn coco_from_initdata(r: &mut Report, subject: &Subject, init: &InitData) -> Document {
    let derived = init
        .revision()
        .map_err(|e| e.to_string())
        .and_then(|rev| rev.hash().map(|h| (rev, h)).map_err(|e| e.to_string()));
    let (revision, hash) = match derived {
        Ok(v) => v,
        Err(e) => {
            r.check("revision", Err(format!("the init-data: {e}")));
            return Document::Unknown;
        }
    };
    if !r.check(
        "revision",
        matches_leaf(
            subject,
            hash,
            Some(revision.app_id),
            "the init-data's Revision v2",
        ),
    ) {
        return Document::Unknown;
    }
    let policy = init
        .policy()
        .map_err(|e| e.to_string())
        .and_then(|p| agent_policy::summarize(p).map_err(|e| e.to_string()));
    r.check(
        "agent policy",
        policy
            .as_ref()
            .map(|_| "read from the init-data's policy.rego".to_owned())
            .map_err(Clone::clone),
    );
    Document::Coco {
        revision,
        policy: Some(policy),
    }
}

fn registered(r: &mut Report, subject: &Subject, text: &str) -> Document {
    let hash = alpha_core::compose_hash(text);
    let coco = alpha_core::coco::is_revision_v2(text);
    let checked = match subject.app_id() {
        Some(app) if coco => CocoRevision::check_registered(text, app)
            .map(|_| ())
            .map_err(|e| e.to_string()),
        Some(app) => alpha_core::check_registration(text, app)
            .map(|_| ())
            .map_err(|e| e.to_string()),
        None => Ok(()),
    };
    let what = if coco {
        "the Revision v2"
    } else {
        "the compose"
    };
    let result = checked
        .map_err(|e| format!("{what} is not one the KMS registers for this App: {e}"))
        .and_then(|()| matches_leaf(subject, hash, None, what));
    if !r.check("revision", result) {
        return Document::Unknown;
    }
    if !coco {
        return Document::Compose;
    }
    match alpha_core::parse(text.as_bytes())
        .map_err(|e| e.to_string())
        .and_then(|v| serde_json::from_value::<CocoRevision>(v).map_err(|e| e.to_string()))
    {
        Ok(revision) => Document::Coco {
            revision,
            policy: None,
        },
        Err(_) => Document::Unknown,
    }
}

fn matches_leaf(
    subject: &Subject,
    hash: ComposeHash,
    app: Option<AppId>,
    what: &str,
) -> Result<String, String> {
    if hash != subject.revision() {
        return Err(format!(
            "{what} is {hash}, not the Revision {} the leaf names",
            subject.revision()
        ));
    }
    match (app, subject.app_id()) {
        (Some(app), Some(leaf_app)) if app != leaf_app => Err(format!(
            "{what} is of App {app}, not the leaf's App {leaf_app}"
        )),
        _ => Ok(format!("{what} hashes to the Revision the leaf names")),
    }
}

fn verdict_text(verdict: agent_policy::Verdict) -> &'static str {
    use agent_policy::Verdict::*;
    match verdict {
        Denied => "denied",
        Ruled => "not denied: the policy has rules that may allow it",
        Replaceable => "not denied: the policy lets the host replace the policy",
        FailuresAllowed => "not denied: the policy lets refused requests through",
    }
}

/// The reference values the KMS could have matched the TD against, by profile.
fn references(doc: &PlatformDocument, kind: ReferenceKind, class: Option<&str>) -> Vec<String> {
    doc.reference_values
        .iter()
        .filter(|v| v.kind == kind && (class.is_none() || v.runtime_class.as_deref() == class))
        .map(|v| v.name.clone())
        .collect()
}

/// Returns the reported attestation result when it agrees with the leaf.
fn kms_cpu<'a>(
    r: &mut Report,
    doc: &PlatformDocument,
    leaf: &[u8],
    subject: &Subject,
    document: &Document,
    given: &'a Given,
) -> Option<&'a AttestationResult> {
    let mut out = Map::new();
    out.insert(
        "appraised_by".into(),
        json!("alpha-kms, before it issued this leaf; an App serves no evidence of its own"),
    );
    let (profile, kind, class) = match document {
        Document::Coco { revision, .. } => (
            "kata-tdx/1 (Intel TDX, Kata confidential pod)",
            Some(ReferenceKind::KataTdx),
            Some(revision.runtime_class.as_str()),
        ),
        Document::Compose => (
            "alphacompute-evidence/1 (Intel TDX, prototype CVM)",
            Some(ReferenceKind::PrototypeTdx),
            None,
        ),
        Document::Unknown => ("unknown without the document", None, None),
    };
    out.insert("profile".into(), json!(profile));
    if let Some(kind) = kind {
        out.insert(
            "reference_values".into(),
            json!(references(doc, kind, class)),
        );
    }
    out.insert(
        "tcb_statuses_allowed".into(),
        json!(doc.policy.tcb_statuses),
    );
    let mut reported = None;
    if let Some(result) = &given.attestation_result {
        let agrees = result_agrees(leaf, subject, document, result);
        if r.check("attestation result", agrees) {
            reported = Some(result);
            out.insert(
                "reported_result".into(),
                json!({
                    "note": "as the App reports the KMS's result; not signed, consistent with the leaf",
                    "measured": result.measured,
                    "tcb_status": result.tcb_status,
                    "advisories": result.advisories,
                    "os_image": result.os_image,
                    "verified_at": result.verified_at,
                    "policy_version": result.policy_version,
                }),
            );
        }
    }
    r.cpu = Value::Object(out);
    reported
}

/// The result the App reports, held to the leaf and the Revision: nothing in it is believed
/// unless it names what the leaf does.
fn result_agrees(
    leaf: &[u8],
    subject: &Subject,
    document: &Document,
    result: &AttestationResult,
) -> Result<String, String> {
    if result.verdict != Verdict::Verified {
        return Err("the reported result is not verified".into());
    }
    if result.revision.compose_hash != subject.revision() {
        return Err("the reported result names another Revision than the leaf".into());
    }
    if let Subject::Instance(sans) = subject
        && (result.revision.app_id != sans.app_id || result.revision.org_id != sans.org_id)
    {
        return Err("the reported result names another App or organization than the leaf".into());
    }
    let spki = cert::spki_of(leaf).map_err(|e| e.to_string())?;
    if result.runtime_pubkey_sha256 != sha256_label(&spki) {
        return Err("the reported result is for another runtime key than the leaf's".into());
    }
    match (document, &result.coco) {
        (Document::Coco { revision, .. }, Some(coco)) => {
            if coco.initdata_sha256 != revision.initdata_sha256
                || coco.policy_sha256 != revision.policy_sha256
                || coco.runtime_class != revision.runtime_class
            {
                return Err(
                    "the reported result's init-data, policy or class is not the Revision's".into(),
                );
            }
            let gpus_match = match &revision.gpu {
                None => coco.gpus.is_empty(),
                Some(shape) => {
                    usize::try_from(shape.count).is_ok_and(|n| n == coco.gpus.len())
                        && coco
                            .gpus
                            .iter()
                            .all(|g| g.model == shape.model && g.cc_mode)
                }
            };
            if !gpus_match {
                return Err(
                    "the reported GPUs are not the Revision's count and model in CC mode".into(),
                );
            }
        }
        (Document::Coco { .. }, None) => {
            return Err("the reported result has no kata-tdx/1 findings for a Revision v2".into());
        }
        (Document::Compose, Some(_)) => {
            return Err("the reported result has Kata findings for a compose".into());
        }
        _ => {}
    }
    Ok("the reported result names this leaf's Revision, App, organization and key".into())
}

fn node_cpu(
    r: &mut Report,
    doc: &PlatformDocument,
    leaf: &[u8],
    subject: &Subject,
    fetched: Result<NodeFetch, String>,
    now: SystemTime,
) {
    let appraised = fetched.and_then(|f| {
        let runtime_spki = f.evidence.runtime_spki().map_err(|e| e.to_string())?;
        let appraised = alpha_attest::appraise(
            &f.evidence.evidence().map_err(|e| e.to_string())?,
            &f.nonce,
            &runtime_spki,
            Some(f.evidence.xwing_pubkey.as_bytes()),
            doc,
            &f.collateral,
            now,
        )
        .map_err(|e| format!("{}: {e}", e.code()))?;
        let leaf_spki = cert::spki_of(leaf).map_err(|e| e.to_string())?;
        if f.server_spki != runtime_spki || leaf_spki != runtime_spki {
            return Err(
                "the node's attested runtime key is not the key that served the leaf".into(),
            );
        }
        if appraised.compose_hash != subject.revision() {
            return Err(format!(
                "the node's quote measures Revision {}, not the leaf's {}",
                appraised.compose_hash,
                subject.revision()
            ));
        }
        Ok(appraised)
    });
    match appraised {
        Ok(a) => {
            r.check(
                "cpu appraisal",
                Ok("the node's quote over a fresh nonce appraises here under the platform document".into()),
            );
            r.cpu = json!({
                "appraised_by": "this command, from the node's quote over a fresh nonce",
                "profile": "alphacompute-evidence/1 (Intel TDX)",
                "measured": a.measured,
                "tcb_status": a.tcb_status,
                "advisories": a.advisories,
                "os_image": a.os_image,
            });
        }
        Err(e) => {
            r.check("cpu appraisal", Err(e));
        }
    }
}

fn gpu(
    r: &mut Report,
    doc: &PlatformDocument,
    document: &Document,
    reported: Option<&AttestationResult>,
) {
    let revision = match document {
        Document::Coco { revision, .. } => revision,
        Document::Compose => {
            r.gpu = json!({ "gpus": "none: a prototype CVM has no GPU" });
            return;
        }
        Document::Unknown => {
            r.gpu = json!({ "gpus": "unknown without the document" });
            return;
        }
    };
    let Some(shape) = revision
        .gpu
        .as_ref()
        .filter(|_| revision.class() == Some(RuntimeClass::Gpu))
    else {
        r.gpu = json!({ "gpus": format!("none: {} runs no GPU", revision.runtime_class) });
        return;
    };
    let mut out = Map::new();
    out.insert(
        "gpus".into(),
        json!(format!(
            "{} × {}, each verified in CC mode by every verifier of the gpu_policy before the KMS issued this leaf",
            shape.count, shape.model
        )),
    );
    if let Some(policy) = &doc.gpu_policy {
        out.insert("verifiers".into(), json!(policy.verifiers));
        out.insert("allowed_models".into(), json!(policy.allowed_models));
    }
    if let Some(coco) = reported.and_then(|res| res.coco.as_ref()) {
        out.insert("reported_gpus".into(), json!(coco.gpus));
        out.insert("reported_gpu_verifiers".into(), json!(coco.gpu_verifiers));
    }
    r.gpu = Value::Object(out);
}

fn value_text(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Array(items) if items.iter().all(Value::is_string) => items
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(", "),
        other => other.to_string(),
    }
}

/// The report for a person: one section per finding, then every check.
pub fn text(report: &Report) -> String {
    let mut out = format!(
        "{}: {}\n",
        report.url,
        if report.verified {
            "verified"
        } else {
            "NOT VERIFIED"
        }
    );
    for (title, section) in [
        ("Platform document", &report.platform_document),
        ("Certificate", &report.certificate),
        ("Revision", &report.revision),
        ("CPU", &report.cpu),
        ("GPU", &report.gpu),
    ] {
        let Some(fields) = section.as_object() else {
            continue;
        };
        out.push_str(&format!("\n{title}\n"));
        for (key, value) in fields {
            out.push_str(&format!("  {key}: {}\n", value_text(value)));
        }
    }
    out.push_str("\nChecks\n");
    for c in &report.checks {
        let mark = if c.ok { "ok    " } else { "FAILED" };
        out.push_str(&format!("  {mark} {}: {}\n", c.name, c.detail));
    }
    out
}

/// The command: 0 when every check passed, 1 when one failed, 2 for a usage error.
pub async fn run(
    args: &Args,
    platform_document_url: Option<&str>,
    pccs_url: &str,
    now: SystemTime,
) -> i32 {
    let usage = |m: String| {
        eprintln!("alpha: {m}");
        2
    };
    let Some(doc_url) = platform_document_url else {
        return usage("--platform-document-url (or ALPHACOMPUTE_*) is required".into());
    };
    let given = match given(args) {
        Ok(given) => given,
        Err(e) => return usage(e),
    };
    let doc = match crate::release_key() {
        Ok(key) => alpha_client::platform::fetch(doc_url, &key, now)
            .await
            .map_err(|e| e.to_string()),
        Err(e) => Err(e),
    };
    let doc = match doc {
        Ok(doc) => doc,
        Err(e) => {
            eprintln!("alpha: platform document: {e}");
            return 1;
        }
    };
    let leaf = served_leaf(&args.url).await;
    let node = match &leaf {
        Ok(leaf) if is_node_leaf(leaf) => Some(node_fetch(&args.url, pccs_url).await),
        _ => None,
    };
    let report = report(&args.url, &doc, leaf, node, &given, now);
    if args.json {
        println!("{:#}", json!(report));
    } else {
        print!("{}", text(&report));
    }
    if report.verified { 0 } else { 1 }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::UNIX_EPOCH;

    use alpha_attest::gpu::{GpuVerifierKind, GpuVouch, VerifiedGpu};
    use alpha_attest::{CocoAppraised, Measured, Measurement, Revision};
    use alpha_core::OrgId;
    use base64::Engine;
    use base64::prelude::BASE64_URL_SAFE_NO_PAD;
    use clap::Parser;
    use rcgen::string::Ia5String;
    use rcgen::{
        BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, PKCS_ECDSA_P256_SHA256,
        PublicKeyData, SanType, SubjectPublicKeyInfo,
    };
    use sha2::{Digest, Sha256};

    use super::*;

    const KEYED: &str = "../../testdata/attest/phala-0.5.9-1c-2g-keyed";
    const INITDATA: &str = include_str!("../../../testdata/coco/b300x1/initdata.toml");
    const REVISION: &str = include_str!("../../../testdata/coco/b300x1/revision.json");
    const URL: &str = "https://app.example";

    fn keyed(name: &str) -> Vec<u8> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join(KEYED)
            .join(name);
        fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
    }

    fn captured_at() -> SystemTime {
        let text = String::from_utf8(keyed("captured_at.txt")).unwrap();
        let t = chrono::DateTime::parse_from_rfc3339(text.trim()).unwrap();
        UNIX_EPOCH + Duration::from_secs(t.timestamp() as u64)
    }

    struct Ca {
        key: KeyPair,
        der: Vec<u8>,
        pem: String,
    }

    fn ca() -> Ca {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.not_before = (captured_at() - Duration::from_secs(86400)).into();
        params.not_after = (captured_at() + Duration::from_secs(86400)).into();
        let cert = params.self_signed(&key).unwrap();
        Ca {
            der: cert.der().to_vec(),
            pem: cert.pem(),
            key,
        }
    }

    /// A one-hour leaf from `ca` over `spki`, issued at the capture time, as the KMS issues one.
    fn leaf(ca: &Ca, spki: &[u8], sans: &[String]) -> Vec<u8> {
        leaf_cert(ca, spki, sans).der().to_vec()
    }

    fn leaf_cert(ca: &Ca, spki: &[u8], sans: &[String]) -> rcgen::Certificate {
        let issuer = Issuer::from_ca_cert_der(&ca.der.clone().into(), &ca.key).unwrap();
        let mut params = CertificateParams::default();
        params.subject_alt_names = sans
            .iter()
            .map(|s| SanType::URI(Ia5String::try_from(s.as_str()).unwrap()))
            .collect();
        params.not_before = captured_at().into();
        params.not_after = (captured_at() + Duration::from_secs(3600)).into();
        let spki = SubjectPublicKeyInfo::from_der(spki).unwrap();
        params.signed_by(&spki, &issuer).unwrap()
    }

    fn doc(ca: &Ca) -> PlatformDocument {
        let mut doc: PlatformDocument =
            serde_json::from_slice(&keyed("platform-document.json")).unwrap();
        doc.kms_ca_pem = ca.pem.clone();
        doc
    }

    fn runtime_spki() -> Vec<u8> {
        KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .unwrap()
            .subject_public_key_info()
    }

    fn org() -> OrgId {
        "01920000-0000-7000-8000-000000000001".parse().unwrap()
    }

    fn app() -> AppId {
        "01994b3e-5c8a-7d3e-9a1b-2c3d4e5f6a7b".parse().unwrap()
    }

    fn instance_sans(spki: &[u8], revision: ComposeHash) -> Vec<String> {
        vec![
            format!(
                "alphacompute://{}/{}/{}",
                org(),
                app(),
                hex::encode(Sha256::digest(spki))
            ),
            format!("urn:alphacompute:revision:{revision}"),
        ]
    }

    fn pod_revision() -> ComposeHash {
        alpha_core::compose_hash(REVISION)
    }

    fn with_initdata() -> Given {
        Given {
            initdata: Some(InitData::parse(INITDATA.as_bytes()).unwrap()),
            ..Given::default()
        }
    }

    /// A pod's leaf and what verifying it with `given` reports.
    fn pod_report(given: &Given) -> (Report, Vec<u8>) {
        let ca = ca();
        let spki = runtime_spki();
        let leaf = leaf(&ca, &spki, &instance_sans(&spki, pod_revision()));
        let r = report(URL, &doc(&ca), Ok(leaf), None, given, captured_at());
        (r, spki)
    }

    fn failed(r: &Report) -> Vec<&'static str> {
        r.checks.iter().filter(|c| !c.ok).map(|c| c.name).collect()
    }

    #[test]
    fn a_gpu_pod_with_its_initdata_verifies_section_by_section() {
        let (r, spki) = pod_report(&with_initdata());
        assert!(r.verified, "{}", text(&r));
        assert_eq!(r.certificate["kind"], "App Instance");
        assert_eq!(r.certificate["app_id"], json!(app()));
        assert_eq!(r.certificate["runtime_pubkey_sha256"], sha256_label(&spki));
        assert_eq!(r.revision["hash"], json!(pod_revision()));
        assert_eq!(r.revision["runtime_class"], "kata-qemu-nvidia-gpu-tdx");
        assert_eq!(r.revision["exec"], "denied");
        assert_eq!(r.revision["logs"], "denied");
        assert_eq!(r.revision["images"].as_array().unwrap().len(), 3);
        assert!(r.cpu["profile"].as_str().unwrap().starts_with("kata-tdx/1"));
        assert!(r.gpu["gpus"].as_str().unwrap().starts_with("1 × B300"));
        let shown = text(&r);
        assert!(
            shown.starts_with("https://app.example: verified\n"),
            "{shown}"
        );
        assert!(shown.contains("  exec: denied\n"), "{shown}");
        assert!(!shown.contains("FAILED"), "{shown}");
    }

    #[test]
    fn without_a_document_only_the_leaf_is_reported() {
        let (r, _) = pod_report(&Given::default());
        assert!(r.verified, "{}", text(&r));
        assert!(
            r.revision["document"]
                .as_str()
                .unwrap()
                .contains("--initdata")
        );
        assert_eq!(r.cpu["profile"], "unknown without the document");
        assert_eq!(r.gpu["gpus"], "unknown without the document");
    }

    #[test]
    fn a_leaf_the_document_does_not_vouch_for_fails() {
        let ca = ca();
        let spki = runtime_spki();
        let sans = instance_sans(&spki, pod_revision());
        let given = with_initdata();

        let foreign = leaf(&self::ca(), &spki, &sans);
        let r = report(URL, &doc(&ca), Ok(foreign), None, &given, captured_at());
        assert!(!r.verified);
        assert_eq!(failed(&r), ["certificate"]);

        let late = captured_at() + Duration::from_secs(3601);
        let r = report(
            URL,
            &doc(&ca),
            Ok(leaf(&ca, &spki, &sans)),
            None,
            &given,
            late,
        );
        assert_eq!(failed(&r), ["certificate"]);

        let other_key = instance_sans(&runtime_spki(), pod_revision());
        let r = report(
            URL,
            &doc(&ca),
            Ok(leaf(&ca, &spki, &other_key)),
            None,
            &given,
            captured_at(),
        );
        assert_eq!(failed(&r), ["identity"]);

        let one_san = leaf(&ca, &spki, &sans[..1]);
        let r = report(URL, &doc(&ca), Ok(one_san), None, &given, captured_at());
        assert_eq!(failed(&r), ["identity"]);

        let r = report(
            URL,
            &doc(&ca),
            Err("refused".into()),
            None,
            &given,
            captured_at(),
        );
        assert!(!r.verified);
        assert_eq!(failed(&r), ["tls"]);
        assert!(text(&r).contains("NOT VERIFIED"));
    }

    #[test]
    fn a_document_of_another_revision_fails() {
        let edited = INITDATA.replace(
            "default ExecProcessRequest := false",
            "default ExecProcessRequest := true",
        );
        let given = Given {
            initdata: Some(InitData::parse(edited.as_bytes()).unwrap()),
            ..Given::default()
        };
        let (r, _) = pod_report(&given);
        assert_eq!(failed(&r), ["revision"]);

        let given = Given {
            compose: Some(format!("{REVISION} ")),
            ..Given::default()
        };
        assert_eq!(failed(&pod_report(&given).0), ["revision"]);
    }

    #[test]
    fn the_registered_revision_v2_gives_the_shape_but_not_the_policy() {
        let given = Given {
            compose: Some(REVISION.into()),
            ..Given::default()
        };
        let (r, _) = pod_report(&given);
        assert!(r.verified, "{}", text(&r));
        assert_eq!(r.revision["runtime_class"], "kata-qemu-nvidia-gpu-tdx");
        assert!(
            r.revision["policy"]
                .as_str()
                .unwrap()
                .contains("--initdata")
        );
        assert!(r.gpu["gpus"].as_str().unwrap().starts_with("1 × B300"));
    }

    fn result(spki: &[u8]) -> AttestationResult {
        let m = Measurement([7u8; 48]);
        let revision: CocoRevision = serde_json::from_str(REVISION).unwrap();
        AttestationResult {
            format: "alphacompute-attestation/1".into(),
            verdict: Verdict::Verified,
            measured: Measured {
                mrtd: m,
                rtmr0: m,
                rtmr1: m,
                rtmr2: m,
                rtmr3: m,
                mrconfigid: Some(m),
            },
            tcb_status: "UpToDate".into(),
            advisories: Vec::new(),
            os_image: "nvidia-uvm-tdx/b300x1".into(),
            revision: Revision {
                compose_hash: pod_revision(),
                app_id: app(),
                org_id: org(),
            },
            runtime_pubkey_sha256: sha256_label(spki),
            evidence_sha256: sha256_label(b"evidence"),
            verified_at: "2026-09-14T03:22:17Z".into(),
            policy_version: 3,
            coco: Some(CocoAppraised {
                profile: "kata-tdx/1".into(),
                initdata_sha256: revision.initdata_sha256,
                policy_sha256: revision.policy_sha256,
                runtime_class: revision.runtime_class,
                gpus: vec![VerifiedGpu {
                    index: 0,
                    device_id: "ueid-0".into(),
                    model: "B300".into(),
                    driver_version: "580.0".into(),
                    vbios_version: "97.0".into(),
                    cc_mode: true,
                    nonce: [1u8; 32],
                }],
                gpu_verifiers: vec![GpuVouch {
                    verifier: GpuVerifierKind::Nras,
                    token_sha256: sha256_label(b"token"),
                }],
            }),
        }
    }

    /// The report for the pod's leaf with its init-data and `edit` applied to a result that
    /// agrees with it.
    fn reported(edit: impl FnOnce(&mut AttestationResult)) -> Report {
        let ca = ca();
        let spki = runtime_spki();
        let leaf = leaf(&ca, &spki, &instance_sans(&spki, pod_revision()));
        let mut res = result(&spki);
        edit(&mut res);
        let given = Given {
            attestation_result: Some(res),
            ..with_initdata()
        };
        report(URL, &doc(&ca), Ok(leaf), None, &given, captured_at())
    }

    #[test]
    fn a_reported_result_is_shown_only_where_it_agrees_with_the_leaf() {
        let r = reported(|_| {});
        assert!(r.verified, "{}", text(&r));
        assert_eq!(r.cpu["reported_result"]["tcb_status"], "UpToDate");
        assert_eq!(r.gpu["reported_gpus"][0]["device_id"], "ueid-0");
        assert_eq!(r.gpu["reported_gpu_verifiers"][0]["verifier"], "nras");

        let faults: [fn(&mut AttestationResult); 8] = [
            |res| res.verdict = Verdict::Failed,
            |res| res.runtime_pubkey_sha256 = sha256_label(b"other"),
            |res| res.revision.app_id = AppId::mint(),
            |res| res.revision.compose_hash = alpha_core::compose_hash("x"),
            |res| res.coco = None,
            |res| res.coco.as_mut().unwrap().policy_sha256 = alpha_core::compose_hash("other"),
            |res| {
                let gpus = &mut res.coco.as_mut().unwrap().gpus;
                gpus.push(gpus[0].clone());
            },
            |res| res.coco.as_mut().unwrap().gpus[0].cc_mode = false,
        ];
        for fault in faults {
            let r = reported(fault);
            assert_eq!(failed(&r), ["attestation result"], "{}", text(&r));
            assert!(r.cpu.get("reported_result").is_none());
            assert!(r.gpu.get("reported_gpus").is_none());
        }
    }

    struct Node {
        ca: Ca,
        leaf: Vec<u8>,
        fetch: NodeFetch,
    }

    /// The keyed capture's node behind a leaf naming its measured Revision.
    fn node() -> Node {
        let ca = ca();
        let spki = keyed("runtime_spki.der");
        let revision =
            alpha_core::compose_hash(std::str::from_utf8(&keyed("app-compose.json")).unwrap());
        let sans = vec![
            cert::KMS_SAN.to_owned(),
            format!("urn:alphacompute:revision:{revision}"),
        ];
        let quote =
            hex::decode(String::from_utf8(keyed("quote.node.hex")).unwrap().trim()).unwrap();
        let evidence = NodeEvidence {
            quote: BASE64_URL_SAFE_NO_PAD.encode(quote),
            event_log: serde_json::from_slice(&keyed("event_log.json")).unwrap(),
            runtime_pubkey: BASE64_URL_SAFE_NO_PAD.encode(&spki),
            xwing_pubkey: alpha_crypto::PublicKey::try_from(
                keyed("node_xwing_pubkey.bin").as_slice(),
            )
            .unwrap(),
            compose_hash: revision,
        };
        Node {
            leaf: leaf(&ca, &spki, &sans),
            ca,
            fetch: NodeFetch {
                evidence,
                nonce: keyed("nonce.bin").try_into().unwrap(),
                server_spki: spki,
                collateral: serde_json::from_slice(&keyed("collateral.json")).unwrap(),
            },
        }
    }

    #[test]
    fn a_kms_node_is_appraised_here_from_its_own_quote() {
        let n = node();
        assert!(is_node_leaf(&n.leaf));
        let r = report(
            URL,
            &doc(&n.ca),
            Ok(n.leaf),
            Some(Ok(n.fetch)),
            &Given::default(),
            captured_at(),
        );
        assert!(r.verified, "{}", text(&r));
        assert_eq!(r.certificate["kind"], "KMS node");
        assert!(
            r.cpu["appraised_by"]
                .as_str()
                .unwrap()
                .starts_with("this command")
        );
        assert!(r.cpu["measured"]["mrtd"].is_string());
        assert!(r.cpu["tcb_status"].is_string());

        let mut n = node();
        n.fetch.server_spki = runtime_spki();
        let r = report(
            URL,
            &doc(&n.ca),
            Ok(n.leaf),
            Some(Ok(n.fetch)),
            &Given::default(),
            captured_at(),
        );
        assert_eq!(failed(&r), ["cpu appraisal"]);

        let mut n = node();
        n.fetch.nonce = [0u8; 32];
        let r = report(
            URL,
            &doc(&n.ca),
            Ok(n.leaf),
            Some(Ok(n.fetch)),
            &Given::default(),
            captured_at(),
        );
        assert_eq!(failed(&r), ["cpu appraisal"]);

        let n = node();
        let mut d = doc(&n.ca);
        d.kms_revisions.clear();
        let r = report(
            URL,
            &d,
            Ok(n.leaf),
            Some(Err("no evidence".into())),
            &Given::default(),
            captured_at(),
        );
        assert_eq!(failed(&r), ["identity", "cpu appraisal"]);
    }

    #[tokio::test]
    async fn the_served_leaf_is_read_over_the_hybrid_and_judged_after() {
        use std::sync::Arc;

        use alpha_client::runtime::RuntimeIdentity;
        use alpha_client::tls::{InstanceCert, serve, server_config};

        let ca = ca();
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let spki = key.subject_public_key_info();
        let cert = leaf_cert(&ca, &spki, &instance_sans(&spki, pod_revision()));
        let identity = RuntimeIdentity {
            app_id: app(),
            org_id: org(),
            compose_hash: pod_revision(),
            certificate_chain: format!("{}{}", cert.pem(), ca.pem),
            tls_private_key: zeroize::Zeroizing::new(key.serialize_der()),
            attestation_result: result(&spki),
            app_compose: String::new(),
        };
        let config = server_config(Arc::new(InstanceCert::new(&identity).unwrap())).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("https://{}/", listener.local_addr().unwrap());
        let server = tokio::spawn(serve(
            listener,
            config,
            axum::Router::new(),
            std::future::pending(),
        ));

        let served = served_leaf(&url).await.unwrap();
        assert_eq!(served, cert.der().to_vec());
        let r = report(
            &url,
            &doc(&ca),
            Ok(served),
            None,
            &with_initdata(),
            captured_at(),
        );
        assert!(r.verified, "{}", text(&r));
        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
        assert!(served_leaf(&url).await.is_err());
    }

    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        args: Args,
    }

    #[test]
    fn initdata_and_compose_exclude_each_other() {
        let parse = |flags: &[&str]| Cli::try_parse_from(["verify"].iter().chain(flags)).is_ok();
        assert!(parse(&[URL]));
        assert!(parse(&["--json", "--initdata", "i.toml", URL]));
        assert!(parse(&[
            "--compose",
            "c.json",
            "--attestation-result",
            "r.json",
            URL
        ]));
        assert!(!parse(&[
            "--initdata",
            "i.toml",
            "--compose",
            "c.json",
            URL
        ]));
        assert!(!parse(&[]));
    }
}
