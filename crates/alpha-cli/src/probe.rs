//! `alpha probe`: whether KMS nodes and App Endpoints are serving, judged the way a client judges
//! them — TLS 1.3 with `X25519MLKEM768` and the server pinned by value, never by its host name.
//! Every leaf the KMS CA issues carries URI SANs and no DNS name, so a check that verifies the
//! host name reads every healthy node as down. The stand runs this against the owned platform.

use std::str::FromStr;
use std::time::Duration;

use alpha_client::{Pin, Probe, Ready, TimeProvider, error_chain, probe_instance, tls};
use alpha_core::ComposeHash;
use reqwest::StatusCode;
use serde::Serialize;
use serde_json::{Value, json};

/// Each request's own bound: a target that does not answer within it is not serving.
const TIMEOUT: Duration = Duration::from_secs(10);

/// What a probe found. A KMS node is `ready`, `sealed` or `down`. An App Endpoint is `attested`
/// (a leaf from the KMS CA naming a listed Revision), `other_revision` (a leaf from the KMS CA
/// naming another Revision), `silent` (no leaf from the KMS CA) or `down` (a leaf from the KMS CA
/// that is not an Instance's).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Ready,
    Sealed,
    Down,
    Attested,
    OtherRevision,
    Silent,
}

/// One target's answer. `finding` is one line that names the target, present exactly when it is
/// not serving.
#[derive(Debug, Serialize)]
pub struct Report {
    pub target: String,
    pub state: State,
    pub serving: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compose_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finding: Option<String>,
}

impl Report {
    fn failing(target: &str, state: State, finding: String) -> Self {
        Self {
            target: target.to_owned(),
            state,
            serving: false,
            app_id: None,
            compose_hash: None,
            finding: Some(finding),
        }
    }
}

/// An App Endpoint and the Revisions it may serve: more than one while a deploy replaces one
/// Revision with the next.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppTarget {
    pub url: String,
    pub revisions: Vec<ComposeHash>,
}

impl FromStr for AppTarget {
    type Err = String;

    /// `<url>=<revision>[,<revision>...]`, split at the last `=`: a Revision has none, a URL may.
    fn from_str(s: &str) -> Result<Self, String> {
        let (url, revisions) = s
            .rsplit_once('=')
            .ok_or_else(|| format!("{s}: not <url>=<revision>[,<revision>...]"))?;
        let url = https(url)?;
        let revisions = revisions
            .split(',')
            .map(|r| {
                r.parse().map_err(|_| {
                    format!("{s}: {r:?} is not a Revision (sha256:<64 lowercase hex>)")
                })
            })
            .collect::<Result<Vec<ComposeHash>, String>>()?;
        Ok(Self { url, revisions })
    }
}

/// `https://` with a host, without its trailing slash. Over plain HTTP nothing is pinned, so a
/// `/ready` from anyone would pass.
fn https(url: &str) -> Result<String, String> {
    let parsed = reqwest::Url::parse(url).map_err(|e| format!("{url}: {e}"))?;
    if parsed.scheme() != "https" || parsed.host().is_none() {
        return Err(format!("{url}: not an https:// URL"));
    }
    Ok(url.trim_end_matches('/').to_owned())
}

/// What one run probes.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Targets {
    pub kms: Vec<String>,
    pub apps: Vec<AppTarget>,
}

/// Every whitespace-separated word of the `--kms` and `--app` values, so that a list kept in one
/// variable is passed as it is. Refuses a set with nothing in it, which would pass vacuously.
pub fn targets(kms: &[String], apps: &[String]) -> Result<Targets, String> {
    let words = |values: &[String]| -> Vec<String> {
        values
            .iter()
            .flat_map(|v| v.split_whitespace())
            .map(str::to_owned)
            .collect()
    };
    let targets = Targets {
        kms: words(kms)
            .iter()
            .map(String::as_str)
            .map(https)
            .collect::<Result<_, _>>()?,
        apps: words(apps)
            .iter()
            .map(|a| a.parse())
            .collect::<Result<_, _>>()?,
    };
    if targets.kms.is_empty() && targets.apps.is_empty() {
        return Err("nothing to probe: --kms and --app name no target".into());
    }
    Ok(targets)
}

/// `pin: None` is only for saying why a target failed its pin; nothing read over it counts.
fn client(pin: Option<Pin>, time: &TimeProvider) -> Result<reqwest::Client, String> {
    let tls = tls::client_config(pin, None, time.clone()).map_err(|e| e.to_string())?;
    reqwest::Client::builder()
        .tls_backend_preconfigured(tls)
        .tls_info(true)
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(TIMEOUT)
        .build()
        .map_err(|e| format!("http client: {e}"))
}

/// The KMS error envelope as `code: message`; any other body, such as an ingress's HTML error
/// page, as its first 200 characters. Either is one line, since it goes into a finding: each run
/// of whitespace, line breaks included, reads as one space, before the body is cut, and a cut
/// that ends on a space drops it.
fn body_text(bytes: &[u8]) -> String {
    let value: Option<Value> = serde_json::from_slice(bytes).ok();
    if let Some(error) = value.as_ref().and_then(|v| v.get("error")) {
        let field = |name: &str| error.get(name).and_then(Value::as_str).unwrap_or("?");
        return one_line(&format!("{}: {}", field("code"), field("message")));
    }
    let cut: String = one_line(&String::from_utf8_lossy(bytes))
        .chars()
        .take(200)
        .collect();
    cut.trim_end().to_owned()
}

/// `text` with each run of whitespace as one space and none at either end.
fn one_line(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

struct Answer {
    status: StatusCode,
    body: Vec<u8>,
    leaf: Option<Vec<u8>>,
}

impl Answer {
    /// `sealed` of a `{"sealed": bool}` body.
    fn sealed(&self) -> Option<bool> {
        serde_json::from_slice::<Ready>(&self.body)
            .ok()
            .map(|r| r.sealed)
    }
}

async fn get(http: &reqwest::Client, url: &str) -> Result<Answer, String> {
    let response = http.get(url).send().await.map_err(|e| error_chain(&e))?;
    let leaf = response
        .extensions()
        .get::<reqwest::tls::TlsInfo>()
        .and_then(|info| info.peer_certificate().map(<[u8]>::to_vec));
    let status = response.status();
    let body = response
        .bytes()
        .await
        .map_err(|e| error_chain(&e))?
        .to_vec();
    Ok(Answer { status, body, leaf })
}

/// One KMS node: `/ready` must answer 200 `{"sealed": false}` over a connection pinned the way the
/// admin CLI pins it, to the KMS CA and a leaf that names the KMS and one of `pin`'s node
/// Revisions. A node that fails the pin is asked again unpinned, only to say why it is down: a
/// sealed node presents its self-signed sealed-phase certificate and answers 503
/// `{"sealed": true}`, which no pin to the CA accepts.
pub async fn kms_node(endpoint: &str, pin: &Pin, time: &TimeProvider) -> Report {
    let url = format!("{endpoint}/ready");
    let pinned = match client(Some(pin.clone()), time) {
        Ok(http) => get(&http, &url).await,
        Err(e) => Err(e),
    };
    let answer = match pinned {
        Ok(answer) => answer,
        Err(why) => return unpinned_kms(endpoint, &url, &why, time).await,
    };
    match (answer.status, answer.sealed()) {
        (StatusCode::OK, Some(false)) => {
            let revision = answer
                .leaf
                .and_then(|leaf| tls::uri_sans(&leaf).ok())
                .and_then(|sans| alpha_channel::cert::parse_kms_sans(&sans).ok());
            Report {
                target: endpoint.to_owned(),
                state: State::Ready,
                serving: true,
                app_id: None,
                compose_hash: revision.map(|r| r.to_string()),
                finding: None,
            }
        }
        (status, Some(true)) => Report::failing(
            endpoint,
            State::Sealed,
            format!(
                "{endpoint}: sealed: /ready answers {status}; a quorum of custodians must unseal it"
            ),
        ),
        (status, _) => Report::failing(
            endpoint,
            State::Down,
            format!(
                "{endpoint}: /ready answers {status}: {}",
                body_text(&answer.body)
            ),
        ),
    }
}

/// Why a node failed its pin, from an unpinned `/ready`. The node is down whatever this reads.
async fn unpinned_kms(endpoint: &str, url: &str, why: &str, time: &TimeProvider) -> Report {
    let answer = match client(None, time) {
        Ok(http) => get(&http, url).await.ok(),
        Err(_) => None,
    };
    match answer {
        Some(answer) if answer.sealed() == Some(true) => Report::failing(
            endpoint,
            State::Sealed,
            format!(
                "{endpoint}: sealed: /ready answers {} {{\"sealed\": true}} under the node's \
                 self-signed sealed-phase certificate; a quorum of custodians must unseal it",
                answer.status
            ),
        ),
        Some(answer) => Report::failing(
            endpoint,
            State::Down,
            format!(
                "{endpoint}: /ready answers {} ({}), but not under the platform document's KMS CA \
                 and node Revisions: {why}",
                answer.status,
                body_text(&answer.body)
            ),
        ),
        None => Report::failing(
            endpoint,
            State::Down,
            format!(
                "{endpoint}: no answer under the platform document's KMS CA and node Revisions: \
                 {why}"
            ),
        ),
    }
}

/// One App Endpoint, judged by the handshake alone as `deploy --wait` judges it: a leaf from the
/// KMS CA, which issues one only to an attested Instance of a registered Revision, naming one of
/// the listed Revisions. The status of the HTTP answer is not looked at.
pub async fn app_endpoint(target: &AppTarget, kms_ca_pem: &str, time: &TimeProvider) -> Report {
    let url = target.url.as_str();
    let Some(first) = target.revisions.first() else {
        return Report::failing(url, State::Silent, format!("{url}: no Revision listed"));
    };
    let attested = |state: State, sans: &tls::InstanceSans, finding: Option<String>| Report {
        target: url.to_owned(),
        state,
        serving: finding.is_none(),
        app_id: Some(sans.app_id.to_string()),
        compose_hash: Some(sans.compose_hash.to_string()),
        finding,
    };
    match probe_instance(url, kms_ca_pem, first, time.clone()).await {
        Ok(Probe::Attested(sans)) => attested(State::Attested, &sans, None),
        Ok(Probe::OtherRevision(sans)) if target.revisions.contains(&sans.compose_hash) => {
            attested(State::Attested, &sans, None)
        }
        Ok(Probe::OtherRevision(sans)) => {
            let finding = format!(
                "{url}: serves Revision {} of App {}, which is not listed",
                sans.compose_hash, sans.app_id
            );
            attested(State::OtherRevision, &sans, Some(finding))
        }
        Ok(Probe::Silent(why)) => {
            let prefix = format!("{url}: ");
            let why = why.strip_prefix(&prefix).unwrap_or(&why);
            let unpinned = match client(None, time) {
                Ok(http) => match get(&http, url).await {
                    Ok(answer) => format!(
                        "; unpinned it answers {}, so its certificate is not a current leaf from \
                         the KMS CA",
                        answer.status
                    ),
                    Err(_) => String::new(),
                },
                Err(_) => String::new(),
            };
            Report::failing(
                url,
                State::Silent,
                format!("{url}: no leaf from the KMS CA: {why}{unpinned}"),
            )
        }
        Err(e) => Report::failing(url, State::Down, format!("{url}: {e}")),
    }
}

/// Every target in turn, KMS nodes first, each judged against the KMS CA and node Revisions the
/// caller took from the verified platform document. The flag says whether any is not serving.
pub async fn run(
    targets: &Targets,
    kms_ca_pem: &str,
    kms_revisions: Vec<ComposeHash>,
    time: TimeProvider,
) -> Result<(Value, bool), String> {
    let ca = tls::cert_from_pem(kms_ca_pem)
        .map_err(|e| format!("the platform document's kms_ca_pem: {e}"))?;
    let pin = Pin::CaAndRevisions(ca, kms_revisions);
    let mut kms = Vec::with_capacity(targets.kms.len());
    for endpoint in &targets.kms {
        kms.push(kms_node(endpoint, &pin, &time).await);
    }
    let mut apps = Vec::with_capacity(targets.apps.len());
    for app in &targets.apps {
        apps.push(app_endpoint(app, kms_ca_pem, &time).await);
    }
    let failed = kms.iter().chain(&apps).any(|r| !r.serving);
    Ok((json!({ "kms": kms, "apps": apps }), failed))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(byte: &str) -> String {
        format!("sha256:{}", byte.repeat(64))
    }

    fn words(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| (*v).to_owned()).collect()
    }

    #[test]
    fn an_app_target_is_a_url_and_its_revisions() {
        let target: AppTarget = format!("https://broker.example/={},{}", hash("a"), hash("b"))
            .parse()
            .unwrap();
        assert_eq!(target.url, "https://broker.example");
        assert_eq!(
            target.revisions,
            vec![hash("a").parse().unwrap(), hash("b").parse().unwrap()]
        );
        // A URL may carry `=`; a Revision may not, so the last one splits them.
        let query: AppTarget = format!("https://a.example/x?y=z={}", hash("c"))
            .parse()
            .unwrap();
        assert_eq!(query.url, "https://a.example/x?y=z");
    }

    #[test]
    fn an_app_target_refuses_what_would_not_be_pinned_or_names_no_revision() {
        let refused = |s: String| s.parse::<AppTarget>().unwrap_err();
        assert!(refused(format!("http://a.example={}", hash("a"))).contains("not an https://"));
        assert!(refused("https://a.example".into()).contains("not <url>=<revision>"));
        assert!(refused("https://a.example=".into()).contains("is not a Revision"));
        assert!(refused(format!("https://a.example={},", hash("a"))).contains("is not a Revision"));
        assert!(refused(format!("https://a.example={}", hash("A"))).contains("is not a Revision"));
        assert!(refused(format!("={}", hash("a"))).contains("relative URL"));
    }

    #[test]
    fn targets_split_on_any_whitespace_and_refuse_an_empty_set() {
        let app = format!("https://a.example={}", hash("a"));
        let t = targets(
            &words(&[
                "https://kms-a.example:8443/\n\thttps://kms-b.example:8443",
                "",
            ]),
            &words(&[&format!("  {app}\n")]),
        )
        .unwrap();
        assert_eq!(
            t.kms,
            ["https://kms-a.example:8443", "https://kms-b.example:8443"]
        );
        assert_eq!(t.apps.len(), 1);
        assert!(targets(&words(&["https://kms.example"]), &[]).is_ok());
        assert!(targets(&[], &words(&[&app])).is_ok());
        for blank in [&[][..], &words(&[""]), &words(&[" \n\t "])] {
            assert!(
                targets(blank, blank)
                    .unwrap_err()
                    .contains("nothing to probe")
            );
        }
        assert!(
            targets(&words(&["http://kms.example"]), &[])
                .unwrap_err()
                .contains("not an https://")
        );
        assert!(
            targets(&words(&["kms.example"]), &[])
                .unwrap_err()
                .contains("relative URL")
        );
    }

    #[test]
    fn a_kms_error_envelope_reads_as_code_and_message() {
        let envelope =
            br#"{"error":{"code":"internal","message":"database: down","request_id":"r"}}"#;
        assert_eq!(body_text(envelope), "internal: database: down");
        assert_eq!(body_text(b"  plain\n"), "plain");
        assert_eq!(body_text("x".repeat(500).as_bytes()).len(), 200);
    }

    #[test]
    fn a_body_reads_as_one_line() {
        let page = b"<html>\r\n<head><title>502 Bad Gateway</title></head>\r\n<body>\r\n\
            <center><h1>502 Bad Gateway</h1></center>\r\n</body>\r\n</html>\r\n";
        assert_eq!(
            body_text(page),
            "<html> <head><title>502 Bad Gateway</title></head> <body> \
             <center><h1>502 Bad Gateway</h1></center> </body> </html>"
        );
        // Collapsed before the cut, so the 200 characters are all the body's own, and the space
        // the cut ends on is dropped.
        let spread = format!("\n\n{}", "a\n\t \n".repeat(300));
        assert_eq!(body_text(spread.as_bytes()), "a ".repeat(100).trim_end());
        let envelope = br#"{"error":{"code":"internal","message":"database:\n  down"}}"#;
        assert_eq!(body_text(envelope), "internal: database: down");
        // A no-break space, and the Unicode line breaks: next line, line and paragraph separator.
        let unicode = "ready\u{a0}\u{2028}now\u{85}and\u{2029}then";
        assert_eq!(body_text(unicode.as_bytes()), "ready now and then");
    }
}
