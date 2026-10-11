//! Our own model servers: one `alpha-model-server` App per model, an OpenAI-compatible server on
//! a whole confidential-computing GPU in a Kata TDX pod VM, whose `alpha-runtime` sidecar
//! terminates TLS with the Instance leaf the KMS issued after CPU and GPU appraisal. Nothing here
//! reads a report: the KMS already appraised the evidence before it issued the leaf, so the
//! handshake itself is the verdict. Every connection is pinned inside the handshake to this
//! Instance's own KMS CA and to one of the model's measured Revisions — the same pin the
//! supervisor and the judge use for their peers — and a leaf of any other CA or Revision never
//! sees a request byte. This Instance's own leaf is the client certificate: a model server admits
//! only an Instance of the front's App (`ALPHACOMPUTE_TLS_CALLER_APPS` in its runtime), so nobody
//! else reaches any of vLLM's routes. Each server has its own bearer, a Secret named per server.
//!
//! Before a model is used, and at most once a minute, `/v1/models` is read over the pinned
//! connection: the server must list the model, and the Revision the leaf carried is logged, so an
//! operator can see which measured build served the model. Every completion logs the Revision of
//! the leaf on its own connection too. A failure leaves the model unverified until the next
//! check; nothing falls back to another provider on its own.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use alpha_client::runtime::RuntimeIdentity;
use alpha_client::tls::Pin;
use alpha_core::ComposeHash;
use rustls::pki_types::CertificateDer;
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::Mutex;

use crate::upstream::Clock;
use crate::{COMPLETION_TIMEOUT, Error};

/// A check is trusted for one minute, as for the external provider.
const VERIFIED_TTL: Duration = Duration::from_secs(60);
const CHECK_TIMEOUT: Duration = Duration::from_secs(10);

/// One model's server, as the measured `MODEL_SERVERS` names it.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ModelServer {
    /// `https://host[:port]`, no path; `/v1/...` is appended.
    pub url: String,
    /// The model server's Revisions this front will talk to, while it changes Revision.
    pub revisions: Vec<ComposeHash>,
    /// The name of this front's Secret holding the bearer this server alone expects, so one
    /// server's bearer opens no other.
    pub bearer: String,
}

/// Parses `MODEL_SERVERS`: a JSON object of model id to `{url, revisions, bearer}`. Every url
/// must be an https origin, every Revision list non-empty — an empty list would match nothing,
/// and is refused here so the mistake shows at start rather than as a model that never verifies —
/// and every bearer a Secret name.
pub fn parse_servers(raw: &str) -> Result<BTreeMap<String, ModelServer>, Error> {
    let servers: BTreeMap<String, ModelServer> =
        serde_json::from_str(raw).map_err(|e| Error::internal(format!("MODEL_SERVERS: {e}")))?;
    for (model, server) in &servers {
        if model.trim().is_empty() || model.trim() != model {
            return Err(Error::internal(
                "MODEL_SERVERS: a model id is empty or padded",
            ));
        }
        let url = reqwest::Url::parse(&server.url)
            .map_err(|e| Error::internal(format!("MODEL_SERVERS[{model}].url: {e}")))?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || url.path() != "/"
            || url.query().is_some()
            || !url.username().is_empty()
        {
            return Err(Error::internal(format!(
                "MODEL_SERVERS[{model}].url must be an https origin without a path"
            )));
        }
        if server.revisions.is_empty() {
            return Err(Error::internal(format!(
                "MODEL_SERVERS[{model}].revisions names no Revision"
            )));
        }
        if !alpha_core::is_key_purpose(&server.bearer) {
            return Err(Error::internal(format!(
                "MODEL_SERVERS[{model}].bearer is not a lowercase Secret name"
            )));
        }
    }
    Ok(servers
        .into_iter()
        .map(|(model, mut server)| {
            server.url = server.url.trim_end_matches('/').to_owned();
            (model, server)
        })
        .collect())
}

/// Why one of our model servers is not trusted right now. Logged by code and model only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    /// No handshake completed against a leaf of the KMS CA carrying a listed Revision: still
    /// booting, still attesting, a Revision not in the list, not ours, or a server that does not
    /// admit this front's App.
    Handshake,
    /// The handshake passed but `/v1/models` did not answer 2xx.
    Status,
    /// The server answered but does not list this model.
    NotServed,
}

impl Reason {
    pub fn code(self) -> &'static str {
        match self {
            Reason::Handshake => "handshake",
            Reason::Status => "status",
            Reason::NotServed => "not_served",
        }
    }
}

struct Checked {
    at: SystemTime,
    outcome: Result<(), Reason>,
}

struct Server {
    origin: String,
    revisions: Vec<ComposeHash>,
    /// Rebuilt with every renewed leaf of this Instance.
    client: parking_lot::RwLock<reqwest::Client>,
    /// The single flight for this model's check, as in `upstream`.
    slot: Mutex<Option<Checked>>,
}

/// The pinned clients for our own model servers, one per model.
pub struct Servers {
    servers: BTreeMap<String, Server>,
    kms_ca: Option<CertificateDer<'static>>,
    now: Clock,
}

fn pinned_client(
    kms_ca: CertificateDer<'static>,
    revisions: Vec<ComposeHash>,
    identity: Option<&RuntimeIdentity>,
) -> Result<reqwest::Client, Error> {
    let tls = alpha_client::tls::client_config(
        Some(Pin::CaAndInstanceRevisions(kms_ca, revisions)),
        identity.map(crate::guard::client_identity).transpose()?,
        alpha_client::system_time_provider(),
    )
    .map_err(|e| Error::internal(format!("model server tls: {e}")))?;
    reqwest::Client::builder()
        .tls_backend_preconfigured(tls)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .tls_info(true)
        .build()
        .map_err(|e| Error::internal(format!("model server client: {e}")))
}

/// The Revision the server's leaf carried on this response's connection, for the log line.
fn served_revision(response: &reqwest::Response) -> Option<ComposeHash> {
    let leaf = response
        .extensions()
        .get::<reqwest::tls::TlsInfo>()?
        .peer_certificate()?
        .to_vec();
    let sans = alpha_client::tls::uri_sans(&leaf).ok()?;
    Some(
        alpha_client::tls::parse_instance_sans(&sans)
            .ok()?
            .compose_hash,
    )
}

fn lists(body: &Value, model: &str) -> bool {
    body.get("data")
        .and_then(Value::as_array)
        .is_some_and(|entries| {
            entries
                .iter()
                .any(|m| m.get("id").and_then(Value::as_str) == Some(model))
        })
}

impl Servers {
    /// No model servers: every allowlisted model goes to the external provider.
    pub fn none() -> Self {
        Self {
            servers: BTreeMap::new(),
            kms_ca: None,
            now: std::sync::Arc::new(SystemTime::now),
        }
    }

    /// `identity` is this Instance's: its leaf is the client certificate a caller-pinning model
    /// server admits. Without one (tests), such a server refuses the handshake.
    pub fn new(
        servers: &BTreeMap<String, ModelServer>,
        kms_ca: &CertificateDer<'static>,
        identity: Option<&RuntimeIdentity>,
    ) -> Result<Self, Error> {
        Self::build(
            servers,
            kms_ca,
            identity,
            std::sync::Arc::new(SystemTime::now),
        )
    }

    pub fn build(
        servers: &BTreeMap<String, ModelServer>,
        kms_ca: &CertificateDer<'static>,
        identity: Option<&RuntimeIdentity>,
        now: Clock,
    ) -> Result<Self, Error> {
        let servers = servers
            .iter()
            .map(|(model, server)| {
                let client = pinned_client(kms_ca.clone(), server.revisions.clone(), identity)?;
                Ok((
                    model.clone(),
                    Server {
                        origin: server.url.clone(),
                        revisions: server.revisions.clone(),
                        client: parking_lot::RwLock::new(client),
                        slot: Mutex::new(None),
                    },
                ))
            })
            .collect::<Result<_, Error>>()?;
        Ok(Self {
            servers,
            kms_ca: Some(kms_ca.clone()),
            now,
        })
    }

    /// Presents the renewed leaf from the next connection on.
    pub fn renew(&self, identity: &RuntimeIdentity) -> Result<(), Error> {
        let Some(kms_ca) = &self.kms_ca else {
            return Ok(());
        };
        for server in self.servers.values() {
            *server.client.write() =
                pinned_client(kms_ca.clone(), server.revisions.clone(), Some(identity))?;
        }
        Ok(())
    }

    pub fn serves(&self, model: &str) -> bool {
        self.servers.contains_key(model)
    }

    /// Checked within the last minute — checking again first if the last check is older, or
    /// there was none. Callers racing a cold model share the one check's outcome.
    pub async fn verified(&self, model: &str, bearer: &str) -> Result<(), Reason> {
        let Some(server) = self.servers.get(model) else {
            return Err(Reason::NotServed);
        };
        let mut guard = server.slot.lock().await;
        let now = (self.now)();
        if let Some(checked) = guard.as_ref()
            && now.duration_since(checked.at).unwrap_or(Duration::MAX) < VERIFIED_TTL
        {
            return checked.outcome;
        }
        let outcome = Self::check(server, model, bearer).await;
        if let Err(reason) = &outcome {
            eprintln!(
                "alpha-inference: model server for {model} not verified: {}",
                reason.code()
            );
        }
        *guard = Some(Checked { at: now, outcome });
        outcome
    }

    async fn check(server: &Server, model: &str, bearer: &str) -> Result<(), Reason> {
        let client = server.client.read().clone();
        let response = client
            .get(format!("{}/v1/models", server.origin))
            .bearer_auth(bearer)
            .timeout(CHECK_TIMEOUT)
            .send()
            .await
            .map_err(|_| Reason::Handshake)?;
        let revision = served_revision(&response);
        if !response.status().is_success() {
            return Err(Reason::Status);
        }
        let body: Value = response.json().await.map_err(|_| Reason::Status)?;
        if !lists(&body, model) {
            return Err(Reason::NotServed);
        }
        // Fixed labels only: the model id and the Revision the pinned leaf carried.
        eprintln!(
            "alpha-inference: model {model} served by alphacompute revision {}",
            revision.map_or_else(|| "unknown".to_owned(), |r| r.to_string())
        );
        Ok(())
    }

    /// The pinned connection failed after a passing check; check again before the next use.
    pub async fn forget(&self, model: &str) {
        if let Some(server) = self.servers.get(model) {
            *server.slot.lock().await = None;
        }
    }

    /// `POST /v1/chat/completions` on `model`'s server over the pinned client, the body as the
    /// caller sent it and the model-server bearer in place of the caller's. The whole exchange,
    /// body included, ends after [`COMPLETION_TIMEOUT`]; the Revision of the leaf that served it
    /// is logged.
    pub async fn complete(
        &self,
        model: &str,
        bearer: &str,
        body: axum::body::Bytes,
    ) -> Result<reqwest::Response, Error> {
        let server = self
            .servers
            .get(model)
            .ok_or_else(|| Error::internal(format!("{model} has no model server")))?;
        let client = server.client.read().clone();
        let response = client
            .post(format!("{}/v1/chat/completions", server.origin))
            .bearer_auth(bearer)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .timeout(COMPLETION_TIMEOUT)
            .body(body)
            .send()
            .await
            .map_err(|_| Error::Upstream)?;
        // Fixed labels only, as for the check: the model, the Revision and the status.
        eprintln!(
            "alpha-inference: model {model} completion served by alphacompute revision {} status={}",
            served_revision(&response).map_or_else(|| "unknown".to_owned(), |r| r.to_string()),
            response.status().as_u16()
        );
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use alpha_client::runtime::RuntimeIdentity;
    use alpha_client::tls::{InstanceCert, server_config};
    use alpha_core::{AppId, OrgId};
    use axum::Router;
    use axum::http::StatusCode;
    use axum::routing::{get, post};
    use rcgen::string::Ia5String;
    use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, SanType};
    use serde_json::json;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;
    use zeroize::Zeroizing;

    use super::*;

    fn new_ca() -> (KeyPair, rcgen::Certificate) {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let now = SystemTime::now();
        params.not_before = (now - Duration::from_secs(3600)).into();
        params.not_after = (now + Duration::from_secs(3600 * 24)).into();
        let cert = params.self_signed(&key).unwrap();
        (key, cert)
    }

    fn revision(c: char) -> ComposeHash {
        format!("sha256:{}", c.to_string().repeat(64))
            .parse()
            .unwrap()
    }

    fn dummy_attestation() -> alpha_attest::AttestationResult {
        let m = alpha_attest::Measurement([0u8; 48]);
        alpha_attest::AttestationResult {
            format: "test".into(),
            verdict: alpha_attest::Verdict::Verified,
            measured: alpha_attest::Measured {
                mrtd: m,
                rtmr0: m,
                rtmr1: m,
                rtmr2: m,
                rtmr3: m,
                mrconfigid: None,
            },
            tcb_status: "UpToDate".into(),
            advisories: Vec::new(),
            os_image: "test".into(),
            revision: alpha_attest::Revision {
                compose_hash: alpha_core::compose_hash("test"),
                app_id: AppId::mint(),
                org_id: OrgId::mint(),
            },
            runtime_pubkey_sha256: format!("sha256:{}", "0".repeat(64)),
            evidence_sha256: format!("sha256:{}", "0".repeat(64)),
            verified_at: "1970-01-01T00:00:00Z".into(),
            policy_version: 1,
            coco: None,
        }
    }

    /// An Instance-shaped leaf under `ca` carrying `rev`, as the KMS would issue it.
    fn leaf(ca_key: &KeyPair, ca_cert: &rcgen::Certificate, rev: &ComposeHash) -> RuntimeIdentity {
        leaf_of(ca_key, ca_cert, AppId::mint(), rev)
    }

    /// As `leaf`, an Instance of `app`.
    fn leaf_of(
        ca_key: &KeyPair,
        ca_cert: &rcgen::Certificate,
        app: AppId,
        rev: &ComposeHash,
    ) -> RuntimeIdentity {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let issuer = Issuer::from_ca_cert_der(ca_cert.der(), ca_key).unwrap();
        let mut params = CertificateParams::default();
        params.subject_alt_names = [
            format!("alphacompute://{}/{app}/{}", OrgId::mint(), "a".repeat(64)),
            format!("urn:alphacompute:revision:{rev}"),
        ]
        .iter()
        .map(|s| SanType::URI(Ia5String::try_from(s.as_str()).unwrap()))
        .collect();
        params.not_before = (SystemTime::now() - Duration::from_secs(60)).into();
        params.not_after = (SystemTime::now() + Duration::from_secs(3600)).into();
        let cert = params.signed_by(&key, &issuer).unwrap();
        RuntimeIdentity {
            app_id: app,
            org_id: OrgId::mint(),
            compose_hash: *rev,
            certificate_chain: format!("{}\n{}", cert.pem(), ca_cert.pem()),
            tls_private_key: Zeroizing::new(key.serialize_der()),
            attestation_result: dummy_attestation(),
            app_compose: String::new(),
        }
    }

    /// A fake model server behind TLS with `identity`'s leaf, listing `models` and counting
    /// every request that reaches it — a refused handshake never does.
    async fn spawn_model_server(
        identity: RuntimeIdentity,
        models: &'static [&'static str],
    ) -> (String, Arc<AtomicUsize>) {
        spawn_model_server_for(identity, models, None).await
    }

    /// As `spawn_model_server`; with `callers`, its runtime admits only an Instance of one of
    /// those Apps under its own KMS CA, as `ALPHACOMPUTE_TLS_CALLER_APPS` makes it.
    async fn spawn_model_server_for(
        identity: RuntimeIdentity,
        models: &'static [&'static str],
        callers: Option<Vec<AppId>>,
    ) -> (String, Arc<AtomicUsize>) {
        let hits = Arc::new(AtomicUsize::new(0));
        let counted = hits.clone();
        let completed = hits.clone();
        let app = Router::new()
            .route(
                "/v1/models",
                get(move || {
                    let counted = counted.clone();
                    async move {
                        counted.fetch_add(1, Ordering::SeqCst);
                        let data: Vec<Value> = models.iter().map(|m| json!({"id": m})).collect();
                        axum::Json(json!({"object": "list", "data": data}))
                    }
                }),
            )
            .route(
                "/v1/chat/completions",
                post(move || {
                    let completed = completed.clone();
                    async move {
                        completed.fetch_add(1, Ordering::SeqCst);
                        StatusCode::OK
                    }
                }),
            );
        let cert = Arc::new(InstanceCert::new(&identity).unwrap());
        let config = match callers {
            None => server_config(cert).unwrap(),
            Some(apps) => {
                let ca = alpha_client::tls::kms_ca(&identity).unwrap();
                Arc::new(
                    rustls::ServerConfig::builder_with_provider(alpha_client::tls::provider())
                        .with_protocol_versions(&[&rustls::version::TLS13])
                        .unwrap()
                        .with_client_cert_verifier(alpha_client::tls::instance_app_client_verifier(
                            Arc::new(move || Some(ca.clone())),
                            apps,
                        ))
                        .with_cert_resolver(cert),
                )
            }
        };
        let acceptor = TlsAcceptor::from(config);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                let app = app.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let service = hyper_util::service::TowerToHyperService::new(app);
                    let _ = hyper_util::server::conn::auto::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    )
                    .serve_connection(hyper_util::rt::TokioIo::new(tls), service)
                    .await;
                });
            }
        });
        (format!("https://localhost:{}", addr.port()), hits)
    }

    fn servers_for(url: &str, ca: &rcgen::Certificate, revs: Vec<ComposeHash>) -> Servers {
        servers_presenting(url, ca, revs, None)
    }

    /// As `servers_for`, presenting `front`'s leaf as the client certificate.
    fn servers_presenting(
        url: &str,
        ca: &rcgen::Certificate,
        revs: Vec<ComposeHash>,
        front: Option<&RuntimeIdentity>,
    ) -> Servers {
        let mut map = BTreeMap::new();
        map.insert(
            "m1".to_owned(),
            ModelServer {
                url: url.to_owned(),
                revisions: revs,
                bearer: "model-server-bearer-m1".to_owned(),
            },
        );
        Servers::new(&map, &CertificateDer::from(ca.der().to_vec()), front).unwrap()
    }

    #[test]
    fn parse_servers_refuses_a_path_an_http_url_an_empty_revision_list_and_a_bad_bearer() {
        let ok = format!(
            r#"{{"m1":{{"url":"https://ms.example:8443/","revisions":["{}"],"bearer":"model-server-bearer-m1"}}}}"#,
            revision('1')
        );
        let parsed = parse_servers(&ok).unwrap();
        assert_eq!(parsed["m1"].url, "https://ms.example:8443");
        assert_eq!(parsed["m1"].bearer, "model-server-bearer-m1");
        for bad in [
            format!(
                r#"{{"m1":{{"url":"https://ms.example/v1","revisions":["{}"],"bearer":"b"}}}}"#,
                revision('1')
            ),
            format!(
                r#"{{"m1":{{"url":"http://ms.example","revisions":["{}"],"bearer":"b"}}}}"#,
                revision('1')
            ),
            format!(
                r#"{{"m1":{{"url":"https://ms.example","revisions":["{}"]}}}}"#,
                revision('1')
            ),
            format!(
                r#"{{"m1":{{"url":"https://ms.example","revisions":["{}"],"bearer":"../b"}}}}"#,
                revision('1')
            ),
            r#"{"m1":{"url":"https://ms.example","revisions":[],"bearer":"b"}}"#.to_owned(),
            r#"{"m1":{"url":"https://ms.example","revisions":["nope"],"bearer":"b"}}"#.to_owned(),
            r#"{"m1":{"url":"https://ms.example","revisions":[],"bearer":"b","extra":1}}"#
                .to_owned(),
        ] {
            let err = parse_servers(&bad).unwrap_err();
            assert!(err.to_string().contains("MODEL_SERVERS"), "{bad}: {err}");
        }
    }

    #[tokio::test]
    async fn a_leaf_with_a_listed_revision_verifies_and_completes() {
        let (ca_key, ca_cert) = new_ca();
        let rev = revision('1');
        let (url, hits) = spawn_model_server(leaf(&ca_key, &ca_cert, &rev), &["m1"]).await;
        let servers = servers_for(&url, &ca_cert, vec![rev]);
        assert_eq!(servers.verified("m1", "ms-bearer").await, Ok(()));
        let response = servers
            .complete("m1", "ms-bearer", axum::body::Bytes::from_static(b"{}"))
            .await
            .unwrap();
        assert!(response.status().is_success());
        // What the per-completion log line names: the Revision of this connection's leaf.
        assert_eq!(served_revision(&response), Some(rev));
        assert_eq!(hits.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_leaf_with_another_revision_is_refused_before_any_request_byte() {
        let (ca_key, ca_cert) = new_ca();
        let (url, hits) =
            spawn_model_server(leaf(&ca_key, &ca_cert, &revision('2')), &["m1"]).await;
        let servers = servers_for(&url, &ca_cert, vec![revision('1')]);
        assert_eq!(
            servers.verified("m1", "ms-bearer").await,
            Err(Reason::Handshake)
        );
        assert!(
            servers
                .complete("m1", "ms-bearer", axum::body::Bytes::from_static(b"{}"))
                .await
                .is_err()
        );
        assert_eq!(hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_leaf_of_another_ca_is_refused_before_any_request_byte() {
        let (other_key, other_ca) = new_ca();
        let (_ca_key, ca_cert) = new_ca();
        let rev = revision('1');
        let (url, hits) = spawn_model_server(leaf(&other_key, &other_ca, &rev), &["m1"]).await;
        let servers = servers_for(&url, &ca_cert, vec![rev]);
        assert_eq!(
            servers.verified("m1", "ms-bearer").await,
            Err(Reason::Handshake)
        );
        assert_eq!(hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_server_that_does_not_list_the_model_is_not_verified() {
        let (ca_key, ca_cert) = new_ca();
        let rev = revision('1');
        let (url, _hits) = spawn_model_server(leaf(&ca_key, &ca_cert, &rev), &["other"]).await;
        let servers = servers_for(&url, &ca_cert, vec![rev]);
        assert_eq!(
            servers.verified("m1", "ms-bearer").await,
            Err(Reason::NotServed)
        );
    }

    #[tokio::test]
    async fn a_fresh_check_is_reused_and_forget_forces_a_new_one() {
        let (ca_key, ca_cert) = new_ca();
        let rev = revision('1');
        let (url, hits) = spawn_model_server(leaf(&ca_key, &ca_cert, &rev), &["m1"]).await;
        let servers = servers_for(&url, &ca_cert, vec![rev]);
        servers.verified("m1", "b").await.unwrap();
        servers.verified("m1", "b").await.unwrap();
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        servers.forget("m1").await;
        servers.verified("m1", "b").await.unwrap();
        assert_eq!(hits.load(Ordering::SeqCst), 2);
    }

    /// A model server whose runtime pins its callers to the front's App: the front's leaf gets
    /// through, a leaf of another App or no leaf never reaches a single route, and a renewed
    /// leaf of the front is presented from the next connection on.
    #[tokio::test]
    async fn a_caller_pinning_model_server_serves_only_the_fronts_app() {
        let (ca_key, ca_cert) = new_ca();
        let rev = revision('1');
        let front = AppId::mint();
        let (url, hits) =
            spawn_model_server_for(leaf(&ca_key, &ca_cert, &rev), &["m1"], Some(vec![front])).await;
        let front_leaf = leaf_of(&ca_key, &ca_cert, front, &revision('f'));

        let ours = servers_presenting(&url, &ca_cert, vec![rev], Some(&front_leaf));
        assert_eq!(ours.verified("m1", "b").await, Ok(()));
        assert!(
            ours.complete("m1", "b", axum::body::Bytes::from_static(b"{}"))
                .await
                .unwrap()
                .status()
                .is_success()
        );
        assert_eq!(hits.load(Ordering::SeqCst), 2);

        let stranger = leaf_of(&ca_key, &ca_cert, AppId::mint(), &revision('f'));
        for presenting in [Some(&stranger), None] {
            let other = servers_presenting(&url, &ca_cert, vec![rev], presenting);
            assert_eq!(other.verified("m1", "b").await, Err(Reason::Handshake));
            assert!(
                other
                    .complete("m1", "b", axum::body::Bytes::from_static(b"{}"))
                    .await
                    .is_err()
            );
        }
        assert_eq!(hits.load(Ordering::SeqCst), 2);

        // Renewal swaps the client certificate: a stranger's servers renewed to the front's leaf
        // get through.
        let renewed = servers_presenting(&url, &ca_cert, vec![rev], Some(&stranger));
        renewed.renew(&front_leaf).unwrap();
        assert_eq!(renewed.verified("m1", "b").await, Ok(()));
        assert_eq!(hits.load(Ordering::SeqCst), 3);
    }
}
