//! Our own model servers: per model, an App whose Instances serve an OpenAI-compatible API behind
//! a KMS-issued leaf. The KMS appraised a server before it issued that leaf, so the handshake is
//! the verdict: every connection is pinned to this Instance's KMS CA and one of the model's
//! Revisions, and a server presenting anything else never sees a request byte. The front
//! presents its own leaf in return, so a server admits callers by App; no shared bearer adds
//! anything to that.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use alpha_client::tls::Pin;
use alpha_core::ComposeHash;
use axum::body::Bytes;
use rustls::client::ResolvesClientCert;
use rustls::pki_types::CertificateDer;
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::Mutex;

use crate::Error;

/// Short, because `/ready` reads it: a server back up is ready again within this.
const PROBE_TTL: Duration = Duration::from_secs(10);
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelServer {
    /// `https://host[:port]`, without a path; `/v1/...` is appended.
    pub url: String,
    /// The model server App's Revisions this front talks to.
    pub revisions: Vec<ComposeHash>,
}

/// `MODEL_SERVERS`: a JSON object of model id to `{url, revisions}`.
pub fn parse(raw: &str) -> Result<BTreeMap<String, ModelServer>, Error> {
    let mut servers: BTreeMap<String, ModelServer> =
        serde_json::from_str(raw).map_err(|e| Error::internal(format!("MODEL_SERVERS: {e}")))?;
    for (model, server) in &mut servers {
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
        server.url = url.as_str().trim_end_matches('/').to_owned();
    }
    Ok(servers)
}

pub struct Server {
    url: String,
    client: reqwest::Client,
    /// The last probe: when, and whether the server listed the model. The lock is the single
    /// flight.
    probe: Mutex<Option<(Instant, bool)>>,
}

#[derive(Default)]
pub struct Servers(BTreeMap<String, Server>);

impl Servers {
    /// `leaf` is this Instance's own certificate, renewed in place.
    pub fn new(
        config: &BTreeMap<String, ModelServer>,
        kms_ca: &CertificateDer<'static>,
        leaf: Arc<dyn ResolvesClientCert>,
        completion_timeout: Duration,
    ) -> Result<Self, Error> {
        config
            .iter()
            .map(|(model, server)| {
                let tls = alpha_client::tls::renewing_client_config(
                    Pin::CaAndInstanceRevisions(kms_ca.clone(), server.revisions.clone()),
                    leaf.clone(),
                    alpha_client::system_time_provider(),
                )
                .map_err(|e| Error::internal(format!("model server tls: {e}")))?;
                let client = reqwest::Client::builder()
                    .tls_backend_preconfigured(tls)
                    .no_proxy()
                    .redirect(reqwest::redirect::Policy::none())
                    .timeout(completion_timeout)
                    .build()
                    .map_err(|e| Error::internal(format!("model server client: {e}")))?;
                let server = Server {
                    url: server.url.clone(),
                    client,
                    probe: Mutex::new(None),
                };
                Ok((model.clone(), server))
            })
            .collect::<Result<_, Error>>()
            .map(Servers)
    }

    pub fn get(&self, model: &str) -> Option<&Server> {
        self.0.get(model)
    }
}

impl Server {
    /// Whether the server answered `/v1/models` listing `model` within the last [`PROBE_TTL`],
    /// probing again first if not; callers racing a stale probe share one.
    pub async fn live(&self, model: &str) -> bool {
        let mut last = self.probe.lock().await;
        if let Some((at, live)) = *last
            && at.elapsed() < PROBE_TTL
        {
            return live;
        }
        let live = self.lists(model).await;
        if !live {
            eprintln!("alpha-inference: model server for {model} failed its probe");
        }
        *last = Some((Instant::now(), live));
        live
    }

    async fn lists(&self, model: &str) -> bool {
        let fetch = async {
            let body: Value = self
                .client
                .get(format!("{}/v1/models", self.url))
                .timeout(PROBE_TIMEOUT)
                .send()
                .await
                .ok()?
                .error_for_status()
                .ok()?
                .json()
                .await
                .ok()?;
            body.get("data")?
                .as_array()?
                .iter()
                .any(|m| m.get("id").and_then(Value::as_str) == Some(model))
                .then_some(())
        };
        fetch.await.is_some()
    }

    pub async fn complete(&self, body: Bytes) -> reqwest::Result<reqwest::Response> {
        self.client
            .post(format!("{}/v1/chat/completions", self.url))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use alpha_client::tls::PeerCerts;
    use axum::http::{Request, StatusCode, header};
    use axum::routing::{get, post};
    use axum::{Extension, Router};
    use rcgen::string::Ia5String;
    use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, SanType};
    use rustls::server::{ClientHello, ResolvesServerCert};
    use rustls::sign::CertifiedKey;
    use serde_json::json;
    use tower::ServiceExt;

    use super::*;
    use crate::COMPLETION_TIMEOUT;
    use crate::test_support::{answering, spawn_fake_upstream, test_config, test_state};

    /// One leaf, served or presented as is.
    #[derive(Debug)]
    struct Fixed(Arc<CertifiedKey>);

    impl ResolvesClientCert for Fixed {
        fn resolve(&self, _: &[&[u8]], _: &[rustls::SignatureScheme]) -> Option<Arc<CertifiedKey>> {
            Some(self.0.clone())
        }
        fn has_certs(&self) -> bool {
            true
        }
    }

    impl ResolvesServerCert for Fixed {
        fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
            Some(self.0.clone())
        }
    }

    struct Ca(KeyPair, rcgen::Certificate);

    impl Ca {
        fn new() -> Self {
            let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
            let mut params = CertificateParams::default();
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            let cert = params.self_signed(&key).unwrap();
            Ca(key, cert)
        }

        fn der(&self) -> CertificateDer<'static> {
            self.1.der().clone()
        }

        /// An Instance leaf of some App at `revision`, as the KMS issues it.
        fn leaf(&self, revision: &ComposeHash) -> Arc<Fixed> {
            let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
            let mut params = CertificateParams::default();
            params.subject_alt_names = [
                format!(
                    "alphacompute://{}/{}/{}",
                    alpha_core::OrgId::mint(),
                    alpha_core::AppId::mint(),
                    "a".repeat(64)
                ),
                format!("urn:alphacompute:revision:{revision}"),
            ]
            .into_iter()
            .map(|s| SanType::URI(Ia5String::try_from(s).unwrap()))
            .collect();
            let issuer = Issuer::from_ca_cert_der(self.1.der(), &self.0).unwrap();
            let cert = params.signed_by(&key, &issuer).unwrap();
            let chain = vec![cert.der().clone(), self.der()];
            Arc::new(Fixed(
                alpha_client::tls::certified(chain, &key.serialize_der()).unwrap(),
            ))
        }
    }

    /// A model server serving `leaf` that answers a completion after `delay`, refusing one from
    /// a caller that presented no leaf of `ca`. Counts the completions that reached it.
    async fn spawn_model_server(
        ca: &Ca,
        leaf: Arc<Fixed>,
        delay: Duration,
    ) -> (String, Arc<AtomicUsize>) {
        let hits = Arc::new(AtomicUsize::new(0));
        let counted = hits.clone();
        let app = Router::new()
            .route(
                "/v1/models",
                get(|| async { axum::Json(json!({ "data": [{ "id": "own" }] })) }),
            )
            .route(
                "/v1/chat/completions",
                post(move |Extension(peer): Extension<PeerCerts>| async move {
                    counted.fetch_add(1, Ordering::SeqCst);
                    if peer.0.is_empty() {
                        return StatusCode::UNAUTHORIZED;
                    }
                    tokio::time::sleep(delay).await;
                    StatusCode::OK
                }),
            );
        let tls = alpha_client::tls::mtls_server_config(leaf, ca.der()).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(alpha_client::tls::serve(
            listener,
            tls,
            app,
            std::future::pending(),
        ));
        (format!("https://{addr}"), hits)
    }

    /// A front serving `own` from `url` pinned to `revision`, with its own leaf of `ca`, and
    /// `external` from a RedPill whose check always fails.
    async fn front(
        ca: &Ca,
        url: &str,
        revision: ComposeHash,
        timeout: Duration,
    ) -> (Router, Arc<AtomicUsize>) {
        let (base, report_hits, _) =
            spawn_fake_upstream(answering(StatusCode::INTERNAL_SERVER_ERROR, "")).await;
        let mut config = test_config(&base, &["own", "external"]);
        config.own.insert(
            "own".into(),
            ModelServer {
                url: url.into(),
                revisions: vec![revision],
            },
        );
        let mut state = test_state(config, b"bearer", "key");
        let front_leaf = ca.leaf(&alpha_core::compose_hash("front"));
        let own = Servers::new(&state.config.own, &ca.der(), front_leaf, timeout).unwrap();
        Arc::get_mut(&mut state).unwrap().own = own;
        (crate::router(state), report_hits)
    }

    async fn complete(front: &Router, model: &str) -> (StatusCode, Value) {
        let request = Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header(header::AUTHORIZATION, "Bearer bearer")
            .body(axum::body::Body::from(
                json!({ "model": model }).to_string(),
            ))
            .unwrap();
        let response = front.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    #[tokio::test]
    async fn an_own_model_goes_to_its_server_over_mtls_and_any_other_to_the_verified_provider() {
        let ca = Ca::new();
        let revision = alpha_core::compose_hash("model-server");
        let (url, hits) = spawn_model_server(&ca, ca.leaf(&revision), Duration::ZERO).await;
        let (front, report_hits) = front(&ca, &url, revision, COMPLETION_TIMEOUT).await;

        assert_eq!(complete(&front, "own").await.0, StatusCode::OK);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert_eq!(report_hits.load(Ordering::SeqCst), 0);

        let (status, body) = complete(&front, "external").await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(body["error"]["code"], "upstream_unverified");
        assert_eq!(report_hits.load(Ordering::SeqCst), 1);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_server_of_another_revision_or_ca_never_sees_the_request() {
        let ca = Ca::new();
        let pinned = alpha_core::compose_hash("model-server");
        for leaf in [
            ca.leaf(&alpha_core::compose_hash("other")),
            Ca::new().leaf(&pinned),
        ] {
            let (url, hits) = spawn_model_server(&ca, leaf, Duration::ZERO).await;
            let (front, _) = front(&ca, &url, pinned, COMPLETION_TIMEOUT).await;
            let (status, body) = complete(&front, "own").await;
            assert_eq!(status, StatusCode::BAD_GATEWAY);
            assert_eq!(body["error"]["code"], "upstream");
            assert_eq!(hits.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn a_completion_past_the_timeout_ends_with_a_gateway_error() {
        let ca = Ca::new();
        let revision = alpha_core::compose_hash("model-server");
        let (url, hits) =
            spawn_model_server(&ca, ca.leaf(&revision), Duration::from_secs(30)).await;
        let (front, _) = front(&ca, &url, revision, Duration::from_millis(200)).await;
        let (status, _) = tokio::time::timeout(Duration::from_secs(10), complete(&front, "own"))
            .await
            .unwrap();
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }
}
