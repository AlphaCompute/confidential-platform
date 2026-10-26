//! Our own model servers: per model, an App whose Instances serve an OpenAI-compatible API behind
//! a KMS-issued leaf. The KMS appraised a server before it issued that leaf, so the handshake is
//! the verdict: every connection is pinned to this Instance's KMS CA and one of the model's
//! Revisions, and a server presenting anything else never sees a request byte. The front
//! presents its own leaf in return, so a server admits callers by App; no shared bearer adds
//! anything to that.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use alpha_client::log::Field;
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

#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelServer {
    /// `https://host[:port]`, without a path; `/v1/...` is appended.
    pub url: String,
    /// The model server App's Revisions this front talks to.
    pub revisions: Vec<ComposeHash>,
}

/// `https://host[:port]` without a path, credentials, query or fragment, trailing slash trimmed.
pub fn origin(raw: &str) -> Option<String> {
    let url = reqwest::Url::parse(raw).ok()?;
    (url.scheme() == "https"
        && url.host_str().is_some()
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none()
        && url.username().is_empty()
        && url.password().is_none())
    .then(|| url.as_str().trim_end_matches('/').to_owned())
}

/// `MODEL_SERVERS`: a JSON object of model id to `{url, revisions}`.
pub fn parse(raw: &str) -> Result<BTreeMap<String, ModelServer>, Error> {
    let mut servers: BTreeMap<String, ModelServer> =
        serde_json::from_str(raw).map_err(|e| Error::internal(format!("MODEL_SERVERS: {e}")))?;
    for (model, server) in &mut servers {
        server.url = origin(&server.url).ok_or_else(|| {
            Error::internal(format!(
                "MODEL_SERVERS[{model}].url must be an https origin without a path"
            ))
        })?;
        if server.revisions.is_empty() {
            return Err(Error::internal(format!(
                "MODEL_SERVERS[{model}].revisions names no Revision"
            )));
        }
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

/// `leaf` is this Instance's own certificate, renewed in place.
pub fn servers(
    config: &BTreeMap<String, ModelServer>,
    kms_ca: &CertificateDer<'static>,
    leaf: Arc<dyn ResolvesClientCert>,
    completion_timeout: Duration,
) -> Result<BTreeMap<String, Arc<Server>>, Error> {
    config
        .iter()
        .map(|(model, server)| {
            let pin = Pin::CaAndInstanceRevisions(kms_ca.clone(), server.revisions.clone(), None);
            let server = Server::new(&server.url, pin, leaf.clone(), completion_timeout)?;
            Ok((model.clone(), Arc::new(server)))
        })
        .collect()
}

impl Server {
    pub fn new(
        url: &str,
        pin: Pin,
        leaf: Arc<dyn ResolvesClientCert>,
        completion_timeout: Duration,
    ) -> Result<Self, Error> {
        let tls = alpha_client::tls::renewing_client_config(
            pin,
            leaf,
            alpha_client::system_time_provider(),
        )
        .map_err(|e| Error::internal(format!("model server tls: {e}")))?;
        let client = reqwest::Client::builder()
            .tls_backend_preconfigured(tls)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(completion_timeout)
            .tls_info(true)
            .build()
            .map_err(|e| Error::internal(format!("model server client: {e}")))?;
        Ok(Server {
            url: url.to_owned(),
            client,
            probe: Mutex::new(None),
        })
    }

    /// Whether the server answered `/v1/models` listing `model` within the last [`PROBE_TTL`],
    /// probing again first if not; callers racing a stale probe share one.
    pub async fn live(&self, model: &str) -> bool {
        let mut last = self.probe.lock().await;
        if let Some((at, live)) = *last
            && at.elapsed() < PROBE_TTL
        {
            return live;
        }
        let live = match self.lists(model).await {
            Ok((revision, listed)) => {
                alpha_client::info!(
                    "probe",
                    model = Field::text(model),
                    revision = &revision,
                    listed = listed,
                );
                listed
            }
            Err(_) => {
                alpha_client::warn!("probe_failed", model = Field::text(model));
                false
            }
        };
        *last = Some((Instant::now(), live));
        live
    }

    async fn lists(&self, model: &str) -> Result<(ComposeHash, bool), String> {
        let response = self
            .client
            .get(format!("{}/v1/models", self.url))
            .timeout(PROBE_TIMEOUT)
            .send()
            .await
            .map_err(transport)?;
        let revision = served_revision(&response)?;
        let listed = async {
            response
                .error_for_status()
                .ok()?
                .json::<Value>()
                .await
                .ok()?
                .get("data")?
                .as_array()?
                .iter()
                .any(|m| m.get("id").and_then(Value::as_str) == Some(model))
                .then_some(())
        };
        Ok((revision, listed.await.is_some()))
    }

    /// Logs the model, the Revision that answered, the status and the time to the response
    /// head; never the request or the answer.
    pub async fn complete(&self, model: &str, body: Bytes) -> Result<reqwest::Response, Error> {
        let started = Instant::now();
        let answered = self
            .client
            .post(format!("{}/v1/chat/completions", self.url))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(transport)
            .and_then(|response| served_revision(&response).map(|revision| (response, revision)));
        let duration_ms = started.elapsed();
        match &answered {
            Ok((response, revision)) => alpha_client::info!(
                "completion",
                model = Field::text(model),
                revision = revision,
                status = response.status().as_u16(),
                duration_ms = duration_ms,
            ),
            Err(_) => alpha_client::warn!(
                "completion_failed",
                model = Field::text(model),
                duration_ms = duration_ms,
            ),
        }
        answered
            .map(|(response, _)| response)
            .map_err(|_| Error::Upstream)
    }
}

fn served_revision(response: &reqwest::Response) -> Result<ComposeHash, String> {
    let leaf = response
        .extensions()
        .get::<reqwest::tls::TlsInfo>()
        .and_then(reqwest::tls::TlsInfo::peer_certificate)
        .ok_or("no model server certificate on the connection")?;
    alpha_client::tls::uri_sans(leaf)
        .and_then(|sans| alpha_client::tls::parse_instance_sans(&sans))
        .map(|sans| sans.compose_hash)
        .map_err(|e| format!("model server leaf: {e}"))
}

/// reqwest's own message names only the URL; the cause (timeout, refused, handshake) is in
/// its sources.
fn transport(e: reqwest::Error) -> String {
    std::iter::successors(Some(&e as &dyn std::error::Error), |e| e.source())
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(": ")
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use alpha_client::tls::PeerCerts;
    use axum::http::{Request, StatusCode, header};
    use axum::response::IntoResponse;
    use axum::routing::{get, post};
    use axum::{Extension, Router};
    use rcgen::string::Ia5String;
    use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, SanType};
    use rustls::server::{ClientHello, ResolvesServerCert};
    use rustls::sign::CertifiedKey;
    use serde_json::{Value, json};
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
            self.leaf_of(alpha_core::OrgId::mint(), revision)
        }

        fn leaf_of(&self, org: alpha_core::OrgId, revision: &ComposeHash) -> Arc<Fixed> {
            let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
            let mut params = CertificateParams::default();
            params.subject_alt_names = [
                format!(
                    "alphacompute://{}/{}/{}",
                    org,
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
    /// a caller that presented no leaf of `ca`, as vLLM does: `usage` at the end of a whole
    /// answer, and in a last chunk of a stream only when asked for. Counts the completions that
    /// reached it.
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
                post(
                    move |Extension(peer): Extension<PeerCerts>, body: Bytes| async move {
                        counted.fetch_add(1, Ordering::SeqCst);
                        if peer.0.is_empty() {
                            return StatusCode::UNAUTHORIZED.into_response();
                        }
                        tokio::time::sleep(delay).await;
                        let request: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                        let usage = json!({ "prompt_tokens": 3, "completion_tokens": 4 });
                        if request["stream"] != true {
                            return axum::Json(json!({ "choices": [], "usage": usage }))
                                .into_response();
                        }
                        let mut events =
                            format!("data: {}\n\n", json!({ "choices": [{ "delta": {} }] }));
                        if request["stream_options"]["include_usage"] == true {
                            events +=
                                &format!("data: {}\n\n", json!({ "choices": [], "usage": usage }));
                        }
                        events += "data: [DONE]\n\n";
                        ([(header::CONTENT_TYPE, "text/event-stream")], events).into_response()
                    },
                ),
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
        let own = servers(&state.config.own, &ca.der(), front_leaf, timeout).unwrap();
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

    #[tokio::test]
    async fn a_keyed_completion_records_its_tokens_whole_or_streamed() {
        let Some(pool) = crate::test_support::fresh_database().await else {
            return;
        };
        let ca = Ca::new();
        let revision = alpha_core::compose_hash("model-server");
        let (url, _) = spawn_model_server(&ca, ca.leaf(&revision), Duration::ZERO).await;
        let mut config = test_config("https://example.invalid", &["own"]);
        config.external = None;
        config.own.insert(
            "own".into(),
            ModelServer {
                url,
                revisions: vec![revision],
            },
        );
        let mut state = test_state(config, b"bearer", "key");
        let front_leaf = ca.leaf(&alpha_core::compose_hash("front"));
        let own = servers(&state.config.own, &ca.der(), front_leaf, COMPLETION_TIMEOUT).unwrap();
        let inner = Arc::get_mut(&mut state).unwrap();
        inner.own = own;
        inner.pool = pool.clone();
        let tasks = inner.usage_tasks.clone();
        let org = uuid::Uuid::now_v7();
        let key = crate::keys::create(&pool, &state.keys_key, org, "k")
            .await
            .unwrap();
        let front = crate::router(state);

        for (bearer, stream) in [
            (key.key.as_str(), false),
            (&key.key, true),
            ("bearer", true),
        ] {
            let request = Request::builder()
                .method("POST")
                .uri("/v1/chat/completions")
                .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
                .body(axum::body::Body::from(
                    json!({ "model": "own", "stream": stream }).to_string(),
                ))
                .unwrap();
            let response = front.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            assert_eq!(
                String::from_utf8_lossy(&body).contains("\"usage\""),
                bearer != "bearer" || !stream,
                "the shared bearer's stream is relayed as asked for"
            );
        }

        let coerced = Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header(header::AUTHORIZATION, format!("Bearer {}", key.key))
            .body(axum::body::Body::from(
                json!({ "model": "own", "stream": "true" }).to_string(),
            ))
            .unwrap();
        let response = front.clone().oneshot(coerced).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let usage = |bearer: String| {
            let front = front.clone();
            async move {
                let request = Request::builder()
                    .uri("/v1/usage")
                    .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
                    .body(axum::body::Body::empty())
                    .unwrap();
                let response = front.oneshot(request).await.unwrap();
                let status = response.status();
                let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                    .await
                    .unwrap();
                (
                    status,
                    serde_json::from_slice::<Value>(&body).unwrap_or(Value::Null),
                )
            }
        };
        let expected =
            json!([{ "model": "own", "requests": 2, "prompt_tokens": 6, "completion_tokens": 8 }]);
        tasks.close();
        tasks.wait().await;
        assert_eq!(usage(key.key.clone()).await.1, expected);
        assert_eq!(usage("bearer".into()).await.0, StatusCode::NOT_FOUND);

        let export = |query: String| {
            let front = front.clone();
            async move {
                let admin = std::str::from_utf8(crate::test_support::ADMIN_BEARER).unwrap();
                let request = Request::builder()
                    .uri(format!("/admin/usage?{query}"))
                    .header(header::AUTHORIZATION, format!("Bearer {admin}"))
                    .body(axum::body::Body::empty())
                    .unwrap();
                let body = front.oneshot(request).await.unwrap().into_body();
                serde_json::from_slice::<Value>(
                    &axum::body::to_bytes(body, usize::MAX).await.unwrap(),
                )
                .unwrap()
            }
        };
        let rows = export(format!(
            "from=2000-01-01T00:00:00Z&to=2100-01-01T00:00:00Z&org_id={org}"
        ))
        .await;
        assert_eq!(rows.as_array().unwrap().len(), 1);
        assert_eq!(rows[0]["key_id"], json!(key.id));
        assert_eq!(rows[0]["prompt_tokens"], 6);
        let other = uuid::Uuid::now_v7();
        assert_eq!(
            export(format!(
                "from=2000-01-01T00:00:00Z&to=2100-01-01T00:00:00Z&org_id={other}"
            ))
            .await,
            json!([])
        );
    }

    #[tokio::test]
    async fn an_organization_reaches_only_its_own_model_servers_through_untampered_rows() {
        let Some(pool) = crate::test_support::fresh_database().await else {
            return;
        };
        let ca = Ca::new();
        let revision = alpha_core::compose_hash("model-server");
        let (org, other) = (alpha_core::OrgId::mint(), alpha_core::OrgId::mint());
        let (url, hits) = spawn_model_server(&ca, ca.leaf_of(org, &revision), Duration::ZERO).await;
        let mut config = test_config("https://example.invalid", &["shared"]);
        config.external = None;
        let mut state = test_state(config, b"bearer", "key");
        let inner = Arc::get_mut(&mut state).unwrap();
        inner.pool = pool.clone();
        inner.org_clients =
            crate::org_models::Clients::new(ca.der(), ca.leaf(&alpha_core::compose_hash("front")));
        let key = |org: alpha_core::OrgId| {
            let (pool, k) = (pool.clone(), *state.keys_key);
            async move {
                crate::keys::create(&pool, &k, org.into(), "k")
                    .await
                    .unwrap()
                    .key
            }
        };
        let (mine, theirs) = (key(org).await, key(other).await);
        let front = crate::router(state);
        let admin = std::str::from_utf8(crate::test_support::ADMIN_BEARER).unwrap();
        let call = |method: &'static str, path: String, bearer: String, body: Option<Value>| {
            let front = front.clone();
            async move { crate::tests::call(&front, method, &path, &bearer, body).await }
        };
        let route = |org| format!("/admin/orgs/{org}/models/acme/private");
        let row = json!({ "url": url, "revisions": [revision] });

        for (org, body, bearer, status) in [
            (org, row.clone(), mine.as_str(), StatusCode::UNAUTHORIZED),
            (
                org,
                json!({ "url": format!("{url}/v1"), "revisions": [revision] }),
                admin,
                StatusCode::BAD_REQUEST,
            ),
            (
                org,
                json!({ "url": url, "revisions": [] }),
                admin,
                StatusCode::BAD_REQUEST,
            ),
            (org, row.clone(), admin, StatusCode::NO_CONTENT),
            // The admin may point another organization's row at this server; the pin refuses it.
            (other, row.clone(), admin, StatusCode::NO_CONTENT),
        ] {
            assert_eq!(
                call("PUT", route(org), bearer.into(), Some(body)).await.0,
                status
            );
        }
        let shared = format!("/admin/orgs/{org}/models/shared");
        assert_eq!(
            call("PUT", shared, admin.into(), Some(row)).await.0,
            StatusCode::BAD_REQUEST
        );

        let completion = json!({ "model": "acme/private" });
        let complete = |bearer: &str| {
            call(
                "POST",
                "/v1/chat/completions".into(),
                bearer.into(),
                Some(completion.clone()),
            )
        };
        assert_eq!(complete(&mine).await.0, StatusCode::OK);
        assert_eq!(complete("bearer").await.0, StatusCode::NOT_FOUND);
        assert_eq!(complete(&theirs).await.0, StatusCode::BAD_GATEWAY);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        let listed = |bearer: &str| call("GET", "/v1/models".into(), bearer.into(), None);
        assert!(listed(&mine).await.1.to_string().contains("acme/private"));
        assert!(
            !listed("bearer")
                .await
                .1
                .to_string()
                .contains("acme/private")
        );

        sqlx::query("update model_servers set url = 'https://127.0.0.2:8443' where org_id = $1")
            .bind(uuid::Uuid::from(org))
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(complete(&mine).await.0, StatusCode::NOT_FOUND);
        assert!(!listed(&mine).await.1.to_string().contains("acme/private"));

        for status in [StatusCode::NO_CONTENT, StatusCode::NOT_FOUND] {
            assert_eq!(
                call("DELETE", route(other), admin.into(), None).await.0,
                status
            );
        }
        assert_eq!(complete(&theirs).await.0, StatusCode::NOT_FOUND);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }
}
