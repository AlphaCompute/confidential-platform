//! Tag resolution against an HTTPS stand-in for Docker Hub, ghcr.io and quay.io, reached through
//! the production client builder with only the stand-in's CA trusted and the registries' host
//! names resolved to it.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use alpha_cli::deploy;
use alpha_cli::deploy::wrap::{parse, registry_client_builder, resolve, resolve_all, wrap};
use axum::Router;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

const HOSTS: [&str; 4] = [
    "registry-1.docker.io",
    "auth.docker.io",
    "ghcr.io",
    "quay.io",
];
const MANIFEST_TYPES: [&str; 4] = [
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
];

type Reply = (StatusCode, Option<(&'static str, String)>);

#[derive(Default)]
struct Fake {
    /// Keyed by the request line as `requests` records it.
    replies: HashMap<String, Reply>,
    requests: Vec<String>,
}

type Shared = Arc<Mutex<Fake>>;

fn token(repository: &str) -> String {
    format!("token-{}", repository.replace('/', "-"))
}

async fn registry(State(fake): State<Shared>, request: Request) -> Response {
    let host = request
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let uri = request.uri();
    let line = format!(
        "{} {host}{}",
        request.method(),
        uri.path_and_query().map(|p| p.as_str()).unwrap_or_default()
    );
    let mut fake = fake.lock().unwrap();
    fake.requests.push(line.clone());
    let path = uri.path();
    let manifest = path
        .strip_prefix("/v2/")
        .and_then(|p| p.rsplit_once("/manifests/"));
    if let (&Method::HEAD, Some((repository, _))) = (request.method(), manifest) {
        let header = |name| {
            request
                .headers()
                .get(name)
                .and_then(|h| h.to_str().ok())
                .unwrap_or_default()
        };
        if header(header::AUTHORIZATION) != format!("Bearer {}", token(repository)) {
            return StatusCode::UNAUTHORIZED.into_response();
        }
        if !MANIFEST_TYPES
            .iter()
            .all(|t| header(header::ACCEPT).contains(t))
        {
            return StatusCode::NOT_ACCEPTABLE.into_response();
        }
    }
    if let Some((status, extra)) = fake.replies.get(&line) {
        let mut response = status.into_response();
        if let Some((name, value)) = extra {
            response
                .headers_mut()
                .insert(*name, HeaderValue::from_str(value).unwrap());
        }
        return response;
    }
    let token_path = matches!(
        (host.as_str(), path),
        ("auth.docker.io" | "ghcr.io", "/token") | ("quay.io", "/v2/auth")
    );
    if request.method() == Method::GET && token_path {
        let repository = uri
            .query()
            .unwrap_or_default()
            .split('&')
            .find_map(|p| p.strip_prefix("scope=repository:"))
            .and_then(|s| s.strip_suffix(":pull"))
            .unwrap_or_default();
        return (
            [(header::CONTENT_TYPE, "application/json")],
            format!(r#"{{"token":"{}"}}"#, token(repository)),
        )
            .into_response();
    }
    StatusCode::NOT_FOUND.into_response()
}

struct FakeRegistry {
    fake: Shared,
    addr: SocketAddr,
    ca: Vec<u8>,
}

impl FakeRegistry {
    async fn start() -> Self {
        let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let issuer = Issuer::from_ca_cert_der(ca.der(), &ca_key).unwrap();
        let leaf = CertificateParams::new(HOSTS.map(String::from).to_vec())
            .unwrap()
            .signed_by(&leaf_key, &issuer)
            .unwrap();
        let config = rustls::ServerConfig::builder_with_provider(alpha_client::tls::provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![leaf.der().clone(), ca.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
            )
            .unwrap();
        let fake = Shared::default();
        let app = Router::new().fallback(registry).with_state(fake.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(alpha_client::tls::serve(
            listener,
            Arc::new(config),
            app,
            std::future::pending(),
        ));
        FakeRegistry {
            fake,
            addr,
            ca: ca.der().to_vec(),
        }
    }

    fn client(&self) -> reqwest::Client {
        self.client_at(self.addr)
    }

    fn client_at(&self, addr: SocketAddr) -> reqwest::Client {
        let mut builder = registry_client_builder()
            .tls_certs_only([reqwest::Certificate::from_der(&self.ca).unwrap()]);
        for host in HOSTS {
            builder = builder.resolve(host, addr);
        }
        builder.build().unwrap()
    }

    fn reply(&self, line: &str, status: StatusCode, header: Option<(&'static str, &str)>) {
        self.fake.lock().unwrap().replies.insert(
            line.to_owned(),
            (status, header.map(|(k, v)| (k, v.to_owned()))),
        );
    }

    fn digest(&self, line: &str, digest: &str) {
        self.reply(
            line,
            StatusCode::OK,
            Some(("docker-content-digest", digest)),
        );
    }

    fn requests(&self) -> Vec<String> {
        std::mem::take(&mut self.fake.lock().unwrap().requests)
    }
}

fn digest(first: &str) -> String {
    format!("sha256:{first}{}", "0".repeat(64 - first.len()))
}

/// The first service publishes the compose's one port.
fn compose(services: &[(&str, &str)]) -> String {
    let mut text = "services:\n".to_owned();
    for (i, (name, image)) in services.iter().enumerate() {
        text.push_str(&format!("  {name}:\n    image: {image}\n"));
        if i == 0 {
            text.push_str("    ports: [\"8080:80\"]\n");
        }
    }
    text
}

fn wrapped(text: &str, digests: &BTreeMap<String, String>) -> String {
    let app = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/manifest/05-deploy/app.yaml");
    let spec = deploy::parse(&std::fs::read_to_string(app).unwrap()).unwrap();
    wrap(
        parse(text.as_bytes()).unwrap(),
        digests,
        spec.app_id,
        &spec.runtime,
    )
    .unwrap()
    .compose
}

fn compose_file(wrapped: &str) -> String {
    let json: serde_json::Value = serde_json::from_str(wrapped).unwrap();
    json["docker_compose_file"].as_str().unwrap().to_owned()
}

const NGINX_TOKEN: &str =
    "GET auth.docker.io/token?service=registry.docker.io&scope=repository:library/nginx:pull";
const NGINX_HEAD: &str = "HEAD registry-1.docker.io/v2/library/nginx/manifests/1.27";

#[tokio::test]
async fn a_docker_hub_tag_resolves_and_is_pinned() {
    let registry = FakeRegistry::start().await;
    let pinned = digest("6784fb08");
    registry.digest(NGINX_HEAD, &pinned);
    let client = registry.client();
    assert_eq!(resolve(&client, "nginx:1.27").await.unwrap(), pinned);
    assert_eq!(registry.requests(), [NGINX_TOKEN, NGINX_HEAD]);

    let text = compose(&[("web", "nginx:1.27")]);
    let digests = resolve_all(&client, &parse(text.as_bytes()).unwrap())
        .await
        .unwrap();
    assert_eq!(
        digests,
        BTreeMap::from([("nginx:1.27".to_owned(), pinned.clone())])
    );
    assert!(
        compose_file(&wrapped(&text, &digests)).contains(&format!("image: nginx:1.27@{pinned}"))
    );
    assert_eq!(registry.requests(), [NGINX_TOKEN, NGINX_HEAD]);
}
