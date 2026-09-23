//! A fresh database per test migrated with the broker's own migrations, a TLS stand-in for
//! Google's OAuth endpoints that the router's HTTP client reaches through its real host names,
//! and a request helper that fails any test whose reply leaks a token, code, verifier or the
//! client secret. The broker itself listens over mTLS on a real port, with a stand-in KMS CA
//! issuing both its own leaf and the callers'.
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use alpha_broker::{AppState, Config, Secrets, oauth, router, tls};
use alpha_client::tls::{Identity, Pin};
use axum::body::{Body, to_bytes};
use axum::extract::{Form, Query, State};
use axum::http::{HeaderMap, Request, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use hyper_util::service::TowerToHyperService;
use rcgen::string::Ia5String;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::SingleCertAndKey;
use serde_json::{Value, json};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;
use uuid::Uuid;

pub const BEARER: &str = "connect-bearer-for-tests";
pub const PROXY_BEARER: &str = "proxy-bearer-for-tests";
pub const CLIENT_ID: &str = "corpus-test.apps.googleusercontent.com";
pub const CLIENT_SECRET: &str = "client-secret-for-tests";
pub const REDIRECT_URI: &str = "https://corpus.example/oauth/google/callback";
pub const KEY: [u8; 32] = [9; 32];
pub const EMAIL: &str = "member@example.com";
pub const MEMBER: &str = "1111111111111111111111111111111111111111111111111111111111111111";
pub const OTHER_MEMBER: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const HOSTS: [&str; 4] = [
    "accounts.google.com",
    "oauth2.googleapis.com",
    "openidconnect.googleapis.com",
    "www.googleapis.com",
];
pub const MEDIA: &str = "https://www.googleapis.com/drive/v3/files/file-1?alt=media";
pub const LISTING: &str = r#"{"files":[{"id":"file-1","name":"Notes"}]}"#;

/// A fresh database per test, migrated; `None` when `DATABASE_URL` is unset.
pub async fn fresh_database() -> Option<PgPool> {
    let admin_url = std::env::var("DATABASE_URL").ok()?;
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&admin_url)
        .await
        .unwrap();
    let name = format!("alpha_test_{}", Uuid::now_v7().simple());
    sqlx::query(sqlx::AssertSqlSafe(format!("create database {name}")))
        .execute(&admin)
        .await
        .unwrap();
    let url = {
        let mut u = reqwest::Url::parse(&admin_url).unwrap();
        u.set_path(&format!("/{name}"));
        u.to_string()
    };
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    alpha_broker::store::migrate(&pool).await.unwrap();
    Some(pool)
}

/// What the member's consent at Google produced: the code the popup relays, and the tokens the
/// token endpoint will issue for it.
#[derive(Clone)]
pub struct Consent {
    pub code: String,
    pub access_token: String,
    pub refresh_token: String,
    challenge: String,
    subject: String,
    email: String,
    used: bool,
}

/// One request that reached Google's data API.
#[derive(Clone, Debug)]
pub struct DataRequest {
    pub path: String,
    pub query: HashMap<String, String>,
    pub authorization: Option<String>,
}

pub struct Fake {
    consents: Vec<Consent>,
    /// Every request that reached the stand-in's OAuth endpoints: path and form or query fields.
    pub requests: Vec<(String, HashMap<String, String>)>,
    pub data: Vec<DataRequest>,
    /// A status other than 200 refuses every token request; 400 with `invalid_grant`.
    pub token_status: StatusCode,
    pub omit_refresh_token: bool,
    pub account_status: StatusCode,
    pub revoke_status: StatusCode,
    /// Refreshes issue a new refresh token and stop accepting the one presented.
    pub rotate: bool,
    /// How long a refresh takes to answer.
    pub refresh_delay: Duration,
    /// The next this many data requests answer 401 whatever token they carry.
    pub unauthorized: usize,
    pub media_size: usize,
    /// Access tokens the data API accepts, and refresh tokens the token endpoint accepts.
    pub access: Vec<String>,
    pub refresh: Vec<String>,
    issued: Vec<String>,
}

impl Fake {
    pub fn hits(&self, path: &str) -> usize {
        self.requests.iter().filter(|(p, _)| p == path).count()
    }

    pub fn refreshes(&self) -> usize {
        self.requests
            .iter()
            .filter(|(_, form)| form.get("grant_type").map(String::as_str) == Some("refresh_token"))
            .count()
    }

    /// Every value that must never appear in a reply to the tenant.
    fn secrets(&self) -> Vec<String> {
        let mut out = vec![CLIENT_SECRET.to_string()];
        for c in &self.consents {
            out.extend([
                c.code.clone(),
                c.access_token.clone(),
                c.refresh_token.clone(),
            ]);
        }
        out.extend(
            self.requests
                .iter()
                .filter_map(|(_, form)| form.get("code_verifier").cloned()),
        );
        out.extend(self.issued.iter().cloned());
        out
    }
}

type Shared = Arc<Mutex<Fake>>;

fn invalid_grant() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "error": "invalid_grant" })),
    )
        .into_response()
}

async fn token(State(fake): State<Shared>, Form(form): Form<HashMap<String, String>>) -> Response {
    let delay = {
        let mut fake = fake.lock().unwrap();
        fake.requests.push(("/token".into(), form.clone()));
        fake.refresh_delay
    };
    let field = |k: &str| form.get(k).map(String::as_str).unwrap_or_default();
    if field("grant_type") == "refresh_token" {
        tokio::time::sleep(delay).await;
    }
    let mut fake = fake.lock().unwrap();
    if fake.token_status != StatusCode::OK {
        let status = fake.token_status;
        let error = if status == StatusCode::BAD_REQUEST {
            "invalid_grant"
        } else {
            "server_error"
        };
        return (status, Json(json!({ "error": error }))).into_response();
    }
    if field("grant_type") == "refresh_token" {
        let presented = field("refresh_token").to_string();
        if field("client_id") != CLIENT_ID
            || field("client_secret") != CLIENT_SECRET
            || !fake.refresh.contains(&presented)
        {
            return invalid_grant();
        }
        let n = fake.refreshes();
        let access = format!("ya29.fake-refreshed-{n}");
        fake.access.push(access.clone());
        fake.issued.push(access.clone());
        let mut reply =
            json!({ "access_token": access, "expires_in": 3599, "token_type": "Bearer" });
        if fake.rotate {
            let rotated = format!("1//fake-rotated-{n}");
            fake.refresh.retain(|t| *t != presented);
            fake.refresh.push(rotated.clone());
            fake.issued.push(rotated.clone());
            reply["refresh_token"] = json!(rotated);
        }
        return Json(reply).into_response();
    }
    let ok_client = field("grant_type") == "authorization_code"
        && field("client_id") == CLIENT_ID
        && field("client_secret") == CLIENT_SECRET
        && field("redirect_uri") == REDIRECT_URI;
    let verifier_challenge = oauth::challenge(field("code_verifier"));
    let code = field("code").to_string();
    let omit = fake.omit_refresh_token;
    let Some(consent) = fake
        .consents
        .iter_mut()
        .find(|c| c.code == code && !c.used && c.challenge == verifier_challenge)
        .filter(|_| ok_client)
    else {
        return invalid_grant();
    };
    consent.used = true;
    let mut reply = json!({
        "access_token": consent.access_token,
        "expires_in": 3599,
        "token_type": "Bearer",
        "scope": "openid https://www.googleapis.com/auth/drive.readonly email",
    });
    if !omit {
        reply["refresh_token"] = json!(consent.refresh_token);
    }
    Json(reply).into_response()
}

async fn userinfo(State(fake): State<Shared>, headers: HeaderMap) -> Response {
    let mut fake = fake.lock().unwrap();
    let presented = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or_default()
        .to_string();
    fake.requests.push(("/v1/userinfo".into(), HashMap::new()));
    if fake.account_status != StatusCode::OK {
        return fake.account_status.into_response();
    }
    match fake.consents.iter().find(|c| c.access_token == presented) {
        Some(c) => Json(json!({ "sub": c.subject, "email": c.email, "email_verified": true }))
            .into_response(),
        None => StatusCode::UNAUTHORIZED.into_response(),
    }
}

async fn revoke(State(fake): State<Shared>, Form(form): Form<HashMap<String, String>>) -> Response {
    let mut fake = fake.lock().unwrap();
    fake.requests.push(("/revoke".into(), form));
    fake.revoke_status.into_response()
}

/// Drive, Gmail and Calendar reads, answered only to an access token the stand-in issued.
async fn data(
    State(fake): State<Shared>,
    uri: Uri,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let mut fake = fake.lock().unwrap();
    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    fake.data.push(DataRequest {
        path: uri.path().to_string(),
        query: query.clone(),
        authorization: authorization.clone(),
    });
    let token = authorization
        .as_deref()
        .and_then(|a| a.strip_prefix("Bearer "))
        .unwrap_or_default();
    if fake.unauthorized > 0 || !fake.access.iter().any(|t| t == token) {
        fake.unauthorized = fake.unauthorized.saturating_sub(1);
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": { "code": 401, "message": "Invalid Credentials" } })),
        )
            .into_response();
    }
    let segments: Vec<&str> = uri.path().split('/').skip(1).collect();
    let json_body = |body: String| ([(header::CONTENT_TYPE, "application/json")], body);
    match segments[..] {
        ["drive", "v3", "drives"] => json_body(r#"{"drives":[]}"#.into()).into_response(),
        ["drive", "v3", "files"] => json_body(LISTING.into()).into_response(),
        ["drive", "v3", "files", _] if query.get("alt").map(String::as_str) == Some("media") => (
            [(header::CONTENT_TYPE, "application/octet-stream")],
            vec![b'x'; fake.media_size],
        )
            .into_response(),
        ["drive", "v3", "files", id] => {
            json_body(json!({ "id": id, "name": "Notes" }).to_string()).into_response()
        }
        ["drive", "v3", "files", _, "export"] => {
            ([(header::CONTENT_TYPE, "text/csv")], "a,b\n1,2\n").into_response()
        }
        ["gmail", "v1", "users", "me", "messages"] => {
            json_body(r#"{"messages":[{"id":"m1"}]}"#.into()).into_response()
        }
        ["gmail", "v1", "users", "me", "messages", id] => {
            json_body(json!({ "id": id, "snippet": "hello" }).to_string()).into_response()
        }
        ["calendar", "v3", "calendars", "primary", "events"] => {
            json_body(r#"{"items":[]}"#.into()).into_response()
        }
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

pub struct FakeGoogle {
    pub state: Shared,
    pub addr: SocketAddr,
    ca_der: Vec<u8>,
}

impl FakeGoogle {
    pub async fn start() -> Self {
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

        let state: Shared = Arc::new(Mutex::new(Fake {
            consents: vec![],
            requests: vec![],
            token_status: StatusCode::OK,
            omit_refresh_token: false,
            account_status: StatusCode::OK,
            revoke_status: StatusCode::OK,
            data: vec![],
            rotate: false,
            refresh_delay: Duration::ZERO,
            unauthorized: 0,
            media_size: 0,
            access: vec![],
            refresh: vec![],
            issued: vec![],
        }));
        let app = Router::new()
            .route("/token", post(token))
            .route("/v1/userinfo", get(userinfo))
            .route("/revoke", post(revoke))
            .fallback(data)
            .with_state(state.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                let (acceptor, app) = (acceptor.clone(), app.clone());
                tokio::spawn(async move {
                    if let Ok(tls) = acceptor.accept(tcp).await {
                        let _ = Builder::new(TokioExecutor::new())
                            .serve_connection(TokioIo::new(tls), TowerToHyperService::new(app))
                            .await;
                    }
                });
            }
        });
        FakeGoogle {
            state,
            addr,
            ca_der: ca.der().to_vec(),
        }
    }

    /// A client that reaches Google's host names at the stand-in and trusts only its CA.
    pub fn client(&self) -> reqwest::Client {
        let mut builder = reqwest::Client::builder()
            .tls_certs_only([reqwest::Certificate::from_der(&self.ca_der).unwrap()])
            .redirect(reqwest::redirect::Policy::none());
        for host in HOSTS {
            builder = builder.resolve(host, self.addr);
        }
        builder.build().unwrap()
    }

    /// Stands in for the member consenting as `email` on the page the authorization URL opens.
    pub fn consent(&self, challenge: &str, email: &str) -> Consent {
        self.consent_as(challenge, &format!("subject-of-{email}"), email)
    }

    /// The same, as the Google account `subject` whose address is currently `email`.
    pub fn consent_as(&self, challenge: &str, subject: &str, email: &str) -> Consent {
        let mut fake = self.state.lock().unwrap();
        let n = fake.consents.len() + 1;
        let consent = Consent {
            code: format!("4/fake-code-{n}"),
            access_token: format!("ya29.fake-access-{n}"),
            refresh_token: format!("1//fake-refresh-{n}"),
            challenge: challenge.to_string(),
            subject: subject.to_string(),
            email: email.to_string(),
            used: false,
        };
        fake.consents.push(consent.clone());
        fake.access.push(consent.access_token.clone());
        fake.refresh.push(consent.refresh_token.clone());
        consent
    }

    pub fn with<R>(&self, f: impl FnOnce(&mut Fake) -> R) -> R {
        f(&mut self.state.lock().unwrap())
    }
}

/// A CA standing in for the KMS's, and the leaves it issues.
pub struct Ca {
    key: KeyPair,
    pub cert: rcgen::Certificate,
}

impl Ca {
    pub fn new() -> Self {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let cert = params.self_signed(&key).unwrap();
        Ca { key, cert }
    }

    pub fn der(&self) -> CertificateDer<'static> {
        self.cert.der().clone()
    }

    /// A leaf carrying exactly `sans` as URI SANs, usable as a client and as a server.
    pub fn leaf(&self, sans: &[String]) -> Identity {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::default();
        params.subject_alt_names = sans
            .iter()
            .map(|s| SanType::URI(Ia5String::try_from(s.as_str()).unwrap()))
            .collect();
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ClientAuth,
            ExtendedKeyUsagePurpose::ServerAuth,
        ];
        let issuer = Issuer::from_ca_cert_der(self.cert.der(), &self.key).unwrap();
        let leaf = params.signed_by(&key, &issuer).unwrap();
        Identity {
            chain: vec![leaf.der().to_vec(), self.cert.der().to_vec()],
            pkcs8: key.serialize_der(),
        }
    }

    pub fn instance(&self) -> Identity {
        self.leaf(&[
            format!(
                "alphacompute://{}/{}/{}",
                Uuid::now_v7(),
                Uuid::now_v7(),
                "a".repeat(64)
            ),
            format!("urn:alphacompute:revision:sha256:{}", "1".repeat(64)),
        ])
    }
}

/// A client presenting `identity` (or no certificate) and trusting only `ca` for the broker.
pub fn instance_client(ca: &Ca, identity: Option<Identity>) -> reqwest::Client {
    let config = alpha_client::tls::client_config(
        Some(Pin::Ca(ca.der())),
        identity,
        Arc::new(rustls::time_provider::DefaultTimeProvider),
    )
    .unwrap();
    reqwest::Client::builder()
        .tls_backend_preconfigured(config)
        .build()
        .unwrap()
}

/// Serves the router over the broker's own listener on an ephemeral port.
async fn start_broker(ca: &Ca, app: Router) -> SocketAddr {
    let own = ca.instance();
    let key = rustls::crypto::aws_lc_rs::default_provider()
        .key_provider
        .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(own.pkcs8)))
        .unwrap();
    let certified = rustls::sign::CertifiedKey::new(
        own.chain.into_iter().map(CertificateDer::from).collect(),
        key,
    );
    let config = tls::server_config(Arc::new(SingleCertAndKey::from(certified)), ca.der()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(alpha_client::tls::serve(
        listener,
        config,
        app,
        std::future::pending(),
    ));
    addr
}

pub struct Harness {
    pub state: Arc<AppState>,
    pub pool: PgPool,
    pub google: FakeGoogle,
    pub app: Router,
    pub ca: Ca,
    pub broker: SocketAddr,
    /// An attested Instance's client: a leaf from the broker's CA.
    pub instance: reqwest::Client,
}

pub async fn harness() -> Option<Harness> {
    let pool = fresh_database().await?;
    let google = FakeGoogle::start().await;
    let state = Arc::new(AppState {
        config: Config {
            google_client_id: CLIENT_ID.into(),
            google_redirect_uri: REDIRECT_URI.into(),
        },
        secrets: parking_lot::RwLock::new(Secrets {
            google_client_secret: CLIENT_SECRET.to_string().into(),
            connect_bearer: BEARER.as_bytes().to_vec().into(),
            proxy_bearer: PROXY_BEARER.as_bytes().to_vec().into(),
            connectors_key: KEY.into(),
        }),
        pool: pool.clone(),
        http: google.client(),
        tokens: Default::default(),
    });
    let app = router(state.clone());
    let ca = Ca::new();
    let broker = start_broker(&ca, app.clone()).await;
    let instance = instance_client(&ca, Some(ca.instance()));
    Some(Harness {
        state,
        pool,
        app,
        google,
        ca,
        broker,
        instance,
    })
}

pub struct Reply {
    pub status: StatusCode,
    pub body: Value,
}

/// A `/proxy` reply: the provider's bytes are not always JSON.
pub struct Raw {
    pub status: StatusCode,
    pub content_type: Option<String>,
    pub bytes: Vec<u8>,
}

impl Raw {
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.bytes).unwrap()
    }

    pub fn code(&self) -> Value {
        self.json()["error"]["code"].clone()
    }
}

pub fn read(connection: Uuid, url: &str) -> Value {
    json!({ "member": MEMBER, "connection_id": connection, "method": "GET", "url": url })
}

impl Harness {
    /// One request through the router, with the connect bearer unless `bearer` says otherwise.
    pub async fn call_as(
        &self,
        bearer: Option<&str>,
        method: &str,
        uri: &str,
        body: Option<Value>,
    ) -> Reply {
        let mut builder = Request::builder().method(method).uri(uri);
        if let Some(bearer) = bearer {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {bearer}"));
        }
        let request = match body {
            Some(body) => builder
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string())),
            None => builder.body(Body::empty()),
        }
        .unwrap();
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let text = String::from_utf8_lossy(&bytes).to_string();
        for secret in self.google.with(|f| f.secrets()) {
            assert!(
                !text.contains(&secret),
                "{method} {uri} answered a secret: {text}"
            );
        }
        let body = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap()
        };
        Reply { status, body }
    }

    pub async fn call(&self, method: &str, uri: &str, body: Option<Value>) -> Reply {
        self.call_as(Some(BEARER), method, uri, body).await
    }

    /// Starts a connect for `member` and returns the authorization URL's query.
    pub async fn start(&self, member: &str) -> HashMap<String, String> {
        let reply = self
            .call("POST", "/connect/google", Some(json!({ "member": member })))
            .await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        let url = reqwest::Url::parse(reply.body["url"].as_str().unwrap()).unwrap();
        url.query_pairs().into_owned().collect()
    }

    pub async fn finish(&self, member: &str, code: &str, state: &str) -> Reply {
        self.call(
            "POST",
            "/connect/finish",
            Some(json!({ "member": member, "code": code, "state": state })),
        )
        .await
    }

    /// A whole connect as `email`; returns the finish reply and the consent behind it.
    pub async fn connect(&self, member: &str, email: &str) -> (Reply, Consent) {
        let query = self.start(member).await;
        let consent = self.google.consent(&query["code_challenge"], email);
        let reply = self.finish(member, &consent.code, &query["state"]).await;
        (reply, consent)
    }

    /// `POST /proxy` over the real listener from `client`; fails the test if anything in the
    /// reply, headers included, carries a token or secret. `Err` when the request itself failed.
    pub async fn proxy_with(
        &self,
        client: &reqwest::Client,
        bearer: Option<&str>,
        body: &Value,
    ) -> Result<Raw, reqwest::Error> {
        let mut request = client
            .post(format!("https://{}/proxy", self.broker))
            .header(header::CONTENT_TYPE, "application/json")
            .body(body.to_string());
        if let Some(bearer) = bearer {
            request = request.bearer_auth(bearer);
        }
        let response = request.send().await?;
        let status = response.status();
        let headers = format!("{:?}", response.headers());
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .map(|v| v.to_str().unwrap().to_string());
        let bytes = response.bytes().await?.to_vec();
        let text = String::from_utf8_lossy(&bytes);
        for secret in self.google.with(|f| f.secrets()) {
            assert!(!text.contains(&secret), "/proxy answered a secret: {text}");
            assert!(
                !headers.contains(&secret),
                "/proxy answered a secret: {headers}"
            );
        }
        Ok(Raw {
            status,
            content_type,
            bytes,
        })
    }

    /// From the attested Instance with the proxy bearer.
    pub async fn proxy(&self, body: &Value) -> Raw {
        self.proxy_with(&self.instance, Some(PROXY_BEARER), body)
            .await
            .unwrap()
    }

    /// A connection of `MEMBER` to Google, made through the connect routes.
    pub async fn connected(&self) -> (Uuid, Consent) {
        let (reply, consent) = self.connect(MEMBER, EMAIL).await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        (id_of(&reply), consent)
    }

    pub async fn stored_token(&self, id: Uuid) -> Option<Vec<u8>> {
        sqlx::query_scalar("select enc_refresh_token from connections where id = $1")
            .bind(id)
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }
}

pub async fn count(h: &Harness, table: &str) -> i64 {
    sqlx::query_scalar(sqlx::AssertSqlSafe(format!("select count(*) from {table}")))
        .fetch_one(&h.pool)
        .await
        .unwrap()
}

pub fn id_of(reply: &Reply) -> Uuid {
    Uuid::parse_str(reply.body["id"].as_str().unwrap()).unwrap()
}
