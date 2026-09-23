//! A fresh database per test migrated with the broker's own migrations, a TLS stand-in for
//! Google's OAuth endpoints that the router's HTTP client reaches through its real host names,
//! and a request helper that fails any test whose reply leaks a token, code, verifier or the
//! client secret.
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

use alpha_broker::{AppState, Config, Secrets, oauth, router};
use axum::body::{Body, to_bytes};
use axum::extract::{Form, State};
use axum::http::{HeaderMap, Request, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use hyper_util::service::TowerToHyperService;
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::{Value, json};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;
use uuid::Uuid;

pub const BEARER: &str = "connect-bearer-for-tests";
pub const CLIENT_ID: &str = "corpus-test.apps.googleusercontent.com";
pub const CLIENT_SECRET: &str = "client-secret-for-tests";
pub const REDIRECT_URI: &str = "https://corpus.example/oauth/google/callback";
pub const KEY: [u8; 32] = [9; 32];
pub const EMAIL: &str = "member@example.com";
pub const MEMBER: &str = "1111111111111111111111111111111111111111111111111111111111111111";
pub const OTHER_MEMBER: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const HOSTS: [&str; 3] = [
    "accounts.google.com",
    "oauth2.googleapis.com",
    "openidconnect.googleapis.com",
];

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
    email: String,
    used: bool,
}

pub struct Fake {
    consents: Vec<Consent>,
    /// Every request that reached the stand-in: path and form or query fields.
    pub requests: Vec<(String, HashMap<String, String>)>,
    pub token_status: StatusCode,
    pub omit_refresh_token: bool,
    pub account_status: StatusCode,
    pub revoke_status: StatusCode,
}

impl Fake {
    pub fn hits(&self, path: &str) -> usize {
        self.requests.iter().filter(|(p, _)| p == path).count()
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
        out
    }
}

type Shared = Arc<Mutex<Fake>>;

async fn token(State(fake): State<Shared>, Form(form): Form<HashMap<String, String>>) -> Response {
    let mut fake = fake.lock().unwrap();
    fake.requests.push(("/token".into(), form.clone()));
    if fake.token_status != StatusCode::OK {
        let status = fake.token_status;
        return (status, Json(json!({ "error": "invalid_grant" }))).into_response();
    }
    let field = |k: &str| form.get(k).map(String::as_str).unwrap_or_default();
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
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid_grant" })),
        )
            .into_response();
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
        Some(c) => {
            Json(json!({ "sub": "1", "email": c.email, "email_verified": true })).into_response()
        }
        None => StatusCode::UNAUTHORIZED.into_response(),
    }
}

async fn revoke(State(fake): State<Shared>, Form(form): Form<HashMap<String, String>>) -> Response {
    let mut fake = fake.lock().unwrap();
    fake.requests.push(("/revoke".into(), form));
    fake.revoke_status.into_response()
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
        }));
        let app = Router::new()
            .route("/token", post(token))
            .route("/v1/userinfo", get(userinfo))
            .route("/revoke", post(revoke))
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
        let mut fake = self.state.lock().unwrap();
        let n = fake.consents.len() + 1;
        let consent = Consent {
            code: format!("4/fake-code-{n}"),
            access_token: format!("ya29.fake-access-{n}"),
            refresh_token: format!("1//fake-refresh-{n}"),
            challenge: challenge.to_string(),
            email: email.to_string(),
            used: false,
        };
        fake.consents.push(consent.clone());
        consent
    }

    pub fn with<R>(&self, f: impl FnOnce(&mut Fake) -> R) -> R {
        f(&mut self.state.lock().unwrap())
    }
}

pub struct Harness {
    pub pool: PgPool,
    pub google: FakeGoogle,
    pub app: Router,
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
            connectors_key: KEY.into(),
        }),
        pool: pool.clone(),
        http: google.client(),
    });
    Some(Harness {
        pool,
        app: router(state),
        google,
    })
}

pub struct Reply {
    pub status: StatusCode,
    pub body: Value,
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
