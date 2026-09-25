//! A fresh database per test migrated with the broker's own migrations, a TLS stand-in for
//! every provider's OAuth and data endpoints that the router's HTTP client reaches through their
//! real host names, and a request helper that fails any test whose reply leaks a token, code,
//! verifier or a client secret. The broker itself listens over mTLS on a real port, with a stand-in KMS CA
//! issuing both its own leaf and the callers'. Members are fixed P-256 keys that sign their
//! requests as a page would and send them sealed on a channel opened against the broker's leaf.
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
use std::time::{Duration, SystemTime};

use alpha_broker::{AppState, Config, Secrets, oauth, router};
use alpha_channel::frame::{Channel, RequestFrame};
use alpha_channel::handshake::{Expected, Initiator, Responder, ServerHello};
use alpha_client::tls::{Identity, Pin};
use axum::body::{Body, Bytes, to_bytes};
use axum::extract::{DefaultBodyLimit, Form, Query, State};
use axum::http::{HeaderMap, Method, Request, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use hyper_util::service::TowerToHyperService;
use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::Signer;
use p256::pkcs8::EncodePublicKey;
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
pub const DROPBOX_CLIENT_ID: &str = "dropbox-app-key-for-tests";
pub const DROPBOX_CLIENT_SECRET: &str = "dropbox-app-secret-for-tests";
pub const DROPBOX_REDIRECT_URI: &str = "https://corpus.example/oauth/dropbox/callback";
pub const SLACK_CLIENT_ID: &str = "1234.5678";
pub const SLACK_CLIENT_SECRET: &str = "slack-client-secret-for-tests";
pub const FIGMA_CLIENT_ID: &str = "figma-client-id-for-tests";
pub const FIGMA_CLIENT_SECRET: &str = "figma-client-secret-for-tests";
pub const FIGMA_REDIRECT_URI: &str = "https://corpus.example/oauth/figma/callback";
pub const SLACK_REDIRECT_URI: &str = "https://corpus.example/oauth/slack/callback";
pub const HUBSPOT_CLIENT_ID: &str = "hubspot-client-id-for-tests";
pub const HUBSPOT_CLIENT_SECRET: &str = "hubspot-client-secret-for-tests";
pub const HUBSPOT_REDIRECT_URI: &str = "https://corpus.example/oauth/hubspot/callback";
pub const NOTION_CLIENT_ID: &str = "notion-client-id-for-tests";
pub const NOTION_REDIRECT_URI: &str = "https://corpus.example/oauth/notion/callback";
pub const KEY: [u8; 32] = [9; 32];
pub const EMAIL: &str = "member@example.com";
/// The compose the broker's leaf names as its Revision.
pub const BROKER_COMPOSE: &str = r#"{"name":"alpha-broker"}"#;
const HOSTS: [&str; 10] = [
    "accounts.google.com",
    "oauth2.googleapis.com",
    "openidconnect.googleapis.com",
    "www.googleapis.com",
    "api.dropboxapi.com",
    "content.dropboxapi.com",
    "slack.com",
    "api.figma.com",
    "mcp.hubspot.com",
    "mcp.notion.com",
];
pub const MEDIA: &str = "https://www.googleapis.com/drive/v3/files/file-1?alt=media";
pub const LISTING: &str = r#"{"files":[{"id":"file-1","name":"Notes"}]}"#;
pub const SLACK_HISTORY: &str = r#"{"ok":true,"messages":[{"type":"message","user":"U2","text":"hello","ts":"1.2"}],"has_more":false}"#;
pub const MCP_ACCEPT: &str = "application/json, text/event-stream";
pub const MCP_TOOLS: &str = r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"search_crm_objects","inputSchema":{}}]}}"#;
/// A header Notion's stand-in sets on every MCP reply, which the broker must not relay.
pub const MCP_SESSION: &str = "mcp-session-id";
pub const MCP_RESULT: &str = r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"results\":[{\"id\":\"101\"}]}"}],"isError":false}}"#;
pub const DROPBOX_LISTING: &str = r#"{"entries":[{".tag":"file","name":"Notes.txt","id":"id:a1"}],"cursor":"c1","has_more":false}"#;

/// A member: the P-256 key its browser holds.
pub struct Member {
    key: SigningKey,
    pub spki: Vec<u8>,
}

impl Member {
    fn from_seed(seed: u8) -> Self {
        let key = SigningKey::from_slice(&[seed; 32]).unwrap();
        let spki = key.verifying_key().to_public_key_der().unwrap().to_vec();
        Member { key, spki }
    }

    pub fn key_b64(&self) -> String {
        use base64::Engine;
        base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(&self.spki)
    }

    pub fn sha256(&self) -> [u8; 32] {
        use sha2::Digest;
        sha2::Sha256::digest(&self.spki).into()
    }

    /// How `/proxy` and `/write` still name a member: the hex of the key's SHA-256.
    pub fn reference(&self) -> String {
        hex::encode(self.sha256())
    }

    /// Signs a digest as WebCrypto does, `r‖s` in base64url.
    pub fn sign(&self, digest: &[u8; 32]) -> String {
        use base64::Engine;
        let signature: p256::ecdsa::Signature = self.key.sign(digest);
        base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(signature.to_bytes())
    }
}

pub fn member() -> Member {
    Member::from_seed(1)
}

pub fn other_member() -> Member {
    Member::from_seed(2)
}

/// `{document, member_key, signature}` for `fields` under the connector request context, issued
/// at `now`.
pub fn signed_at(key: &Member, fields: Value, now: SystemTime) -> Value {
    let (document, digest) =
        alpha_channel::member::signable(alpha_core::context::CONNECTOR_REQUEST, fields, now)
            .unwrap();
    json!({
        "document": serde_json::from_str::<Value>(&document).unwrap(),
        "member_key": key.key_b64(),
        "signature": { "algorithm": "ecdsa-p256", "signature": key.sign(&digest) },
    })
}

pub fn signed(key: &Member, fields: Value) -> Value {
    signed_at(key, fields, SystemTime::now())
}

/// What the stand-in expects of one provider's client and how its tokens look.
struct Client {
    id: &'static str,
    secret: &'static str,
    redirect: &'static str,
    access: &'static str,
    refresh: &'static str,
    scope: &'static str,
}

const GOOGLE_CLIENT: Client = Client {
    id: CLIENT_ID,
    secret: CLIENT_SECRET,
    redirect: REDIRECT_URI,
    access: "ya29.",
    refresh: "1//",
    scope: "openid https://www.googleapis.com/auth/drive.readonly email",
};

const DROPBOX_CLIENT: Client = Client {
    id: DROPBOX_CLIENT_ID,
    secret: DROPBOX_CLIENT_SECRET,
    redirect: DROPBOX_REDIRECT_URI,
    access: "sl.",
    refresh: "dbx-refresh.",
    scope: "account_info.read files.content.read files.content.write",
};

const SLACK_CLIENT: Client = Client {
    id: SLACK_CLIENT_ID,
    secret: SLACK_CLIENT_SECRET,
    redirect: SLACK_REDIRECT_URI,
    access: "xoxp-",
    refresh: "xoxe-1-",
    scope: "channels:history,users:read",
};

const FIGMA_CLIENT: Client = Client {
    id: FIGMA_CLIENT_ID,
    secret: FIGMA_CLIENT_SECRET,
    redirect: FIGMA_REDIRECT_URI,
    access: "figu_",
    refresh: "figr_",
    scope: "",
};

const HUBSPOT_CLIENT: Client = Client {
    id: HUBSPOT_CLIENT_ID,
    secret: HUBSPOT_CLIENT_SECRET,
    redirect: HUBSPOT_REDIRECT_URI,
    access: "hsat-",
    refresh: "hsrt-",
    scope: "",
};

/// A public client: it has no secret.
const NOTION_CLIENT: Client = Client {
    id: NOTION_CLIENT_ID,
    secret: "",
    redirect: NOTION_REDIRECT_URI,
    access: "ntn_",
    refresh: "ntnr_",
    scope: "default",
};

fn client_of(provider: &str) -> &'static Client {
    match provider {
        "hubspot" => &HUBSPOT_CLIENT,
        "notion" => &NOTION_CLIENT,
        "dropbox" => &DROPBOX_CLIENT,
        "slack" => &SLACK_CLIENT,
        "figma" => &FIGMA_CLIENT,
        _ => &GOOGLE_CLIENT,
    }
}

pub fn bearer_of(headers: &HeaderMap) -> String {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or_default()
        .to_string()
}

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

/// What the member's consent at a provider produced: the code the popup relays, and the tokens
/// the token endpoint will issue for it.
#[derive(Clone)]
pub struct Consent {
    pub provider: &'static str,
    pub code: String,
    pub access_token: String,
    pub refresh_token: String,
    challenge: String,
    subject: String,
    email: String,
    used: bool,
}

/// One request that reached a provider's data API.
#[derive(Clone, Debug)]
pub struct DataRequest {
    pub method: Method,
    pub host: String,
    pub path: String,
    pub query: HashMap<String, String>,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
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
    /// Refreshes issue a new refresh token and stop accepting the one presented; Slack's always
    /// do.
    pub rotate: bool,
    /// Refresh replies leave out `expires_in`.
    pub omit_expires_in: bool,
    /// When set, every refresh is answered with exactly this status and body.
    pub refresh_reply: Option<(StatusCode, Value)>,
    /// How long a refresh takes to answer.
    pub refresh_delay: Duration,
    /// The next this many data requests answer 401 whatever token they carry.
    pub unauthorized: usize,
    pub media_size: usize,
    /// Dropbox folders created so far; creating one again answers 409.
    pub folders: Vec<String>,
    /// Access tokens the data API accepts, and refresh tokens the token endpoint accepts.
    pub access: Vec<String>,
    pub refresh: Vec<String>,
    issued: Vec<String>,
}

impl Fake {
    pub fn hits(&self, path: &str) -> usize {
        self.requests.iter().filter(|(p, _)| p == path).count()
    }

    /// The fields of the first request that reached `path`.
    pub fn form(&self, path: &str) -> HashMap<String, String> {
        self.requests
            .iter()
            .find(|(p, _)| p == path)
            .unwrap()
            .1
            .clone()
    }

    pub fn revoked_tokens(&self) -> Vec<String> {
        self.requests
            .iter()
            .filter(|(p, _)| p == "/revoke" || p == DROPBOX_REVOKE || p == SLACK_REVOKE)
            .map(|(_, form)| form["token"].clone())
            .collect()
    }

    pub fn refreshes(&self) -> usize {
        self.requests
            .iter()
            .filter(|(_, form)| form.get("grant_type").map(String::as_str) == Some("refresh_token"))
            .count()
    }

    /// Every value that must never appear in a reply to the tenant.
    fn secrets(&self) -> Vec<String> {
        let mut out = vec![
            CLIENT_SECRET.to_string(),
            DROPBOX_CLIENT_SECRET.to_string(),
            SLACK_CLIENT_SECRET.to_string(),
            HUBSPOT_CLIENT_SECRET.to_string(),
            FIGMA_CLIENT_SECRET.to_string(),
        ];
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

pub const DROPBOX_TOKEN: &str = "/oauth2/token";
pub const DROPBOX_ACCOUNT: &str = "/2/users/get_current_account";
pub const DROPBOX_REVOKE: &str = "/2/auth/token/revoke";
pub const SLACK_TOKEN: &str = "/api/oauth.v2.access";
pub const SLACK_IDENTITY: &str = "/api/auth.test";
pub const SLACK_REVOKE: &str = "/api/auth.revoke";
pub const FIGMA_TOKEN: &str = "/v1/oauth/token";
pub const FIGMA_REFRESH: &str = "/v1/oauth/refresh";
pub const FIGMA_ME: &str = "/v1/me";
pub const HUBSPOT_TOKEN: &str = "/oauth/v3/token";

/// The `id:secret` of an HTTP Basic authorization header.
fn basic_of(headers: &HeaderMap) -> Option<String> {
    use base64::Engine;
    let encoded = headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Basic ")?;
    let decoded = base64::prelude::BASE64_STANDARD.decode(encoded).ok()?;
    String::from_utf8(decoded).ok()
}

fn invalid_grant() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "error": "invalid_grant" })),
    )
        .into_response()
}

fn host_of(headers: &HeaderMap) -> String {
    headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

/// Every provider's token and refresh URLs, each accepting only its own client: Google, Dropbox,
/// Slack and HubSpot with the secret in the form, Figma only in HTTP Basic and refreshing only at
/// its own URL, Notion as a public client that must send no secret. Notion's `/token` also takes a
/// revocation, a post without `grant_type`, recorded as `/revoke`.
async fn token(
    State(fake): State<Shared>,
    uri: Uri,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let provider = match uri.path() {
        DROPBOX_TOKEN => "dropbox",
        SLACK_TOKEN => "slack",
        FIGMA_TOKEN | FIGMA_REFRESH => "figma",
        HUBSPOT_TOKEN => "hubspot",
        _ if host_of(&headers) == "mcp.notion.com" => "notion",
        _ => "google",
    };
    if provider == "notion" && !form.contains_key("grant_type") {
        let mut fake = fake.lock().unwrap();
        fake.requests.push(("/revoke".into(), form));
        return fake.revoke_status.into_response();
    }
    let client = client_of(provider);
    let delay = {
        let mut fake = fake.lock().unwrap();
        fake.requests.push((uri.path().into(), form.clone()));
        fake.refresh_delay
    };
    let field = |k: &str| form.get(k).map(String::as_str).unwrap_or_default();
    let refreshing = field("grant_type") == "refresh_token";
    if refreshing {
        tokio::time::sleep(delay).await;
    }
    let mut fake = fake.lock().unwrap();
    if let Some((status, body)) = fake.refresh_reply.clone().filter(|_| refreshing) {
        return (status, Json(body)).into_response();
    }
    if fake.token_status != StatusCode::OK {
        let status = fake.token_status;
        let error = if status == StatusCode::BAD_REQUEST {
            "invalid_grant"
        } else {
            "server_error"
        };
        return (status, Json(json!({ "error": error }))).into_response();
    }
    let authenticated = match provider {
        "figma" => {
            basic_of(&headers) == Some(format!("{}:{}", client.id, client.secret))
                && !form.contains_key("client_id")
                && !form.contains_key("client_secret")
                && (uri.path() == FIGMA_REFRESH) == refreshing
        }
        "notion" => field("client_id") == client.id && !form.contains_key("client_secret"),
        _ => field("client_id") == client.id && field("client_secret") == client.secret,
    };
    if refreshing {
        let presented = field("refresh_token").to_string();
        if !authenticated
            || !presented.starts_with(client.refresh)
            || !fake.refresh.contains(&presented)
        {
            return invalid_grant();
        }
        let n = fake.refreshes();
        let access = format!("{}fake-refreshed-{n}", client.access);
        fake.access.push(access.clone());
        fake.issued.push(access.clone());
        let mut reply = json!({ "access_token": access, "token_type": "Bearer" });
        if !fake.omit_expires_in {
            reply["expires_in"] = json!(3599);
        }
        if fake.rotate || provider == "slack" || provider == "notion" {
            let rotated = format!("{}fake-rotated-{n}", client.refresh);
            fake.refresh.retain(|t| *t != presented);
            fake.refresh.push(rotated.clone());
            fake.issued.push(rotated.clone());
            reply["refresh_token"] = json!(rotated);
        }
        if provider == "slack" {
            reply["ok"] = json!(true);
        }
        return Json(reply).into_response();
    }
    let ok_client = field("grant_type") == "authorization_code"
        && authenticated
        && field("redirect_uri") == client.redirect;
    let verifier_challenge = oauth::challenge(field("code_verifier"));
    let code = field("code").to_string();
    let omit = fake.omit_refresh_token;
    let Some(consent) = fake
        .consents
        .iter_mut()
        .find(|c| {
            c.provider == provider && c.code == code && !c.used && c.challenge == verifier_challenge
        })
        .filter(|_| ok_client)
    else {
        return invalid_grant();
    };
    consent.used = true;
    let mut reply = json!({
        "access_token": consent.access_token,
        "expires_in": 3599,
        "token_type": "Bearer",
        "scope": client.scope,
    });
    if !omit {
        reply["refresh_token"] = json!(consent.refresh_token);
    }
    if provider == "slack" {
        reply = json!({
            "ok": true,
            "app_id": "A1",
            "authed_user": reply,
            "team": { "id": "T1", "name": "Team" },
            "is_enterprise_install": false,
        });
    }
    Json(reply).into_response()
}

async fn userinfo(State(fake): State<Shared>, headers: HeaderMap) -> Response {
    let mut fake = fake.lock().unwrap();
    let presented = bearer_of(&headers);
    fake.requests.push(("/v1/userinfo".into(), HashMap::new()));
    if fake.account_status != StatusCode::OK {
        return fake.account_status.into_response();
    }
    let consent = fake
        .consents
        .iter()
        .find(|c| c.provider == "google" && c.access_token == presented);
    match consent {
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

/// Dropbox's account lookup: recorded with the content type and body it arrived with, answered
/// only to the access token a Dropbox consent issued.
async fn current_account(State(fake): State<Shared>, headers: HeaderMap, body: Bytes) -> Response {
    let mut fake = fake.lock().unwrap();
    let presented = bearer_of(&headers);
    let mut seen = HashMap::from([("body".to_string(), String::from_utf8_lossy(&body).into())]);
    if let Some(content_type) = headers.get(header::CONTENT_TYPE) {
        seen.insert("content_type".into(), content_type.to_str().unwrap().into());
    }
    fake.requests.push((DROPBOX_ACCOUNT.into(), seen));
    if fake.account_status != StatusCode::OK {
        return fake.account_status.into_response();
    }
    let consent = fake
        .consents
        .iter()
        .find(|c| c.provider == "dropbox" && c.access_token == presented);
    match consent {
        Some(c) => Json(json!({
            "account_id": c.subject,
            "email": c.email,
            "name": { "display_name": "Member" },
        }))
        .into_response(),
        None => StatusCode::UNAUTHORIZED.into_response(),
    }
}

/// Dropbox's and Slack's revoke: the access token is the bearer; recorded as the token it ended.
async fn bearer_revoke(State(fake): State<Shared>, uri: Uri, headers: HeaderMap) -> Response {
    let mut fake = fake.lock().unwrap();
    let token = bearer_of(&headers);
    fake.requests
        .push((uri.path().into(), HashMap::from([("token".into(), token)])));
    fake.revoke_status.into_response()
}

/// Figma's `/v1/me`, answered to any Figma access token the stand-in issued with the account of
/// the first Figma consent.
async fn figma_me(State(fake): State<Shared>, headers: HeaderMap) -> Response {
    let mut fake = fake.lock().unwrap();
    let presented = bearer_of(&headers);
    fake.requests.push((FIGMA_ME.into(), HashMap::new()));
    if !presented.starts_with(FIGMA_CLIENT.access) || !fake.access.contains(&presented) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Some(c) = fake.consents.iter().find(|c| c.provider == "figma") else {
        return StatusCode::FORBIDDEN.into_response();
    };
    Json(json!({ "id": c.subject, "email": c.email, "handle": "Member" })).into_response()
}

/// Slack's `auth.test`, answered only to the access token a Slack consent issued. A consent's
/// subject reads `<team_id>:<user_id>` and its email `<user> @ <team>`.
async fn slack_identity(State(fake): State<Shared>, headers: HeaderMap) -> Response {
    let mut fake = fake.lock().unwrap();
    let presented = bearer_of(&headers);
    fake.requests.push((SLACK_IDENTITY.into(), HashMap::new()));
    let Some(c) = fake
        .consents
        .iter()
        .find(|c| c.provider == "slack" && c.access_token == presented)
    else {
        return Json(json!({ "ok": false, "error": "invalid_auth" })).into_response();
    };
    let (team_id, user_id) = c.subject.split_once(':').unwrap_or(("T1", &c.subject));
    let (user, team) = c.email.split_once(" @ ").unwrap_or((&c.email, "Team"));
    Json(json!({
        "ok": true,
        "url": "https://team.slack.com/",
        "team": team,
        "user": user,
        "team_id": team_id,
        "user_id": user_id,
    }))
    .into_response()
}

/// The account an MCP server's identity tool names for consent `c`, whose subject reads
/// `<hub>:<user>` or `<workspace>:<user>`. HubSpot's `get_user_details` gives numbers when they
/// parse; Notion's `notion-fetch` of `self` gives an email only when the consent's name holds one.
fn mcp_account(provider: &str, c: &Consent) -> Value {
    let (outer, user) = c.subject.split_once(':').unwrap_or(("1", &c.subject));
    if provider == "notion" {
        let mut user = json!({ "id": user, "type": "person", "name": c.email });
        if c.email.contains('@') {
            user["name"] = json!("Member");
            user["email"] = json!(c.email);
        }
        return json!({
            "metadata": { "type": "self" },
            "self": { "workspace": { "id": outer, "name": "Workspace" }, "user": user },
        });
    }
    let number = |v: &str| v.parse::<u64>().map_or(json!(v), Value::from);
    json!({
        "accountId": number(outer),
        "userId": number(user),
        "userInformation": { "email": c.email, "type": "USER" },
        "toolInformation": {},
    })
}

/// HubSpot's and Notion's MCP servers, told apart by host; HubSpot replies in JSON, Notion in
/// server-sent events with a session header. The identity call, which arrives with the access
/// token a consent's exchange issued, is recorded as an OAuth request; every other call is data,
/// answered only to a token the stand-in issued. Both need the Accept header the MCP transport
/// requires.
async fn mcp(State(fake): State<Shared>, uri: Uri, headers: HeaderMap, body: Bytes) -> Response {
    let mut fake = fake.lock().unwrap();
    let host = host_of(&headers);
    let provider = if host == "mcp.notion.com" {
        "notion"
    } else {
        "hubspot"
    };
    let token = bearer_of(&headers);
    if headers.get(header::ACCEPT).and_then(|v| v.to_str().ok()) != Some(MCP_ACCEPT) {
        return StatusCode::NOT_ACCEPTABLE.into_response();
    }
    let request: Value = serde_json::from_slice(&body).unwrap_or_default();
    let reply = |body: String| {
        if provider == "notion" {
            (
                [
                    (header::CONTENT_TYPE, "text/event-stream"),
                    (header::HeaderName::from_static(MCP_SESSION), "stand-in"),
                ],
                sse(&body),
            )
                .into_response()
        } else {
            ([(header::CONTENT_TYPE, "application/json")], body).into_response()
        }
    };
    let identity = fake
        .consents
        .iter()
        .find(|c| c.provider == provider && c.access_token == token)
        .cloned();
    if let Some(c) = identity {
        fake.requests.push(("mcp-identity".into(), HashMap::new()));
        let expected = match provider {
            "notion" => json!({ "name": "notion-fetch", "arguments": { "id": "self" } }),
            _ => json!({ "name": "get_user_details", "arguments": {} }),
        };
        if request["method"] != "tools/call" || request["params"] != expected {
            return StatusCode::BAD_REQUEST.into_response();
        }
        let text = mcp_account(provider, &c).to_string();
        let result = json!({
            "jsonrpc": "2.0",
            "id": request["id"],
            "result": { "content": [{ "type": "text", "text": text }], "isError": false },
        });
        return reply(result.to_string());
    }
    fake.data.push(DataRequest {
        method: Method::POST,
        host,
        path: uri.path().to_string(),
        query: HashMap::new(),
        headers: headers.clone(),
        body: body.to_vec(),
    });
    if fake.unauthorized > 0
        || !token.starts_with(client_of(provider).access)
        || !fake.access.contains(&token)
    {
        fake.unauthorized = fake.unauthorized.saturating_sub(1);
        return StatusCode::UNAUTHORIZED.into_response();
    }
    reply(
        match request["method"].as_str() {
            Some("tools/list") => MCP_TOOLS,
            Some("tools/call") => MCP_RESULT,
            _ => r#"{"jsonrpc":"2.0","id":1,"result":{}}"#,
        }
        .to_string(),
    )
}

/// One JSON-RPC message as the one event of a server-sent event stream.
pub fn sse(message: &str) -> String {
    format!("event: message\ndata: {message}\n\n")
}

/// Google's and Dropbox's data APIs, told apart by host and answered only to an access token the
/// stand-in issued for that provider.
async fn data(
    State(fake): State<Shared>,
    method: Method,
    uri: Uri,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let mut fake = fake.lock().unwrap();
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    fake.data.push(DataRequest {
        method: method.clone(),
        host: host.clone(),
        path: uri.path().to_string(),
        query: query.clone(),
        headers: headers.clone(),
        body: body.to_vec(),
    });
    let token = bearer_of(&headers);
    let provider = match host.as_str() {
        "slack.com" => "slack",
        "api.figma.com" => "figma",
        h if h.ends_with(".dropboxapi.com") => "dropbox",
        _ => "google",
    };
    if fake.unauthorized > 0
        || !token.starts_with(client_of(provider).access)
        || !fake.access.contains(&token)
    {
        fake.unauthorized = fake.unauthorized.saturating_sub(1);
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": { "code": 401, "message": "Invalid Credentials" } })),
        )
            .into_response();
    }
    let segments: Vec<&str> = uri.path().split('/').skip(1).collect();
    let json_body = |body: String| ([(header::CONTENT_TYPE, "application/json")], body);
    match (provider, method.as_str(), &segments[..]) {
        ("google", "GET", ["drive", "v3", "drives"]) => {
            json_body(r#"{"drives":[]}"#.into()).into_response()
        }
        ("google", "GET", ["drive", "v3", "files"]) => json_body(LISTING.into()).into_response(),
        ("google", "GET", ["drive", "v3", "files", _])
            if query.get("alt").map(String::as_str) == Some("media") =>
        {
            (
                [(header::CONTENT_TYPE, "application/octet-stream")],
                vec![b'x'; fake.media_size],
            )
                .into_response()
        }
        ("google", "GET", ["drive", "v3", "files", id]) => {
            json_body(json!({ "id": id, "name": "Notes" }).to_string()).into_response()
        }
        ("google", "GET", ["drive", "v3", "files", _, "export"]) => {
            ([(header::CONTENT_TYPE, "text/csv")], "a,b\n1,2\n").into_response()
        }
        ("google", "GET", ["gmail", "v1", "users", "me", "messages"]) => {
            json_body(r#"{"messages":[{"id":"m1"}]}"#.into()).into_response()
        }
        ("google", "GET", ["gmail", "v1", "users", "me", "messages", id]) => {
            json_body(json!({ "id": id, "snippet": "hello" }).to_string()).into_response()
        }
        ("google", "GET", ["calendar", "v3", "calendars", "primary", "events"]) => {
            json_body(r#"{"items":[]}"#.into()).into_response()
        }
        ("google", "POST", ["upload", "drive", "v3", "files"]) => {
            json_body(r#"{"id":"uploaded-1","name":"report.pdf"}"#.into()).into_response()
        }
        ("google", "POST", ["drive", "v3", "files"]) => {
            json_body(r#"{"id":"folder-1","name":"Corpus"}"#.into()).into_response()
        }
        ("dropbox", "POST", ["2", "files", "list_folder"]) => {
            json_body(DROPBOX_LISTING.into()).into_response()
        }
        ("dropbox", "POST", ["2", "files", "download"]) => (
            [(header::CONTENT_TYPE, "application/octet-stream")],
            vec![b'x'; fake.media_size],
        )
            .into_response(),
        ("dropbox", "POST", ["2", "files", "upload"]) => {
            json_body(r#"{"id":"id:up1","name":"report.pdf"}"#.into()).into_response()
        }
        ("dropbox", "POST", ["2", "files", "create_folder_v2"]) => {
            let path = serde_json::from_slice::<Value>(&body).unwrap()["path"]
                .as_str()
                .unwrap()
                .to_string();
            if fake.folders.contains(&path) {
                return (
                    StatusCode::CONFLICT,
                    json_body(
                        json!({
                            "error_summary": "path/conflict/folder/..",
                            "error": { ".tag": "path", "path": { ".tag": "conflict" } },
                        })
                        .to_string(),
                    ),
                )
                    .into_response();
            }
            fake.folders.push(path.clone());
            json_body(json!({ "metadata": { "path_display": path } }).to_string()).into_response()
        }
        ("figma", "GET", _) => json_body(json!({ "path": uri.path() }).to_string()).into_response(),
        ("slack", "GET", ["api", "conversations.history"]) => {
            json_body(SLACK_HISTORY.into()).into_response()
        }
        ("slack", "GET", ["api", "conversations.list"]) => {
            json_body(r#"{"ok":true,"channels":[{"id":"C1","name":"general"}]}"#.into())
                .into_response()
        }
        ("slack", "GET", ["api", "users.info"]) => {
            json_body(r#"{"ok":true,"user":{"id":"U2","name":"ann"}}"#.into()).into_response()
        }
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

pub struct FakeProviders {
    pub state: Shared,
    pub addr: SocketAddr,
    ca_der: Vec<u8>,
}

impl FakeProviders {
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
            omit_expires_in: false,
            refresh_reply: None,
            refresh_delay: Duration::ZERO,
            unauthorized: 0,
            media_size: 0,
            folders: vec![],
            access: vec![],
            refresh: vec![],
            issued: vec![],
        }));
        let app = Router::new()
            .route("/token", post(token))
            .route(DROPBOX_TOKEN, post(token))
            .route(SLACK_TOKEN, post(token))
            .route(SLACK_IDENTITY, post(slack_identity))
            .route(SLACK_REVOKE, post(bearer_revoke))
            .route(FIGMA_TOKEN, post(token))
            .route(FIGMA_REFRESH, post(token))
            .route(FIGMA_ME, get(figma_me))
            .route(HUBSPOT_TOKEN, post(token))
            .route("/", post(mcp))
            .route("/mcp", post(mcp))
            .route("/v1/userinfo", get(userinfo))
            .route(DROPBOX_ACCOUNT, post(current_account))
            .route("/revoke", post(revoke))
            .route(DROPBOX_REVOKE, post(bearer_revoke))
            .fallback(data)
            .layer(DefaultBodyLimit::disable())
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
        FakeProviders {
            state,
            addr,
            ca_der: ca.der().to_vec(),
        }
    }

    /// A client that reaches the providers' host names at the stand-in and trusts only its CA.
    pub fn client(&self) -> reqwest::Client {
        let mut builder = reqwest::Client::builder()
            .tls_certs_only([reqwest::Certificate::from_der(&self.ca_der).unwrap()])
            .redirect(reqwest::redirect::Policy::none());
        for host in HOSTS {
            builder = builder.resolve(host, self.addr);
        }
        builder.build().unwrap()
    }

    /// Stands in for the member consenting at Google as `email` on the page the authorization
    /// URL opens.
    pub fn consent(&self, challenge: &str, email: &str) -> Consent {
        self.consent_on("google", challenge, &format!("subject-of-{email}"), email)
    }

    /// The member consenting at `provider` as the account `subject` named `email`.
    pub fn consent_on(
        &self,
        provider: &'static str,
        challenge: &str,
        subject: &str,
        email: &str,
    ) -> Consent {
        let client = client_of(provider);
        let mut fake = self.state.lock().unwrap();
        let n = fake.consents.len() + 1;
        let consent = Consent {
            provider,
            code: format!("4/fake-code-{n}"),
            access_token: format!("{}fake-access-{n}", client.access),
            refresh_token: format!("{}fake-refresh-{n}", client.refresh),
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
        self.leaf_pem(sans).0
    }

    /// As `leaf`, with the leaf's PEM.
    pub fn leaf_pem(&self, sans: &[String]) -> (Identity, String) {
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
        let identity = Identity {
            chain: vec![leaf.der().to_vec(), self.cert.der().to_vec()],
            pkcs8: key.serialize_der(),
        };
        (identity, leaf.pem())
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
async fn start_broker(ca: &Ca, own: Identity, app: Router) -> SocketAddr {
    let key = rustls::crypto::aws_lc_rs::default_provider()
        .key_provider
        .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(own.pkcs8)))
        .unwrap();
    let certified = rustls::sign::CertifiedKey::new(
        own.chain.into_iter().map(CertificateDer::from).collect(),
        key,
    );
    let config = alpha_client::tls::mtls_server_config(
        Arc::new(SingleCertAndKey::from(certified)),
        ca.der(),
    )
    .unwrap();
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
    pub fake: FakeProviders,
    pub app: Router,
    pub ca: Ca,
    pub broker: SocketAddr,
    /// An attested Instance's client: a leaf from the broker's CA.
    pub instance: reqwest::Client,
    /// Who a page expects the broker to be: its org, App and Revision.
    pub expected: Expected,
    own: Identity,
    own_chain: Vec<String>,
}

fn config() -> Config {
    Config::build(|name| match name {
        "GOOGLE_CLIENT_ID" => Some(CLIENT_ID.into()),
        "DROPBOX_CLIENT_ID" => Some(DROPBOX_CLIENT_ID.into()),
        "SLACK_CLIENT_ID" => Some(SLACK_CLIENT_ID.into()),
        "FIGMA_CLIENT_ID" => Some(FIGMA_CLIENT_ID.into()),
        "HUBSPOT_CLIENT_ID" => Some(HUBSPOT_CLIENT_ID.into()),
        "NOTION_CLIENT_ID" => Some(NOTION_CLIENT_ID.into()),
        "OAUTH_REDIRECT_BASE" => Some("https://corpus.example/oauth".into()),
        _ => None,
    })
    .unwrap()
}

/// The broker's state as it starts: no channels, nothing cached.
fn app_state(
    pool: &PgPool,
    fake: &FakeProviders,
    own: &Identity,
    own_chain: &[String],
) -> Arc<AppState> {
    let client_secrets = oauth::PROVIDERS
        .into_iter()
        .filter(|p| !matches!(p.client_auth, oauth::ClientAuth::Public))
        .map(|p| (p.name, client_of(p.name).secret.to_string().into()))
        .collect();
    let responder =
        Responder::new(own_chain.to_vec(), &own.pkcs8, BROKER_COMPOSE.to_string()).unwrap();
    Arc::new(AppState {
        config: config(),
        secrets: parking_lot::RwLock::new(Secrets {
            client_secrets,
            connect_bearer: BEARER.as_bytes().to_vec().into(),
            proxy_bearer: PROXY_BEARER.as_bytes().to_vec().into(),
            connectors_key: KEY.into(),
        }),
        pool: pool.clone(),
        http: fake.client(),
        tokens: Default::default(),
        responder: parking_lot::RwLock::new(responder),
        channels: Default::default(),
    })
}

pub async fn harness() -> Option<Harness> {
    let pool = fresh_database().await?;
    let fake = FakeProviders::start().await;
    let ca = Ca::new();
    let (org_id, app_id) = (Uuid::now_v7(), Uuid::now_v7());
    let revision = alpha_core::compose_hash(BROKER_COMPOSE);
    let (own, leaf_pem) = ca.leaf_pem(&[
        format!("alphacompute://{org_id}/{app_id}/{}", "b".repeat(64)),
        format!("urn:alphacompute:revision:{revision}"),
    ]);
    let own_chain = vec![leaf_pem, ca.cert.pem()];
    let expected = Expected {
        org_id: org_id.to_string().parse().unwrap(),
        app_id: app_id.to_string().parse().unwrap(),
        revisions: vec![revision],
    };
    let state = app_state(&pool, &fake, &own, &own_chain);
    let app = router(state.clone());
    let broker = start_broker(
        &ca,
        Identity {
            chain: own.chain.clone(),
            pkcs8: own.pkcs8.clone(),
        },
        app.clone(),
    )
    .await;
    let instance = instance_client(&ca, Some(ca.instance()));
    Some(Harness {
        state,
        pool,
        app,
        fake,
        ca,
        broker,
        instance,
        expected,
        own,
        own_chain,
    })
}

pub struct Reply {
    pub status: StatusCode,
    pub body: Value,
    /// Whether the body came sealed on the channel rather than as a plaintext refusal.
    pub sealed: bool,
}

/// A `/proxy` reply: the provider's bytes are not always JSON.
pub struct Raw {
    pub status: StatusCode,
    pub content_type: Option<String>,
    pub headers: HeaderMap,
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
    json!({ "member": member().reference(), "connection_id": connection, "method": "GET", "url": url })
}

/// A `/proxy` body posting the JSON-RPC `body` to the MCP server at `url`.
pub fn mcp_rpc(connection: Uuid, url: &str, body: Value) -> Value {
    json!({ "member": member().reference(), "connection_id": connection, "method": "POST", "url": url, "body": body })
}

pub fn mcp_call(connection: Uuid, url: &str, tool: &str) -> Value {
    let call = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": { "name": tool, "arguments": {} } });
    mcp_rpc(connection, url, call)
}

pub fn dropbox_read(connection: Uuid, url: &str) -> Value {
    json!({ "member": member().reference(), "connection_id": connection, "method": "POST", "url": url })
}

/// A `/write` body carrying `bytes` base64-encoded.
pub fn upload(connection: Uuid, url: &str, content_type: &str, bytes: &[u8]) -> Value {
    use base64::Engine;
    json!({
        "member": member().reference(),
        "connection_id": connection,
        "method": "POST",
        "url": url,
        "content_type": content_type,
        "body_base64": base64::prelude::BASE64_STANDARD.encode(bytes),
    })
}

impl Harness {
    /// The broker as a restart leaves it: the same database, no channels.
    pub fn restart(&mut self) {
        self.state = app_state(&self.pool, &self.fake, &self.own, &self.own_chain);
        self.app = router(self.state.clone());
    }

    /// One request through the router; fails the test if the reply carries a token or secret.
    pub async fn send(
        &self,
        bearer: Option<&str>,
        method: &str,
        uri: &str,
        body: Option<String>,
    ) -> (StatusCode, String) {
        let mut builder = Request::builder().method(method).uri(uri);
        if let Some(bearer) = bearer {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {bearer}"));
        }
        let request = match body {
            Some(body) => builder
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body)),
            None => builder.body(Body::empty()),
        }
        .unwrap();
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let text = String::from_utf8(bytes.to_vec()).unwrap();
        self.assert_no_secret(&format!("{method} {uri}"), &text);
        (status, text)
    }

    fn assert_no_secret(&self, what: &str, text: &str) {
        for secret in self.fake.with(|f| f.secrets()) {
            assert!(!text.contains(&secret), "{what} answered a secret: {text}");
        }
    }

    /// One plaintext request, with the connect bearer unless `bearer` says otherwise.
    pub async fn call_as(
        &self,
        bearer: Option<&str>,
        method: &str,
        uri: &str,
        body: Option<Value>,
    ) -> Reply {
        let (status, text) = self
            .send(bearer, method, uri, body.map(|b| b.to_string()))
            .await;
        let body = if text.is_empty() {
            Value::Null
        } else {
            serde_json::from_str(&text).unwrap()
        };
        Reply {
            status,
            body,
            sealed: false,
        }
    }

    pub async fn call(&self, method: &str, uri: &str, body: Option<Value>) -> Reply {
        self.call_as(Some(BEARER), method, uri, body).await
    }

    /// A handshake through `POST /channel`, checked as a page checks it.
    pub async fn channel(&self) -> Channel {
        let (initiator, hello) = Initiator::new().unwrap();
        let reply = self
            .call(
                "POST",
                "/channel",
                Some(serde_json::to_value(&hello).unwrap()),
            )
            .await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        let hello: ServerHello = serde_json::from_value(reply.body).unwrap();
        let (channel, _) = initiator
            .finish(
                &hello,
                &self.ca.cert.pem(),
                &self.expected,
                SystemTime::now(),
            )
            .unwrap();
        channel
    }

    /// Sends `frame` to `path` with the connect bearer and opens a sealed reply on `channel`;
    /// a body starting with `{` is a plaintext refusal.
    pub async fn send_frame(
        &self,
        channel: &Channel,
        method: &str,
        path: &str,
        frame: &RequestFrame,
    ) -> Reply {
        let (status, text) = self
            .send(
                Some(BEARER),
                method,
                path,
                Some(serde_json::to_string(frame).unwrap()),
            )
            .await;
        if text.trim_start().starts_with('{') {
            let body = serde_json::from_str(&text).unwrap();
            return Reply {
                status,
                body,
                sealed: false,
            };
        }
        let mut reader = channel.response(frame.seq);
        let mut opened = Vec::new();
        for line in text.lines() {
            if let Some(part) = reader.open_line(line).unwrap() {
                opened.extend_from_slice(&part);
            }
        }
        reader.finish().unwrap();
        let opened = String::from_utf8(opened).unwrap();
        self.assert_no_secret(&format!("{method} {path}"), &opened);
        Reply {
            status,
            body: serde_json::from_str(&opened).unwrap(),
            sealed: true,
        }
    }

    /// `plaintext` sealed on `channel` for `method` and `path`, sent there.
    pub async fn sealed(
        &self,
        channel: &mut Channel,
        method: &str,
        path: &str,
        plaintext: &Value,
    ) -> Reply {
        let frame = channel
            .seal_request(method, path, plaintext.to_string().as_bytes())
            .unwrap();
        self.send_frame(channel, method, path, &frame).await
    }

    /// `fields` signed by `key`, sealed on a new channel to `method path`.
    pub async fn as_member(&self, key: &Member, method: &str, path: &str, fields: Value) -> Reply {
        let mut channel = self.channel().await;
        self.sealed(&mut channel, method, path, &signed(key, fields))
            .await
    }

    /// Starts a connect to `provider` for `key` and returns the authorization URL's query.
    pub async fn start(&self, provider: &str, key: &Member) -> HashMap<String, String> {
        let reply = self
            .as_member(
                key,
                "POST",
                &format!("/connect/{provider}"),
                json!({ "op": "connect", "provider": provider }),
            )
            .await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        assert!(reply.sealed);
        let url = reqwest::Url::parse(reply.body["url"].as_str().unwrap()).unwrap();
        url.query_pairs().into_owned().collect()
    }

    pub async fn finish(&self, key: &Member, code: &str, state: &str) -> Reply {
        self.as_member(
            key,
            "POST",
            "/connect/finish",
            json!({ "op": "finish", "state": state, "code": code }),
        )
        .await
    }

    pub async fn list(&self, key: &Member) -> Reply {
        self.as_member(key, "POST", "/connections", json!({ "op": "list" }))
            .await
    }

    pub async fn disconnect(&self, key: &Member, id: Uuid) -> Reply {
        self.as_member(
            key,
            "DELETE",
            &format!("/connections/{id}"),
            json!({ "op": "disconnect", "connection_id": id }),
        )
        .await
    }

    /// A whole connect to Google as `email`; returns the finish reply and the consent behind it.
    pub async fn connect(&self, key: &Member, email: &str) -> (Reply, Consent) {
        self.connect_to("google", key, email).await
    }

    pub async fn connect_to(
        &self,
        provider: &'static str,
        key: &Member,
        email: &str,
    ) -> (Reply, Consent) {
        self.connect_as(provider, key, &format!("subject-of-{email}"), email)
            .await
    }

    /// A whole connect to `provider` as the account `subject` the provider names `name`.
    pub async fn connect_as(
        &self,
        provider: &'static str,
        key: &Member,
        subject: &str,
        name: &str,
    ) -> (Reply, Consent) {
        let query = self.start(provider, key).await;
        let consent = self
            .fake
            .consent_on(provider, &query["code_challenge"], subject, name);
        let reply = self.finish(key, &consent.code, &query["state"]).await;
        (reply, consent)
    }

    /// `POST path` over the real listener from `client`; fails the test if anything in the
    /// reply, headers included, carries a token or secret. `Err` when the request itself failed.
    pub async fn post_with(
        &self,
        client: &reqwest::Client,
        bearer: Option<&str>,
        path: &str,
        body: &Value,
    ) -> Result<Raw, reqwest::Error> {
        self.post_text(client, bearer, path, body.to_string()).await
    }

    /// As `post_with`, with the request body sent exactly as given.
    pub async fn post_text(
        &self,
        client: &reqwest::Client,
        bearer: Option<&str>,
        path: &str,
        body: String,
    ) -> Result<Raw, reqwest::Error> {
        let mut request = client
            .post(format!("https://{}{path}", self.broker))
            .header(header::CONTENT_TYPE, "application/json")
            .body(body);
        if let Some(bearer) = bearer {
            request = request.bearer_auth(bearer);
        }
        let response = request.send().await?;
        let status = response.status();
        let header_map = response.headers().clone();
        let headers = format!("{header_map:?}");
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .map(|v| v.to_str().unwrap().to_string());
        let bytes = response.bytes().await?.to_vec();
        let text = String::from_utf8_lossy(&bytes);
        for secret in self.fake.with(|f| f.secrets()) {
            assert!(!text.contains(&secret), "{path} answered a secret: {text}");
            assert!(
                !headers.contains(&secret),
                "{path} answered a secret: {headers}"
            );
        }
        Ok(Raw {
            status,
            content_type,
            headers: header_map,
            bytes,
        })
    }

    /// From the attested Instance with the proxy bearer.
    pub async fn proxy(&self, body: &Value) -> Raw {
        self.post_with(&self.instance, Some(PROXY_BEARER), "/proxy", body)
            .await
            .unwrap()
    }

    /// `POST /write` over the real listener with the connect bearer and no client certificate,
    /// as the tenant's backend calls it.
    pub async fn write(&self, body: &Value) -> Raw {
        let backend = instance_client(&self.ca, None);
        self.post_with(&backend, Some(BEARER), "/write", body)
            .await
            .unwrap()
    }

    /// Nothing reached a provider's data API and no token was refreshed.
    pub fn untouched(&self) -> bool {
        self.fake.with(|f| f.data.is_empty() && f.refreshes() == 0)
    }

    /// A connection of `member()` to Google, made through the connect routes.
    pub async fn connected(&self) -> (Uuid, Consent) {
        self.connected_to("google").await
    }

    pub async fn connected_to(&self, provider: &'static str) -> (Uuid, Consent) {
        let (reply, consent) = self.connect_to(provider, &member(), EMAIL).await;
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

/// Nothing reached a provider, its OAuth endpoints included, while `f` ran.
pub async fn nothing_reaches<F: Future<Output = ()>>(h: &Harness, f: F) {
    let before = h.fake.with(|f| (f.data.len(), f.requests.len()));
    f.await;
    assert_eq!(h.fake.with(|f| (f.data.len(), f.requests.len())), before);
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
