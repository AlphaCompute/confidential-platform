//! The harness the db and cli tests share: a fresh database per test, a node acting as the keyed
//! Phala capture's CVM (its nonce key and collateral, its clock as the test chooses), a local
//! HTTP server standing in for the release artifact URL, and a bootstrapped organization.
#![allow(dead_code)]

use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alpha_attest::{EVIDENCE_FORMAT, EventLogEntry, Evidence};
use alpha_cli::node::{NodeIdentity, ShareFile};
use alpha_client::{Anchor, Client, Pin};
use alpha_core::{AppId, KeyId, OrgId, PrincipalId, context};
use alpha_crypto::{INFO_UNSEAL_SHARE, PrivateKey, PublicKey};
use alpha_kms::{Clock, CollateralSource, Config, Node, platform, rfc3339, tls};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::EncodePublicKey;
use reqwest::StatusCode;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

pub const KEYED: &str = "phala-0.5.9-1c-2g-keyed";
pub const DEV_KEYED: &str = "phala-dev-0.5.9-keyed";

pub fn testdata() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata")
}

pub fn read(capture: &str, name: &str) -> Vec<u8> {
    let path = testdata().join("attest").join(capture).join(name);
    fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

pub fn text(capture: &str, name: &str) -> String {
    String::from_utf8(read(capture, name)).unwrap()
}

pub fn nonce_key() -> [u8; 32] {
    alpha_core::hex_bytes(
        fs::read_to_string(testdata().join("attest/capture/nonce_key.hex"))
            .unwrap()
            .trim(),
    )
    .unwrap()
}

pub fn captured_at(capture: &str) -> SystemTime {
    let t = chrono::DateTime::parse_from_rfc3339(text(capture, "captured_at.txt").trim()).unwrap();
    UNIX_EPOCH + Duration::from_secs(t.timestamp() as u64)
}

/// The instant the capture's nonce was minted (its first eight bytes): a node clocked to it
/// mints exactly `nonce.bin` again.
pub fn nonce_minted_at(capture: &str) -> SystemTime {
    let nonce = read(capture, "nonce.bin");
    let ts = u64::from_be_bytes(nonce[..8].try_into().unwrap());
    UNIX_EPOCH + Duration::from_secs(ts)
}

pub fn evidence(capture: &str, kind: &str) -> Evidence {
    Evidence {
        format: EVIDENCE_FORMAT.into(),
        quote: hex::decode(text(capture, &format!("quote.{kind}.hex")).trim()).unwrap(),
        event_log: serde_json::from_slice(&read(capture, "event_log.json")).unwrap(),
    }
}

pub fn b64(bytes: &[u8]) -> String {
    BASE64_URL_SAFE_NO_PAD.encode(bytes)
}

pub fn spki_b64(key: &SigningKey) -> String {
    b64(key.verifying_key().to_public_key_der().unwrap().as_bytes())
}

/// A fresh database per test, migrated.
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
    alpha_kms::migrate(&pool).await.unwrap();
    Some(pool)
}

pub struct ReleaseServer {
    pub url: String,
    pub document: Arc<RwLock<Value>>,
    pub key: SigningKey,
}

impl ReleaseServer {
    pub async fn start(document: Value) -> Self {
        let key = SigningKey::from_bytes(&[42u8; 32]);
        let document = Arc::new(RwLock::new(document));
        let (doc, signer) = (document.clone(), key.clone());
        let app = axum::Router::new().route(
            "/platform.json",
            axum::routing::get(move || {
                let signed =
                    alpha_client::platform::sign(doc.read().unwrap().clone(), &signer).unwrap();
                async move { axum::Json(signed) }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/platform.json", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self { url, document, key }
    }

    pub fn set(&self, document: Value) {
        *self.document.write().unwrap() = document;
    }
}

pub struct Harness {
    pub node: Arc<Node>,
    pub pool: PgPool,
    pub url: String,
    pub release: ReleaseServer,
    pub org: OrgId,
    pub anchor: (KeyId, SigningKey),
    pub custodians: Vec<PrivateKey>,
    pub shares: Vec<Vec<u8>>,
    /// `alpha bootstrap`'s reply; the share files it names live in `dir` until the harness drops.
    pub bootstrap: Value,
    pub dir: PathBuf,
    pub ca_pem: String,
    pub _shutdown: tokio::sync::oneshot::Sender<()>,
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

pub fn node_identity(node: &Node) -> NodeIdentity {
    NodeIdentity {
        runtime_spki: node.runtime_spki.clone(),
        xwing: node.xwing_key.public(),
    }
}

/// The custodian CLI's client: pinned to the node's runtime key, so any clock passes.
pub fn spki_client(url: &str, node: &Node) -> Client {
    Client::new(vec![url.to_owned()], Pin::Spki(node.runtime_spki.clone())).unwrap()
}

pub fn custodian_pubs(custodians: &[PrivateKey]) -> [PublicKey; 3] {
    custodians
        .iter()
        .map(PrivateKey::public)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

pub fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
}

/// Status and JSON body (`null` when the body is not JSON).
pub async fn send(request: reqwest::RequestBuilder) -> (StatusCode, Value) {
    let r = request.send().await.unwrap();
    (r.status(), r.json().await.unwrap_or(Value::Null))
}

pub fn client_with(identity_pem: &str) -> reqwest::Client {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .identity(reqwest::Identity::from_pem(identity_pem.as_bytes()).unwrap())
        .build()
        .unwrap()
}

/// A node acting as the keyed capture's CVM: its event log, nonce key and collateral, and `clock`
/// (the capture's time when a test attests with its quote, the wall clock when a pinned TLS
/// client must accept the node's one-hour leaf).
pub async fn start_node(
    pool: PgPool,
    release_url: &str,
    release_key: &SigningKey,
    clock: Clock,
) -> (Arc<Node>, String, tokio::sync::oneshot::Sender<()>) {
    let event_log: Vec<EventLogEntry> =
        serde_json::from_slice(&read(KEYED, "event_log.json")).unwrap();
    let collateral = serde_json::from_slice(&read(KEYED, "collateral.json")).unwrap();
    let config = Config {
        kms_endpoints: vec![],
        platform_document_url: release_url.to_owned(),
        #[cfg(feature = "dev-root")]
        dev_root_kek: None,
    };
    let node = Node::new(
        pool,
        config,
        clock,
        CollateralSource::Fixed(Box::new(collateral)),
        nonce_key(),
        event_log,
        release_key.verifying_key(),
    )
    .unwrap();
    platform::start(&node).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("https://{}", listener.local_addr().unwrap());
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let app = alpha_kms::router(node.clone());
    let cert = node.server_cert.clone();
    tokio::spawn(async move {
        tls::serve(listener, cert, app, async {
            let _ = rx.await;
        })
        .await
    });
    (node, base, tx)
}

pub fn platform_document(capture: &str) -> Value {
    serde_json::from_slice(&read(capture, "platform-document.json")).unwrap()
}

/// Bootstraps a fresh node on a fresh database through `alpha bootstrap`: three custodians,
/// the pilot organization's anchor.
pub async fn harness() -> Option<Harness> {
    let now = captured_at(KEYED);
    harness_with_clock(Arc::new(move || now)).await
}

pub async fn harness_with_clock(clock: Clock) -> Option<Harness> {
    let pool = fresh_database().await?;
    let release = ReleaseServer::start(platform_document(KEYED)).await;
    let (node, base, shutdown) = start_node(pool.clone(), &release.url, &release.key, clock).await;
    let custodians: Vec<PrivateKey> = (0..3).map(|_| PrivateKey::generate().unwrap()).collect();
    let anchor_key = SigningKey::from_bytes(&[7u8; 32]);
    let org = OrgId::mint();
    let anchor = Anchor {
        org_id: org,
        principal_id: PrincipalId::mint(),
        public_key: spki_b64(&anchor_key),
        label: "pilot anchor".into(),
    };
    let dir = std::env::temp_dir().join(format!("alpha-harness-{}", Uuid::now_v7()));
    fs::create_dir_all(&dir).unwrap();
    let identity = node_identity(&node);
    let bootstrap = alpha_cli::node::bootstrap(
        &spki_client(&base, &node),
        &identity,
        custodian_pubs(&custodians),
        anchor,
        1,
        &dir,
    )
    .await
    .unwrap();
    let shares = (1..=3)
        .zip(&custodians)
        .map(|(i, custodian)| {
            let file = ShareFile::read(&dir.join(format!("share-{i}.json"))).unwrap();
            alpha_crypto::open(
                custodian,
                INFO_UNSEAL_SHARE,
                &identity.aad(),
                &file.share_hpke,
            )
            .unwrap()
            .to_vec()
        })
        .collect();
    Some(Harness {
        node,
        pool,
        url: base,
        release,
        org,
        anchor: (
            bootstrap["anchor_key_id"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap(),
            anchor_key,
        ),
        custodians,
        shares,
        ca_pem: bootstrap["kms_ca_pem"].as_str().unwrap().to_owned(),
        bootstrap,
        dir,
        _shutdown: shutdown,
    })
}

impl Harness {
    pub fn now(&self) -> SystemTime {
        self.node.now()
    }

    pub fn signed(&self, ctx: &str, payload: Value, key: &(KeyId, SigningKey)) -> Value {
        json!(alpha_client::sign(ctx, payload, key.0, &key.1).unwrap())
    }

    pub async fn call(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Value,
    ) -> (StatusCode, Value) {
        send(
            client()
                .request(method, format!("{}{path}", self.url))
                .json(&body),
        )
        .await
    }

    pub async fn post(&self, path: &str, body: Value) -> (StatusCode, Value) {
        self.call(reqwest::Method::POST, path, body).await
    }

    /// Route 4 by `signer`: a new admin key for the organization.
    pub async fn register_key(
        &self,
        signer: &(KeyId, SigningKey),
        seed: u8,
    ) -> (KeyId, SigningKey) {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let payload = json!({ "principal_id": PrincipalId::mint(), "public_key": spki_b64(&key),
                              "label": format!("key {seed}"), "issued_at": rfc3339(self.now()) });
        let (status, reply) = self
            .post(
                "/v1/keys",
                self.signed(context::PRINCIPAL_KEY, payload, signer),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{reply}");
        (reply["id"].as_str().unwrap().parse().unwrap(), key)
    }

    /// The capture's compose as a Revision of `app_id`, signed by `signer`, straight into the table
    /// (its Phala `name` is not a UUID, so route 1 would refuse it — the KMS never checks the form later).
    pub async fn insert_capture_revision(
        &self,
        app_id: AppId,
        signer: &(KeyId, SigningKey),
    ) -> alpha_core::ComposeHash {
        let compose = text(KEYED, "app-compose.json");
        let hash = alpha_core::compose_hash(&compose);
        let document = json!({ "app_id": app_id, "compose": compose });
        let sig = self.signed(context::REVISION, document, signer)["signature"].clone();
        sqlx::query!("insert into revisions (compose_hash, app_id, org_id, compose, created_by_key, signature, created_at) values ($1, $2, $3, $4, $5, $6, $7)",
            hash.as_bytes().as_slice(), Uuid::from(app_id), Uuid::from(self.org), compose, Uuid::from(signer.0), sig,
            chrono::DateTime::<chrono::Utc>::from(self.now()))
            .execute(&self.pool).await.unwrap();
        hash
    }

    pub async fn put_secret(
        &self,
        name: &str,
        app_ids: &[AppId],
        value: &[u8],
        issued_at: SystemTime,
        signer: &(KeyId, SigningKey),
    ) -> (StatusCode, Value) {
        let payload = json!({ "name": name, "app_ids": app_ids, "content_sha256": format!("sha256:{}", hex::encode(Sha256::digest(value))), "issued_at": rfc3339(issued_at) });
        let mut body = self.signed(context::SECRET, payload, signer);
        body["value"] = json!(b64(value));
        self.call(reqwest::Method::PUT, &format!("/v1/secrets/{name}"), body)
            .await
    }

    pub fn nonce(&self) -> String {
        b64(&read(KEYED, "nonce.bin"))
    }

    pub async fn attest(&self, capture: &str) -> (StatusCode, Value) {
        let body = json!({ "runtime_pubkey": b64(&read(capture, "runtime_spki.der")), "nonce": b64(&read(capture, "nonce.bin")), "evidence": evidence(capture, "instance") });
        self.post("/v1/attest", body).await
    }

    /// Attests and returns an HTTPS client holding the Instance's leaf and the capture's key.
    pub async fn instance_client(&self) -> reqwest::Client {
        let (status, reply) = self.attest(KEYED).await;
        assert_eq!(status, StatusCode::OK, "{reply}");
        let leaf = reply["certificate_chain"][0].as_str().unwrap();
        client_with(&format!("{}{leaf}", text(KEYED, "runtime.key.pem")))
    }

    pub async fn audit(&self, action: &str) -> Vec<(i64, String, Value)> {
        sqlx::query!(
            "select seq, outcome, details from audit_log where action = $1 order by seq",
            action
        )
        .fetch_all(&self.pool)
        .await
        .unwrap()
        .into_iter()
        .map(|r| (r.seq, r.outcome, r.details))
        .collect()
    }
}

pub fn code(reply: &Value) -> &str {
    reply["error"]["code"].as_str().unwrap_or("")
}
