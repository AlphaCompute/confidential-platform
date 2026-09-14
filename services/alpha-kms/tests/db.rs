//! The route contracts against a real Postgres (`DATABASE_URL`; skipped without it). Each test gets
//! its own database, a node pinned to a Phala capture's time, nonce key and collateral, and a
//! local HTTP server standing in for the release artifact URL.

use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alpha_attest::{EVIDENCE_FORMAT, EventLogEntry, Evidence};
use alpha_core::{AppId, KeyId, OrgId, PrincipalId, context, signing_digest};
use alpha_crypto::{INFO_NODE_BOOTSTRAP, INFO_UNSEAL_SHARE, Sealed};
use alpha_kms::{CollateralSource, Config, Node, certs, instance, platform, rfc3339, tls};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use ed25519_dalek::pkcs8::EncodePublicKey;
use ed25519_dalek::{Signer, SigningKey};
use reqwest::StatusCode;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

const KEYED: &str = "phala-0.5.9-1c-2g-keyed";
const DEV_KEYED: &str = "phala-dev-0.5.9-keyed";

fn testdata() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata")
}

fn read(capture: &str, name: &str) -> Vec<u8> {
    let path = testdata().join("attest").join(capture).join(name);
    fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn text(capture: &str, name: &str) -> String {
    String::from_utf8(read(capture, name)).unwrap()
}

fn nonce_key() -> [u8; 32] {
    alpha_core::hex_bytes(
        fs::read_to_string(testdata().join("attest/capture/nonce_key.hex"))
            .unwrap()
            .trim(),
    )
    .unwrap()
}

fn captured_at(capture: &str) -> SystemTime {
    let t = chrono::DateTime::parse_from_rfc3339(text(capture, "captured_at.txt").trim()).unwrap();
    UNIX_EPOCH + Duration::from_secs(t.timestamp() as u64)
}

fn evidence(capture: &str, kind: &str) -> Evidence {
    Evidence {
        format: EVIDENCE_FORMAT.into(),
        quote: hex::decode(text(capture, &format!("quote.{kind}.hex")).trim()).unwrap(),
        event_log: serde_json::from_slice(&read(capture, "event_log.json")).unwrap(),
    }
}

fn b64(bytes: &[u8]) -> String {
    BASE64_URL_SAFE_NO_PAD.encode(bytes)
}

/// A fresh database per test, migrated.
async fn fresh_database() -> Option<(PgPool, String)> {
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
    Some((pool, url))
}

struct ReleaseServer {
    url: String,
    document: Arc<RwLock<Value>>,
    key: SigningKey,
}

impl ReleaseServer {
    async fn start(document: Value) -> Self {
        let key = SigningKey::from_bytes(&[42u8; 32]);
        let document = Arc::new(RwLock::new(document));
        let (doc, signer) = (document.clone(), key.clone());
        let app = axum::Router::new().route(
            "/platform.json",
            axum::routing::get(move || {
                let signed = sign_platform(&doc.read().unwrap(), &signer);
                async move { axum::Json(signed) }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/platform.json", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self { url, document, key }
    }

    fn set(&self, document: Value) {
        *self.document.write().unwrap() = document;
    }
}

fn sign_platform(document: &Value, key: &SigningKey) -> Value {
    let digest = signing_digest(context::PLATFORM, document);
    json!({ "document": document, "signature": { "algorithm": "ed25519", "signature": b64(&key.sign(&digest).to_bytes()) } })
}

struct Harness {
    node: Arc<Node>,
    pool: PgPool,
    url: String,
    release: ReleaseServer,
    org: OrgId,
    anchor: (KeyId, SigningKey),
    shares: Vec<Vec<u8>>,
    ca_pem: String,
    capture: &'static str,
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
}

fn client_with(identity_pem: &str) -> reqwest::Client {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .identity(reqwest::Identity::from_pem(identity_pem.as_bytes()).unwrap())
        .build()
        .unwrap()
}

async fn start_node(
    pool: PgPool,
    url: String,
    capture: &'static str,
    release_url: &str,
    release_key: &SigningKey,
) -> (Arc<Node>, String, tokio::sync::oneshot::Sender<()>) {
    let event_log: Vec<EventLogEntry> =
        serde_json::from_slice(&read(capture, "event_log.json")).unwrap();
    let collateral = serde_json::from_slice(&read(capture, "collateral.json")).unwrap();
    let now = captured_at(capture);
    let config = Config {
        database_url: url,
        kms_endpoints: vec![],
        pccs_url: "unused".into(),
        platform_document_url: release_url.to_owned(),
        #[cfg(feature = "dev-root")]
        dev_root_kek: None,
    };
    let node = Node::new(
        pool,
        config,
        Arc::new(move || now),
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

fn platform_document(capture: &str) -> Value {
    serde_json::from_slice(&read(capture, "platform-document.json")).unwrap()
}

/// Bootstraps a fresh node on a fresh database: three custodians, the pilot organization's anchor.
async fn harness(capture: &'static str) -> Option<Harness> {
    let (pool, url) = fresh_database().await?;
    let release = ReleaseServer::start(platform_document(capture)).await;
    let (node, base, shutdown) = start_node(
        pool.clone(),
        url.clone(),
        capture,
        &release.url,
        &release.key,
    )
    .await;
    let custodians: Vec<alpha_crypto::PrivateKey> = (0..3)
        .map(|_| alpha_crypto::PrivateKey::generate())
        .collect();
    let anchor_key = SigningKey::from_bytes(&[7u8; 32]);
    let org = OrgId::mint();
    let body = json!({
        "custodians": custodians.iter().map(|c| c.public()).collect::<Vec<_>>(),
        "anchor": { "org_id": org, "principal_id": PrincipalId::mint(),
                    "public_key": b64(anchor_key.verifying_key().to_public_key_der().unwrap().as_bytes()),
                    "label": "pilot anchor" },
    });
    let aad: [u8; 32] = Sha256::digest(&node.runtime_spki).into();
    let sealed = alpha_crypto::seal(
        &node.xwing_key.public(),
        INFO_NODE_BOOTSTRAP,
        &aad,
        &serde_json::to_vec(&body).unwrap(),
    );
    let reply: Value = client()
        .post(format!("{base}/v1/node/bootstrap"))
        .json(&json!({ "body_hpke": sealed }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let shares_hpke: Vec<Sealed> =
        serde_json::from_value(reply["payload"]["shares_hpke"].clone()).unwrap();
    let shares: Vec<Vec<u8>> = shares_hpke
        .iter()
        .zip(&custodians)
        .map(|(s, c)| {
            alpha_crypto::open(c, INFO_UNSEAL_SHARE, &aad, s)
                .unwrap()
                .to_vec()
        })
        .collect();
    let sig = BASE64_URL_SAFE_NO_PAD
        .decode(reply["signature"]["signature"].as_str().unwrap())
        .unwrap();
    let digest = signing_digest(alpha_kms::node::CONTEXT_BOOTSTRAP, &reply["payload"]);
    use p256::ecdsa::signature::Verifier;
    node.runtime_key
        .verifying_key()
        .verify(&digest, &p256::ecdsa::Signature::from_slice(&sig).unwrap())
        .unwrap();
    let anchor_id: Uuid =
        sqlx::query_scalar!("select id from principal_keys where registered_by_key is null")
            .fetch_one(&pool)
            .await
            .unwrap();
    Some(Harness {
        node,
        pool,
        url: base,
        release,
        org,
        anchor: (anchor_id.into(), anchor_key),
        shares,
        ca_pem: reply["payload"]["kms_ca_pem"].as_str().unwrap().to_owned(),
        capture,
        _shutdown: shutdown,
    })
}

impl Harness {
    fn now(&self) -> SystemTime {
        captured_at(self.capture)
    }

    fn signed(&self, ctx: &str, payload: Value, key: &(KeyId, SigningKey)) -> Value {
        let digest = signing_digest(ctx, &payload);
        json!({ "payload": payload, "signature": { "key_id": key.0, "algorithm": "ed25519", "signature": b64(&key.1.sign(&digest).to_bytes()) } })
    }

    async fn call(&self, method: reqwest::Method, path: &str, body: Value) -> (StatusCode, Value) {
        let r = client()
            .request(method, format!("{}{path}", self.url))
            .json(&body)
            .send()
            .await
            .unwrap();
        let status = r.status();
        (status, r.json().await.unwrap_or(Value::Null))
    }

    async fn post(&self, path: &str, body: Value) -> (StatusCode, Value) {
        self.call(reqwest::Method::POST, path, body).await
    }

    /// Route 4 by `signer`: a new admin key for the organization.
    async fn register_key(&self, signer: &(KeyId, SigningKey), seed: u8) -> (KeyId, SigningKey) {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let payload = json!({ "principal_id": PrincipalId::mint(), "public_key": b64(key.verifying_key().to_public_key_der().unwrap().as_bytes()),
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
    async fn insert_capture_revision(
        &self,
        app_id: AppId,
        signer: &(KeyId, SigningKey),
    ) -> alpha_core::ComposeHash {
        let compose = text(self.capture, "app-compose.json");
        let hash = alpha_core::compose_hash(&compose);
        let document = json!({ "app_id": app_id, "compose": compose });
        let sig = self.signed(context::REVISION, document, signer)["signature"].clone();
        sqlx::query!("insert into revisions (compose_hash, app_id, org_id, compose, created_by_key, signature, created_at) values ($1, $2, $3, $4, $5, $6, $7)",
            hash.as_bytes().as_slice(), Uuid::from(app_id), Uuid::from(self.org), compose, Uuid::from(signer.0), sig,
            chrono::DateTime::<chrono::Utc>::from(self.now()))
            .execute(&self.pool).await.unwrap();
        hash
    }

    async fn put_secret(
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

    fn nonce(&self) -> String {
        b64(&read(self.capture, "nonce.bin"))
    }

    async fn attest(&self, capture: &str) -> (StatusCode, Value) {
        let body = json!({ "runtime_pubkey": b64(&read(capture, "runtime_spki.der")), "nonce": b64(&read(capture, "nonce.bin")), "evidence": evidence(capture, "instance") });
        self.post("/v1/attest", body).await
    }

    /// Attests and returns an HTTPS client holding the Instance's leaf and the capture's key.
    async fn instance_client(&self) -> reqwest::Client {
        let (status, reply) = self.attest(self.capture).await;
        assert_eq!(status, StatusCode::OK, "{reply}");
        let leaf = reply["certificate_chain"][0].as_str().unwrap();
        client_with(&format!("{}{leaf}", text(self.capture, "runtime.key.pem")))
    }

    async fn audit(&self, action: &str) -> Vec<(i64, String, Value)> {
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

fn code(reply: &Value) -> &str {
    reply["error"]["code"].as_str().unwrap_or("")
}

#[tokio::test]
async fn bootstrap_once_unseal_with_two_shares_and_sealed_gate() {
    let Some(h) = harness(KEYED).await else {
        return;
    };
    assert!(h.ca_pem.starts_with("-----BEGIN CERTIFICATE-----"));
    assert_eq!(h.shares.len(), 3);
    let ready: Value = client()
        .get(format!("{}/ready", h.url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(ready, json!({ "sealed": false }));

    let aad: [u8; 32] = Sha256::digest(&h.node.runtime_spki).into();
    let again = alpha_crypto::seal(&h.node.xwing_key.public(), INFO_NODE_BOOTSTRAP, &aad, b"{}");
    let (status, reply) = h
        .post("/v1/node/bootstrap", json!({ "body_hpke": again }))
        .await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::CONFLICT, "already_exists")
    );

    // A second node over the same database comes up sealed and refuses everything but the Node API.
    let (node2, url2, _shutdown2) = start_node(
        h.pool.clone(),
        h.url.clone(),
        KEYED,
        &h.release.url,
        &h.release.key,
    )
    .await;
    assert!(node2.is_sealed());
    let r = client().get(format!("{url2}/ready")).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(r.json::<Value>().await.unwrap(), json!({ "sealed": true }));
    let r = client()
        .post(format!("{url2}/v1/attest/nonce"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(r.headers().get("retry-after").unwrap(), "30");
    assert_eq!(code(&r.json().await.unwrap()), "sealed");
    let r = client()
        .get(format!("{url2}/healthz"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);

    let aad2: [u8; 32] = Sha256::digest(&node2.runtime_spki).into();
    let unseal = |share: &Vec<u8>| json!({ "share_hpke": alpha_crypto::seal(&node2.xwing_key.public(), INFO_UNSEAL_SHARE, &aad2, share) });
    let post = |body: Value| {
        let url2 = url2.clone();
        async move {
            let r = client()
                .post(format!("{url2}/v1/node/unseal"))
                .json(&body)
                .send()
                .await
                .unwrap();
            (r.status(), r.json::<Value>().await.unwrap())
        }
    };
    let (status, reply) = post(unseal(&h.shares[2])).await;
    assert_eq!(
        (status, reply),
        (StatusCode::OK, json!({ "sealed": true, "shares": 1 }))
    );
    let (status, reply) = post(unseal(&h.shares[2])).await;
    assert_eq!(
        (status, reply),
        (StatusCode::OK, json!({ "sealed": true, "shares": 1 })),
        "the same share twice is one share"
    );
    assert!(node2.is_sealed());
    let wrong = alpha_crypto::seal(
        &node2.xwing_key.public(),
        INFO_NODE_BOOTSTRAP,
        &aad2,
        &h.shares[0],
    );
    let (status, reply) = post(json!({ "share_hpke": wrong })).await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::BAD_REQUEST, "malformed")
    );
    let (status, reply) = post(unseal(&h.shares[0])).await;
    assert_eq!(
        (status, reply),
        (StatusCode::OK, json!({ "sealed": false, "shares": 2 }))
    );
    assert!(!node2.is_sealed());
    let r = client().get(format!("{url2}/ready")).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(
        node2.intermediates().unwrap().ca_cert_der,
        h.node.intermediates().unwrap().ca_cert_der
    );
    assert_eq!(
        *node2.intermediates().unwrap().tenant_kek_root,
        *h.node.intermediates().unwrap().tenant_kek_root
    );
}

#[tokio::test]
async fn control_routes_register_revoke_and_put() {
    let Some(h) = harness(KEYED).await else {
        return;
    };
    let admin = h.register_key(&h.anchor, 11).await;

    // Route 4 idempotency: the same public key again is already_exists; unknown signer is signature_invalid.
    let payload = json!({ "principal_id": PrincipalId::mint(), "public_key": b64(admin.1.verifying_key().to_public_key_der().unwrap().as_bytes()), "label": "dup", "issued_at": rfc3339(h.now()) });
    let (status, reply) = h
        .post(
            "/v1/keys",
            h.signed(context::PRINCIPAL_KEY, payload.clone(), &h.anchor),
        )
        .await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::CONFLICT, "already_exists")
    );
    let stranger = (KeyId::mint(), SigningKey::from_bytes(&[99u8; 32]));
    let (status, reply) = h
        .post(
            "/v1/keys",
            h.signed(context::PRINCIPAL_KEY, payload.clone(), &stranger),
        )
        .await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::BAD_REQUEST, "signature_invalid")
    );
    let mut wrong_ctx = h.signed(context::CONTROL, payload.clone(), &h.anchor);
    wrong_ctx["payload"]["label"] = json!("dup2");
    let (status, reply) = h.post("/v1/keys", wrong_ctx).await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::BAD_REQUEST, "signature_invalid")
    );
    let old = json!({ "principal_id": PrincipalId::mint(), "public_key": payload["public_key"], "label": "old", "issued_at": "2020-01-01T00:00:00Z" });
    let (status, reply) = h
        .post("/v1/keys", h.signed(context::PRINCIPAL_KEY, old, &h.anchor))
        .await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::BAD_REQUEST, "malformed")
    );

    // Route 1 with the canonical manifest vector, signed by the registered admin key.
    let compose =
        fs::read_to_string(testdata().join("manifest/01-canonical/app-compose.json")).unwrap();
    let expected: Value = serde_json::from_str(
        &fs::read_to_string(testdata().join("manifest/01-canonical/expected.json")).unwrap(),
    )
    .unwrap();
    let app_id = expected["app_id"].as_str().unwrap();
    let body = h.signed(
        context::REVISION,
        json!({ "app_id": app_id, "compose": compose }),
        &admin,
    );
    let (status, reply) = h.post("/v1/revisions", body.clone()).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["compose_hash"], expected["compose_hash"]);
    assert_eq!(reply["org_id"], json!(h.org));
    let (status, again) = h.post("/v1/revisions", body).await;
    assert_eq!(
        (status, &again["compose_hash"]),
        (StatusCode::OK, &reply["compose_hash"]),
        "a repeat is 200 with the same Revision"
    );
    let tag = fs::read_to_string(testdata().join("manifest/02-reject-image-tag/app-compose.json"))
        .unwrap();
    let (status, reply) = h
        .post(
            "/v1/revisions",
            h.signed(
                context::REVISION,
                json!({ "app_id": app_id, "compose": tag }),
                &admin,
            ),
        )
        .await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::BAD_REQUEST, "malformed")
    );
    let (status, reply) = h
        .post(
            "/v1/revisions",
            h.signed(
                context::REVISION,
                json!({ "app_id": AppId::mint(), "compose": compose }),
                &admin,
            ),
        )
        .await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::BAD_REQUEST, "malformed"),
        "name != app_id"
    );

    // Another organization: its anchor exists only through a second bootstrap, so fake one through the table
    // with a random anchor_check — its keys never converge on a real anchor.
    let other_org = OrgId::mint();
    let other_key = SigningKey::from_bytes(&[12u8; 32]);
    let other_id = Uuid::now_v7();
    let other_spki = other_key.verifying_key().to_public_key_der().unwrap();
    sqlx::query!("insert into principal_keys (id, org_id, principal_id, public_key, document, anchor_check) values ($1, $2, $3, $4, '{}', $5)",
        other_id, Uuid::from(other_org), Uuid::now_v7(), other_spki.as_bytes(), &[0u8; 32][..])
        .execute(&h.pool).await.unwrap();
    let other = (KeyId::from(other_id), other_key);
    let (status, reply) = h
        .post(
            "/v1/revisions",
            h.signed(
                context::REVISION,
                json!({ "app_id": app_id, "compose": compose }),
                &other,
            ),
        )
        .await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::BAD_REQUEST, "signature_invalid"),
        "a row without the real anchor_check is not an anchor"
    );

    // Route 3: put, then a put with an older issued_at is already_exists; a forged signature is refused.
    let app: AppId = app_id.parse().unwrap();
    let (status, reply) = h
        .put_secret("api-key", &[app], b"s3cret", h.now(), &admin)
        .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let (status, reply) = h
        .put_secret("api-key", &[app], b"s3cret", h.now(), &admin)
        .await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::CONFLICT, "already_exists")
    );
    let foreign_app = AppId::mint();
    sqlx::query!("insert into revisions (compose_hash, app_id, org_id, compose, created_by_key, signature) values ($1, $2, $3, '{}', $4, '{}')",
        &[1u8; 32][..], Uuid::from(foreign_app), Uuid::from(other_org), other_id).execute(&h.pool).await.unwrap();
    let (status, reply) = h
        .put_secret(
            "api-key",
            &[app, foreign_app],
            b"newer",
            h.now() + Duration::from_secs(30),
            &admin,
        )
        .await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::NOT_FOUND, "not_found"),
        "an app of another organization"
    );
    let (status, reply) = h
        .put_secret(
            "api-key",
            &[app],
            b"newer",
            h.now() + Duration::from_secs(60),
            &admin,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let (status, reply) = h
        .put_secret(
            "api-key",
            &[app],
            b"forged",
            h.now() + Duration::from_secs(120),
            &(admin.0, SigningKey::from_bytes(&[13u8; 32])),
        )
        .await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::BAD_REQUEST, "signature_invalid")
    );
    let mut bad_hash = h.signed(context::SECRET, json!({ "name": "x", "app_ids": [app], "content_sha256": format!("sha256:{}", "0".repeat(64)), "issued_at": rfc3339(h.now()) }), &admin);
    bad_hash["value"] = json!(b64(b"v"));
    let (status, reply) = h
        .call(reqwest::Method::PUT, "/v1/secrets/x", bad_hash)
        .await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::BAD_REQUEST, "malformed")
    );

    // Route 2 and 5: revoke twice is 200 both times; objects of another organization are not_found.
    let hash = expected["compose_hash"].as_str().unwrap();
    let payload = json!({ "compose_hash": hash, "issued_at": rfc3339(h.now()) });
    let (status, r1) = h
        .post(
            &format!("/v1/revisions/{hash}/revoke"),
            h.signed(context::CONTROL, payload.clone(), &admin),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{r1}");
    let (status, r2) = h
        .post(
            &format!("/v1/revisions/{hash}/revoke"),
            h.signed(context::CONTROL, payload.clone(), &admin),
        )
        .await;
    assert_eq!((status, &r2), (StatusCode::OK, &r1));
    let (status, reply) = h
        .post(
            &format!("/v1/revisions/{hash}/revoke"),
            h.signed(context::CONTROL, payload, &other),
        )
        .await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::BAD_REQUEST, "signature_invalid")
    );
    let payload = json!({ "key_id": admin.0, "reason": "retired", "issued_at": rfc3339(h.now()) });
    let (status, r1) = h
        .post(
            &format!("/v1/keys/{}/revoke", admin.0),
            h.signed(context::CONTROL, payload.clone(), &h.anchor),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{r1}");
    let (status, r2) = h
        .post(
            &format!("/v1/keys/{}/revoke", admin.0),
            h.signed(context::CONTROL, payload, &h.anchor),
        )
        .await;
    assert_eq!((status, &r2), (StatusCode::OK, &r1));
    let (status, reply) = h.post("/v1/keys", h.signed(context::PRINCIPAL_KEY, json!({ "principal_id": PrincipalId::mint(), "public_key": b64(SigningKey::from_bytes(&[14u8; 32]).verifying_key().to_public_key_der().unwrap().as_bytes()), "label": "after", "issued_at": rfc3339(h.now()) }), &admin)).await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::BAD_REQUEST, "signature_invalid"),
        "a revoked key signs nothing"
    );
    let payload =
        json!({ "key_id": KeyId::mint(), "reason": "retired", "issued_at": rfc3339(h.now()) });
    let (status, reply) = h
        .post(
            &format!("/v1/keys/{}/revoke", payload["key_id"].as_str().unwrap()),
            h.signed(context::CONTROL, payload, &h.anchor),
        )
        .await;
    assert_eq!((status, code(&reply)), (StatusCode::NOT_FOUND, "not_found"));

    for action in [
        "key.register",
        "revision.register",
        "secret.put",
        "revision.revoke",
        "key.revoke",
    ] {
        assert!(
            h.audit(action)
                .await
                .iter()
                .any(|(_, outcome, _)| outcome == "ok"),
            "{action}"
        );
    }
}

#[tokio::test]
async fn attest_release_revoke_and_tamper() {
    let Some(h) = harness(KEYED).await else {
        return;
    };
    let admin = h.register_key(&h.anchor, 21).await;
    let app = AppId::mint();
    let hash = h.insert_capture_revision(app, &admin).await;
    let (status, reply) = h
        .put_secret("model-key", &[app], b"the value", h.now(), &admin)
        .await;
    assert_eq!(status, StatusCode::OK, "{reply}");

    // Unknown compose_hash and an image without a reference value are refused.
    let (status, reply) = h.attest(DEV_KEYED).await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::FORBIDDEN, "attestation_unknown"),
        "dev image has no reference value"
    );
    let (status, reply) = h.post("/v1/attest", json!({ "runtime_pubkey": b64(&read(KEYED, "runtime_spki.der")), "nonce": b64(&[1u8; 32]), "evidence": evidence(KEYED, "instance") })).await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::BAD_REQUEST, "nonce_invalid")
    );
    let (status, reply) = h.post("/v1/attest", json!({ "runtime_pubkey": b64(&read(DEV_KEYED, "runtime_spki.der")), "nonce": h.nonce(), "evidence": evidence(KEYED, "instance") })).await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::FORBIDDEN, "attestation_failed"),
        "report_data binds the key"
    );

    // The real thing.
    let (status, reply) = h.attest(KEYED).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let result = &reply["attestation_result"];
    assert_eq!(result["verdict"], "verified");
    assert_eq!(
        result["revision"],
        json!({ "compose_hash": hash, "app_id": app, "org_id": h.org })
    );
    assert_eq!(result["os_image"], "dstack-0.5.9/1c-2g");
    let leaf_pem = reply["certificate_chain"][0].as_str().unwrap();
    assert_eq!(reply["certificate_chain"][1], json!(h.ca_pem));
    let leaf_der =
        <rustls::pki_types::CertificateDer as rustls::pki_types::pem::PemObject>::from_pem_slice(
            leaf_pem.as_bytes(),
        )
        .unwrap();
    let sans = certs::uri_sans(&leaf_der).unwrap();
    assert_eq!(
        sans,
        [
            format!(
                "alphacompute://{}/{app}/{}",
                h.org,
                result["runtime_pubkey_sha256"]
                    .as_str()
                    .unwrap()
                    .trim_start_matches("sha256:")
            ),
            format!("urn:alphacompute:revision:{hash}")
        ]
    );
    let attest_rows = h.audit("attest").await;
    let with_evidence: i64 = sqlx::query_scalar!(
        "select count(*) from audit_log where action = 'attest' and evidence_sha256 is not null"
    )
    .fetch_one(&h.pool)
    .await
    .unwrap()
    .unwrap();
    assert_eq!(with_evidence as usize, attest_rows.len());
    assert!(
        attest_rows
            .iter()
            .any(|(_, o, d)| o == "ok" && d["verdict"] == "verified")
    );
    assert!(
        attest_rows
            .iter()
            .any(|(_, o, d)| o == "denied" && d["code"] == "attestation_unknown")
    );

    let instance = h.instance_client().await;
    let r = instance
        .get(format!("{}/v1/secrets/model-key", h.url))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let secret: Value = r.json().await.unwrap();
    assert_eq!(secret["value"], json!(b64(b"the value")));
    assert_eq!(
        secret["content_sha256"],
        json!(format!(
            "sha256:{}",
            hex::encode(Sha256::digest(b"the value"))
        ))
    );
    let r = instance
        .get(format!("{}/v1/secrets/other", h.url))
        .send()
        .await
        .unwrap();
    assert_eq!(
        (r.status(), code(&r.json().await.unwrap())),
        (StatusCode::NOT_FOUND, "not_found")
    );

    // No certificate, or a self-signed one with the right SANs, is cert_invalid.
    let r = client()
        .get(format!("{}/v1/secrets/model-key", h.url))
        .send()
        .await
        .unwrap();
    assert_eq!(
        (r.status(), code(&r.json().await.unwrap())),
        (StatusCode::UNAUTHORIZED, "cert_invalid")
    );
    let forged = forged_client(&h, &sans);
    let r = forged
        .get(format!("{}/v1/secrets/model-key", h.url))
        .send()
        .await
        .unwrap();
    assert_eq!(
        (r.status(), code(&r.json().await.unwrap())),
        (StatusCode::UNAUTHORIZED, "cert_invalid")
    );

    // Revoke, then the next call on the issued certificate is revision_revoked.
    let payload = json!({ "compose_hash": hash, "issued_at": rfc3339(h.now()) });
    let (status, reply) = h
        .post(
            &format!("/v1/revisions/{hash}/revoke"),
            h.signed(context::CONTROL, payload, &admin),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let r = instance
        .get(format!("{}/v1/secrets/model-key", h.url))
        .send()
        .await
        .unwrap();
    assert_eq!(
        (r.status(), code(&r.json().await.unwrap())),
        (StatusCode::CONFLICT, "revision_revoked")
    );
    let (status, reply) = h.attest(KEYED).await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::CONFLICT, "revision_revoked")
    );
    sqlx::query!("update revisions set revoked_at = null")
        .execute(&h.pool)
        .await
        .unwrap();

    // The row is re-verified on every call.
    sqlx::query!("update revisions set app_id = $1", Uuid::now_v7())
        .execute(&h.pool)
        .await
        .unwrap();
    let (status, reply) = h.attest(KEYED).await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::BAD_REQUEST, "signature_invalid")
    );
    let r = instance
        .get(format!("{}/v1/secrets/model-key", h.url))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        StatusCode::NOT_FOUND,
        "the certificate's app no longer matches the row"
    );
    sqlx::query!("update revisions set app_id = $1", Uuid::from(app))
        .execute(&h.pool)
        .await
        .unwrap();
    sqlx::query!("update revisions set compose = compose || ' '")
        .execute(&h.pool)
        .await
        .unwrap();
    let r = instance
        .get(format!("{}/v1/secrets/model-key", h.url))
        .send()
        .await
        .unwrap();
    assert_eq!(
        (r.status(), code(&r.json().await.unwrap())),
        (StatusCode::BAD_REQUEST, "signature_invalid")
    );
    sqlx::query!("update revisions set compose = left(compose, length(compose) - 1)")
        .execute(&h.pool)
        .await
        .unwrap();
    let r = instance
        .get(format!("{}/v1/secrets/model-key", h.url))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);

    // A retired registering key keeps old objects valid; compromised fails them closed.
    let payload = json!({ "key_id": admin.0, "reason": "retired", "issued_at": rfc3339(h.now() + Duration::from_secs(1)) });
    let (status, reply) = h
        .post(
            &format!("/v1/keys/{}/revoke", admin.0),
            h.signed(context::CONTROL, payload, &h.anchor),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let r = instance
        .get(format!("{}/v1/secrets/model-key", h.url))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        StatusCode::OK,
        "retired: objects signed before revoked_at stay valid"
    );
    sqlx::query!(
        "update principal_keys set revocation_reason = 'compromised' where id = $1",
        Uuid::from(admin.0)
    )
    .execute(&h.pool)
    .await
    .unwrap();
    let r = instance
        .get(format!("{}/v1/secrets/model-key", h.url))
        .send()
        .await
        .unwrap();
    assert_eq!(
        (r.status(), code(&r.json().await.unwrap())),
        (StatusCode::BAD_REQUEST, "signature_invalid")
    );
    let (status, reply) = h.attest(KEYED).await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::BAD_REQUEST, "signature_invalid")
    );

    // A swapped anchor SPKI leaves the organization's secrets undecryptable.
    sqlx::query!(
        "update principal_keys set revoked_at = null, revocation_reason = null where id = $1",
        Uuid::from(admin.0)
    )
    .execute(&h.pool)
    .await
    .unwrap();
    let other = SigningKey::from_bytes(&[22u8; 32])
        .verifying_key()
        .to_public_key_der()
        .unwrap();
    sqlx::query!(
        "update principal_keys set public_key = $1 where registered_by_key is null",
        other.as_bytes()
    )
    .execute(&h.pool)
    .await
    .unwrap();
    let r = instance
        .get(format!("{}/v1/secrets/model-key", h.url))
        .send()
        .await
        .unwrap();
    assert_eq!(
        (r.status(), code(&r.json().await.unwrap())),
        (StatusCode::BAD_REQUEST, "signature_invalid")
    );

    // The service role cannot update or delete audit rows; seq is monotone.
    let rows = h.audit("secret.get").await;
    assert!(rows.windows(2).all(|w| w[0].0 < w[1].0) && rows.len() >= 3);
    let mut conn = h.pool.acquire().await.unwrap();
    sqlx::query("set role alpha_kms")
        .execute(&mut *conn)
        .await
        .unwrap();
    let e = sqlx::query("update audit_log set outcome = 'ok'")
        .execute(&mut *conn)
        .await
        .unwrap_err();
    assert!(e.to_string().contains("permission denied"), "{e}");
    let e = sqlx::query("delete from audit_log")
        .execute(&mut *conn)
        .await
        .unwrap_err();
    assert!(e.to_string().contains("permission denied"), "{e}");
    sqlx::query("insert into audit_log (actor_kind, actor, action, outcome) values ('node', 'node', 'test', 'ok')").execute(&mut *conn).await.unwrap();
}

/// A self-signed certificate carrying an Instance's SANs on a key we hold.
fn forged_client(h: &Harness, sans: &[String]) -> reqwest::Client {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = rcgen::CertificateParams::default();
    params.subject_alt_names = sans
        .iter()
        .map(|s| rcgen::SanType::URI(rcgen::string::Ia5String::try_from(s.as_str()).unwrap()))
        .collect();
    params.not_before = h.now().into();
    params.not_after = (h.now() + Duration::from_secs(3600)).into();
    let cert = params.self_signed(&key).unwrap();
    client_with(&format!("{}{}", key.serialize_pem(), cert.pem()))
}

#[tokio::test]
async fn join_hands_out_intermediates_only_to_an_attested_listed_requesting_node() {
    let Some(h) = harness(KEYED).await else {
        return;
    };
    let pkcs8 = read(KEYED, "runtime.key.pkcs8.der");
    let cert = certs::self_signed(&certs::key_pair(&pkcs8), h.now());
    let joiner = client_with(&format!(
        "{}{}",
        text(KEYED, "runtime.key.pem"),
        certs::pem(&cert)
    ));
    let xwing = alpha_crypto::PrivateKey::from_seed(
        alpha_core::hex_bytes(
            fs::read_to_string(testdata().join("attest/capture/xwing_seed.hex"))
                .unwrap()
                .trim(),
        )
        .unwrap(),
    )
    .public();
    assert_eq!(
        xwing.as_bytes().as_slice(),
        read(KEYED, "node_xwing_pubkey.bin")
    );
    let body =
        json!({ "nonce": h.nonce(), "evidence": evidence(KEYED, "node"), "xwing_pubkey": xwing });
    let post = |client: &reqwest::Client, body: Value| {
        let url = h.url.clone();
        let client = client.clone();
        async move {
            let r = client
                .post(format!("{url}/v1/node/join"))
                .json(&body)
                .send()
                .await
                .unwrap();
            (r.status(), r.json::<Value>().await.unwrap())
        }
    };

    let (status, reply) = post(&joiner, body.clone()).await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::NOT_FOUND, "not_found"),
        "no node.join.request row"
    );
    let (status, reply) = post(&client(), body.clone()).await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::UNAUTHORIZED, "cert_invalid")
    );

    let runtime_sha = hex::encode(Sha256::digest(read(KEYED, "runtime_spki.der")));
    sqlx::query!("insert into audit_log (actor_kind, actor, action, outcome, details, ts) values ('node', 'node', 'node.join.request', 'ok', $1, now() - interval '11 minutes')", json!({ "runtime_pubkey_sha256": runtime_sha })).execute(&h.pool).await.unwrap();
    let (status, reply) = post(&joiner, body.clone()).await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::NOT_FOUND, "not_found"),
        "a stale request does not count"
    );
    sqlx::query!("insert into audit_log (actor_kind, actor, action, outcome, details) values ('node', 'node', 'node.join.request', 'ok', $1)", json!({ "runtime_pubkey_sha256": runtime_sha })).execute(&h.pool).await.unwrap();

    let mut wrong_key = body.clone();
    wrong_key["xwing_pubkey"] = json!(alpha_crypto::PrivateKey::generate().public());
    let (status, reply) = post(&joiner, wrong_key).await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::FORBIDDEN, "attestation_failed"),
        "a substituted xwing_pubkey beside a genuine quote"
    );
    let forged = forged_client(&h, &["alphacompute://kms".into()]);
    let (status, reply) = post(&forged, body.clone()).await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::FORBIDDEN, "attestation_failed"),
        "the client key is not the one in report_data"
    );
    let mut doc = platform_document(KEYED);
    doc["version"] = json!(2);
    doc["kms_revisions"] = json!([]);
    h.release.set(doc);
    platform::reload(&h.node).await.unwrap();
    let (status, reply) = post(&joiner, body.clone()).await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::FORBIDDEN, "attestation_unknown"),
        "revision outside kms_revisions"
    );
    let mut doc = platform_document(KEYED);
    doc["version"] = json!(3);
    h.release.set(doc);
    platform::reload(&h.node).await.unwrap();

    let (status, reply) = post(&joiner, body).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let keys = h.node.intermediates().unwrap();
    assert_eq!(
        reply["tenant_kek_root"],
        json!(b64(keys.tenant_kek_root.as_slice()))
    );
    assert_eq!(reply["ca_cert"], json!(b64(&keys.ca_cert_der)));
    let joins = h.audit("node.join").await;
    assert!(
        joins
            .iter()
            .any(|(_, o, d)| o == "ok" && d["runtime_pubkey_sha256"] == json!(runtime_sha))
    );
    assert!(joins.iter().filter(|(_, o, _)| o == "denied").count() >= 4);
}

#[tokio::test]
async fn platform_document_is_monotone_and_audited_on_change() {
    let Some(h) = harness(KEYED).await else {
        return;
    };
    assert_eq!(h.audit("platform.reload").await.len(), 1);
    platform::reload(&h.node).await.unwrap();
    assert_eq!(
        h.audit("platform.reload").await.len(),
        1,
        "same version: no row"
    );
    let mut doc = platform_document(KEYED);
    doc["version"] = json!(0);
    h.release.set(doc);
    assert!(
        platform::reload(&h.node).await.is_err(),
        "a lower version is refused"
    );
    assert_eq!(h.node.platform_document().unwrap().version, 1);
    let mut doc = platform_document(KEYED);
    doc["version"] = json!(5);
    h.release.set(doc);
    platform::reload(&h.node).await.unwrap();
    assert_eq!(h.node.platform_document().unwrap().version, 5);
    let rows = h.audit("platform.reload").await;
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[1].2, json!({ "version": 5, "previous": 1 }));
    let stored: i32 = sqlx::query_scalar!("select version from platform_document")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(stored, 5);
}

#[tokio::test]
async fn nonce_route_malformed_body_and_unknown_route() {
    let Some(h) = harness(KEYED).await else {
        return;
    };
    let (status, reply) = h.post("/v1/attest/nonce", json!({})).await;
    assert_eq!(status, StatusCode::OK);
    let nonce = BASE64_URL_SAFE_NO_PAD
        .decode(reply["nonce"].as_str().unwrap())
        .unwrap();
    assert!(instance::check_nonce(&nonce_key(), &nonce.try_into().unwrap(), h.now()).is_ok());
    let (status, reply) = h
        .post(
            "/v1/attest",
            json!({ "runtime_pubkey": "", "nonce": "", "evidence": {}, "extra": 1 }),
        )
        .await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::BAD_REQUEST, "malformed")
    );
    assert!(Uuid::parse_str(reply["error"]["request_id"].as_str().unwrap()).is_ok());
    let r = client()
        .get(format!("{}/v1/nope", h.url))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
}
