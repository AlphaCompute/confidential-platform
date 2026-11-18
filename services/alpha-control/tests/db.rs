#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use alpha_control::{AppState, Oidc, router};
use alpha_core::{InitData, InitDataError, KataPolicy};
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use data_encoding::BASE64URL_NOPAD;
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use tokio::sync::oneshot;
use tower::ServiceExt;
use uuid::Uuid;

const OPERATOR: &str = "operator-token";

/// A fresh database per test, empty; `None` when `DATABASE_URL` is unset.
async fn fresh_database() -> Option<PgPool> {
    let admin_url = std::env::var("DATABASE_URL").ok()?;
    let admin = PgPoolOptions::new().connect(&admin_url).await.unwrap();
    let name = format!("alpha_test_{}", Uuid::now_v7().simple());
    sqlx::query(sqlx::AssertSqlSafe(format!("create database {name}")))
        .execute(&admin)
        .await
        .unwrap();
    let (base, _) = admin_url.rsplit_once('/').unwrap();
    let pool = PgPoolOptions::new()
        .connect(&format!("{base}/{name}"))
        .await
        .unwrap();
    Some(pool)
}

const KEYED: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../testdata/attest/phala-0.5.9-1c-2g-keyed"
);

fn capture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{KEYED}/{name}")).unwrap()
}

/// An alpha-kms node in this process, as the keyed capture's CVM, on its own database, reading
/// its platform document from `url` and bootstrapped with throwaway custodians. Answers the node,
/// its URL, its CA and the sender that keeps it serving.
async fn start_kms(
    url: &str,
    release: &SigningKey,
) -> (alpha_core::ComposeHash, String, String, oneshot::Sender<()>) {
    let pool = fresh_database().await.unwrap();
    // The migrations create the cluster-wide `alpha_kms` role; two at once both try.
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    sqlx::query("select pg_advisory_lock(0)")
        .execute(&admin)
        .await
        .unwrap();
    alpha_kms::migrate(&pool).await.unwrap();
    sqlx::query("select pg_advisory_unlock(0)")
        .execute(&admin)
        .await
        .unwrap();
    let event_log: Vec<alpha_attest::EventLogEntry> =
        serde_json::from_slice(&capture("event_log.json")).unwrap();
    let nonce_key = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/attest/capture/nonce_key.hex"
    ))
    .unwrap();
    let config = alpha_kms::Config {
        substrate: alpha_tsm::Substrate::Dstack,
        kms_endpoints: vec![],
        platform_document_url: url.to_owned(),
        nvidia_ocsp_url: String::new(),
    };
    let node = alpha_kms::Node::new(
        pool,
        config,
        Arc::new(SystemTime::now),
        alpha_kms::CollateralSource::Fixed(Box::new(
            serde_json::from_slice(&capture("collateral.json")).unwrap(),
        )),
        alpha_core::hex_bytes(nonce_key.trim()).unwrap(),
        alpha_attest::event_log_compose_hash(&event_log).unwrap(),
        release.verifying_key().into(),
    )
    .unwrap();
    alpha_kms::platform::start(&node).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("https://{}", listener.local_addr().unwrap());
    let (shutdown, stopped) = oneshot::channel::<()>();
    let app = alpha_kms::router(node.clone());
    let tls = alpha_kms::tls::server_config(node.server_cert.clone()).unwrap();
    tokio::spawn(async move {
        alpha_client::tls::serve(listener, tls, app, async {
            let _ = stopped.await;
        })
        .await
    });
    let identity = alpha_cli::node::NodeIdentity {
        runtime_spki: node.runtime_spki.clone(),
        xwing: node.xwing_key.public(),
    };
    let custodians = [(); 3].map(|_| alpha_crypto::PrivateKey::generate().unwrap().public());
    let dir = std::env::temp_dir().join(format!("alpha-control-kms-{}", Uuid::now_v7()));
    std::fs::create_dir_all(&dir).unwrap();
    let client = alpha_client::Client::new(
        vec![base.clone()],
        alpha_client::Pin::Spki(node.runtime_spki.clone()),
    )
    .unwrap();
    let bootstrap = alpha_cli::node::bootstrap(&client, &identity, custodians, None, 2, &dir)
        .await
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    let ca = bootstrap["kms_ca_pem"].as_str().unwrap().to_owned();
    (node.compose_hash, base, ca, shutdown)
}

const CATALOG: &str = include_str!("../../../testdata/catalog/valid.json");
const CATALOG_EXPECTED: &str = include_str!("../../../testdata/catalog/expected.json");

/// The agent policy hashes of the catalog template, read back from the checks that refuse them.
fn kata_policy(template: &str) -> KataPolicy {
    let init_data = InitData::parse(template.to_owned()).unwrap();
    let zero = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    let mut pinned = KataPolicy {
        rules_sha256: zero.parse().unwrap(),
        data_sha256: zero.parse().unwrap(),
    };
    let Err(InitDataError::Rules(rules)) = init_data.check_policy(&pinned, "") else {
        panic!("the rules were accepted")
    };
    pinned.rules_sha256 = rules;
    let Err(InitDataError::PolicyData(data)) = init_data.check_policy(&pinned, "") else {
        panic!("the policy data was accepted")
    };
    pinned.data_sha256 = data;
    pinned
}

/// The keyed capture's platform document at `version`, naming the catalog test key and `kms`'s
/// fields over the capture's, signed by `release`.
fn platform_document(release: &SigningKey, version: u64, kms: Value) -> Value {
    let catalog: Value = serde_json::from_str(CATALOG).unwrap();
    let expected: Value = serde_json::from_str(CATALOG_EXPECTED).unwrap();
    let mut document: Value = serde_json::from_slice(&capture("platform-document.json")).unwrap();
    document["version"] = json!(version);
    document["catalog_key"] = expected["catalog_key"].clone();
    document["kata_policy"] = json!(kata_policy(catalog["template"].as_str().unwrap()));
    for (key, value) in kms.as_object().unwrap() {
        document[key] = value.clone();
    }
    serde_json::to_value(alpha_client::platform::sign(document, release).unwrap()).unwrap()
}

const ISSUER: &str = "https://login.example";

/// The router, its database, the platform document its URL serves, the claims of the ID token
/// the fake token endpoint answers, and the KMS node behind the relay, if any.
struct Api(
    axum::Router,
    PgPool,
    Arc<Mutex<Value>>,
    SigningKey,
    Arc<Mutex<Value>>,
    Option<(String, oneshot::Sender<()>)>,
);

impl Api {
    async fn new() -> Option<Self> {
        Self::start(false).await
    }

    async fn start(with_kms: bool) -> Option<Self> {
        let pool = fresh_database().await?;
        alpha_control::migrate(&pool).await.unwrap();
        let release = SigningKey::from_bytes(&[7; 32]);
        let served = Arc::new(Mutex::new(platform_document(&release, 2, json!({}))));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/platform.json", listener.local_addr().unwrap());
        let base = format!("http://{}", listener.local_addr().unwrap());
        let document = served.clone();
        let claims = Arc::new(Mutex::new(json!({})));
        let id_claims = claims.clone();
        // A public client: the code is redeemed with its PKCE verifier and no secret.
        let token = move |form: String| async move {
            let expected = [
                "grant_type=authorization_code",
                "code=good",
                "client_id=signer",
                "code_verifier=verifier",
                "redirect_uri=https%3A%2F%2Fsign.example%2Fclaim",
            ];
            if !expected
                .iter()
                .all(|pair| form.split('&').any(|p| p == *pair))
            {
                return Err(StatusCode::BAD_REQUEST);
            }
            let payload = id_claims.lock().unwrap().to_string();
            let id_token = format!("e30.{}.sig", BASE64URL_NOPAD.encode(payload.as_bytes()));
            Ok(axum::Json(
                json!({ "id_token": id_token, "token_type": "Bearer" }),
            ))
        };
        let host = axum::Router::new()
            .route(
                "/platform.json",
                axum::routing::get(
                    move || async move { axum::Json(document.lock().unwrap().clone()) },
                ),
            )
            .route("/token", axum::routing::post(token));
        tokio::spawn(async move { axum::serve(listener, host).await });
        let mut kms = None;
        if with_kms {
            let (compose_hash, kms_url, ca, shutdown) = start_kms(&url, &release).await;
            let pins = json!({
                "kms_ca_pem": ca,
                "kms_revisions": [{ "compose_hash": compose_hash, "build": "test",
                                    "source_url": "https://example.test" }],
            });
            *served.lock().unwrap() = platform_document(&release, 2, pins);
            kms = Some((kms_url, shutdown));
        }
        let state = Arc::new(AppState {
            pool: pool.clone(),
            operator_token_sha256: Sha256::digest(OPERATOR).into(),
            platform_document_url: url,
            release_keys: release.verifying_key().into(),
            kms_endpoints: kms.iter().map(|(url, _)| url.clone()).collect(),
            signer_url: "https://sign.example".into(),
            code_lookups: Default::default(),
            oidc: Oidc {
                issuer: ISSUER.into(),
                token_endpoint: format!("{base}/token"),
                client_id: "signer".into(),
            },
        });
        Some(Api(router(state), pool, served, release, claims, kms))
    }

    async fn call(
        &self,
        method: Method,
        uri: &str,
        bearer: &str,
        body: Value,
    ) -> (StatusCode, Value) {
        self.call_with(method, uri, bearer, &[], body).await
    }

    async fn call_with(
        &self,
        method: Method,
        uri: &str,
        bearer: &str,
        headers: &[(&str, &str)],
        body: Value,
    ) -> (StatusCode, Value) {
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", format!("Bearer {bearer}"));
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let request = request
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let response = self.0.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    async fn read_ticket(&self, ticket: &str) -> Value {
        let (status, read) = self
            .call(
                Method::GET,
                &format!("/v1/tickets/{ticket}"),
                "",
                Value::Null,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{read}");
        read
    }

    /// An Organization with a deploy key of `scopes`; returns its id and token.
    async fn org(&self, scopes: &[&str]) -> (String, String) {
        let body = json!({
            "name": "Acme", "owner_email": "owner@acme.test", "deploy_key": { "scopes": scopes },
        });
        let (status, created) = self.call(Method::POST, "/v1/orgs", OPERATOR, body).await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let token = created["deploy_key"]["token"].as_str().unwrap().to_owned();
        (created["org_id"].as_str().unwrap().to_owned(), token)
    }
}

#[tokio::test]
async fn an_organization_is_created_unrooted_by_the_operator_or_an_onboarding_key_only() {
    let Some(api) = Api::new().await else { return };
    let body = json!({ "name": "Acme", "owner_email": "owner@acme.test" });
    let (_, deploy) = api.org(&["apps:write", "org:admin"]).await;
    for bearer in ["", "alpha_unknown", deploy.as_str()] {
        let (status, _) = api
            .call(Method::POST, "/v1/orgs", bearer, body.clone())
            .await;
        assert!(
            status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN,
            "{bearer}"
        );
    }

    let onboard = "alpha_onboard";
    sqlx::query("insert into api_keys (id, token_sha256, scopes, issuer) values ($1, $2, '{onboard}', 'rafay:console.example')")
        .bind(Uuid::now_v7())
        .bind(Sha256::digest(onboard).as_slice())
        .execute(&api.1)
        .await
        .unwrap();
    let link = json!({ "issuer": "i", "external_id": "e" });
    for bad in [
        json!({ "name": "Acme", "owner_email": "o@acme.test", "deploy_key": { "scopes": ["onboard"] } }),
        json!({ "name": "Acme", "owner_email": "owner@" }),
        json!({ "name": "Acme", "owner_email": "a@b@c" }),
        json!({ "name": "Acme", "owner_email": "o@acme.test", "links": vec![link; 17] }),
    ] {
        let (status, _) = api
            .call(Method::POST, "/v1/orgs", onboard, bad.clone())
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}");
    }
    let foreign = json!({ "name": "Acme", "owner_email": "o@acme.test", "links": [{ "issuer": "other", "external_id": "org-1" }] });
    let (status, _) = api.call(Method::POST, "/v1/orgs", onboard, foreign).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let linked = json!({
        "name": "Acme", "owner_email": "owner@acme.test",
        "links": [{ "issuer": "rafay:console.example", "external_id": "org-1" }],
    });
    let (status, created) = api
        .call(Method::POST, "/v1/orgs", onboard, linked.clone())
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(
        created.as_object().unwrap().keys().collect::<Vec<_>>(),
        ["org_id"]
    );
    let (status, _) = api.call(Method::POST, "/v1/orgs", OPERATOR, linked).await;
    assert_eq!(status, StatusCode::CONFLICT);
    let orgs: i64 = sqlx::query_scalar("select count(*) from organizations")
        .fetch_one(&api.1)
        .await
        .unwrap();
    let audited: i64 =
        sqlx::query_scalar("select count(*) from audit_log where action = 'org.create'")
            .fetch_one(&api.1)
            .await
            .unwrap();
    assert_eq!((orgs, audited), (2, 2));
}

#[tokio::test]
async fn a_key_reaches_only_its_own_organizations_apps() {
    let Some(api) = Api::new().await else { return };
    let (_, a) = api.org(&["apps:write"]).await;
    let (_, b) = api.org(&["apps:write"]).await;
    let (_, read_only) = api.org(&["apps:read"]).await;

    let (status, app) = api
        .call(Method::PUT, "/v1/apps/hello", &a, Value::Null)
        .await;
    assert_eq!(status, StatusCode::OK, "{app}");
    assert_eq!(app["endpoint"], "https://hello.app.alphacompute.cc");
    let (status, again) = api
        .call(Method::PUT, "/v1/apps/hello", &a, Value::Null)
        .await;
    assert_eq!((status, &again["app_id"]), (StatusCode::OK, &app["app_id"]));

    let (status, taken) = api
        .call(Method::PUT, "/v1/apps/hello", &b, Value::Null)
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(!taken.to_string().contains(app["app_id"].as_str().unwrap()));
    for bearer in [read_only.as_str(), OPERATOR] {
        let (status, _) = api
            .call(Method::PUT, "/v1/apps/other", bearer, Value::Null)
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
    let (status, _) = api
        .call(Method::PUT, "/v1/apps/a--b", &a, Value::Null)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_retried_create_returns_the_same_organization_and_replaces_the_lost_deploy_key() {
    let Some(api) = Api::new().await else { return };
    let create = json!({
        "name": "Acme", "owner_email": "owner@acme.test",
        "links": [{ "issuer": "rafay:console.example", "external_id": "org-1" }],
        "deploy_key": { "scopes": ["apps:write"] },
    });
    let (status, first) = api
        .call(Method::POST, "/v1/orgs", OPERATOR, create.clone())
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, retry) = api
        .call(Method::POST, "/v1/orgs", OPERATOR, create.clone())
        .await;
    let org_id = |reply: &Value| reply["org_id"].as_str().unwrap().parse::<Uuid>().unwrap();
    assert_eq!((status, org_id(&retry)), (StatusCode::OK, org_id(&first)));
    let lost = first["deploy_key"]["token"].as_str().unwrap();
    let kept = retry["deploy_key"]["token"].as_str().unwrap();
    for (token, expected) in [(lost, StatusCode::UNAUTHORIZED), (kept, StatusCode::OK)] {
        let (status, _) = api
            .call(Method::PUT, "/v1/apps/hello", token, Value::Null)
            .await;
        assert_eq!(status, expected);
    }

    let mut renamed = create.clone();
    renamed["name"] = json!("Other");
    let (status, _) = api.call(Method::POST, "/v1/orgs", OPERATOR, renamed).await;
    assert_eq!(status, StatusCode::CONFLICT);
    sqlx::query("update organizations set created_at = now() - interval '2 hours'")
        .execute(&api.1)
        .await
        .unwrap();
    let (status, _) = api.call(Method::POST, "/v1/orgs", OPERATOR, create).await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn a_revoked_key_or_a_disabled_organization_authenticates_nothing() {
    let Some(api) = Api::new().await else { return };
    let (org, admin) = api.org(&["apps:write", "org:admin"]).await;
    let (other_org, other) = api.org(&["apps:write", "org:admin"]).await;
    let other_key: Uuid = sqlx::query_scalar("select id from api_keys where org_id = $1::uuid")
        .bind(&other_org)
        .fetch_one(&api.1)
        .await
        .unwrap();
    let (status, _) = api
        .call(
            Method::DELETE,
            &format!("/v1/orgs/{other_org}/keys/{other_key}"),
            &admin,
            Value::Null,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = api
        .call(
            Method::POST,
            &format!("/v1/orgs/{org}/disable"),
            &other,
            Value::Null,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = api
        .call(
            Method::DELETE,
            &format!("/v1/orgs/{other_org}/keys/{other_key}"),
            &other,
            Value::Null,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = api
        .call(
            Method::POST,
            &format!("/v1/orgs/{org}/disable"),
            OPERATOR,
            Value::Null,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    for token in [admin.as_str(), other.as_str()] {
        let (status, _) = api
            .call(Method::PUT, "/v1/apps/hello", token, Value::Null)
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
}

#[tokio::test]
async fn a_catalog_revision_is_rendered_for_its_app_and_stored_once() {
    let Some(api) = Api::new().await else { return };
    let (_, a) = api.org(&["apps:read", "apps:write"]).await;
    let (_, b) = api.org(&["apps:read", "apps:write"]).await;
    let (_, app) = api
        .call(Method::PUT, "/v1/apps/board", &a, Value::Null)
        .await;
    let app_id = app["app_id"].as_str().unwrap();
    let catalog: Value = serde_json::from_str(CATALOG).unwrap();
    let body = json!({ "catalog": catalog });

    let (status, created) = api
        .call(Method::POST, "/v1/apps/board/revisions", &a, body.clone())
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let hash = created["compose_hash"].as_str().unwrap();
    let (status, again) = api
        .call(Method::POST, "/v1/apps/board/revisions", &a, body.clone())
        .await;
    assert_eq!(
        (status, again["compose_hash"].as_str()),
        (StatusCode::OK, Some(hash))
    );

    let (status, read) = api
        .call(
            Method::GET,
            &format!("/v1/apps/board/revisions/{hash}"),
            &a,
            Value::Null,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let init_data = read["init_data"].as_str().unwrap();
    assert_eq!(alpha_core::compose_hash(init_data).to_string(), hash);
    assert!(init_data.contains(&format!("\"app_id\" = \"{app_id}\"")));
    assert!(
        read["pod"]
            .as_str()
            .unwrap()
            .contains("board.app.alphacompute.cc")
    );
    assert_eq!(read["shape"], catalog["entry"]["resources"]);

    let (status, _) = api
        .call(Method::POST, "/v1/apps/board/revisions", &b, body.clone())
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = api
        .call(
            Method::GET,
            &format!("/v1/apps/board/revisions/{hash}"),
            &b,
            Value::Null,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let mut tampered = catalog.clone();
    tampered["entry"]["title"] = json!("Something else");
    let (status, refused) = api
        .call(
            Method::POST,
            "/v1/apps/board/revisions",
            &a,
            json!({ "catalog": tampered }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        refused.to_string().contains("signature_invalid"),
        "{refused}"
    );

    // The same init-data stored with another pod is another entry, not a replay.
    sqlx::query("update revisions set pod = 'other'")
        .execute(&api.1)
        .await
        .unwrap();
    let (status, _) = api
        .call(Method::POST, "/v1/apps/board/revisions", &a, body.clone())
        .await;
    assert_eq!(status, StatusCode::CONFLICT);

    *api.2.lock().unwrap() = platform_document(&api.3, 1, json!({}));
    let (status, _) = api
        .call(Method::POST, "/v1/apps/board/revisions", &a, body)
        .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn a_create_waits_for_an_open_create_with_the_same_links_in_any_order() {
    let Some(api) = Api::new().await else { return };
    let link = |id: &str| json!({ "issuer": "rafay:console.example", "external_id": id });
    // A create of [a, b] still open holds the lock named after its lowest link.
    let mut open = api.1.begin().await.unwrap();
    sqlx::query("select pg_advisory_xact_lock(hashtext($1), hashtext($2))")
        .bind("rafay:console.example")
        .bind("org-a")
        .execute(&mut *open)
        .await
        .unwrap();
    let reordered = json!({
        "name": "Acme", "owner_email": "owner@acme.test", "links": [link("org-b"), link("org-a")],
    });
    let router = api.0.clone();
    let waiting = tokio::spawn(async move {
        let request = Request::builder()
            .method(Method::POST)
            .uri("/v1/orgs")
            .header("authorization", format!("Bearer {OPERATOR}"))
            .header("content-type", "application/json")
            .body(Body::from(reordered.to_string()))
            .unwrap();
        router.oneshot(request).await.unwrap().status()
    });
    // The request waits on exactly that lock, not on anything else.
    let mut queued = false;
    for _ in 0..50 {
        queued = sqlx::query_scalar(
            "select exists (select 1 from pg_locks where locktype = 'advisory' and not granted \
               and classid = hashtext($1)::oid and objid = hashtext($2)::oid and objsubid = 2)",
        )
        .bind("rafay:console.example")
        .bind("org-a")
        .fetch_one(&api.1)
        .await
        .unwrap();
        if queued {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(queued && !waiting.is_finished());
    open.commit().await.unwrap();
    assert_eq!(waiting.await.unwrap(), StatusCode::CREATED);
}

#[tokio::test]
async fn an_approve_ticket_reads_as_the_signer_page_expects_and_closes_once() {
    let Some(api) = Api::new().await else { return };
    let (org, a) = api.org(&["apps:write"]).await;
    api.call(Method::PUT, "/v1/apps/board", &a, Value::Null)
        .await;
    let catalog: Value = serde_json::from_str(CATALOG).unwrap();
    let (status, created) = api
        .call(
            Method::POST,
            "/v1/apps/board/revisions",
            &a,
            json!({ "catalog": catalog }),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let ticket = created["ticket"].as_str().unwrap();
    assert_eq!(ticket.len(), 43);
    assert_eq!(
        created["approval_url"],
        format!("https://sign.example/approve#{ticket}")
    );
    let code = created["code"].as_str().unwrap();
    assert!(
        code.len() == 8
            && code
                .bytes()
                .all(|b| b"0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(&b)),
        "{code}"
    );
    let (status, found) = api
        .call(
            Method::GET,
            &format!("/v1/tickets/by-code/{code}"),
            "",
            Value::Null,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(found, json!({ "kind": "approve", "ticket": ticket }));
    let mut limited = None;
    // Enough lookups that, even split across two one-second windows, one window exceeds 20.
    for _ in 0..60 {
        let (status, _) = api
            .call(Method::GET, "/v1/tickets/by-code/00000000", "", Value::Null)
            .await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            limited = Some(status);
            break;
        }
    }
    assert!(limited.is_some(), "code lookups are not limited");

    let read = api.read_ticket(ticket).await;
    for key in ["expires_at", "server_time"] {
        assert!(read[key].as_str().unwrap().ends_with('Z'), "{read}");
    }
    let app_id = read["app_id"].clone();
    let mut fixed = read.clone();
    for key in ["expires_at", "server_time", "app_id"] {
        fixed.as_object_mut().unwrap().remove(key);
    }
    assert_eq!(
        fixed,
        json!({
            "kind": "approve", "state": "open", "org_id": org, "org_name": "Acme",
            "credentials": [], "slug": "board", "compose_hash": created["compose_hash"],
            "title": catalog["entry"]["title"],
            "catalog_template_sha256": catalog["entry"]["template_sha256"],
            "secrets": [], "predecessor": null,
        })
    );
    assert!(app_id.is_string());

    let decline = format!("/v1/tickets/{ticket}/decline");
    let (status, _) = api.call(Method::POST, &decline, "", Value::Null).await;
    assert_eq!(status, StatusCode::OK);
    let (status, closed) = api.call(Method::POST, &decline, "", Value::Null).await;
    assert_eq!(
        (status, &closed["error"]["code"]),
        (StatusCode::CONFLICT, &json!("ticket_closed"))
    );
    let read = api.read_ticket(ticket).await;
    assert_eq!(read["state"], "declined");
    let (status, missing) = api
        .call(Method::GET, "/v1/tickets/unknown", "", Value::Null)
        .await;
    assert_eq!(
        (status, &missing["error"]["code"]),
        (StatusCode::NOT_FOUND, &json!("ticket_not_found"))
    );
}

fn with(claims: &Value, key: &str, value: Value) -> Value {
    let mut claims = claims.clone();
    claims[key] = value;
    claims
}

/// Opens a claim ticket of `org` as the operator and answers it.
async fn claim_ticket(api: &Api, org: &str) -> String {
    let (status, created) = api
        .call(
            Method::POST,
            &format!("/v1/orgs/{org}/tickets"),
            OPERATOR,
            Value::Null,
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let ticket = created["ticket"].as_str().unwrap().to_owned();
    assert_eq!(
        created["url"],
        format!("https://sign.example/claim#{ticket}")
    );
    ticket
}

#[tokio::test]
async fn only_the_owners_verified_sign_in_binds_a_session_to_a_claim_ticket() {
    let Some(api) = Api::new().await else { return };
    let (org, deploy) = api.org(&["apps:write"]).await;
    let (_, other_admin) = api.org(&["org:admin"]).await;
    for bearer in [deploy.as_str(), other_admin.as_str()] {
        let (status, _) = api
            .call(
                Method::POST,
                &format!("/v1/orgs/{org}/tickets"),
                bearer,
                Value::Null,
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
    let ticket = claim_ticket(&api, &org).await;
    let read = api.read_ticket(&ticket).await;
    assert_eq!(
        (&read["kind"], &read["rooted"], &read["owner_email"]),
        (&json!("claim"), &json!(false), &json!("owner@acme.test"))
    );
    assert!(read.get("principal_id").is_none(), "{read}");

    let path = format!("/v1/tickets/{ticket}/session");
    let request = |code: &str| json!({ "code": code, "code_verifier": "verifier", "redirect_uri": "https://sign.example/claim" });
    let exp = 4_000_000_000u64;
    let owner = json!({
        "iss": ISSUER, "aud": "signer", "exp": exp, "sub": "owner",
        "email": "Owner@acme.test", "email_verified": true,
    });
    let refused = [
        ("bad", owner.clone()),
        ("good", with(&owner, "email_verified", json!(false))),
        ("good", with(&owner, "aud", json!("other"))),
        ("good", with(&owner, "aud", json!(["signer", "other"]))),
        ("good", with(&owner, "iss", json!("https://other.example"))),
        ("good", with(&owner, "exp", json!(1))),
        ("good", with(&owner, "email", json!("someone@acme.test"))),
    ];
    for (code, claims) in refused {
        *api.4.lock().unwrap() = claims.clone();
        let (status, reply) = api.call(Method::POST, &path, "", request(code)).await;
        assert_eq!(
            (status, &reply["error"]["code"]),
            (StatusCode::FORBIDDEN, &json!("session_refused")),
            "{code} {claims}"
        );
    }

    *api.4.lock().unwrap() = owner.clone();
    let (status, bound) = api.call(Method::POST, &path, "", request("good")).await;
    assert_eq!(status, StatusCode::OK, "{bound}");
    let session = bound["session"].as_str().unwrap();
    assert_eq!(
        BASE64URL_NOPAD.decode(session.as_bytes()).unwrap().len(),
        32
    );
    let stored: Vec<u8> =
        sqlx::query_scalar("select session_sha256 from tickets where ticket = $1")
            .bind(&ticket)
            .fetch_one(&api.1)
            .await
            .unwrap();
    assert_eq!(stored, Sha256::digest(session.as_bytes()).as_slice());

    // The owner is now that principal: the same address from another account is refused.
    *api.4.lock().unwrap() = with(&owner, "sub", json!("someone-else"));
    let (status, _) = api.call(Method::POST, &path, "", request("good")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    *api.4.lock().unwrap() = owner;
    let (status, again) = api.call(Method::POST, &path, "", request("good")).await;
    assert_eq!(
        (status, &again["principal_id"]),
        (StatusCode::OK, &bound["principal_id"])
    );
    let renewed = again["session"].as_str().unwrap();
    let stored: Vec<u8> =
        sqlx::query_scalar("select session_sha256 from tickets where ticket = $1")
            .bind(&ticket)
            .fetch_one(&api.1)
            .await
            .unwrap();
    assert!(renewed != session && stored == Sha256::digest(renewed.as_bytes()).as_slice());

    // A disabled Organization binds no owner.
    sqlx::query("update organizations set disabled_at = now()")
        .execute(&api.1)
        .await
        .unwrap();
    let (status, _) = api.call(Method::POST, &path, "", request("good")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    sqlx::query("update organizations set disabled_at = null")
        .execute(&api.1)
        .await
        .unwrap();

    sqlx::query("update tickets set expires_at = now() - interval '1 second'")
        .execute(&api.1)
        .await
        .unwrap();
    let read = api.read_ticket(&ticket).await;
    assert_eq!(read["state"], "expired");
    let (status, expired) = api.call(Method::POST, &path, "", request("good")).await;
    assert_eq!(
        (status, &expired["error"]["code"]),
        (StatusCode::GONE, &json!("ticket_expired"))
    );
}

fn spki(key: &SigningKey) -> String {
    use ed25519_dalek::pkcs8::EncodePublicKey;
    BASE64URL_NOPAD.encode(key.verifying_key().to_public_key_der().unwrap().as_bytes())
}

/// A key registration: self-signed for `org`'s root when `signer` is `None`, else signed by the
/// roster key `signer`.
fn registration(
    key: &SigningKey,
    org: &str,
    principal: &Value,
    signer: Option<(&str, &SigningKey)>,
) -> Value {
    let issued_at = alpha_kms::rfc3339(SystemTime::now());
    let signed = match signer {
        None => alpha_client::sign_self(
            alpha_core::context::ORG_ROOT_KEY,
            json!({ "org_id": org, "principal_id": principal, "public_key": spki(key),
                    "label": "passkey-1", "issued_at": issued_at }),
            key,
        ),
        Some((key_id, signer)) => alpha_client::sign(
            alpha_core::context::PRINCIPAL_KEY,
            json!({ "principal_id": principal, "public_key": spki(key), "label": "passkey-2",
                    "issued_at": issued_at }),
            key_id.parse().unwrap(),
            signer,
        ),
    };
    json!(signed.unwrap())
}

#[tokio::test]
async fn only_the_owners_session_roots_and_only_roster_keys_of_the_organization_add_keys() {
    let Some(api) = Api::start(true).await else {
        return;
    };
    let (org, admin) = api.org(&["org:admin"]).await;
    let ticket = claim_ticket(&api, &org).await;
    *api.4.lock().unwrap() = json!({
        "iss": ISSUER, "aud": "signer", "exp": 4_000_000_000u64, "sub": "owner",
        "email": "owner@acme.test", "email_verified": true,
    });
    let (_, bound) = api
        .call(
            Method::POST,
            &format!("/v1/tickets/{ticket}/session"),
            "",
            json!({ "code": "good", "code_verifier": "verifier",
                    "redirect_uri": "https://sign.example/claim" }),
        )
        .await;
    let session = bound["session"].as_str().unwrap();
    let owner = bound["principal_id"].clone();
    let root = SigningKey::from_bytes(&[21; 32]);
    let root_body = json!({ "credential_id": "cred-1",
                            "registration": registration(&root, &org, &owner, None) });
    let relay = |op: &str| format!("/v1/tickets/{ticket}/kms/{op}");
    let code = |reply: &Value| reply["error"]["code"].clone();

    // A ticket alone never adds a key: not without the session, nor as a self-signed key step.
    let wrong = "x".repeat(43);
    for headers in [&[][..], &[("alpha-claim-session", wrong.as_str())][..]] {
        let (status, refused) = api
            .call_with(Method::POST, &relay("root"), "", headers, root_body.clone())
            .await;
        assert_eq!(
            (status, code(&refused)),
            (StatusCode::FORBIDDEN, json!("session_refused"))
        );
    }
    let (status, _) = api
        .call(Method::POST, &relay("key"), &admin, root_body.clone())
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let session_header = [("alpha-claim-session", session)];
    let (status, rooted) = api
        .call_with(
            Method::POST,
            &relay("root"),
            "",
            &session_header,
            root_body.clone(),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{rooted}");
    assert!(rooted["receipt"].is_object());
    let root_id = rooted["id"].as_str().unwrap().to_owned();
    let (status, again) = api
        .call_with(Method::POST, &relay("root"), "", &session_header, root_body)
        .await;
    assert_eq!(
        (status, code(&again)),
        (StatusCode::CONFLICT, json!("ticket_closed"))
    );
    let read = api.read_ticket(&ticket).await;
    assert_eq!(
        read["credentials"],
        json!([{ "credential_id": "cred-1", "key_id": root_id }])
    );

    // Another Organization's roster key, and a bearer with a forged signature, add nothing here.
    let (kms_url, _) = api.5.as_ref().unwrap();
    let foreign = SigningKey::from_bytes(&[22; 32]);
    let foreign_org = Uuid::now_v7().to_string();
    let (status, foreign_root) = send_kms(
        kms_url,
        "/v1/keys",
        registration(&foreign, &foreign_org, &json!(Uuid::now_v7()), None),
    )
    .await;
    assert_eq!(status, 200, "{foreign_root}");
    let second = SigningKey::from_bytes(&[23; 32]);
    let by_foreign = registration(
        &second,
        &org,
        &owner,
        Some((foreign_root["id"].as_str().unwrap(), &foreign)),
    );
    let forged = registration(&second, &org, &owner, Some((&root_id, &foreign)));
    for (body, expected) in [
        (by_foreign, "upstream_invalid"),
        (forged, "signature_invalid"),
    ] {
        let (status, refused) = api
            .call(
                Method::POST,
                &relay("key"),
                &admin,
                json!({ "credential_id": "cred-2", "registration": body }),
            )
            .await;
        assert_eq!(code(&refused), json!(expected), "{status}");
    }
    let read = api.read_ticket(&ticket).await;
    assert_eq!(
        (
            read["state"].clone(),
            read["credentials"].as_array().unwrap().len()
        ),
        (json!("open"), 1)
    );

    // The foreign key step registered `second` under the other Organization at the KMS.
    let own = SigningKey::from_bytes(&[25; 32]);
    let by_root = registration(&own, &org, &owner, Some((&root_id, &root)));
    let added = json!({ "credential_id": "cred-2", "registration": by_root });
    let (status, reply) = api
        .call(Method::POST, &relay("key"), "", added.clone())
        .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let (status, closed) = api.call(Method::POST, &relay("key"), "", added).await;
    assert_eq!(
        (status, code(&closed)),
        (StatusCode::CONFLICT, json!("ticket_closed"))
    );
    let read = api.read_ticket(&ticket).await;
    assert_eq!(
        (
            read["state"].clone(),
            read["credentials"].as_array().unwrap().len()
        ),
        (json!("done"), 2)
    );

    // A rooted Organization's claim ticket names the holder of the key it adds and takes no root.
    let rooted_ticket = claim_ticket(&api, &org).await;
    let read = api.read_ticket(&rooted_ticket).await;
    assert_eq!(read["rooted"], true);
    assert!(
        read["principal_id"].is_string() && read.get("owner_email").is_none(),
        "{read}"
    );
    sqlx::query("update tickets set expires_at = now() where ticket = $1")
        .bind(&rooted_ticket)
        .execute(&api.1)
        .await
        .unwrap();
    let third = SigningKey::from_bytes(&[24; 32]);
    let body = json!({ "credential_id": "cred-3",
                       "registration": registration(&third, &org, &owner, Some((&root_id, &root))) });
    let (status, expired) = api
        .call(
            Method::POST,
            &format!("/v1/tickets/{rooted_ticket}/kms/key"),
            "",
            body,
        )
        .await;
    assert_eq!(
        (status, code(&expired)),
        (StatusCode::GONE, json!("ticket_expired"))
    );
}

/// A request straight to the KMS, as another Organization's own CLI would make it.
async fn send_kms(url: &str, path: &str, body: Value) -> (u16, Value) {
    let reply = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
        .post(format!("{url}{path}"))
        .json(&body)
        .send()
        .await
        .unwrap();
    (
        reply.status().as_u16(),
        reply.json().await.unwrap_or(Value::Null),
    )
}
