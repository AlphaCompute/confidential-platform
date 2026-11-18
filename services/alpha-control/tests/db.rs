#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::sync::{Arc, Mutex};

use alpha_control::{AppState, router};
use alpha_core::{InitData, InitDataError, KataPolicy};
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;
use uuid::Uuid;

const OPERATOR: &str = "operator-token";

/// A fresh database per test, migrated; `None` when `DATABASE_URL` is unset.
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
    alpha_control::migrate(&pool).await.unwrap();
    Some(pool)
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

/// A platform document of `version` that names the catalog test key, signed by `release`.
fn platform_document(release: &SigningKey, version: u64) -> Value {
    let catalog: Value = serde_json::from_str(CATALOG).unwrap();
    let expected: Value = serde_json::from_str(CATALOG_EXPECTED).unwrap();
    let document = json!({
        "version": version, "issued_at": "2026-11-01T00:00:00Z",
        "policy": { "tcb_statuses": ["UpToDate"], "tolerated_advisories": [] },
        "reference_values": [], "kms_ca_pem": "", "kms_revisions": [],
        "catalog_key": expected["catalog_key"],
        "kata_policy": kata_policy(catalog["template"].as_str().unwrap()),
    });
    serde_json::to_value(alpha_client::platform::sign(document, release).unwrap()).unwrap()
}

/// The router, its database, and the platform document its URL serves.
struct Api(axum::Router, PgPool, Arc<Mutex<Value>>, SigningKey);

impl Api {
    async fn new() -> Option<Self> {
        let pool = fresh_database().await?;
        let release = SigningKey::from_bytes(&[7; 32]);
        let served = Arc::new(Mutex::new(platform_document(&release, 2)));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/platform.json", listener.local_addr().unwrap());
        let document = served.clone();
        let host = axum::Router::new().route(
            "/platform.json",
            axum::routing::get(move || async move { axum::Json(document.lock().unwrap().clone()) }),
        );
        tokio::spawn(async move { axum::serve(listener, host).await });
        let state = Arc::new(AppState {
            pool: pool.clone(),
            operator_token_sha256: Sha256::digest(OPERATOR).into(),
            platform_document_url: url,
            release_keys: release.verifying_key().into(),
        });
        Some(Api(router(state), pool, served, release))
    }

    async fn call(
        &self,
        method: Method,
        uri: &str,
        bearer: &str,
        body: Value,
    ) -> (StatusCode, Value) {
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", format!("Bearer {bearer}"))
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
    assert_eq!(
        (status, &retry["org_id"]),
        (StatusCode::OK, &first["org_id"])
    );
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

    *api.2.lock().unwrap() = platform_document(&api.3, 1);
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
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(!waiting.is_finished());
    open.commit().await.unwrap();
    assert_eq!(waiting.await.unwrap(), StatusCode::CREATED);
}
