#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::sync::Arc;

use alpha_control::{AppState, router};
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
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

struct Api(axum::Router, PgPool);

impl Api {
    async fn new() -> Option<Self> {
        let pool = fresh_database().await?;
        let state = Arc::new(AppState {
            pool: pool.clone(),
            operator_token_sha256: Sha256::digest(OPERATOR).into(),
        });
        Some(Api(router(state), pool))
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
    sqlx::query("insert into api_keys (id, token_sha256, scopes) values ($1, $2, '{onboard}')")
        .bind(Uuid::now_v7())
        .bind(Sha256::digest(onboard).as_slice())
        .execute(&api.1)
        .await
        .unwrap();
    let escalate = json!({ "name": "Acme", "owner_email": "o@acme.test", "deploy_key": { "scopes": ["onboard"] } });
    let (status, _) = api.call(Method::POST, "/v1/orgs", onboard, escalate).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
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
    let (status, _) = api.call(Method::POST, "/v1/orgs", onboard, linked).await;
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
