//! `alpha request` against copies serving real Instance leaves: the bearer arrives only at a
//! leaf of the named App issued by the platform's CA.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use std::sync::{Arc, Mutex};

use alpha_cli::deploy::Shroud;
use alpha_cli::request::{Call, run, send_to};
use alpha_core::{AppId, ComposeHash, compose_hash};
use axum::http::HeaderMap;
use axum::routing::{get, put};
use common::Ca;
use reqwest::Method;
use serde_json::{Value, json};

const BEARER: &str = "tenant-admin-bearer";

/// Every `PUT /admin/capacity` as `authorization body`.
type Seen = Arc<Mutex<Vec<String>>>;

/// A copy of `app` at `hash` whose one route records what it receives.
async fn copy(ca: &Ca, app: AppId, hash: ComposeHash) -> (String, Seen) {
    let seen = Seen::default();
    let recorded = seen.clone();
    let router = axum::Router::new().route(
        "/admin/capacity",
        put(move |headers: HeaderMap, body: String| async move {
            let auth = headers
                .get("authorization")
                .map(|v| v.to_str().unwrap().to_owned())
                .unwrap_or_default();
            recorded.lock().unwrap().push(format!("{auth} {body}"));
            axum::Json(json!({ "ok": true }))
        }),
    );
    (ca.instance_serving(app, hash, router).await, seen)
}

/// shroud-go listing `copies` as `(id, url)` of the App's one Revision.
async fn shroud(app: AppId, hash: ComposeHash, copies: &[(&str, &str)]) -> Shroud {
    let list = json!({ "instances": copies.iter().map(|(id, url)| json!({
        "id": id,
        "app_id": app.to_string(),
        "compose_hash": hash.to_string(),
        "url": url,
    })).collect::<Vec<_>>() });
    let router = axum::Router::new().route(
        &format!("/v1/apps/{app}/instances"),
        get(move || async move { axum::Json(list) }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, router).await });
    Shroud {
        url,
        api_key: "sk_test_organization".into(),
    }
}

fn call(body: &Value) -> Call<'_> {
    Call {
        method: Method::PUT,
        path: "/admin/capacity",
        bearer: BEARER,
        body: Some(body),
    }
}

#[tokio::test]
async fn the_bearer_reaches_a_leaf_of_the_named_app() {
    let ca = Ca::new();
    let app = AppId::mint();
    let hash = compose_hash("{\"name\":\"worker\"}");
    let (url, seen) = copy(&ca, app, hash).await;
    let body = json!({ "k": 3 });

    let reply = send_to(&url, hash, app, &ca.pem(), &call(&body))
        .await
        .unwrap();

    assert_eq!(
        reply,
        json!({ "compose_hash": hash.to_string(), "status": 200, "body": { "ok": true } })
    );
    assert_eq!(*seen.lock().unwrap(), [format!("Bearer {BEARER} {body}")]);
}

#[tokio::test]
async fn a_leaf_of_another_app_never_sees_the_bearer() {
    let ca = Ca::new();
    let (app, other) = (AppId::mint(), AppId::mint());
    let hash = compose_hash("{\"name\":\"worker\"}");
    let (url, seen) = copy(&ca, other, hash).await;

    let message = send_to(&url, hash, app, &ca.pem(), &call(&json!({})))
        .await
        .unwrap_err();

    assert!(message.contains(&other.to_string()), "{message}");
    assert!(message.contains(&app.to_string()), "{message}");
    assert!(seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_leaf_from_another_ca_never_sees_the_bearer() {
    let app = AppId::mint();
    let hash = compose_hash("{\"name\":\"worker\"}");
    let (url, seen) = copy(&Ca::new(), app, hash).await;

    let message = send_to(&url, hash, app, &Ca::new().pem(), &call(&json!({})))
        .await
        .unwrap_err();

    assert!(message.contains("no Instance leaf"), "{message}");
    assert!(seen.lock().unwrap().is_empty());
}

const FIRST: &str = "0199a1b2-0000-7000-8000-000000000001";
const SECOND: &str = "0199a1b2-0000-7000-8000-000000000002";
const FOREIGN: &str = "0199a1b2-0000-7000-8000-000000000003";

#[tokio::test]
async fn all_reaches_every_copy_and_reports_each() {
    let ca = Ca::new();
    let app = AppId::mint();
    let hash = compose_hash("{\"name\":\"worker\"}");
    let (first, first_seen) = copy(&ca, app, hash).await;
    let (second, second_seen) = copy(&ca, app, hash).await;
    let (foreign, foreign_seen) = copy(&ca, AppId::mint(), hash).await;
    let shroud = shroud(
        app,
        hash,
        &[(FIRST, &first), (FOREIGN, &foreign), (SECOND, &second)],
    )
    .await;
    let body = json!({ "k": 2 });

    let (out, failed) = run(&shroud, app, None, &ca.pem(), &call(&body))
        .await
        .unwrap();

    assert!(failed);

    let responses = out["responses"].as_array().unwrap();
    assert_eq!(responses.len(), 3);
    assert_eq!(responses[0]["instance"], FIRST);
    assert_eq!(responses[0]["status"], 200);
    assert_eq!(responses[1]["instance"], FOREIGN);
    assert!(responses[1]["error"].is_string(), "{out}");
    assert_eq!(responses[2]["instance"], SECOND);
    assert_eq!(responses[2]["body"], json!({ "ok": true }));
    let once = [format!("Bearer {BEARER} {body}")];
    assert_eq!(*first_seen.lock().unwrap(), once);
    assert_eq!(*second_seen.lock().unwrap(), once);
    assert!(foreign_seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn an_unlisted_copy_is_refused_before_any_connection() {
    let ca = Ca::new();
    let app = AppId::mint();
    let hash = compose_hash("{\"name\":\"worker\"}");
    let (url, seen) = copy(&ca, app, hash).await;
    let shroud = shroud(app, hash, &[(FIRST, &url)]).await;

    let message = run(
        &shroud,
        app,
        Some(SECOND.parse().unwrap()),
        &ca.pem(),
        &call(&json!({})),
    )
    .await
    .unwrap_err();

    assert!(message.contains(SECOND), "{message}");
    assert!(seen.lock().unwrap().is_empty());
}
