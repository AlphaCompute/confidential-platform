#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use std::time::Duration;

use axum::http::StatusCode;
use common::*;
use serde_json::json;

const FILE: &str = "https://api.figma.com/v1/files/AbC123";

#[tokio::test]
async fn a_member_connects_figma_with_basic_auth_and_an_instance_reads_a_file() {
    let Some(h) = harness().await else { return };
    let query = h.start("figma", MEMBER).await;
    assert_eq!(
        query["scope"],
        "current_user:read file_content:read file_metadata:read file_comments:read folders:read"
    );

    let (reply, _) = h.connect_as("figma", MEMBER, "1234567", EMAIL).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    let id = id_of(&reply);
    assert_eq!(reply.body["account"], EMAIL);
    let subject: String = sqlx::query_scalar("select subject from connections where id = $1")
        .bind(id)
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(subject, "1234567");
    let exchange = h.fake.with(|f| f.form(FIGMA_TOKEN));
    assert!(!exchange.contains_key("client_id") && !exchange.contains_key("client_secret"));

    let stored = h.stored_token(id).await;
    let reply = h.proxy(&read(id, FILE)).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.json(), json!({ "path": "/v1/files/AbC123" }));
    assert_eq!(h.fake.with(|f| f.hits(FIGMA_REFRESH)), 1);

    h.state.tokens.lock().clear();
    let again = h.proxy(&read(id, FILE)).await;
    assert_eq!(again.status, StatusCode::OK);
    assert_eq!(h.fake.with(|f| f.hits(FIGMA_REFRESH)), 2);
    assert_eq!(h.stored_token(id).await, stored);
}

#[tokio::test]
async fn each_figma_read_is_forwarded_and_anything_else_is_refused() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected_to("figma").await;
    for path in [
        "/v2/teams/123/folders",
        "/v2/folders/456/folders",
        "/v2/folders/456/files",
        "/v1/files/AbC123",
        "/v1/files/AbC123/nodes?ids=1:2",
        "/v1/images/AbC123?ids=1:2&format=png",
        "/v1/files/AbC123/comments",
    ] {
        let reply = h
            .proxy(&read(id, &format!("https://api.figma.com{path}")))
            .await;
        assert_eq!(reply.status, StatusCode::OK, "{path}");
        let seen = h.fake.with(|f| f.data.last().cloned().unwrap());
        assert_eq!(seen.host, "api.figma.com");
        assert_eq!(Some(seen.path.as_str()), path.split('?').next());
    }
    let me = h.proxy(&read(id, "https://api.figma.com/v1/me")).await;
    assert_eq!(me.status, StatusCode::OK);
    assert_eq!(me.json()["email"], EMAIL);

    let before = h.fake.with(|f| (f.data.len(), f.requests.len()));
    for url in [
        "https://api.figma.com/v1/teams/123/projects",
        "https://api.figma.com/v1/projects/789/files",
        "https://api.figma.com/v1/files/AbC123/versions",
        "https://www.figma.com/file/AbC123",
        "https://api.figma.com:8443/v1/files/AbC123",
    ] {
        let reply = h.proxy(&read(id, url)).await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN, "{url}");
        assert_eq!(reply.code(), "not_allowed");
    }
    let mut comment = read(id, "https://api.figma.com/v1/files/AbC123/comments");
    comment["method"] = json!("POST");
    comment["body"] = json!({ "message": "x" });
    let reply = h.proxy(&comment).await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(h.fake.with(|f| (f.data.len(), f.requests.len())), before);
}

#[tokio::test]
async fn a_figma_id_of_256_characters_is_accepted_and_257_refused() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected_to("figma").await;
    let file = |n| {
        read(
            id,
            &format!("https://api.figma.com/v1/files/{}", "k".repeat(n)),
        )
    };
    assert_eq!(h.proxy(&file(256)).await.status, StatusCode::OK);
    let refused = h.proxy(&file(257)).await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    assert_eq!(h.fake.with(|f| f.data.len()), 1);
}

#[tokio::test]
async fn two_calls_on_an_expired_figma_token_refresh_once() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected_to("figma").await;
    h.fake
        .with(|f| f.refresh_delay = Duration::from_millis(300));
    let body = read(id, FILE);
    let (a, b) = tokio::join!(h.proxy(&body), h.proxy(&body));
    assert_eq!((a.status, b.status), (StatusCode::OK, StatusCode::OK));
    assert_eq!(h.fake.with(|f| f.hits(FIGMA_REFRESH)), 1);
}

#[tokio::test]
async fn an_invalid_grant_marks_a_figma_connection_dead() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected_to("figma").await;
    h.fake.with(|f| {
        f.refresh_reply = Some((StatusCode::BAD_REQUEST, json!({ "error": "invalid_grant" })))
    });
    let reply = h.proxy(&read(id, FILE)).await;
    assert_eq!(reply.status, StatusCode::CONFLICT);
    assert_eq!(reply.code(), "reconnect_required");
    let listed = h
        .call("GET", &format!("/connections?member={MEMBER}"), None)
        .await;
    assert_eq!(listed.body["connections"][0]["dead"], true);
}

#[tokio::test]
async fn a_refresh_error_that_is_not_a_string_is_upstream_and_keeps_the_connection() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected_to("figma").await;
    h.fake.with(|f| {
        f.refresh_reply = Some((
            StatusCode::BAD_REQUEST,
            json!({ "error": true, "message": "x" }),
        ))
    });
    let reply = h.proxy(&read(id, FILE)).await;
    assert_eq!(reply.status, StatusCode::BAD_GATEWAY);
    assert_eq!(reply.code(), "upstream");
    let listed = h
        .call("GET", &format!("/connections?member={MEMBER}"), None)
        .await;
    assert_eq!(listed.body["connections"][0]["dead"], false);
}

#[tokio::test]
async fn a_refresh_without_a_lifetime_is_cached_for_an_hour() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected_to("figma").await;
    h.fake.with(|f| f.omit_expires_in = true);
    for _ in 0..2 {
        assert_eq!(h.proxy(&read(id, FILE)).await.status, StatusCode::OK);
    }
    assert_eq!(h.fake.with(|f| f.hits(FIGMA_REFRESH)), 1);
}

#[tokio::test]
async fn disconnecting_figma_revokes_only_locally() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected_to("figma").await;
    let before = h.fake.with(|f| f.requests.len());
    let reply = h
        .call(
            "DELETE",
            &format!("/connections/{id}?member={MEMBER}"),
            None,
        )
        .await;
    assert_eq!(reply.status, StatusCode::NO_CONTENT);
    assert_eq!(h.fake.with(|f| f.requests.len()), before);
    assert_eq!(h.stored_token(id).await, None);
    let reply = h.proxy(&read(id, FILE)).await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
}
