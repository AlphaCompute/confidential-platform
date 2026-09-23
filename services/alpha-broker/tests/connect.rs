#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use alpha_broker::store;
use axum::http::StatusCode;
use common::*;
use serde_json::json;

#[tokio::test]
async fn a_member_connects_google_and_the_stored_token_is_sealed() {
    let Some(h) = harness().await else { return };

    let (reply, consent) = h.connect(MEMBER, EMAIL).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    let id = id_of(&reply);
    assert_eq!(
        reply.body,
        json!({ "id": id.to_string(), "provider": "google", "account": EMAIL })
    );

    let listed = h
        .call("GET", &format!("/connections?member={MEMBER}"), None)
        .await;
    assert_eq!(listed.status, StatusCode::OK);
    assert_eq!(
        listed.body,
        json!({ "connections": [
            { "id": id.to_string(), "provider": "google", "account": EMAIL, "dead": false }
        ] })
    );

    let blob = h.stored_token(id).await.unwrap();
    let token = consent.refresh_token.as_bytes();
    assert!(!blob.windows(token.len()).any(|w| w == token));
    assert_eq!(
        store::open(&KEY, id.as_bytes(), &blob).unwrap().as_slice(),
        token
    );
    assert!(store::open(&KEY, uuid::Uuid::now_v7().as_bytes(), &blob).is_none());

    let pending: i64 = sqlx::query_scalar("select count(*) from pending_connects")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(pending, 0);
}
