#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use axum::http::StatusCode;
use common::*;
use serde_json::json;

const HISTORY: &str = "https://slack.com/api/conversations.history?channel=C1&limit=20";

#[tokio::test]
async fn a_member_connects_slack_and_an_instance_reads_history_without_seeing_a_token() {
    let Some(h) = harness().await else { return };
    let (reply, consent) = h.connect_as("slack", MEMBER, "T1:U1", "ann @ Acme").await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    let id = id_of(&reply);
    assert_eq!(
        reply.body,
        json!({ "id": id.to_string(), "provider": "slack", "account": "ann @ Acme" })
    );
    let exchange = h.fake.with(|f| {
        f.requests
            .iter()
            .find(|(p, _)| p == SLACK_TOKEN)
            .cloned()
            .unwrap()
            .1
    });
    assert_eq!(exchange["client_id"], SLACK_CLIENT_ID);
    assert!(!exchange.contains_key("client_secret"), "{exchange:?}");
    assert_eq!(exchange["code_verifier"].len(), 43);

    let reply = h.proxy(&read(id, HISTORY)).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.bytes, SLACK_HISTORY.as_bytes());

    let (seen, issued) = h.fake.with(|f| (f.data.clone(), f.access.clone()));
    let [seen] = &seen[..] else {
        panic!("{seen:?}")
    };
    assert_eq!(seen.method, "GET");
    assert_eq!(seen.host, "slack.com");
    assert_eq!(seen.path, "/api/conversations.history");
    assert_eq!(seen.query["channel"], "C1");
    assert_eq!(seen.query["limit"], "20");
    let token = bearer_of(&seen.headers);
    assert!(token.starts_with("xoxp-") && issued.contains(&token));
    assert_ne!(token, consent.access_token);
}
