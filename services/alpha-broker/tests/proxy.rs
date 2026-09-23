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

#[tokio::test]
async fn an_instance_reads_drive_through_the_proxy_and_never_sees_a_token() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected().await;

    let reply = h
        .proxy(&read(
            id,
            "https://www.googleapis.com/drive/v3/files?pageSize=10",
        ))
        .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.bytes, LISTING.as_bytes());
    assert_eq!(reply.content_type.as_deref(), Some("application/json"));

    let (seen, access) = h.google.with(|f| (f.data.clone(), f.access.clone()));
    let [seen] = &seen[..] else {
        panic!("{seen:?}")
    };
    assert_eq!(seen.path, "/drive/v3/files");
    assert_eq!(seen.query["pageSize"], "10");
    let token = seen
        .authorization
        .as_deref()
        .unwrap()
        .strip_prefix("Bearer ")
        .unwrap();
    assert!(access.iter().any(|t| t == token));
}
