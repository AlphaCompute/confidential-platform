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

const LIST_FOLDER: &str = "https://api.dropboxapi.com/2/files/list_folder";
const PATH_ROOT: &str = r#"{".tag": "root", "root": "42"}"#;

#[tokio::test]
async fn a_member_connects_dropbox_and_an_instance_lists_a_folder_without_seeing_a_token() {
    let Some(h) = harness().await else { return };
    let (reply, consent) = h.connect_to("dropbox", MEMBER, EMAIL).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    let id = id_of(&reply);
    assert_eq!(
        reply.body,
        json!({ "id": id.to_string(), "provider": "dropbox", "account": EMAIL })
    );
    let lookup = h.fake.with(|f| {
        f.requests
            .iter()
            .find(|(p, _)| p == DROPBOX_ACCOUNT)
            .cloned()
            .unwrap()
    });
    assert_eq!(lookup.1.get("content_type"), None);
    assert_eq!(lookup.1["body"], "");

    let reply = h
        .proxy(&json!({
            "member": MEMBER,
            "connection_id": id,
            "method": "POST",
            "url": LIST_FOLDER,
            "body": { "path": "" },
            "headers": { "Dropbox-API-Path-Root": PATH_ROOT },
        }))
        .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.bytes, DROPBOX_LISTING.as_bytes());
    assert_eq!(reply.content_type.as_deref(), Some("application/json"));

    let (seen, issued) = h.fake.with(|f| (f.data.clone(), f.access.clone()));
    let [seen] = &seen[..] else {
        panic!("{seen:?}")
    };
    assert_eq!(seen.method, "POST");
    assert_eq!(seen.host, "api.dropboxapi.com");
    assert_eq!(seen.path, "/2/files/list_folder");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&seen.body).unwrap(),
        json!({ "path": "" })
    );
    assert_eq!(seen.headers["dropbox-api-path-root"], PATH_ROOT);
    let token = seen
        .authorization
        .as_deref()
        .unwrap()
        .strip_prefix("Bearer ")
        .unwrap();
    assert!(token.starts_with("sl.") && issued.iter().any(|t| t == token));
    assert_ne!(token, consent.access_token);
}
