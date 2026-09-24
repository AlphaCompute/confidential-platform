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
use serde_json::{Value, json};
use uuid::Uuid;

const MCP: &str = "https://mcp.hubspot.com/";

fn rpc(connection: Uuid, body: Value) -> Value {
    json!({
        "member": MEMBER,
        "connection_id": connection,
        "method": "POST",
        "url": MCP,
        "body": body,
    })
}

fn call(connection: Uuid, tool: &str) -> Value {
    rpc(
        connection,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": tool, "arguments": { "objectType": "contacts" } },
        }),
    )
}

#[tokio::test]
async fn a_member_connects_hubspot_and_an_instance_calls_a_listed_tool_without_seeing_a_token() {
    let Some(h) = harness().await else { return };
    let query = h.start("hubspot", MEMBER).await;
    assert_eq!(query["client_id"], HUBSPOT_CLIENT_ID);
    assert!(!query.contains_key("scope"), "{query:?}");

    let (reply, consent) = h
        .connect_as("hubspot", MEMBER, "247507114:77", "ann@acme.example")
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    let id = id_of(&reply);
    assert_eq!(
        reply.body,
        json!({ "id": id.to_string(), "provider": "hubspot", "account": "ann@acme.example" })
    );
    let subject: String = sqlx::query_scalar("select subject from connections where id = $1")
        .bind(id)
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(subject, "247507114:77");
    let exchange = h.fake.with(|f| f.form(HUBSPOT_TOKEN));
    assert_eq!(exchange["client_secret"], HUBSPOT_CLIENT_SECRET);

    let request = call(id, "search_crm_objects");
    let reply = h.proxy(&request).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.bytes, MCP_RESULT.as_bytes());

    let (seen, issued) = h.fake.with(|f| (f.data.clone(), f.access.clone()));
    let [seen] = &seen[..] else {
        panic!("{seen:?}")
    };
    assert_eq!(
        (seen.host.as_str(), seen.path.as_str()),
        ("mcp.hubspot.com", "/")
    );
    assert_eq!(seen.headers["accept"], MCP_ACCEPT);
    let token = bearer_of(&seen.headers);
    assert!(token.starts_with("hsat-") && issued.contains(&token));
    assert_ne!(token, consent.access_token);
    let sent: Value = serde_json::from_slice(&seen.body).unwrap();
    assert_eq!(sent, request["body"]);
}
