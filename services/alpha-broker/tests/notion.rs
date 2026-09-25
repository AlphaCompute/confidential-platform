#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use axum::http::StatusCode;
use common::*;
use serde_json::{Value, json};

const MCP: &str = "https://mcp.notion.com/mcp";

#[tokio::test]
async fn a_member_connects_notion_as_a_public_client_and_an_instance_searches_it() {
    let Some(h) = harness().await else { return };
    let query = h.start("notion", &member()).await;
    assert_eq!(query["client_id"], NOTION_CLIENT_ID);
    assert_eq!(query["scope"], "default");
    assert_eq!(query["redirect_uri"], NOTION_REDIRECT_URI);
    assert_eq!(query["code_challenge_method"], "S256");

    let (reply, consent) = h
        .connect_as("notion", &member(), "ws-1:user-1", "ann@acme.example")
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    let id = id_of(&reply);
    assert_eq!(
        reply.body,
        json!({ "id": id.to_string(), "provider": "notion", "account": "ann@acme.example" })
    );
    let subject: String = sqlx::query_scalar("select subject from connections where id = $1")
        .bind(id)
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(subject, "ws-1:user-1");
    let exchange = h.fake.with(|f| f.form("/token"));
    assert_eq!(exchange["client_id"], NOTION_CLIENT_ID);
    assert_eq!(exchange["code_verifier"].len(), 43);
    assert!(!exchange.contains_key("client_secret"), "{exchange:?}");

    let request = mcp_call(id, MCP, "notion-search");
    let reply = h.proxy(&request).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.content_type.as_deref(), Some("text/event-stream"));
    assert_eq!(reply.bytes, sse(MCP_RESULT).as_bytes());

    let seen = h.fake.with(|f| f.data.clone());
    let [seen] = &seen[..] else {
        panic!("{seen:?}")
    };
    assert_eq!(
        (seen.host.as_str(), seen.path.as_str()),
        ("mcp.notion.com", "/mcp")
    );
    assert_eq!(seen.headers["accept"], MCP_ACCEPT);
    assert_ne!(bearer_of(&seen.headers), consent.access_token);
    let sent: Value = serde_json::from_slice(&seen.body).unwrap();
    assert_eq!(sent, request["body"]);
}

#[tokio::test]
async fn a_notion_member_without_an_email_is_named_by_name() {
    let Some(h) = harness().await else { return };
    let (reply, _) = h
        .connect_as("notion", &member(), "ws-1:user-2", "Research Desk")
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    assert_eq!(reply.body["account"], "Research Desk");
}

#[tokio::test]
async fn every_listed_notion_tool_is_forwarded_and_acting_tools_are_refused_before_notion() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected_to("notion").await;
    for tool in alpha_broker::oauth::NOTION_READ_TOOLS {
        assert_eq!(
            h.proxy(&mcp_call(id, MCP, tool)).await.status,
            StatusCode::OK,
            "{tool}"
        );
    }
    nothing_reaches(&h, async {
        for tool in [
            "notion-ai-search",
            "notion-spawn-session",
            "notion-send-message-to-session",
            "notion-update-page",
            "notion-create-pages",
            "notion-create-comment",
            "notion-search-skills",
            "notion-create-view",
            "notion-search-v2",
            "Notion-search",
            "search_crm_objects",
        ] {
            let reply = h.proxy(&mcp_call(id, MCP, tool)).await;
            assert_eq!(reply.status, StatusCode::FORBIDDEN, "{tool}");
            assert_eq!(reply.code(), "not_allowed");
        }
        let batch = mcp_rpc(
            id,
            MCP,
            json!([{ "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": "notion-update-page" } }]),
        );
        assert_eq!(h.proxy(&batch).await.status, StatusCode::FORBIDDEN);
        let resources = mcp_rpc(
            id,
            MCP,
            json!({ "jsonrpc": "2.0", "id": 1, "method": "resources/read" }),
        );
        assert_eq!(h.proxy(&resources).await.status, StatusCode::FORBIDDEN);
        let elsewhere = mcp_rpc(
            id,
            "https://mcp.notion.com/",
            json!({ "method": "tools/list" }),
        );
        assert_eq!(h.proxy(&elsewhere).await.status, StatusCode::FORBIDDEN);
    })
    .await;
}

#[tokio::test]
async fn notion_tools_list_comes_back_as_the_same_event_stream_without_its_session_header() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected_to("notion").await;
    let reply = h
        .proxy(&mcp_rpc(
            id,
            MCP,
            json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" }),
        ))
        .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.content_type.as_deref(), Some("text/event-stream"));
    assert_eq!(reply.bytes, sse(MCP_TOOLS).as_bytes());
    assert!(
        !reply.headers.contains_key(MCP_SESSION),
        "{:?}",
        reply.headers
    );
}

#[tokio::test]
async fn neither_mcp_row_takes_an_accept_or_session_header_from_the_caller() {
    let Some(h) = harness().await else { return };
    for (provider, url) in [("hubspot", "https://mcp.hubspot.com/"), ("notion", MCP)] {
        let (id, _) = h.connected_to(provider).await;
        nothing_reaches(&h, async {
            for name in ["accept", "Accept", MCP_SESSION] {
                let mut body = mcp_rpc(
                    id,
                    url,
                    json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" }),
                );
                body["headers"] = json!(BTreeMap::from([(name, "text/html")]));
                let reply = h.proxy(&body).await;
                assert_eq!(reply.status, StatusCode::FORBIDDEN, "{provider} {name}");
            }
        })
        .await;
    }
}

#[tokio::test]
async fn a_notion_refresh_answered_invalid_grant_or_invalid_token_marks_the_connection_dead() {
    for code in ["invalid_grant", "invalid_token"] {
        let Some(h) = harness().await else { return };
        let (id, _) = h.connected_to("notion").await;
        h.fake
            .with(|f| f.refresh_reply = Some((StatusCode::BAD_REQUEST, json!({ "error": code }))));
        let reply = h.proxy(&mcp_call(id, MCP, "notion-search")).await;
        assert_eq!(reply.status, StatusCode::CONFLICT, "{code}");
        assert_eq!(reply.code(), "reconnect_required");
        let listed = h.list(&member()).await;
        assert_eq!(listed.body["connections"][0]["dead"], true, "{code}");
        assert!(h.fake.with(|f| f.data.is_empty()));
    }
}

#[tokio::test]
async fn a_notion_refresh_without_expires_in_is_used_for_the_default_hour() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected_to("notion").await;
    h.fake.with(|f| f.omit_expires_in = true);
    for _ in 0..2 {
        assert_eq!(
            h.proxy(&mcp_call(id, MCP, "notion-search")).await.status,
            StatusCode::OK
        );
    }
    assert_eq!(h.fake.with(|f| f.refreshes()), 1);
    let until = h.state.tokens.lock().get(&id).unwrap().1;
    assert!(until > Instant::now() + Duration::from_secs(58 * 60));
}

#[tokio::test]
async fn disconnecting_notion_revokes_a_fresh_access_token_at_notion() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected_to("notion").await;
    let reply = h.disconnect(&member(), id).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(h.stored_token(id).await, None);
    let (paths, revoke) = h.fake.with(|f| {
        let paths: Vec<String> = f.requests.iter().map(|(p, _)| p.clone()).collect();
        (paths, f.form("/revoke"))
    });
    assert_eq!(paths[paths.len() - 2..], ["/token", "/revoke"]);
    assert!(
        revoke["token"].starts_with("ntn_fake-refreshed-"),
        "{revoke:?}"
    );
    assert_eq!(revoke["token_type_hint"], "access_token");
    assert_eq!(revoke["client_id"], NOTION_CLIENT_ID);
    assert!(!revoke.contains_key("client_secret"));
}
