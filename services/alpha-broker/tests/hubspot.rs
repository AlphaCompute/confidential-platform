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

const MCP: &str = "https://mcp.hubspot.com/";

#[tokio::test]
async fn a_member_connects_hubspot_and_an_instance_calls_a_listed_tool_without_seeing_a_token() {
    let Some(h) = harness().await else { return };
    let query = h.start("hubspot", &member()).await;
    assert_eq!(query["client_id"], HUBSPOT_CLIENT_ID);
    assert!(!query.contains_key("scope"), "{query:?}");

    let (reply, consent) = h
        .connect_as("hubspot", &member(), "247507114:77", "ann@acme.example")
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

    let request = mcp_call(id, MCP, "search_crm_objects");
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

#[tokio::test]
async fn every_listed_hubspot_tool_is_forwarded_and_every_other_is_refused_before_hubspot() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected_to("hubspot").await;
    for tool in alpha_broker::oauth::HUBSPOT_READ_TOOLS {
        let reply = h.proxy(&mcp_call(id, MCP, tool)).await;
        assert_eq!(reply.status, StatusCode::OK, "{tool}");
    }
    nothing_reaches(&h, async {
        for tool in [
            "manage_crm_objects",
            "manage_campaign_objects",
            "manage_segment",
            "manage_landing_page",
            "manage_aeo_recommendations",
            "manage_aeo_prompts",
            "manage_marketing_email",
            "manage_onboarding",
            "manage_custom_properties",
            "manage_custom_pipelines",
            "manage_website_page",
            "manage_blog_post",
            "submit_feedback",
            "render_asset",
            "render_landing_page_ui",
            "search_crm_objects_v2",
            "search_crm_object",
            "Search_crm_objects",
            " search_crm_objects",
            "notion-search",
        ] {
            let reply = h.proxy(&mcp_call(id, MCP, tool)).await;
            assert_eq!(reply.status, StatusCode::FORBIDDEN, "{tool}");
            assert_eq!(reply.code(), "not_allowed");
        }
    })
    .await;
}

#[tokio::test]
async fn a_body_that_is_not_one_well_formed_tool_call_is_refused_before_hubspot() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected_to("hubspot").await;
    let listed = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": { "name": "search_crm_objects" } });
    let write = json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": { "name": "manage_crm_objects" } });
    nothing_reaches(&h, async {
        for body in [
            json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call" }),
            json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {} }),
            json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": { "name": 7 } }),
            json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": { "name": "" } }),
            json!([listed, write]),
            json!("tools/list"),
            json!({ "jsonrpc": "2.0", "id": 1, "method": "resources/read",
                "params": { "uri": "hubspot://contacts" } }),
            json!({ "jsonrpc": "2.0", "id": 1, "method": "prompts/get" }),
            Value::Null,
        ] {
            let reply = h.proxy(&mcp_rpc(id, MCP, body.clone())).await;
            assert_eq!(reply.status, StatusCode::FORBIDDEN, "{body}");
        }
        let mut bare = mcp_rpc(id, MCP, Value::Null);
        bare.as_object_mut().unwrap().remove("body");
        assert_eq!(h.proxy(&bare).await.status, StatusCode::FORBIDDEN);
    })
    .await;
}

#[tokio::test]
async fn a_duplicated_tool_name_is_judged_and_sent_by_its_last_value() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected_to("hubspot").await;
    let reference = member().reference();
    let raw = |first: &str, last: &str| {
        format!(
            r#"{{"member":"{reference}","connection_id":"{id}","method":"POST","url":"{MCP}",
            "body":{{"jsonrpc":"2.0","id":1,"method":"tools/call",
            "params":{{"name":"{first}","name":"{last}"}}}}}}"#
        )
    };
    let proxy = |body: String| h.post_text(&h.instance, Some(PROXY_BEARER), "/proxy", body);
    nothing_reaches(&h, async {
        let reply = proxy(raw("search_crm_objects", "manage_crm_objects"))
            .await
            .unwrap();
        assert_eq!(reply.status, StatusCode::FORBIDDEN);
    })
    .await;
    let reply = proxy(raw("manage_crm_objects", "search_crm_objects"))
        .await
        .unwrap();
    assert_eq!(reply.status, StatusCode::OK);
    let sent = h.fake.with(|f| f.data.last().unwrap().body.clone());
    let sent: Value = serde_json::from_slice(&sent).unwrap();
    assert_eq!(sent["params"], json!({ "name": "search_crm_objects" }));
}

#[tokio::test]
async fn tools_list_and_initialize_pass_and_come_back_byte_for_byte() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected_to("hubspot").await;
    let list = h
        .proxy(&mcp_rpc(
            id,
            MCP,
            json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" }),
        ))
        .await;
    assert_eq!(list.status, StatusCode::OK);
    assert_eq!(list.content_type.as_deref(), Some("application/json"));
    assert_eq!(list.bytes, MCP_TOOLS.as_bytes());
    let init = h
        .proxy(&mcp_rpc(
            id,
            MCP,
            json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {} }),
        ))
        .await;
    assert_eq!(init.status, StatusCode::OK);
    let methods: Vec<Value> = h.fake.with(|f| {
        f.data
            .iter()
            .map(|d| serde_json::from_slice::<Value>(&d.body).unwrap()["method"].clone())
            .collect()
    });
    assert_eq!(methods, [json!("tools/list"), json!("initialize")]);
}

#[tokio::test]
async fn a_hubspot_refresh_stores_whatever_refresh_token_comes_back() {
    let Some(h) = harness().await else { return };
    let (id, consent) = h.connected_to("hubspot").await;
    h.fake.with(|f| f.rotate = true);
    for round in 0..2 {
        h.state.tokens.lock().clear();
        assert_eq!(
            h.proxy(&mcp_call(id, MCP, "get_user_details")).await.status,
            StatusCode::OK
        );
        let sealed = h.stored_token(id).await.unwrap();
        let stored = alpha_broker::store::open(&KEY, id.as_bytes(), &sealed).unwrap();
        let newest = h.fake.with(|f| f.refresh.last().cloned().unwrap());
        assert_eq!(stored.as_slice(), newest.as_bytes(), "round {round}");
        assert_ne!(newest, consent.refresh_token);
    }
    let refresh = h.fake.with(|f| f.form(HUBSPOT_TOKEN));
    assert_eq!(refresh["client_secret"], HUBSPOT_CLIENT_SECRET);
}

#[tokio::test]
async fn disconnecting_hubspot_revokes_only_locally() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected_to("hubspot").await;
    nothing_reaches(&h, async {
        let reply = h.disconnect(&member(), id).await;
        assert_eq!(reply.status, StatusCode::OK);
    })
    .await;
    assert_eq!(h.stored_token(id).await, None);
}
