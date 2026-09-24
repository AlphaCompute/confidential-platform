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

#[tokio::test]
async fn slack_is_asked_for_the_nine_user_scopes_and_no_bot_scope() {
    let Some(h) = harness().await else { return };
    let query = h.start("slack", MEMBER).await;
    assert_eq!(query["client_id"], SLACK_CLIENT_ID);
    assert_eq!(query["redirect_uri"], SLACK_REDIRECT_URI);
    assert_eq!(query["code_challenge_method"], "S256");
    assert_eq!(
        query["user_scope"],
        "channels:read,channels:history,groups:read,groups:history,im:read,im:history,\
         mpim:read,mpim:history,users:read"
    );
    assert!(!query.contains_key("scope"), "{query:?}");
}

#[tokio::test]
async fn the_three_slack_reads_pass_and_nothing_that_writes() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected_to("slack").await;
    for url in [
        "https://slack.com/api/conversations.list?types=im,mpim",
        HISTORY,
        "https://slack.com/api/users.info?user=U2",
    ] {
        let reply = h.proxy(&read(id, url)).await;
        assert_eq!(reply.status, StatusCode::OK, "{url}");
        assert_eq!(reply.json()["ok"], true, "{url}");
    }
    let before = h.fake.with(|f| (f.data.len(), f.requests.len()));
    for method in [
        "chat.postMessage",
        "conversations.replies",
        "conversations.mark",
        "reactions.add",
        "users.list",
    ] {
        let reply = h
            .proxy(&read(
                id,
                &format!("https://slack.com/api/{method}?channel=C1"),
            ))
            .await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN, "{method}");
        assert_eq!(reply.code(), "not_allowed");
    }
    let mut post = read(id, HISTORY);
    post["method"] = json!("POST");
    assert_eq!(h.proxy(&post).await.status, StatusCode::FORBIDDEN);
    assert_eq!(h.fake.with(|f| (f.data.len(), f.requests.len())), before);
}

#[tokio::test]
async fn a_dead_slack_refresh_token_inside_http_200_marks_the_connection_dead() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected_to("slack").await;
    h.fake.with(|f| {
        f.refresh_reply = Some((
            StatusCode::OK,
            json!({ "ok": false, "error": "invalid_refresh_token" }),
        ))
    });
    let reply = h.proxy(&read(id, HISTORY)).await;
    assert_eq!(reply.status, StatusCode::CONFLICT);
    assert_eq!(reply.code(), "reconnect_required");
    let listed = h
        .call("GET", &format!("/connections?member={MEMBER}"), None)
        .await;
    assert_eq!(listed.body["connections"][0]["dead"], true);

    let again = h.proxy(&read(id, HISTORY)).await;
    assert_eq!(again.status, StatusCode::CONFLICT);
    assert_eq!(h.fake.with(|f| f.hits(SLACK_TOKEN)), 2);
    assert!(h.fake.with(|f| f.data.is_empty()));
}

#[tokio::test]
async fn every_slack_refresh_stores_the_rotated_refresh_token() {
    let Some(h) = harness().await else { return };
    let (id, consent) = h.connected_to("slack").await;
    for round in 0..2 {
        h.state.tokens.lock().clear();
        assert_eq!(h.proxy(&read(id, HISTORY)).await.status, StatusCode::OK);
        let sealed = h.stored_token(id).await.unwrap();
        let stored = alpha_broker::store::open(&KEY, id.as_bytes(), &sealed).unwrap();
        let newest = h.fake.with(|f| f.refresh.last().cloned().unwrap());
        assert_eq!(stored.as_slice(), newest.as_bytes(), "round {round}");
        assert_ne!(newest, consent.refresh_token);
    }
    assert_eq!(h.fake.with(|f| f.refreshes()), 2);
}

#[tokio::test]
async fn disconnecting_slack_revokes_at_slack_with_an_access_token() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected_to("slack").await;
    let reply = h
        .call(
            "DELETE",
            &format!("/connections/{id}?member={MEMBER}"),
            None,
        )
        .await;
    assert_eq!(reply.status, StatusCode::NO_CONTENT);
    assert_eq!(h.stored_token(id).await, None);
    let (paths, revoked) = h.fake.with(|f| {
        let paths: Vec<String> = f.requests.iter().map(|(p, _)| p.clone()).collect();
        (paths, f.revoked_tokens())
    });
    assert_eq!(
        paths[paths.len() - 2..],
        [SLACK_TOKEN.to_string(), SLACK_REVOKE.to_string()]
    );
    let [revoked] = &revoked[..] else {
        panic!("{revoked:?}")
    };
    assert!(revoked.starts_with("xoxp-fake-refreshed-"));
}

#[tokio::test]
async fn one_slack_user_keeps_one_connection_and_a_second_workspace_makes_another() {
    let Some(h) = harness().await else { return };
    let (first, _) = h.connect_as("slack", MEMBER, "T1:U1", "ann @ Acme").await;
    let (again, _) = h.connect_as("slack", MEMBER, "T1:U1", "ann @ Acme").await;
    let (other, _) = h.connect_as("slack", MEMBER, "T2:U1", "ann @ Beta").await;
    assert_eq!(id_of(&first), id_of(&again));
    assert_ne!(id_of(&first), id_of(&other));
    let listed = h
        .call("GET", &format!("/connections?member={MEMBER}"), None)
        .await;
    assert_eq!(listed.body["connections"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn slack_needs_no_client_secret_and_figma_needs_one() {
    let Some(h) = harness().await else { return };
    let slack = alpha_broker::oauth::provider("slack").unwrap();
    let figma = alpha_broker::oauth::provider("figma").unwrap();
    let (client_id, secret) = h.state.client(slack).unwrap();
    assert_eq!((client_id, secret), (SLACK_CLIENT_ID, None));
    assert!(h.state.client(figma).unwrap().1.is_some());
    h.state.secrets.write().client_secrets.remove("figma");
    let err = h.state.client(figma).unwrap_err();
    assert!(err.to_string().contains("figma"), "{err}");
}
