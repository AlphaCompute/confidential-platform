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

    let (seen, access) = h.fake.with(|f| (f.data.clone(), f.access.clone()));
    let [seen] = &seen[..] else {
        panic!("{seen:?}")
    };
    assert_eq!(seen.path, "/drive/v3/files");
    assert_eq!(seen.query["pageSize"], "10");
    let token = bearer_of(&seen.headers);
    assert!(access.contains(&token));
}

const FILES: &str = "https://www.googleapis.com/drive/v3/files";

#[tokio::test]
async fn a_caller_without_a_client_certificate_is_refused() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected().await;
    let anonymous = instance_client(&h.ca, None);
    let reply = h
        .proxy_with(&anonymous, Some(PROXY_BEARER), &read(id, FILES))
        .await
        .unwrap();
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert_eq!(reply.code(), "cert_invalid");
    assert!(h.untouched());
}

#[tokio::test]
async fn a_leaf_from_another_ca_fails_the_handshake() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected().await;
    let stranger = instance_client(&h.ca, Some(Ca::new().instance()));
    assert!(
        h.proxy_with(&stranger, Some(PROXY_BEARER), &read(id, FILES))
            .await
            .is_err()
    );
    assert!(h.untouched());
}

#[tokio::test]
async fn a_kms_node_leaf_is_refused() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected().await;
    let node = h.ca.leaf(&[
        alpha_client::tls::KMS_SAN.to_string(),
        format!("urn:alphacompute:revision:sha256:{}", "1".repeat(64)),
    ]);
    let reply = h
        .proxy_with(
            &instance_client(&h.ca, Some(node)),
            Some(PROXY_BEARER),
            &read(id, FILES),
        )
        .await
        .unwrap();
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert_eq!(reply.code(), "cert_invalid");
    assert!(h.untouched());
}

#[tokio::test]
async fn each_bearer_opens_only_its_own_routes() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected().await;
    for bearer in [None, Some("wrong-bearer"), Some(BEARER)] {
        let reply = h
            .proxy_with(&h.instance, bearer, &read(id, FILES))
            .await
            .unwrap();
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{bearer:?}");
        assert_eq!(reply.code(), "unauthorized");
    }
    let listed = h
        .call_as(
            Some(PROXY_BEARER),
            "GET",
            &format!("/connections?member={MEMBER}"),
            None,
        )
        .await;
    assert_eq!(listed.status, StatusCode::UNAUTHORIZED);
    assert!(h.untouched());
}

#[tokio::test]
async fn a_malformed_body_is_refused() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected().await;
    let mut unknown = read(id, FILES);
    unknown["extra"] = serde_json::json!({});
    let mut short_member = read(id, FILES);
    short_member["member"] = serde_json::json!(&MEMBER[1..]);
    let mut bad_id = read(id, FILES);
    bad_id["connection_id"] = serde_json::json!("not-a-uuid");
    for body in [
        unknown,
        short_member,
        bad_id,
        read(id, "/drive/v3/files"),
        serde_json::json!("not an object"),
    ] {
        let reply = h.proxy(&body).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(reply.code(), "malformed");
    }
    assert!(h.untouched());
}

#[tokio::test]
async fn an_unknown_revoked_or_foreign_connection_is_not_found() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected().await;
    let (foreign, _) = h.connect(OTHER_MEMBER, "other@example.com").await;
    let (revoked, _) = h.connect(MEMBER, "second@example.com").await;
    let revoked = id_of(&revoked);
    let gone = h
        .call(
            "DELETE",
            &format!("/connections/{revoked}?member={MEMBER}"),
            None,
        )
        .await;
    assert_eq!(gone.status, StatusCode::NO_CONTENT);
    for connection in [uuid::Uuid::now_v7(), revoked, id_of(&foreign)] {
        let reply = h.proxy(&read(connection, FILES)).await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{connection}");
        assert_eq!(reply.code(), "not_found");
    }
    assert!(h.untouched());
    assert_eq!(h.proxy(&read(id, FILES)).await.status, StatusCode::OK);
}

#[tokio::test]
async fn a_request_outside_the_allowlist_is_refused_before_google() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected().await;
    let mut post = read(id, FILES);
    post["method"] = serde_json::json!("POST");
    post["body"] = serde_json::json!({ "name": "x" });
    let mut refused = vec![post];
    for url in [
        "https://www.googleapis.com/upload/drive/v3/files",
        "https://www.googleapis.com/drive/v3/files/abc/permissions",
        "https://docs.googleapis.com/v1/documents/x",
        "http://www.googleapis.com/drive/v3/files",
        "https://www.googleapis.com:8443/drive/v3/files",
        "https://user@www.googleapis.com/drive/v3/files",
        "https://www.googleapis.com/drive/v3/files/../../upload/drive/v3/files",
        "https://www.googleapis.com/drive/v3/files/%2e%2e/x",
        "https://www.googleapis.com/drive/v3/files/a.b",
        "https://www.googleapis.com/calendar/v3/calendars/other/events",
    ] {
        refused.push(read(id, url));
    }
    refused.push(read(id, &format!("{FILES}/{}", "a".repeat(257))));
    for body in refused {
        let reply = h.proxy(&body).await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(reply.code(), "not_allowed");
    }
    assert!(h.untouched());
}

#[tokio::test]
async fn an_invalid_grant_marks_the_connection_dead_and_asks_for_a_reconnect() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected().await;
    h.fake.with(|f| f.token_status = StatusCode::BAD_REQUEST);

    let reply = h.proxy(&read(id, FILES)).await;
    assert_eq!(reply.status, StatusCode::CONFLICT);
    assert_eq!(reply.code(), "reconnect_required");
    let dead: bool =
        sqlx::query_scalar("select dead_at is not null from connections where id = $1")
            .bind(id)
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert!(dead);
    let listed = h
        .call("GET", &format!("/connections?member={MEMBER}"), None)
        .await;
    assert_eq!(listed.body["connections"][0]["dead"], true);

    let again = h.proxy(&read(id, FILES)).await;
    assert_eq!(again.status, StatusCode::CONFLICT);
    assert_eq!(again.code(), "reconnect_required");
    assert_eq!(h.fake.with(|f| f.refreshes()), 1);
    assert!(h.fake.with(|f| f.data.is_empty()));
}

#[tokio::test]
async fn a_connection_marked_dead_is_refused_even_with_a_cached_token() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected().await;
    assert_eq!(h.proxy(&read(id, FILES)).await.status, StatusCode::OK);
    sqlx::query("update connections set dead_at = now() where id = $1")
        .bind(id)
        .execute(&h.pool)
        .await
        .unwrap();
    let reply = h.proxy(&read(id, FILES)).await;
    assert_eq!(reply.status, StatusCode::CONFLICT);
    assert_eq!(reply.code(), "reconnect_required");
    assert_eq!(h.fake.with(|f| f.data.len()), 1);
}

#[tokio::test]
async fn any_other_refresh_failure_answers_upstream_and_keeps_the_connection() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected().await;
    h.fake
        .with(|f| f.token_status = StatusCode::INTERNAL_SERVER_ERROR);
    let reply = h.proxy(&read(id, FILES)).await;
    assert_eq!(reply.status, StatusCode::BAD_GATEWAY);
    assert_eq!(reply.code(), "upstream");

    h.fake.with(|f| f.token_status = StatusCode::OK);
    assert_eq!(h.proxy(&read(id, FILES)).await.status, StatusCode::OK);
}

#[tokio::test]
async fn a_rotated_refresh_token_is_sealed_and_stored() {
    let Some(h) = harness().await else { return };
    let (id, consent) = h.connected().await;
    h.fake.with(|f| f.rotate = true);

    assert_eq!(h.proxy(&read(id, FILES)).await.status, StatusCode::OK);
    let live = h.fake.with(|f| f.refresh.clone());
    assert!(!live.contains(&consent.refresh_token));
    let blob = h.stored_token(id).await.unwrap();
    let stored = alpha_broker::store::open(&KEY, id.as_bytes(), &blob).unwrap();
    assert_eq!(live, [String::from_utf8(stored.to_vec()).unwrap()]);
}

#[tokio::test]
async fn a_401_on_a_cached_token_is_retried_once_with_a_fresh_one() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected().await;
    assert_eq!(h.proxy(&read(id, FILES)).await.status, StatusCode::OK);
    assert_eq!(h.proxy(&read(id, FILES)).await.status, StatusCode::OK);
    assert_eq!(h.fake.with(|f| f.refreshes()), 1, "the token is cached");

    h.fake.with(|f| f.unauthorized = 1);
    let reply = h.proxy(&read(id, FILES)).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.bytes, LISTING.as_bytes());
    assert_eq!(h.fake.with(|f| (f.refreshes(), f.data.len())), (2, 4));
}

#[tokio::test]
async fn a_second_401_is_relayed() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected().await;
    assert_eq!(h.proxy(&read(id, FILES)).await.status, StatusCode::OK);

    h.fake.with(|f| f.unauthorized = 2);
    let reply = h.proxy(&read(id, FILES)).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert_eq!(reply.json()["error"]["message"], "Invalid Credentials");
    assert_eq!(h.fake.with(|f| (f.refreshes(), f.data.len())), (2, 3));
}

#[tokio::test]
async fn a_body_of_exactly_the_cap_is_relayed_and_one_byte_more_is_too_large() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected().await;
    let cap = alpha_broker::proxy::MAX_RESPONSE;
    assert_eq!(cap, 16 << 20);

    h.fake.with(|f| f.media_size = cap);
    let whole = h.proxy(&read(id, MEDIA)).await;
    assert_eq!(whole.status, StatusCode::OK);
    assert_eq!(whole.bytes.len(), cap);
    assert_eq!(
        whole.content_type.as_deref(),
        Some("application/octet-stream")
    );

    h.fake.with(|f| f.media_size = cap + 1);
    let over = h.proxy(&read(id, MEDIA)).await;
    assert_eq!(over.status, StatusCode::BAD_GATEWAY);
    assert_eq!(over.code(), "too_large");
}

#[tokio::test]
async fn two_calls_on_an_expired_token_share_one_refresh() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected().await;
    h.fake.with(|f| {
        f.rotate = true;
        f.refresh_delay = std::time::Duration::from_millis(300);
    });

    let body = read(id, FILES);
    let (a, b) = tokio::join!(h.proxy(&body), h.proxy(&body));
    assert_eq!((a.status, b.status), (StatusCode::OK, StatusCode::OK));
    assert_eq!(h.fake.with(|f| f.refreshes()), 1);

    let live = h.fake.with(|f| f.refresh.clone());
    let blob = h.stored_token(id).await.unwrap();
    let stored = alpha_broker::store::open(&KEY, id.as_bytes(), &blob).unwrap();
    assert_eq!(live, [String::from_utf8(stored.to_vec()).unwrap()]);
}

#[tokio::test]
async fn drive_gmail_and_calendar_answer_with_the_callers_query_and_googles_content_type() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected().await;
    let json = "application/json";
    let reads = [
        (
            "/drive/v3/drives",
            "pageSize",
            "100",
            json,
            r#"{"drives":[]}"#,
        ),
        (
            "/drive/v3/files/file-1",
            "fields",
            "id",
            json,
            r#"{"id":"file-1","name":"Notes"}"#,
        ),
        (
            "/drive/v3/files/file-1/export",
            "mimeType",
            "text/csv",
            "text/csv",
            "a,b\n1,2\n",
        ),
        (
            "/gmail/v1/users/me/messages",
            "q",
            "from:x",
            json,
            r#"{"messages":[{"id":"m1"}]}"#,
        ),
        (
            "/gmail/v1/users/me/messages/m1",
            "format",
            "full",
            json,
            r#"{"id":"m1","snippet":"hello"}"#,
        ),
        (
            "/calendar/v3/calendars/primary/events",
            "singleEvents",
            "true",
            json,
            r#"{"items":[]}"#,
        ),
    ];
    for (path, key, value, content_type, body) in reads {
        let url = format!("https://www.googleapis.com{path}?{key}={value}");
        let reply = h.proxy(&read(id, &url)).await;
        assert_eq!(reply.status, StatusCode::OK, "{path}");
        assert_eq!(reply.content_type.as_deref(), Some(content_type), "{path}");
        assert_eq!(reply.bytes, body.as_bytes(), "{path}");
        let seen = h.fake.with(|f| f.data.last().cloned().unwrap());
        assert_eq!(seen.path, path);
        assert_eq!(seen.query[key], value, "{path}");
    }
}

#[tokio::test]
async fn a_disconnect_drops_the_cached_token_and_a_refresh_drops_expired_ones() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected().await;
    let idle = uuid::Uuid::now_v7();
    h.state.tokens.lock().insert(
        idle,
        ("ya29.expired".to_string().into(), std::time::Instant::now()),
    );
    assert_eq!(h.proxy(&read(id, FILES)).await.status, StatusCode::OK);
    assert_eq!(
        h.state.tokens.lock().keys().copied().collect::<Vec<_>>(),
        [id]
    );

    let gone = h
        .call(
            "DELETE",
            &format!("/connections/{id}?member={MEMBER}"),
            None,
        )
        .await;
    assert_eq!(gone.status, StatusCode::NO_CONTENT);
    assert!(h.state.tokens.lock().is_empty());
}

#[tokio::test]
async fn a_request_body_over_two_mib_is_refused_before_google() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected().await;
    let mut body = read(id, FILES);
    body["body"] = serde_json::json!("A".repeat(2 << 20));
    let reply = h.proxy(&body).await;
    assert_eq!(reply.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert!(h.untouched());
}
