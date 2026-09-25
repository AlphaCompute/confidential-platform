#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use std::time::{Duration, SystemTime};

use axum::http::StatusCode;
use common::*;

#[tokio::test]
async fn a_chat_reads_drive_with_a_grant_for_its_own_leaf() {
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
        .post_with(&anonymous, None, "/proxy", &read(id, FILES))
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
        h.post_with(&stranger, None, "/proxy", &read(id, FILES))
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
        .post_with(
            &instance_client(&h.ca, Some(node)),
            None,
            "/proxy",
            &read(id, FILES),
        )
        .await
        .unwrap();
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert_eq!(reply.code(), "cert_invalid");
    assert!(h.untouched());
}

#[tokio::test]
async fn a_bearer_without_a_grant_reads_nothing() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected().await;
    for bearer in [None, Some("supervisor-bearer"), Some(BEARER)] {
        let reply = h
            .post_with(&h.instance, bearer, "/proxy", &read(id, FILES))
            .await
            .unwrap();
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{bearer:?}");
        assert_eq!(reply.code(), "malformed");
    }
    assert!(h.untouched());
}

#[tokio::test]
async fn a_malformed_body_is_refused() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected().await;
    let mut unknown = read(id, FILES);
    unknown["extra"] = serde_json::json!({});
    let mut member_reference = read(id, FILES);
    member_reference["member"] = serde_json::json!(hex::encode(member().sha256()));
    let mut not_a_grant = read(id, FILES);
    not_a_grant["grant"] = serde_json::json!("not-a-grant");
    let mut bad_id = read(id, FILES);
    bad_id["connection_id"] = serde_json::json!("not-a-uuid");
    for body in [
        unknown,
        member_reference,
        not_a_grant,
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
async fn an_unknown_or_revoked_connection_is_not_found_and_a_foreign_one_is_not_granted() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected().await;
    let (foreign, _) = h.connect(&other_member(), "other@example.com").await;
    let (revoked, _) = h.connect(&member(), "second@example.com").await;
    let revoked = id_of(&revoked);
    let gone = h.disconnect(&member(), revoked).await;
    assert_eq!(gone.status, StatusCode::OK);
    for connection in [uuid::Uuid::now_v7(), revoked] {
        let reply = h.proxy(&read(connection, FILES)).await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{connection}");
        assert_eq!(reply.code(), "not_found");
    }
    let reply = h.proxy(&read(id_of(&foreign), FILES)).await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(reply.code(), "grant_invalid");
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
    let listed = h.list(&member()).await;
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

    let gone = h.disconnect(&member(), id).await;
    assert_eq!(gone.status, StatusCode::OK);
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

async fn refused(h: &Harness, body: serde_json::Value, status: StatusCode, code: &str) {
    nothing_reaches(h, async {
        let reply = h.proxy(&body).await;
        assert_eq!(reply.status, status, "{body}");
        assert_eq!(reply.code(), code, "{body}");
    })
    .await;
}

fn with_grant(id: uuid::Uuid, grant: String) -> serde_json::Value {
    let mut body = read(id, FILES);
    body["grant"] = serde_json::json!(grant);
    body
}

#[tokio::test]
async fn a_grant_signed_by_another_member_is_refused_before_google() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected().await;
    let foreign = grant(&other_member(), &h.aud, &[id]);
    refused(
        &h,
        with_grant(id, foreign),
        StatusCode::FORBIDDEN,
        "grant_invalid",
    )
    .await;
}

#[tokio::test]
async fn an_expired_grant_is_refused() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected().await;
    let now = SystemTime::now();
    let expired = grant_at(
        &member(),
        &h.aud,
        &[id],
        now - Duration::from_secs(1200),
        now - Duration::from_secs(1),
    );
    refused(
        &h,
        with_grant(id, expired),
        StatusCode::FORBIDDEN,
        "grant_expired",
    )
    .await;
}

#[tokio::test]
async fn a_grant_longer_than_twelve_hours_issued_ahead_or_ending_before_issue_is_refused() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected().await;
    let now = SystemTime::now();
    let twelve_hours = Duration::from_secs(12 * 3600);
    let overlong = grant_at(
        &member(),
        &h.aud,
        &[id],
        now,
        now + twelve_hours + Duration::from_secs(1),
    );
    let ahead = now + Duration::from_secs(120);
    let early = grant_at(
        &member(),
        &h.aud,
        &[id],
        ahead,
        ahead + Duration::from_secs(600),
    );
    let backwards = grant_at(
        &member(),
        &h.aud,
        &[id],
        now + Duration::from_secs(30),
        now + Duration::from_secs(10),
    );
    for grant in [overlong, early, backwards] {
        refused(
            &h,
            with_grant(id, grant),
            StatusCode::FORBIDDEN,
            "grant_expired",
        )
        .await;
    }
    let longest = grant_at(&member(), &h.aud, &[id], now, now + twelve_hours);
    assert_eq!(
        h.proxy(&with_grant(id, longest)).await.status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn a_grant_presented_by_another_instance_is_refused() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected().await;
    let second = h.ca.instance();
    let for_second = grant(&member(), &aud_of(&second), &[id]);
    let other_client = instance_client(&h.ca, Some(second));
    nothing_reaches(&h, async {
        let reply = h
            .post_with(
                &other_client,
                None,
                "/proxy",
                &with_grant(id, h.grant(&[id])),
            )
            .await
            .unwrap();
        assert_eq!(reply.status, StatusCode::FORBIDDEN);
        assert_eq!(reply.code(), "grant_invalid");
    })
    .await;
    refused(
        &h,
        with_grant(id, for_second),
        StatusCode::FORBIDDEN,
        "grant_invalid",
    )
    .await;
}

#[tokio::test]
async fn a_grant_for_another_connection_of_the_member_is_refused() {
    let Some(h) = harness().await else { return };
    let (named, _) = h.connected().await;
    let (other, _) = h.connect(&member(), "second@example.com").await;
    refused(
        &h,
        with_grant(id_of(&other), h.grant(&[named])),
        StatusCode::FORBIDDEN,
        "grant_invalid",
    )
    .await;
}

#[tokio::test]
async fn a_grant_naming_a_disconnected_connection_is_not_found() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected().await;
    let (gone, _) = h.connect(&member(), "second@example.com").await;
    let gone = id_of(&gone);
    assert_eq!(h.disconnect(&member(), gone).await.status, StatusCode::OK);
    refused(
        &h,
        with_grant(id, h.grant(&[id, gone])),
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await;
}

#[tokio::test]
async fn a_grant_naming_two_members_connections_is_refused() {
    let Some(h) = harness().await else { return };
    let (mine, _) = h.connected().await;
    let (theirs, _) = h.connect(&other_member(), "other@example.com").await;
    refused(
        &h,
        with_grant(mine, h.grant(&[mine, id_of(&theirs)])),
        StatusCode::FORBIDDEN,
        "grant_invalid",
    )
    .await;
}

#[tokio::test]
async fn a_grant_naming_no_or_more_than_sixteen_connections_is_malformed() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected().await;
    let mut seventeen = vec![id];
    seventeen.extend((0..16).map(|_| uuid::Uuid::now_v7()));
    for connections in [vec![], seventeen] {
        refused(
            &h,
            with_grant(id, h.grant(&connections)),
            StatusCode::BAD_REQUEST,
            "malformed",
        )
        .await;
    }
}
