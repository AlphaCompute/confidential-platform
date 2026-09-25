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
async fn a_member_connects_google_over_the_sealed_channel() {
    let Some(h) = harness().await else { return };
    let me = member();

    let (reply, consent) = h.connect(&me, EMAIL).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    assert!(reply.sealed);
    let id = id_of(&reply);
    assert_eq!(
        reply.body,
        json!({ "id": id.to_string(), "provider": "google", "account": EMAIL })
    );

    let listed = h.list(&me).await;
    assert_eq!(listed.status, StatusCode::OK);
    assert!(listed.sealed);
    assert_eq!(
        listed.body,
        json!({ "connections": [
            { "id": id.to_string(), "provider": "google", "account": EMAIL, "dead": false }
        ] })
    );

    let (hash, key): (Vec<u8>, Vec<u8>) =
        sqlx::query_as("select member_key_sha256, member_key from connections where id = $1")
            .bind(id)
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert_eq!(hash, me.sha256());
    assert_eq!(key, me.spki);

    let blob = h.stored_token(id).await.unwrap();
    let token = consent.refresh_token.as_bytes();
    assert!(!blob.windows(token.len()).any(|w| w == token));
    assert_eq!(
        store::open(&KEY, id.as_bytes(), &blob).unwrap().as_slice(),
        token
    );
    assert!(store::open(&KEY, uuid::Uuid::now_v7().as_bytes(), &blob).is_none());

    assert_eq!(count(&h, "pending_connects").await, 0);
}

#[tokio::test]
async fn every_route_refuses_a_missing_or_wrong_bearer_before_any_google_contact() {
    let Some(h) = harness().await else { return };
    let me = member();
    let mut channel = h.channel().await;
    let id = uuid::Uuid::now_v7();
    let routes = [
        ("POST", "/channel".to_string()),
        ("POST", "/connect/google".to_string()),
        ("POST", "/connect/finish".to_string()),
        ("POST", "/connections".to_string()),
        ("DELETE", format!("/connections/{id}")),
    ];
    for (method, path) in routes {
        let frame = channel
            .seal_request(
                method,
                &path,
                signed(&me, json!({ "op": "list" })).to_string().as_bytes(),
            )
            .unwrap();
        for bearer in [None, Some("wrong-bearer")] {
            let (status, text) = h
                .send(
                    bearer,
                    method,
                    &path,
                    Some(serde_json::to_string(&frame).unwrap()),
                )
                .await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {path}");
            let body: serde_json::Value = serde_json::from_str(&text).unwrap();
            assert_eq!(body["error"]["code"], "unauthorized");
        }
    }
    assert!(h.fake.with(|f| f.requests.is_empty()));
    assert_eq!(count(&h, "member_nonces").await, 0);
}

#[tokio::test]
async fn an_unknown_provider_is_not_found_and_a_malformed_member_key_is_refused() {
    let Some(h) = harness().await else { return };
    let me = member();
    let reply = h
        .as_member(
            &me,
            "POST",
            "/connect/unknown",
            json!({ "op": "connect", "provider": "unknown" }),
        )
        .await;
    assert!(reply.sealed);
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    assert_eq!(reply.body["error"]["code"], "not_found");

    let not_p256 = {
        use base64::Engine;
        base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(b"not a key")
    };
    for member_key in ["not base64url!".to_string(), not_p256] {
        let mut body = signed(&me, json!({ "op": "connect", "provider": "google" }));
        body["member_key"] = json!(member_key);
        let mut channel = h.channel().await;
        let reply = h
            .sealed(&mut channel, "POST", "/connect/google", &body)
            .await;
        assert!(reply.sealed);
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{}", reply.body);
        assert_eq!(reply.body["error"]["code"], "malformed");
    }
    assert_eq!(count(&h, "pending_connects").await, 0);
}

#[tokio::test]
async fn the_authorization_url_asks_google_for_exactly_six_scopes_with_s256_offline_and_consent() {
    let Some(h) = harness().await else { return };
    let me = member();
    let reply = h
        .as_member(
            &me,
            "POST",
            "/connect/google",
            json!({ "op": "connect", "provider": "google" }),
        )
        .await;
    let url = reqwest::Url::parse(reply.body["url"].as_str().unwrap()).unwrap();
    assert_eq!(url.scheme(), "https");
    assert_eq!(url.host_str(), Some("accounts.google.com"));
    assert_eq!(url.path(), "/o/oauth2/v2/auth");
    let query: std::collections::HashMap<String, String> = url.query_pairs().into_owned().collect();
    assert_eq!(query["client_id"], CLIENT_ID);
    assert_eq!(query["redirect_uri"], REDIRECT_URI);
    assert_eq!(query["response_type"], "code");
    assert_eq!(query["code_challenge_method"], "S256");
    assert_eq!(query["access_type"], "offline");
    assert_eq!(query["prompt"], "consent");
    assert_eq!(query["code_challenge"].len(), 43);
    assert_eq!(query["state"].len(), 43);
    let mut scopes: Vec<&str> = query["scope"].split(' ').collect();
    scopes.sort_unstable();
    assert_eq!(
        scopes,
        [
            "email",
            "https://www.googleapis.com/auth/calendar.readonly",
            "https://www.googleapis.com/auth/drive.file",
            "https://www.googleapis.com/auth/drive.readonly",
            "https://www.googleapis.com/auth/gmail.readonly",
            "openid",
        ]
    );
}

#[tokio::test]
async fn a_state_that_is_unknown_used_expired_or_another_members_never_reaches_google() {
    let Some(h) = harness().await else { return };
    let me = member();
    let refused = |reply: &Reply| {
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{}", reply.body);
        assert_eq!(reply.body["error"]["code"], "state_invalid");
    };

    refused(&h.finish(&me, "4/any", "no-such-state").await);

    let query = h.start("google", &me).await;
    let consent = h.fake.consent(&query["code_challenge"], EMAIL);
    assert_eq!(
        h.finish(&me, &consent.code, &query["state"]).await.status,
        StatusCode::OK
    );
    let again = h.fake.consent(&query["code_challenge"], EMAIL);
    refused(&h.finish(&me, &again.code, &query["state"]).await);

    let query = h.start("google", &me).await;
    sqlx::query("update pending_connects set exp = now() - interval '1 second'")
        .execute(&h.pool)
        .await
        .unwrap();
    let consent = h.fake.consent(&query["code_challenge"], EMAIL);
    refused(&h.finish(&me, &consent.code, &query["state"]).await);

    let query = h.start("google", &me).await;
    let consent = h.fake.consent(&query["code_challenge"], EMAIL);
    refused(
        &h.finish(&other_member(), &consent.code, &query["state"])
            .await,
    );
    refused(&h.finish(&me, &consent.code, &query["state"]).await);

    assert_eq!(h.fake.with(|f| f.hits("/token")), 1);
}

#[tokio::test]
async fn two_concurrent_finishes_with_one_state_connect_exactly_once() {
    let Some(h) = harness().await else { return };
    let me = member();
    let query = h.start("google", &me).await;
    let consent = h.fake.consent(&query["code_challenge"], EMAIL);
    let (a, b) = tokio::join!(
        h.finish(&me, &consent.code, &query["state"]),
        h.finish(&me, &consent.code, &query["state"]),
    );
    let mut statuses = [a.status, b.status];
    statuses.sort();
    assert_eq!(statuses, [StatusCode::OK, StatusCode::BAD_REQUEST]);
    assert_eq!(count(&h, "connections").await, 1);
    assert_eq!(h.fake.with(|f| f.hits("/token")), 1);
}

#[tokio::test]
async fn a_failed_exchange_or_account_lookup_answers_exchange_failed_and_writes_nothing() {
    let Some(h) = harness().await else { return };
    let me = member();
    let failures: [fn(&mut Fake); 3] = [
        |f| f.token_status = StatusCode::BAD_REQUEST,
        |f| f.omit_refresh_token = true,
        |f| f.account_status = StatusCode::UNAUTHORIZED,
    ];
    for fail in failures {
        h.fake.with(|f| {
            f.token_status = StatusCode::OK;
            f.omit_refresh_token = false;
            f.account_status = StatusCode::OK;
            fail(f);
        });
        let (reply, _) = h.connect(&me, EMAIL).await;
        assert_eq!(reply.status, StatusCode::BAD_GATEWAY, "{}", reply.body);
        assert_eq!(reply.body["error"]["code"], "exchange_failed");
    }
    assert_eq!(count(&h, "connections").await, 0);
}

#[tokio::test]
async fn disconnect_revokes_locally_and_at_google() {
    let Some(h) = harness().await else { return };
    let me = member();
    let (reply, consent) = h.connect(&me, EMAIL).await;
    let id = id_of(&reply);

    let reply = h.disconnect(&me, id).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert!(reply.sealed);
    assert_eq!(reply.body, json!({}));
    let revoked: bool =
        sqlx::query_scalar("select revoked_at is not null from connections where id = $1")
            .bind(id)
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert!(revoked);
    assert_eq!(h.stored_token(id).await, None);
    assert_eq!(h.fake.with(|f| f.revoked_tokens()), [consent.refresh_token]);

    let listed = h.list(&me).await;
    assert_eq!(listed.body, json!({ "connections": [] }));
}

#[tokio::test]
async fn disconnect_leaves_google_alone_while_another_member_holds_the_same_account() {
    let Some(h) = harness().await else { return };
    let me = member();
    let (mine, _) = h.connect(&me, EMAIL).await;
    let (theirs, their_consent) = h.connect(&other_member(), EMAIL).await;

    let reply = h.disconnect(&me, id_of(&mine)).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(h.stored_token(id_of(&mine)).await, None);
    assert_eq!(h.fake.with(|f| f.hits("/revoke")), 0);

    let reply = h.disconnect(&other_member(), id_of(&theirs)).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(
        h.fake.with(|f| f.revoked_tokens()),
        [their_consent.refresh_token]
    );
}

#[tokio::test]
async fn the_last_of_two_concurrent_disconnects_of_one_account_revokes_at_google() {
    let Some(h) = harness().await else { return };
    let me = member();
    let (mine, my_consent) = h.connect(&me, EMAIL).await;
    let (theirs, _) = h.connect(&other_member(), EMAIL).await;

    let mut their_disconnect = h.pool.begin().await.unwrap();
    sqlx::query(
        "update connections set revoked_at = now(), enc_refresh_token = null where id = $1",
    )
    .bind(id_of(&theirs))
    .execute(&mut *their_disconnect)
    .await
    .unwrap();
    let my_disconnect = h.disconnect(&me, id_of(&mine));
    let commit_theirs_while_mine_waits = async {
        loop {
            let waiting: i64 = sqlx::query_scalar(
                "select count(*) from pg_stat_activity
                 where datname = current_database() and wait_event_type = 'Lock'",
            )
            .fetch_one(&h.pool)
            .await
            .unwrap();
            if waiting > 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        their_disconnect.commit().await.unwrap();
    };
    let (reply, ()) = tokio::join!(my_disconnect, commit_theirs_while_mine_waits);

    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(
        h.fake.with(|f| f.revoked_tokens()),
        [my_consent.refresh_token]
    );
}

#[tokio::test]
async fn disconnect_succeeds_even_when_google_refuses_the_revoke() {
    let Some(h) = harness().await else { return };
    let me = member();
    let (reply, _) = h.connect(&me, EMAIL).await;
    let id = id_of(&reply);
    h.fake
        .with(|f| f.revoke_status = StatusCode::INTERNAL_SERVER_ERROR);

    let reply = h.disconnect(&me, id).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(h.stored_token(id).await, None);
    assert_eq!(h.fake.with(|f| f.hits("/revoke")), 1);
}

#[tokio::test]
async fn disconnect_of_a_foreign_unknown_or_revoked_connection_is_not_found() {
    let Some(h) = harness().await else { return };
    let me = member();
    let (reply, _) = h.connect(&me, EMAIL).await;
    let id = id_of(&reply);
    let not_found = |reply: Reply| {
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{}", reply.body);
        assert_eq!(reply.body["error"]["code"], "not_found");
    };

    not_found(h.disconnect(&other_member(), id).await);
    assert!(h.stored_token(id).await.is_some());
    not_found(h.disconnect(&me, uuid::Uuid::now_v7()).await);
    not_found(
        h.as_member(
            &me,
            "DELETE",
            "/connections/not-a-uuid",
            json!({ "op": "disconnect", "connection_id": id }),
        )
        .await,
    );

    assert_eq!(h.disconnect(&me, id).await.status, StatusCode::OK);
    not_found(h.disconnect(&me, id).await);
    assert_eq!(h.fake.with(|f| f.hits("/revoke")), 1);
}

#[tokio::test]
async fn reconnecting_a_dead_account_keeps_its_id_and_seals_the_new_token() {
    let Some(h) = harness().await else { return };
    let me = member();
    let (first, _) = h.connect(&me, EMAIL).await;
    let id = id_of(&first);
    sqlx::query("update connections set dead_at = now() where id = $1")
        .bind(id)
        .execute(&h.pool)
        .await
        .unwrap();
    let listed = h.list(&me).await;
    assert_eq!(listed.body["connections"][0]["dead"], true);

    let (second, consent) = h.connect(&me, EMAIL).await;
    assert_eq!(second.status, StatusCode::OK);
    assert_eq!(id_of(&second), id);
    let listed = h.list(&me).await;
    assert_eq!(listed.body["connections"][0]["dead"], false);
    assert_eq!(listed.body["connections"].as_array().unwrap().len(), 1);
    let blob = h.stored_token(id).await.unwrap();
    assert_eq!(
        store::open(&KEY, id.as_bytes(), &blob).unwrap().as_slice(),
        consent.refresh_token.as_bytes()
    );
}

#[tokio::test]
async fn two_accounts_are_listed_in_the_order_they_were_connected() {
    let Some(h) = harness().await else { return };
    let me = member();
    let (a, _) = h.connect(&me, "b@example.com").await;
    let (b, _) = h.connect(&me, "a@example.com").await;
    let listed = h.list(&me).await;
    let ids: Vec<&str> = listed.body["connections"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].as_str().unwrap())
        .collect();
    assert_eq!(
        ids,
        [
            a.body["id"].as_str().unwrap(),
            b.body["id"].as_str().unwrap()
        ]
    );

    let other = h.list(&other_member()).await;
    assert_eq!(other.body, json!({ "connections": [] }));
}

#[tokio::test]
async fn healthz_and_ready_need_no_bearer() {
    let Some(h) = harness().await else { return };
    for path in ["/healthz", "/ready"] {
        let reply = h.call_as(None, "GET", path, None).await;
        assert_eq!(reply.status, StatusCode::OK, "{path}");
        assert_eq!(reply.body, json!({ "ok": true }));
    }
}

#[tokio::test]
async fn a_reconnect_that_waits_on_a_disconnect_makes_a_new_connection() {
    let Some(h) = harness().await else { return };
    let me = member();
    let (first, _) = h.connect(&me, EMAIL).await;
    let id = id_of(&first);

    let mut disconnect = h.pool.begin().await.unwrap();
    sqlx::query("select id from connections where id = $1 for update")
        .bind(id)
        .execute(&mut *disconnect)
        .await
        .unwrap();
    let reconnect = h.connect(&me, EMAIL);
    let revoke_while_reconnect_waits = async {
        loop {
            let waiting: i64 = sqlx::query_scalar(
                "select count(*) from pg_stat_activity
                 where datname = current_database() and wait_event_type = 'Lock'",
            )
            .fetch_one(&h.pool)
            .await
            .unwrap();
            if waiting > 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        sqlx::query(
            "update connections set revoked_at = now(), enc_refresh_token = null where id = $1",
        )
        .bind(id)
        .execute(&mut *disconnect)
        .await
        .unwrap();
        disconnect.commit().await.unwrap();
    };
    let ((second, _), ()) = tokio::join!(reconnect, revoke_while_reconnect_waits);

    assert_eq!(second.status, StatusCode::OK, "{}", second.body);
    assert_ne!(id_of(&second), id);
    assert_eq!(h.stored_token(id).await, None);
}

#[tokio::test]
async fn a_connection_follows_the_google_account_not_its_email() {
    let Some(h) = harness().await else { return };
    let me = &member();
    let h = &h;
    let connect_as = |subject: &'static str, email: &'static str| async move {
        let query = h.start("google", me).await;
        let consent = h
            .fake
            .consent_on("google", &query["code_challenge"], subject, email);
        let reply = h.finish(me, &consent.code, &query["state"]).await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        id_of(&reply)
    };

    let first = connect_as("account-1", "old@example.com").await;
    let renamed = connect_as("account-1", "new@example.com").await;
    assert_eq!(renamed, first);
    let listed = h.list(me).await;
    assert_eq!(listed.body["connections"][0]["account"], "new@example.com");
    assert_eq!(listed.body["connections"].as_array().unwrap().len(), 1);

    let reassigned = connect_as("account-2", "new@example.com").await;
    assert_ne!(reassigned, first);
    assert_eq!(count(h, "connections").await, 2);
}

/// One signed request per member route, for `id` where the route names a connection.
fn member_routes(id: uuid::Uuid) -> [(&'static str, String, serde_json::Value); 4] {
    [
        (
            "POST",
            "/connect/google".to_string(),
            json!({ "op": "connect", "provider": "google" }),
        ),
        (
            "POST",
            "/connect/finish".to_string(),
            json!({ "op": "finish", "state": "s", "code": "c" }),
        ),
        ("POST", "/connections".to_string(), json!({ "op": "list" })),
        (
            "DELETE",
            format!("/connections/{id}"),
            json!({ "op": "disconnect", "connection_id": id }),
        ),
    ]
}

async fn nothing_stored(h: &Harness) {
    for table in ["pending_connects", "connections", "member_nonces"] {
        assert_eq!(count(h, table).await, 0, "{table}");
    }
}

#[tokio::test]
async fn a_finish_signed_by_another_key_is_state_invalid_and_spends_the_state() {
    let Some(h) = harness().await else { return };
    let me = member();
    let query = h.start("google", &me).await;
    let consent = h.fake.consent(&query["code_challenge"], EMAIL);

    for key in [other_member(), member()] {
        let reply = h.finish(&key, &consent.code, &query["state"]).await;
        assert!(reply.sealed);
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{}", reply.body);
        assert_eq!(reply.body["error"]["code"], "state_invalid");
    }
    assert_eq!(h.fake.with(|f| f.hits("/token")), 0);
    assert_eq!(count(&h, "connections").await, 0);
}

#[tokio::test]
async fn another_key_lists_none_of_the_connections_and_cannot_disconnect_them() {
    let Some(h) = harness().await else { return };
    let me = member();
    let (reply, _) = h.connect(&me, EMAIL).await;
    let id = id_of(&reply);

    let theirs = h.list(&other_member()).await;
    assert!(theirs.sealed);
    assert_eq!(theirs.body, json!({ "connections": [] }));

    let reply = h.disconnect(&other_member(), id).await;
    assert!(reply.sealed);
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    assert_eq!(reply.body["error"]["code"], "not_found");
    assert!(h.stored_token(id).await.is_some());
    assert_eq!(
        h.list(&me).await.body["connections"][0]["id"],
        id.to_string()
    );
    assert_eq!(h.fake.with(|f| f.hits("/revoke")), 0);
}

#[tokio::test]
async fn a_request_issued_more_than_a_minute_off_is_request_stale() {
    let Some(h) = harness().await else { return };
    let me = member();
    // Times are whole seconds on both ends, so 61 seconds ahead can read as 60 once the
    // broker's clock ticks over.
    let off = std::time::Duration::from_secs(62);
    nothing_reaches(&h, async {
        for ahead in [false, true] {
            for (method, path, fields) in member_routes(uuid::Uuid::now_v7()) {
                let mut channel = h.channel().await;
                let now = std::time::SystemTime::now();
                let at = if ahead { now + off } else { now - off };
                let body = signed_at(&me, fields, at);
                let reply = h.sealed(&mut channel, method, &path, &body).await;
                assert!(reply.sealed);
                assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{method} {path}");
                assert_eq!(reply.body["error"]["code"], "request_stale");
            }
        }
    })
    .await;
    nothing_stored(&h).await;
}

#[tokio::test]
async fn a_nonce_is_used_once_even_across_a_restart() {
    let Some(mut h) = harness().await else { return };
    let me = member();
    let body = signed(&me, json!({ "op": "list" }));

    let mut first = h.channel().await;
    let reply = h.sealed(&mut first, "POST", "/connections", &body).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);

    let replayed = |reply: Reply| {
        assert!(reply.sealed);
        assert_eq!(reply.status, StatusCode::CONFLICT, "{}", reply.body);
        assert_eq!(reply.body["error"]["code"], "nonce_replayed");
    };
    let mut second = h.channel().await;
    replayed(h.sealed(&mut second, "POST", "/connections", &body).await);

    h.restart();
    let stale = h
        .sealed(&mut first, "POST", "/connections", &json!({}))
        .await;
    assert!(!stale.sealed);
    assert_eq!(stale.status, StatusCode::CONFLICT);
    assert_eq!(stale.body["error"]["code"], "channel_unknown");
    let mut third = h.channel().await;
    replayed(h.sealed(&mut third, "POST", "/connections", &body).await);
    assert_eq!(count(&h, "member_nonces").await, 1);
}

#[tokio::test]
async fn another_keys_signature_another_op_or_another_target_is_refused() {
    let Some(h) = harness().await else { return };
    let me = member();
    let id = uuid::Uuid::now_v7();
    let mut foreign_key = signed(&me, json!({ "op": "connect", "provider": "google" }));
    foreign_key["member_key"] = json!(other_member().key_b64());
    let cases = [
        (
            "POST",
            "/connect/google".to_string(),
            foreign_key,
            "signature_invalid",
        ),
        (
            "POST",
            "/connect/google".to_string(),
            signed(&me, json!({ "op": "list" })),
            "malformed",
        ),
        (
            "POST",
            "/connect/google".to_string(),
            signed(&me, json!({ "op": "connect", "provider": "dropbox" })),
            "malformed",
        ),
        (
            "POST",
            "/connect/finish".to_string(),
            signed(&me, json!({ "op": "connect", "provider": "google" })),
            "malformed",
        ),
        (
            "POST",
            "/connections".to_string(),
            signed(&me, json!({ "op": "disconnect", "connection_id": id })),
            "malformed",
        ),
        (
            "DELETE",
            format!("/connections/{id}"),
            signed(
                &me,
                json!({ "op": "disconnect", "connection_id": uuid::Uuid::now_v7() }),
            ),
            "malformed",
        ),
        (
            "POST",
            "/connect/google".to_string(),
            signed(
                &me,
                json!({ "op": "connect", "provider": "google", "member": hex::encode(me.sha256()) }),
            ),
            "malformed",
        ),
    ];
    nothing_reaches(&h, async {
        for (method, path, body, code) in cases {
            let mut channel = h.channel().await;
            let reply = h.sealed(&mut channel, method, &path, &body).await;
            assert!(reply.sealed);
            assert_eq!(reply.body["error"]["code"], code, "{method} {path} {body}");
        }
    })
    .await;
    nothing_stored(&h).await;
}

#[tokio::test]
async fn a_sealed_request_without_a_signature_is_refused_on_every_route() {
    let Some(h) = harness().await else { return };
    let me = member();
    nothing_reaches(&h, async {
        for (method, path, fields) in member_routes(uuid::Uuid::now_v7()) {
            let signed = signed(&me, fields);
            for body in [
                json!({ "document": signed["document"], "member_key": me.key_b64() }),
                json!({ "member": hex::encode(me.sha256()) }),
            ] {
                let mut channel = h.channel().await;
                let reply = h.sealed(&mut channel, method, &path, &body).await;
                assert!(reply.sealed);
                assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{method} {path}");
                assert_eq!(reply.body["error"]["code"], "malformed");
            }
        }
    })
    .await;
    nothing_stored(&h).await;
}

#[tokio::test]
async fn the_connect_bearer_alone_opens_no_member_route() {
    let Some(h) = harness().await else { return };
    let me = member();
    let id = uuid::Uuid::now_v7();
    nothing_reaches(&h, async {
        for (method, path, _) in member_routes(id) {
            for body in [
                json!({ "member": hex::encode(me.sha256()) }),
                json!({ "member": hex::encode(me.sha256()), "code": "4/any", "state": "s" }),
            ] {
                let reply = h.call(method, &path, Some(body)).await;
                assert!(!reply.sealed);
                assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{method} {path}");
                assert_eq!(reply.body["error"]["code"], "frame_invalid");
            }
        }
        let listed = h
            .call(
                "GET",
                &format!("/connections?member={}", hex::encode(me.sha256())),
                None,
            )
            .await;
        assert_eq!(listed.status, StatusCode::METHOD_NOT_ALLOWED);
    })
    .await;
    nothing_stored(&h).await;
}

#[tokio::test]
async fn a_frame_opened_twice_moved_to_another_route_or_on_an_unknown_channel_is_refused() {
    let Some(h) = harness().await else { return };
    let me = member();
    nothing_reaches(&h, async {
        let mut channel = h.channel().await;
        let frame = channel
            .seal_request(
                "POST",
                "/connections",
                signed(&me, json!({ "op": "list" })).to_string().as_bytes(),
            )
            .unwrap();
        let reply = h.send_frame(&channel, "POST", "/connections", &frame).await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        let again = h.send_frame(&channel, "POST", "/connections", &frame).await;
        assert!(!again.sealed);
        assert_eq!(again.status, StatusCode::CONFLICT);
        assert_eq!(again.body["error"]["code"], "replayed");

        let finish = json!({ "op": "finish", "state": "s", "code": "c" });
        let moved = channel
            .seal_request(
                "POST",
                "/connect/finish",
                signed(&me, finish).to_string().as_bytes(),
            )
            .unwrap();
        let reply = h.send_frame(&channel, "POST", "/connections", &moved).await;
        assert!(!reply.sealed);
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
        assert_eq!(reply.body["error"]["code"], "frame_invalid");

        let mut unknown = channel
            .seal_request(
                "POST",
                "/connections",
                signed(&me, json!({ "op": "list" })).to_string().as_bytes(),
            )
            .unwrap();
        unknown.channel = "AAAAAAAAAAAAAAAAAAAAAA".into();
        let reply = h
            .send_frame(&channel, "POST", "/connections", &unknown)
            .await;
        assert!(!reply.sealed);
        assert_eq!(reply.status, StatusCode::CONFLICT);
        assert_eq!(reply.body["error"]["code"], "channel_unknown");
    })
    .await;
    assert_eq!(count(&h, "member_nonces").await, 1);
}

#[tokio::test]
async fn a_rows_key_hash_cannot_be_written() {
    let Some(h) = harness().await else { return };
    let written = sqlx::query("update connections set member_key_sha256 = $1")
        .bind(member().sha256().to_vec())
        .execute(&h.pool)
        .await
        .unwrap_err();
    assert!(
        written.to_string().contains("only be updated to DEFAULT"),
        "{written}"
    );
}
