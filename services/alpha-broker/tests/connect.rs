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
async fn a_member_connects_google_and_the_stored_token_is_sealed() {
    let Some(h) = harness().await else { return };

    let (reply, consent) = h.connect(MEMBER, EMAIL).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    let id = id_of(&reply);
    assert_eq!(
        reply.body,
        json!({ "id": id.to_string(), "provider": "google", "account": EMAIL })
    );

    let listed = h
        .call("GET", &format!("/connections?member={MEMBER}"), None)
        .await;
    assert_eq!(listed.status, StatusCode::OK);
    assert_eq!(
        listed.body,
        json!({ "connections": [
            { "id": id.to_string(), "provider": "google", "account": EMAIL, "dead": false }
        ] })
    );

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
    let finish = json!({ "member": MEMBER, "code": "c", "state": "s" });
    let routes = [
        (
            "POST",
            "/connect/google".to_string(),
            Some(json!({ "member": MEMBER })),
        ),
        ("POST", "/connect/finish".to_string(), Some(finish)),
        ("GET", format!("/connections?member={MEMBER}"), None),
        (
            "DELETE",
            format!("/connections/{}?member={MEMBER}", uuid::Uuid::now_v7()),
            None,
        ),
    ];
    for (method, uri, body) in routes {
        for bearer in [None, Some("wrong-bearer")] {
            let reply = h.call_as(bearer, method, &uri, body.clone()).await;
            assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{method} {uri}");
            assert_eq!(reply.body["error"]["code"], "unauthorized");
        }
    }
    assert!(h.google.with(|f| f.requests.is_empty()));
}

#[tokio::test]
async fn an_unknown_provider_is_not_found_and_a_malformed_member_is_refused() {
    let Some(h) = harness().await else { return };
    let reply = h
        .call(
            "POST",
            "/connect/dropbox",
            Some(json!({ "member": MEMBER })),
        )
        .await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    assert_eq!(reply.body["error"]["code"], "not_found");

    let id = uuid::Uuid::now_v7();
    for member in [
        &MEMBER[1..],
        &MEMBER.to_uppercase().replace('1', "A"),
        &"zz".repeat(32),
    ] {
        let replies = [
            h.call("POST", "/connect/google", Some(json!({ "member": member })))
                .await,
            h.call("GET", &format!("/connections?member={member}"), None)
                .await,
            h.call(
                "DELETE",
                &format!("/connections/{id}?member={member}"),
                None,
            )
            .await,
        ];
        for reply in replies {
            assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{member}");
            assert_eq!(reply.body["error"]["code"], "malformed");
        }
    }
    assert_eq!(count(&h, "pending_connects").await, 0);
}

#[tokio::test]
async fn the_authorization_url_asks_google_for_exactly_six_scopes_with_s256_offline_and_consent() {
    let Some(h) = harness().await else { return };
    let reply = h
        .call("POST", "/connect/google", Some(json!({ "member": MEMBER })))
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
    let refused = |reply: &Reply| {
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{}", reply.body);
        assert_eq!(reply.body["error"]["code"], "state_invalid");
    };

    refused(&h.finish(MEMBER, "4/any", "no-such-state").await);

    let query = h.start(MEMBER).await;
    let consent = h.google.consent(&query["code_challenge"], EMAIL);
    assert_eq!(
        h.finish(MEMBER, &consent.code, &query["state"])
            .await
            .status,
        StatusCode::OK
    );
    let again = h.google.consent(&query["code_challenge"], EMAIL);
    refused(&h.finish(MEMBER, &again.code, &query["state"]).await);

    let query = h.start(MEMBER).await;
    sqlx::query("update pending_connects set exp = now() - interval '1 second'")
        .execute(&h.pool)
        .await
        .unwrap();
    let consent = h.google.consent(&query["code_challenge"], EMAIL);
    refused(&h.finish(MEMBER, &consent.code, &query["state"]).await);

    let query = h.start(MEMBER).await;
    let consent = h.google.consent(&query["code_challenge"], EMAIL);
    refused(&h.finish(OTHER_MEMBER, &consent.code, &query["state"]).await);
    refused(&h.finish(MEMBER, &consent.code, &query["state"]).await);

    assert_eq!(h.google.with(|f| f.hits("/token")), 1);
}

#[tokio::test]
async fn two_concurrent_finishes_with_one_state_connect_exactly_once() {
    let Some(h) = harness().await else { return };
    let query = h.start(MEMBER).await;
    let consent = h.google.consent(&query["code_challenge"], EMAIL);
    let (a, b) = tokio::join!(
        h.finish(MEMBER, &consent.code, &query["state"]),
        h.finish(MEMBER, &consent.code, &query["state"]),
    );
    let mut statuses = [a.status, b.status];
    statuses.sort();
    assert_eq!(statuses, [StatusCode::OK, StatusCode::BAD_REQUEST]);
    assert_eq!(count(&h, "connections").await, 1);
    assert_eq!(h.google.with(|f| f.hits("/token")), 1);
}

#[tokio::test]
async fn a_failed_exchange_or_account_lookup_answers_exchange_failed_and_writes_nothing() {
    let Some(h) = harness().await else { return };
    let failures: [fn(&mut Fake); 3] = [
        |f| f.token_status = StatusCode::BAD_REQUEST,
        |f| f.omit_refresh_token = true,
        |f| f.account_status = StatusCode::UNAUTHORIZED,
    ];
    for fail in failures {
        h.google.with(|f| {
            f.token_status = StatusCode::OK;
            f.omit_refresh_token = false;
            f.account_status = StatusCode::OK;
            fail(f);
        });
        let (reply, _) = h.connect(MEMBER, EMAIL).await;
        assert_eq!(reply.status, StatusCode::BAD_GATEWAY, "{}", reply.body);
        assert_eq!(reply.body["error"]["code"], "exchange_failed");
    }
    assert_eq!(count(&h, "connections").await, 0);
}

#[tokio::test]
async fn disconnect_revokes_locally_and_at_google() {
    let Some(h) = harness().await else { return };
    let (reply, consent) = h.connect(MEMBER, EMAIL).await;
    let id = id_of(&reply);

    let reply = h
        .call(
            "DELETE",
            &format!("/connections/{id}?member={MEMBER}"),
            None,
        )
        .await;
    assert_eq!(reply.status, StatusCode::NO_CONTENT);
    let revoked: bool =
        sqlx::query_scalar("select revoked_at is not null from connections where id = $1")
            .bind(id)
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert!(revoked);
    assert_eq!(h.stored_token(id).await, None);
    let revokes: Vec<String> = h.google.with(|f| {
        f.requests
            .iter()
            .filter(|(p, _)| p == "/revoke")
            .map(|(_, form)| form["token"].clone())
            .collect()
    });
    assert_eq!(revokes, [consent.refresh_token]);

    let listed = h
        .call("GET", &format!("/connections?member={MEMBER}"), None)
        .await;
    assert_eq!(listed.body, json!({ "connections": [] }));
}

#[tokio::test]
async fn disconnect_answers_204_even_when_google_refuses_the_revoke() {
    let Some(h) = harness().await else { return };
    let (reply, _) = h.connect(MEMBER, EMAIL).await;
    let id = id_of(&reply);
    h.google
        .with(|f| f.revoke_status = StatusCode::INTERNAL_SERVER_ERROR);

    let reply = h
        .call(
            "DELETE",
            &format!("/connections/{id}?member={MEMBER}"),
            None,
        )
        .await;
    assert_eq!(reply.status, StatusCode::NO_CONTENT);
    assert_eq!(h.stored_token(id).await, None);
    assert_eq!(h.google.with(|f| f.hits("/revoke")), 1);
}

#[tokio::test]
async fn disconnect_of_a_foreign_unknown_or_revoked_connection_is_not_found() {
    let Some(h) = harness().await else { return };
    let (reply, _) = h.connect(MEMBER, EMAIL).await;
    let id = id_of(&reply);
    let not_found = |reply: Reply| {
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{}", reply.body);
        assert_eq!(reply.body["error"]["code"], "not_found");
    };

    not_found(
        h.call(
            "DELETE",
            &format!("/connections/{id}?member={OTHER_MEMBER}"),
            None,
        )
        .await,
    );
    assert!(h.stored_token(id).await.is_some());
    not_found(
        h.call(
            "DELETE",
            &format!("/connections/{}?member={MEMBER}", uuid::Uuid::now_v7()),
            None,
        )
        .await,
    );
    not_found(
        h.call(
            "DELETE",
            &format!("/connections/not-a-uuid?member={MEMBER}"),
            None,
        )
        .await,
    );

    let path = format!("/connections/{id}?member={MEMBER}");
    assert_eq!(
        h.call("DELETE", &path, None).await.status,
        StatusCode::NO_CONTENT
    );
    not_found(h.call("DELETE", &path, None).await);
    assert_eq!(h.google.with(|f| f.hits("/revoke")), 1);
}

#[tokio::test]
async fn reconnecting_a_dead_account_keeps_its_id_and_seals_the_new_token() {
    let Some(h) = harness().await else { return };
    let (first, _) = h.connect(MEMBER, EMAIL).await;
    let id = id_of(&first);
    sqlx::query("update connections set dead_at = now() where id = $1")
        .bind(id)
        .execute(&h.pool)
        .await
        .unwrap();
    let listed = h
        .call("GET", &format!("/connections?member={MEMBER}"), None)
        .await;
    assert_eq!(listed.body["connections"][0]["dead"], true);

    let (second, consent) = h.connect(MEMBER, EMAIL).await;
    assert_eq!(second.status, StatusCode::OK);
    assert_eq!(id_of(&second), id);
    let listed = h
        .call("GET", &format!("/connections?member={MEMBER}"), None)
        .await;
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
    let (a, _) = h.connect(MEMBER, "b@example.com").await;
    let (b, _) = h.connect(MEMBER, "a@example.com").await;
    let listed = h
        .call("GET", &format!("/connections?member={MEMBER}"), None)
        .await;
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

    let other = h
        .call("GET", &format!("/connections?member={OTHER_MEMBER}"), None)
        .await;
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
    let (first, _) = h.connect(MEMBER, EMAIL).await;
    let id = id_of(&first);

    let mut disconnect = h.pool.begin().await.unwrap();
    sqlx::query("select id from connections where id = $1 for update")
        .bind(id)
        .execute(&mut *disconnect)
        .await
        .unwrap();
    let reconnect = h.connect(MEMBER, EMAIL);
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
