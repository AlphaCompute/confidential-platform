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
    let token = bearer_of(&seen.headers);
    assert!(token.starts_with("sl.") && issued.contains(&token));
    assert_ne!(token, consent.access_token);
}

#[tokio::test]
async fn each_of_the_ten_reads_reaches_dropbox_with_post_and_the_callers_body() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected_to("dropbox").await;
    for entry in alpha_broker::oauth::DROPBOX.reads {
        let url = format!("https://{}{}", entry.host, entry.path);
        let mut body = dropbox_read(id, &url);
        if entry.host == "api.dropboxapi.com" && entry.path != DROPBOX_ACCOUNT {
            body["body"] = json!({ "path": "/Notes" });
        } else if entry.host == "content.dropboxapi.com" {
            body["headers"] = json!({ "Dropbox-API-Arg": r#"{"path":"/Notes.txt"}"# });
        }
        let reply = h.proxy(&body).await;
        assert_ne!(reply.status, StatusCode::FORBIDDEN, "{url}");
        if entry.path == DROPBOX_ACCOUNT {
            let lookups = h.fake.with(|f| {
                f.requests
                    .iter()
                    .filter(|(p, _)| p == DROPBOX_ACCOUNT)
                    .count()
            });
            assert!(lookups >= 2, "{url}");
            continue;
        }
        let seen = h.fake.with(|f| f.data.last().cloned().unwrap());
        assert_eq!(
            (seen.method.as_str(), seen.host.as_str(), seen.path.as_str()),
            ("POST", entry.host, entry.path)
        );
        if body.get("body").is_some() {
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&seen.body).unwrap(),
                json!({ "path": "/Notes" })
            );
        } else {
            assert!(seen.body.is_empty(), "{url}");
            assert_eq!(seen.headers["dropbox-api-arg"], r#"{"path":"/Notes.txt"}"#);
        }
    }
}

#[tokio::test]
async fn only_the_providers_listed_headers_pass_and_a_value_with_a_line_break_is_malformed() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected_to("dropbox").await;
    let (google, _) = h.connected().await;
    let with = |id, url: &str, headers: serde_json::Value| {
        let mut body = dropbox_read(id, url);
        body["body"] = json!({ "path": "" });
        body["headers"] = headers;
        body
    };

    let reply = h
        .proxy(&with(
            id,
            LIST_FOLDER,
            json!({ "Dropbox-API-Arg": "{}", "DROPBOX-API-PATH-ROOT": PATH_ROOT }),
        ))
        .await;
    assert_eq!(reply.status, StatusCode::OK);
    let seen = h.fake.with(|f| f.data.last().cloned().unwrap());
    assert_eq!(seen.headers["dropbox-api-arg"], "{}");
    assert_eq!(seen.headers["dropbox-api-path-root"], PATH_ROOT);
    let before = h.fake.with(|f| f.data.len());

    for name in ["authorization", "Host", "cookie", "content-type", "x-other"] {
        let reply = h.proxy(&with(id, LIST_FOLDER, json!({ name: "x" }))).await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN, "{name}");
        assert_eq!(reply.code(), "not_allowed");
    }
    let mut on_google = read(google, "https://www.googleapis.com/drive/v3/files");
    on_google["headers"] = json!({ "dropbox-api-arg": "{}" });
    let reply = h.proxy(&on_google).await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);

    for value in ["{}\r\nx-other: 1", "{}\nx", "{}\rx"] {
        let reply = h
            .proxy(&with(id, LIST_FOLDER, json!({ "Dropbox-API-Arg": value })))
            .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{value:?}");
        assert_eq!(reply.code(), "malformed");
    }
    assert_eq!(h.fake.with(|f| f.data.len()), before);
}

#[tokio::test]
async fn an_invalid_grant_marks_a_dropbox_connection_dead() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected_to("dropbox").await;
    h.fake.with(|f| f.token_status = StatusCode::BAD_REQUEST);
    let mut body = dropbox_read(id, LIST_FOLDER);
    body["body"] = json!({ "path": "" });

    let reply = h.proxy(&body).await;
    assert_eq!(reply.status, StatusCode::CONFLICT);
    assert_eq!(reply.code(), "reconnect_required");
    let listed = h
        .call("GET", &format!("/connections?member={MEMBER}"), None)
        .await;
    assert_eq!(listed.body["connections"][0]["dead"], true);

    let again = h.proxy(&body).await;
    assert_eq!(again.status, StatusCode::CONFLICT);
    assert_eq!(h.fake.with(|f| f.refreshes()), 1);
    assert!(h.fake.with(|f| f.data.is_empty()));
}

#[tokio::test]
async fn a_download_of_exactly_the_cap_is_relayed_and_one_byte_more_is_too_large() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected_to("dropbox").await;
    let cap = alpha_broker::proxy::MAX_RESPONSE;
    let mut body = dropbox_read(id, "https://content.dropboxapi.com/2/files/download");
    body["headers"] = json!({ "Dropbox-API-Arg": r#"{"path":"/big.bin"}"# });

    h.fake.with(|f| f.media_size = cap);
    let whole = h.proxy(&body).await;
    assert_eq!(whole.status, StatusCode::OK);
    assert_eq!(whole.bytes.len(), cap);

    h.fake.with(|f| f.media_size = cap + 1);
    let over = h.proxy(&body).await;
    assert_eq!(over.status, StatusCode::BAD_GATEWAY);
    assert_eq!(over.code(), "too_large");
}

#[tokio::test]
async fn disconnect_revokes_at_dropbox_with_a_fresh_access_token() {
    let Some(h) = harness().await else { return };
    let (id, consent) = h.connected_to("dropbox").await;
    let reply = h
        .call(
            "DELETE",
            &format!("/connections/{id}?member={MEMBER}"),
            None,
        )
        .await;
    assert_eq!(reply.status, StatusCode::NO_CONTENT);
    assert_eq!(h.stored_token(id).await, None);
    let (paths, refreshed, revoked) = h.fake.with(|f| {
        let paths: Vec<String> = f.requests.iter().map(|(p, _)| p.clone()).collect();
        let refreshed = f
            .requests
            .iter()
            .rev()
            .find_map(|(p, form)| (p == DROPBOX_TOKEN).then(|| form["refresh_token"].clone()));
        (paths, refreshed, f.revoked_tokens())
    });
    assert_eq!(
        paths[paths.len() - 2..],
        [DROPBOX_TOKEN.to_string(), DROPBOX_REVOKE.to_string()]
    );
    assert_eq!(refreshed.as_deref(), Some(consent.refresh_token.as_str()));
    let [revoked] = &revoked[..] else {
        panic!("{revoked:?}")
    };
    assert!(revoked.starts_with("sl.fake-refreshed-"));
}

#[tokio::test]
async fn a_dropbox_revoke_that_fails_leaves_the_local_revocation_in_place() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected_to("dropbox").await;
    h.fake
        .with(|f| f.revoke_status = StatusCode::INTERNAL_SERVER_ERROR);
    let reply = h
        .call(
            "DELETE",
            &format!("/connections/{id}?member={MEMBER}"),
            None,
        )
        .await;
    assert_eq!(reply.status, StatusCode::NO_CONTENT);
    assert_eq!(h.fake.with(|f| f.revoked_tokens().len()), 1);
    let mut body = dropbox_read(id, LIST_FOLDER);
    body["body"] = json!({ "path": "" });
    let reply = h.proxy(&body).await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    assert_eq!(reply.code(), "not_found");
}

#[tokio::test]
async fn every_provider_mints_its_own_authorization_url() {
    let Some(h) = harness().await else { return };
    for provider in alpha_broker::oauth::PROVIDERS {
        let reply = h
            .call(
                "POST",
                &format!("/connect/{}", provider.name),
                Some(json!({ "member": MEMBER })),
            )
            .await;
        let url = reqwest::Url::parse(reply.body["url"].as_str().unwrap()).unwrap();
        let query: std::collections::HashMap<String, String> =
            url.query_pairs().into_owned().collect();
        let expected = reqwest::Url::parse(provider.authorization).unwrap();
        assert_eq!(url.host_str(), expected.host_str(), "{}", provider.name);
        assert_eq!(url.path(), expected.path());
        assert_eq!(
            query["redirect_uri"],
            format!("https://corpus.example/oauth/{}/callback", provider.name)
        );
        assert_eq!(query["code_challenge_method"], "S256");
    }

    let query = h.start("dropbox", MEMBER).await;
    assert_eq!(query["client_id"], DROPBOX_CLIENT_ID);
    assert_eq!(query["redirect_uri"], DROPBOX_REDIRECT_URI);
    assert_eq!(query["token_access_type"], "offline");
    assert_eq!(query["response_type"], "code");
    assert_eq!(query["code_challenge"].len(), 43);
    assert!(!query.contains_key("access_type") && !query.contains_key("prompt"));
    let mut scopes: Vec<&str> = query["scope"].split(' ').collect();
    scopes.sort_unstable();
    assert_eq!(
        scopes,
        [
            "account_info.read",
            "files.content.read",
            "files.content.write",
            "files.metadata.read",
            "sharing.read",
        ]
    );
}
