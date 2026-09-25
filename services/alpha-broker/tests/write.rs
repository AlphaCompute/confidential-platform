#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use alpha_broker::oauth;
use axum::http::StatusCode;
use common::*;
use serde_json::{Value, json};
use std::time::{Duration, SystemTime};
use uuid::Uuid;

const DRIVE_UPLOAD: &str = "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart";
const DRIVE_FILES: &str = "https://www.googleapis.com/drive/v3/files";
const DROPBOX_UPLOAD: &str = "https://content.dropboxapi.com/2/files/upload";
const DROPBOX_FOLDER: &str = "https://api.dropboxapi.com/2/files/create_folder_v2";

fn url_of(entry: &oauth::Entry) -> String {
    format!(
        "https://{}{}",
        entry.host,
        entry.path.replace("{id}", "abc")
    )
}

fn on(connection: Uuid, method: &str, url: &str) -> Value {
    export_at(
        &member(),
        connection,
        method,
        url,
        "application/json",
        b"{}",
        SystemTime::now(),
    )
}

#[tokio::test]
async fn drive_folder_create_and_multipart_upload_reach_google_with_the_exact_bytes() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected().await;

    let folder = br#"{"name":"Corpus","mimeType":"application/vnd.google-apps.folder"}"#;
    let reply = h
        .write(&upload(id, DRIVE_FILES, "application/json", folder))
        .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.json()["id"], "folder-1");

    let multipart = b"--x\r\nContent-Type: application/json\r\n\r\n{\"name\":\"report.pdf\"}\r\n--x\r\nContent-Type: application/pdf\r\n\r\n%PDF\x00\xff\r\n--x--";
    let reply = h
        .write(&upload(
            id,
            DRIVE_UPLOAD,
            "multipart/related; boundary=x",
            multipart,
        ))
        .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.content_type.as_deref(), Some("application/json"));
    assert_eq!(reply.json()["id"], "uploaded-1");

    let seen = h.fake.with(|f| f.data.clone());
    let [created, uploaded] = &seen[..] else {
        panic!("{seen:?}")
    };
    assert_eq!(
        (created.method.as_str(), created.path.as_str()),
        ("POST", "/drive/v3/files")
    );
    assert_eq!(created.body, folder);
    assert_eq!(created.headers["content-type"], "application/json");
    assert_eq!(uploaded.path, "/upload/drive/v3/files");
    assert_eq!(uploaded.query["uploadType"], "multipart");
    assert_eq!(uploaded.body, multipart);
    assert_eq!(
        uploaded.headers["content-type"],
        "multipart/related; boundary=x"
    );
}

#[tokio::test]
async fn dropbox_create_folder_and_upload_reach_dropbox_and_a_second_create_relays_its_409() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected_to("dropbox").await;

    let folder = || {
        upload(
            id,
            DROPBOX_FOLDER,
            "application/json",
            br#"{"path":"/Corpus","autorename":false}"#,
        )
    };
    assert_eq!(h.write(&folder()).await.status, StatusCode::OK);
    let again = h.write(&folder()).await;
    assert_eq!(again.status, StatusCode::CONFLICT);
    assert_eq!(again.json()["error_summary"], "path/conflict/folder/..");

    let arg = r#"{"path":"/Corpus/report.pdf","mode":"add","autorename":true}"#;
    let mut file = upload(
        id,
        DROPBOX_UPLOAD,
        "application/octet-stream",
        b"%PDF\x00\xff",
    );
    file["headers"] = json!({ "Dropbox-API-Arg": arg });
    let reply = h.write(&file).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.json()["id"], "id:up1");

    let seen = h.fake.with(|f| f.data.last().cloned().unwrap());
    assert_eq!(seen.host, "content.dropboxapi.com");
    assert_eq!(seen.path, "/2/files/upload");
    assert_eq!(seen.body, b"%PDF\x00\xff");
    assert_eq!(seen.headers["content-type"], "application/octet-stream");
    assert_eq!(seen.headers["dropbox-api-arg"], arg);
}

#[tokio::test]
async fn only_the_connect_bearer_opens_write() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected().await;
    let body = upload(id, DRIVE_FILES, "application/json", b"{}");
    let backend = instance_client(&h.ca, None);
    let replies = [
        h.post_with(&backend, Some("wrong-bearer"), "/write", &body)
            .await
            .unwrap(),
        h.post_with(&backend, None, "/write", &body).await.unwrap(),
        h.post_with(&h.instance, None, "/write", &body)
            .await
            .unwrap(),
    ];
    for reply in replies {
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        assert_eq!(reply.code(), "unauthorized");
    }
    assert!(h.untouched());
}

#[tokio::test]
async fn every_read_entry_is_refused_on_write() {
    let Some(h) = harness().await else { return };
    let (google, _) = h.connected().await;
    let (dropbox, _) = h.connected_to("dropbox").await;
    for (id, provider) in [(google, &oauth::GOOGLE), (dropbox, &oauth::DROPBOX)] {
        for entry in provider.reads {
            let reply = h
                .write(&on(id, entry.method.as_str(), &url_of(entry)))
                .await;
            assert_eq!(reply.status, StatusCode::FORBIDDEN, "{}", entry.path);
            assert_eq!(reply.code(), "not_allowed");
        }
    }
    assert!(h.untouched());
}

#[tokio::test]
async fn no_write_entry_of_any_provider_reaches_proxy_and_destructive_calls_reach_neither_route() {
    let Some(h) = harness().await else { return };
    for provider in oauth::PROVIDERS {
        let (id, _) = h.connected_to(provider.name).await;
        for entry in provider.writes {
            let mut body = read(id, &url_of(entry));
            body["method"] = json!(entry.method.as_str());
            body["body"] = json!({ "path": "/x" });
            let reply = h.proxy(&body).await;
            assert_eq!(reply.status, StatusCode::FORBIDDEN, "{}", entry.path);
            assert_eq!(reply.code(), "not_allowed");
        }
    }
    let (google, _) = h.connected().await;
    let (dropbox, _) = h.connected_to("dropbox").await;
    let destructive = [
        (
            dropbox,
            "POST",
            "https://api.dropboxapi.com/2/files/delete_v2",
        ),
        (
            dropbox,
            "POST",
            "https://api.dropboxapi.com/2/files/move_v2",
        ),
        (
            dropbox,
            "POST",
            "https://api.dropboxapi.com/2/sharing/create_shared_link_with_settings",
        ),
        (
            google,
            "PATCH",
            "https://www.googleapis.com/drive/v3/files/abc",
        ),
    ];
    for (id, method, url) in destructive {
        let mut body = read(id, url);
        body["method"] = json!(method);
        let reply = h.proxy(&body).await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN, "{url}");
        let reply = h.write(&on(id, method, url)).await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN, "{url}");
    }
    assert!(h.untouched());
}

#[tokio::test]
async fn an_unknown_revoked_or_another_members_connection_is_not_found_on_write() {
    let Some(h) = harness().await else { return };
    let (mine, _) = h.connected().await;
    let (foreign, _) = h.connect(&other_member(), "other@example.com").await;
    let (revoked, _) = h.connect(&member(), "second@example.com").await;
    let revoked = id_of(&revoked);
    let gone = h.disconnect(&member(), revoked).await;
    assert_eq!(gone.status, StatusCode::OK);
    let mut exports: Vec<Value> = [Uuid::now_v7(), revoked, id_of(&foreign)]
        .into_iter()
        .map(|connection| upload(connection, DRIVE_FILES, "application/json", b"{}"))
        .collect();
    exports.push(export_at(
        &other_member(),
        mine,
        "POST",
        DRIVE_FILES,
        "application/json",
        b"{}",
        SystemTime::now(),
    ));
    for body in exports {
        let reply = h.write(&body).await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{body}");
        assert_eq!(reply.code(), "not_found");
    }
    assert!(h.untouched());
}

#[tokio::test]
async fn a_body_that_is_not_base64_a_bad_content_type_or_an_unknown_field_is_malformed() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected().await;
    let mut not_base64 = upload(id, DRIVE_FILES, "application/json", b"{}");
    not_base64["body_base64"] = json!("not base64!");
    let mut url_safe = upload(id, DRIVE_FILES, "application/json", b"{}");
    url_safe["body_base64"] = json!("-_-_");
    let newline = upload(id, DRIVE_FILES, "application/json\r\nx-other: 1", b"{}");
    let mut unknown = upload(id, DRIVE_FILES, "application/json", b"{}");
    unknown["body"] = json!({});
    let mut missing = upload(id, DRIVE_FILES, "application/json", b"{}");
    missing.as_object_mut().unwrap().remove("content_type");
    for body in [not_base64, url_safe, newline, unknown, missing] {
        let reply = h.write(&body).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(reply.code(), "malformed");
    }
    assert!(h.untouched());
}

#[tokio::test]
async fn a_dead_connection_is_refused_on_write() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected_to("dropbox").await;
    sqlx::query("update connections set dead_at = now() where id = $1")
        .bind(id)
        .execute(&h.pool)
        .await
        .unwrap();
    let reply = h
        .write(&upload(
            id,
            DROPBOX_FOLDER,
            "application/json",
            br#"{"path":"/Corpus"}"#,
        ))
        .await;
    assert_eq!(reply.status, StatusCode::CONFLICT);
    assert_eq!(reply.code(), "reconnect_required");
    assert!(h.untouched());
}

#[tokio::test]
async fn an_eight_mib_file_is_forwarded_whole_and_a_body_over_sixteen_mib_is_refused() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected_to("dropbox").await;
    let file = vec![0xa5; 8 << 20];
    let reply = h
        .write(&upload(
            id,
            DROPBOX_UPLOAD,
            "application/octet-stream",
            &file,
        ))
        .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(h.fake.with(|f| f.data.last().unwrap().body.len()), 8 << 20);

    let limit = alpha_broker::proxy::WRITE_BODY_LIMIT;
    assert_eq!(limit, 16 << 20);
    let before = h.fake.with(|f| f.data.len());
    let (status, _) = h
        .send(Some(BEARER), "POST", "/write", Some("A".repeat(limit + 1)))
        .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(h.fake.with(|f| f.data.len()), before);
}

#[tokio::test]
async fn a_replayed_export_is_refused() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected().await;
    let body = upload(id, DRIVE_FILES, "application/json", b"{}");
    assert_eq!(h.write(&body).await.status, StatusCode::OK);
    nothing_reaches(&h, async {
        let again = h.write(&body).await;
        assert_eq!(again.status, StatusCode::CONFLICT);
        assert_eq!(again.code(), "nonce_replayed");
    })
    .await;
}

#[tokio::test]
async fn an_export_signed_more_than_a_minute_ago_is_refused() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected().await;
    let stale = SystemTime::now() - Duration::from_secs(61);
    let body = export_at(
        &member(),
        id,
        "POST",
        DRIVE_FILES,
        "application/json",
        b"{}",
        stale,
    );
    let reply = h.write(&body).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert_eq!(reply.code(), "request_stale");
    assert!(h.untouched());
}

#[tokio::test]
async fn an_export_with_the_connect_bearer_alone_is_refused() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected().await;
    let plain = json!({
        "member": hex::encode(member().sha256()),
        "connection_id": id,
        "method": "POST",
        "url": DRIVE_FILES,
        "content_type": "application/json",
        "body_base64": "e30=",
    });
    let backend = instance_client(&h.ca, None);
    let reply = h
        .post_with(&backend, Some(BEARER), "/write", &plain)
        .await
        .unwrap();
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(reply.code(), "frame_invalid");
    let reply = h.write(&plain).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(reply.code(), "malformed");
    assert!(h.untouched());
}

#[tokio::test]
async fn a_sealed_export_without_the_members_signature_is_refused() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected().await;
    let mut unsigned = upload(id, DRIVE_FILES, "application/json", b"{}");
    unsigned.as_object_mut().unwrap().remove("signature");
    let reply = h.write(&unsigned).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(reply.code(), "malformed");

    let mut forged = upload(id, DRIVE_FILES, "application/json", b"{}");
    forged["signature"] = upload(id, DRIVE_FILES, "application/json", b"[]")["signature"].clone();
    let reply = h.write(&forged).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert_eq!(reply.code(), "signature_invalid");
    assert!(h.untouched());
}

#[tokio::test]
async fn a_body_other_than_the_one_signed_is_refused() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected().await;
    let mut swapped = upload(id, DRIVE_FILES, "application/json", b"{}");
    swapped["body_base64"] = json!("W10=");
    let reply = h.write(&swapped).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(reply.code(), "malformed");
    assert!(h.untouched());
}

#[tokio::test]
async fn a_chat_grant_or_a_connect_request_in_place_of_the_signature_is_refused() {
    let Some(h) = harness().await else { return };
    let (id, _) = h.connected().await;
    let signed_write = upload(id, DRIVE_FILES, "application/json", b"{}");
    let mut with_grant = signed_write.clone();
    let fields = with_grant.as_object_mut().unwrap();
    for field in ["document", "member_key", "signature"] {
        fields.remove(field);
    }
    fields.insert("grant".into(), json!(h.grant(&[id])));
    let reply = h.write(&with_grant).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(reply.code(), "malformed");

    let digest = alpha_core::signing_digest(
        alpha_core::context::CONNECTOR_REQUEST,
        &signed_write["document"],
    )
    .unwrap();
    let mut under_request = signed_write.clone();
    under_request["signature"]["signature"] = json!(member().sign(&digest));
    let reply = h.write(&under_request).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert_eq!(reply.code(), "signature_invalid");
    assert!(h.untouched());
}
