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
    let mut body = upload(connection, url, "application/json", b"{}");
    body["method"] = json!(method);
    body
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

    let folder = upload(
        id,
        DROPBOX_FOLDER,
        "application/json",
        br#"{"path":"/Corpus","autorename":false}"#,
    );
    assert_eq!(h.write(&folder).await.status, StatusCode::OK);
    let again = h.write(&folder).await;
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
        h.post_with(&backend, Some(PROXY_BEARER), "/write", &body)
            .await
            .unwrap(),
        h.post_with(&backend, None, "/write", &body).await.unwrap(),
        h.post_with(&h.instance, Some(PROXY_BEARER), "/write", &body)
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
async fn an_unknown_revoked_or_foreign_connection_is_not_found_on_write() {
    let Some(h) = harness().await else { return };
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
    for connection in [Uuid::now_v7(), revoked, id_of(&foreign)] {
        let reply = h
            .write(&upload(connection, DRIVE_FILES, "application/json", b"{}"))
            .await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{connection}");
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
async fn an_eight_mib_file_is_forwarded_whole_and_a_body_over_twelve_mib_is_refused() {
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

    let limit = 12 << 20;
    let mut over = upload(id, DROPBOX_UPLOAD, "application/octet-stream", b"");
    let envelope = over.to_string().len();
    over["body_base64"] = json!("A".repeat(limit + 1 - envelope));
    assert_eq!(over.to_string().len(), limit + 1);
    let before = h.fake.with(|f| f.data.len());
    let reply = h.write(&over).await;
    assert_eq!(reply.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(h.fake.with(|f| f.data.len()), before);
}
