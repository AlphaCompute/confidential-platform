//! Actual KMS HTTPS routes + PostgreSQL, not a cryptographic model.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod common;
use alpha_core::{AppId, context};
use alpha_kms::{keys, rfc3339};
use common::*;
use reqwest::StatusCode;
use serde_json::{Value, json};
use sqlx::Row;
use std::time::Duration;
use uuid::Uuid;

#[tokio::test]
async fn secret_substitution_and_ciphertext_replay_never_return_bytes() {
    let Some(h) = harness().await else {
        return;
    };
    let app = AppId::mint();
    let admin = h.register_key(&h.root, 77).await;
    h.insert_capture_revision(app, &admin).await;
    assert_eq!(
        h.put_secret("a", &[app], b"approved-a", h.now(), &admin)
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        h.put_secret("b", &[AppId::mint()], b"private-b", h.now(), &admin)
            .await
            .0,
        StatusCode::OK
    );
    let instance = h.instance_client().await;
    let url = format!("{}/v1/secrets/a", h.url);
    assert_eq!(send(instance.get(&url)).await.0, StatusCode::OK);
    let a = sqlx::query("select * from secrets where name='a'")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    let b = sqlx::query("select * from secrets where name='b'")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    let a_id: Uuid = a.get("id");
    let b_id: Uuid = b.get("id");
    let a_ct: Vec<u8> = a.get("ciphertext");
    let b_ct: Vec<u8> = b.get("ciphertext");
    sqlx::query("delete from secrets where id=$1")
        .bind(b_id)
        .execute(&h.pool)
        .await
        .unwrap();
    // Exact S01 attack: replace UUID and ciphertext while retaining A's valid signed policy.
    sqlx::query("update secrets set id=$1,ciphertext=$2 where name='a'")
        .bind(b_id)
        .bind(&b_ct)
        .execute(&h.pool)
        .await
        .unwrap();
    let (status, refused) = send(instance.get(&url)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(code(&refused), "signature_invalid");
    assert!(refused.get("value").is_none());
    sqlx::query("update secrets set id=$1,ciphertext=$2 where name='a'")
        .bind(a_id)
        .bind(&a_ct)
        .execute(&h.pool)
        .await
        .unwrap();
    assert_eq!(
        h.put_secret(
            "a",
            &[app],
            b"new-a",
            h.now() + Duration::from_secs(1),
            &admin
        )
        .await
        .0,
        StatusCode::OK
    );
    sqlx::query("update secrets set ciphertext=$1 where name='a'")
        .bind(&a_ct)
        .execute(&h.pool)
        .await
        .unwrap();
    assert_eq!(send(instance.get(&url)).await.0, StatusCode::BAD_REQUEST);
    // A valid AEAD tag is insufficient: exercise the independent plaintext hash check.
    let document: Value = sqlx::query_scalar("select document from secrets where name='a'")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    let intermediates = h.node.intermediates().unwrap();
    let anchor = base64::Engine::decode(
        &base64::prelude::BASE64_URL_SAFE_NO_PAD,
        spki_b64(&h.root.1),
    )
    .unwrap();
    let key = keys::org_key(&intermediates.tenant_kek_root, h.org, &anchor).unwrap();
    let aad = keys::secret_aad(h.org, a_id, &document).unwrap();
    let wrong = [
        b"AKS2".as_slice(),
        &keys::aead_seal(&key, &aad, b"wrong-but-authenticated").unwrap(),
    ]
    .concat();
    sqlx::query("update secrets set ciphertext=$1 where name='a'")
        .bind(wrong)
        .execute(&h.pool)
        .await
        .unwrap();
    let (_, refused) = send(instance.get(&url)).await;
    assert_eq!(code(&refused), "signature_invalid");
    assert!(refused.get("value").is_none());
    // Cross-organization ciphertext, even with the same row/document, has a different key/AAD.
    let other = alpha_core::OrgId::mint();
    let other_key = keys::org_key(&intermediates.tenant_kek_root, other, &anchor).unwrap();
    let other_aad = keys::secret_aad(other, a_id, &document).unwrap();
    let ct = [
        b"AKS2".as_slice(),
        &keys::aead_seal(&other_key, &other_aad, b"new-a").unwrap(),
    ]
    .concat();
    sqlx::query("update secrets set ciphertext=$1 where name='a'")
        .bind(ct)
        .execute(&h.pool)
        .await
        .unwrap();
    assert_eq!(send(instance.get(&url)).await.0, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn trusted_database_model_does_not_claim_superuser_rollback_resistance() {
    let Some(h) = harness().await else {
        return;
    };
    let app = AppId::mint();
    let admin = h.register_key(&h.root, 83).await;
    let hash = h.insert_capture_revision(app, &admin).await;
    h.put_secret("a", &[app], b"approved", h.now(), &admin)
        .await;
    let instance = h.instance_client().await;
    let url = format!("{}/v1/secrets/a", h.url);
    let revoke = h.signed(
        context::CONTROL,
        json!({"compose_hash":hash,"issued_at":rfc3339(h.now())}),
        &admin,
    );
    assert_eq!(
        h.post(&format!("/v1/revisions/{hash}/revoke"), revoke)
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(send(instance.get(&url)).await.0, StatusCode::CONFLICT);
    // This is deliberately an EXPECTED LIMIT, not evidence of rollback protection.
    // A trusted superuser can restore old authorization. Such restores are prohibited
    // until external recovery records have been reconciled; see database-trust.md.
    sqlx::query("update revisions set revoked_at=null")
        .execute(&h.pool)
        .await
        .unwrap();
    assert_eq!(send(instance.get(&url)).await.0, StatusCode::OK);
}
