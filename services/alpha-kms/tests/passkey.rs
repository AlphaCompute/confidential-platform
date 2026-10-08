//! Passkey signatures against a real Postgres (`DATABASE_URL`; skipped without it).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use std::sync::Arc;
use std::time::SystemTime;

use alpha_core::{AppId, ComposeHash, KeyId, OrgId, PrincipalId, context};
use alpha_kms::{platform, rfc3339};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use common::*;
use reqwest::StatusCode;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

fn origin() -> String {
    webauthn_vector()["origin"].as_str().unwrap().to_owned()
}

async fn trust_signer(h: &Harness, version: u64, origins: &[&str]) {
    let rp_id = webauthn_vector()["rp_id"].as_str().unwrap().to_owned();
    h.release.set(with_signer(
        platform_document(KEYED),
        version,
        origins,
        &rp_id,
    ));
    platform::reload(&h.node).await.unwrap();
}

struct PasskeyOrg {
    org: OrgId,
    root: (KeyId, Passkey),
    admin: (KeyId, Passkey),
}

fn registered(reply: &Value) -> KeyId {
    reply["id"].as_str().unwrap().parse().unwrap()
}

/// A fresh organization claimed by passkey `seed`, which registers passkey `seed + 1` as admin.
async fn passkey_org(h: &Harness, seed: u8) -> PasskeyOrg {
    let org = OrgId::mint();
    let root = Passkey::new(seed);
    let claim = root.signed(
        context::ORG_ROOT_KEY,
        json!({ "org_id": org, "principal_id": PrincipalId::mint(),
                "public_key": root.spki_b64(), "label": "root passkey",
                "issued_at": rfc3339(h.now()) }),
        None,
    );
    let (status, reply) = h.post("/v1/keys", claim).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let root = (registered(&reply), root);

    let admin = Passkey::new(seed + 1);
    let body = root.1.signed(
        context::PRINCIPAL_KEY,
        json!({ "principal_id": PrincipalId::mint(), "public_key": admin.spki_b64(),
                "label": "admin passkey", "issued_at": rfc3339(h.now()) }),
        Some(root.0),
    );
    let (status, reply) = h.post("/v1/keys", body).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    PasskeyOrg {
        org,
        root,
        admin: (registered(&reply), admin),
    }
}

/// The keyed capture's compose as a Revision of `app` in `org`, straight into the table (its
/// Phala `name` is not a UUID, so route 1 would refuse it).
async fn insert_passkey_revision(
    h: &Harness,
    org: OrgId,
    app: AppId,
    signer: &(KeyId, Passkey),
) -> ComposeHash {
    let compose = text(KEYED, "app-compose.json");
    let hash = alpha_core::compose_hash(&compose);
    let signature = signer.1.signature(
        context::REVISION,
        &json!({ "app_id": app, "compose": compose }),
        Some(signer.0),
    );
    sqlx::query("insert into revisions (compose_hash, app_id, org_id, compose, created_by_key, signature, created_at) values ($1, $2, $3, $4, $5, $6, $7)")
        .bind(hash.as_bytes().as_slice())
        .bind(Uuid::from(app))
        .bind(Uuid::from(org))
        .bind(&compose)
        .bind(Uuid::from(signer.0))
        .bind(signature)
        .bind(chrono::DateTime::<chrono::Utc>::from(h.now()))
        .execute(&h.pool)
        .await
        .unwrap();
    hash
}

fn put_payload(name: &str, app_ids: &[AppId], value: &[u8], issued_at: SystemTime) -> Value {
    json!({ "name": name, "app_ids": app_ids,
            "content_sha256": format!("sha256:{}", hex::encode(Sha256::digest(value))),
            "issued_at": rfc3339(issued_at) })
}

fn put_body(
    name: &str,
    app_ids: &[AppId],
    value: &[u8],
    issued_at: SystemTime,
    signer: &(KeyId, Passkey),
) -> Value {
    let mut body = signer.1.signed(
        context::SECRET,
        put_payload(name, app_ids, value, issued_at),
        Some(signer.0),
    );
    body["value"] = json!(b64(value));
    body
}

async fn put(h: &Harness, name: &str, body: Value) -> (StatusCode, Value) {
    h.call(reqwest::Method::PUT, &format!("/v1/secrets/{name}"), body)
        .await
}

async fn derive(client: &reqwest::Client, h: &Harness, purpose: &str) -> (StatusCode, Value) {
    send(
        client
            .post(format!("{}/v1/keys/derive", h.url))
            .json(&json!({ "purpose": purpose })),
    )
    .await
}

fn expected_app_key(
    h: &Harness,
    org: OrgId,
    anchor: &Passkey,
    app: AppId,
    purpose: &str,
) -> String {
    let intermediates = h.node.intermediates().unwrap();
    let org_key =
        alpha_kms::keys::org_key(&intermediates.tenant_kek_root, org, &anchor.spki()).unwrap();
    b64(alpha_kms::keys::app_key(&org_key, app, purpose)
        .unwrap()
        .as_slice())
}

fn assertion_body(assertion: &Value, key_id: Option<&Value>) -> Value {
    let mut signature = json!({
        "algorithm": "webauthn-es256",
        "signature": assertion["signature"],
        "authenticator_data": assertion["authenticator_data"],
        "client_data_json": assertion["client_data_json"],
    });
    if let Some(key_id) = key_id {
        signature["key_id"] = key_id.clone();
    }
    json!({ "payload": assertion["payload"], "signature": signature })
}

#[tokio::test]
async fn a_device_passkey_claims_its_organization_and_registers_a_key() {
    let v = webauthn_vector();
    let (a0, a1) = (&v["assertions"][0], &v["assertions"][1]);
    let at: SystemTime =
        chrono::DateTime::parse_from_rfc3339(a0["payload"]["issued_at"].as_str().unwrap())
            .unwrap()
            .into();
    let Some(h) = harness_with_clock(Arc::new(move || at)).await else {
        return;
    };
    let org: Uuid = a0["payload"]["org_id"].as_str().unwrap().parse().unwrap();
    let claim = assertion_body(a0, None);

    let (status, reply) = h.post("/v1/keys", claim.clone()).await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::BAD_REQUEST, "signature_invalid")
    );
    assert!(
        reply["error"]["message"]
            .as_str()
            .unwrap()
            .contains("no signer"),
        "{reply}"
    );
    let rows =
        sqlx::query_scalar::<_, i64>("select count(*) from principal_keys where org_id = $1")
            .bind(org)
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert_eq!(rows, 0);
    let (_, outcome, details) = h.audit("key.register").await.pop().unwrap();
    assert_eq!(outcome, "denied");
    assert_eq!(details["code"], "signature_invalid");

    let origin = v["origin"].as_str().unwrap();
    h.release.set(with_signer(
        platform_document(KEYED),
        2,
        &[origin],
        v["rp_id"].as_str().unwrap(),
    ));
    platform::reload(&h.node).await.unwrap();

    let (status, root) = h.post("/v1/keys", claim.clone()).await;
    assert_eq!(status, StatusCode::OK, "{root}");
    verified(
        &h,
        &root,
        "key.register",
        &claim,
        json!({ "org_id": org, "public_key": v["credential"]["spki"] }),
    );
    let (status, again) = h.post("/v1/keys", claim.clone()).await;
    assert_eq!((status, &again["id"]), (StatusCode::OK, &root["id"]));

    let endorsed = assertion_body(a1, Some(&root["id"]));
    let (status, second) = h.post("/v1/keys", endorsed.clone()).await;
    assert_eq!(status, StatusCode::OK, "{second}");
    verified(
        &h,
        &second,
        "key.register",
        &endorsed,
        json!({ "principal_id": a1["payload"]["principal_id"], "org_id": org }),
    );

    let second_id: Uuid = second["id"].as_str().unwrap().parse().unwrap();
    let keys = h.node.intermediates().unwrap();
    let doc = h.node.platform_document().unwrap();
    let chain = alpha_kms::keys::walk_chain(
        &h.pool,
        &keys.tenant_kek_root,
        second_id,
        h.node.now_utc(),
        doc.signer.as_ref(),
    )
    .await
    .unwrap();
    let decoded = |field: &Value| {
        BASE64_URL_SAFE_NO_PAD
            .decode(field.as_str().unwrap())
            .unwrap()
    };
    assert_eq!(chain.anchor_spki, decoded(&v["credential"]["spki"]));
    assert_eq!(chain.key.public_key, decoded(&a1["payload"]["public_key"]));
    let refused = alpha_kms::keys::walk_chain(
        &h.pool,
        &keys.tenant_kek_root,
        second_id,
        h.node.now_utc(),
        None,
    )
    .await
    .err()
    .unwrap();
    assert_eq!(refused.code, "signature_invalid");
}

#[tokio::test]
async fn a_passkey_signed_revision_attests_reads_its_secret_and_derives_its_key() {
    let Some(h) = harness().await else {
        return;
    };
    trust_signer(&h, 2, &[&origin()]).await;
    let PasskeyOrg { org, root, admin } = passkey_org(&h, 61).await;
    let app = AppId::mint();
    insert_passkey_revision(&h, org, app, &admin).await;

    let body = put_body("passkey-secret", &[app], b"passkey value", h.now(), &admin);
    let (status, reply) = put(&h, "passkey-secret", body.clone()).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    verified(
        &h,
        &reply,
        "secret.put",
        &body,
        json!({ "name": "passkey-secret", "org_id": org }),
    );

    let (status, reply) = h.attest(KEYED).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(
        reply["attestation_result"]["revision"]["org_id"],
        json!(org)
    );

    let instance = h.instance_client().await;
    let (status, secret) = send(instance.get(format!("{}/v1/secrets/passkey-secret", h.url))).await;
    assert_eq!(status, StatusCode::OK, "{secret}");
    assert_eq!(secret["value"], json!(b64(b"passkey value")));

    let (status, derived) = derive(&instance, &h, "hmac").await;
    assert_eq!(status, StatusCode::OK, "{derived}");
    assert_eq!(
        derived["key"],
        json!(expected_app_key(&h, org, &root.1, app, "hmac"))
    );
}

fn canonical_revision() -> (Value, Value) {
    let dir = testdata().join("manifest/01-canonical");
    let compose = std::fs::read_to_string(dir.join("app-compose.json")).unwrap();
    let expected: Value =
        serde_json::from_slice(&std::fs::read(dir.join("expected.json")).unwrap()).unwrap();
    (
        json!({ "app_id": expected["app_id"], "compose": compose }),
        expected["compose_hash"].clone(),
    )
}

#[tokio::test]
async fn a_second_passkey_signs_every_control_route() {
    let Some(h) = harness().await else {
        return;
    };
    trust_signer(&h, 2, &[&origin()]).await;
    let PasskeyOrg { org, admin, .. } = passkey_org(&h, 63).await;
    let by_admin = |ctx: &str, payload: Value| admin.1.signed(ctx, payload, Some(admin.0));

    let (payload, hash) = canonical_revision();
    let body = by_admin(context::REVISION, payload);
    for _ in 0..2 {
        let (status, reply) = h.post("/v1/revisions", body.clone()).await;
        assert_eq!(status, StatusCode::OK, "{reply}");
        verified(
            &h,
            &reply,
            "revision.register",
            &body,
            json!({ "compose_hash": hash, "org_id": org }),
        );
    }

    let path = format!("/v1/revisions/{}/revoke", hash.as_str().unwrap());
    let body = by_admin(
        context::CONTROL,
        json!({ "compose_hash": hash, "issued_at": rfc3339(h.now()) }),
    );
    let (status, first) = h.post(&path, body.clone()).await;
    assert_eq!(status, StatusCode::OK, "{first}");
    verified(
        &h,
        &first,
        "revision.revoke",
        &body,
        json!({ "compose_hash": hash }),
    );
    let (status, again) = h.post(&path, body.clone()).await;
    assert_eq!(status, StatusCode::OK, "{again}");
    verified(
        &h,
        &again,
        "revision.revoke",
        &body,
        json!({ "compose_hash": hash, "revoked_at": first["revoked_at"] }),
    );

    let app = AppId::mint();
    let body = put_body("passkey-value", &[app], b"by value", h.now(), &admin);
    let (status, reply) = put(&h, "passkey-value", body.clone()).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    verified(
        &h,
        &reply,
        "secret.put",
        &body,
        json!({ "name": "passkey-value", "org_id": org }),
    );

    let payload = put_payload("passkey-sealed", &[app], b"sealed", h.now());
    let sealed = h.sealed(&payload, org, b"sealed").await;
    let mut body = by_admin(context::SECRET, payload);
    body["sealed"] = sealed;
    let (status, reply) = put(&h, "passkey-sealed", body.clone()).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    verified(
        &h,
        &reply,
        "secret.put",
        &body,
        json!({ "name": "passkey-sealed", "org_id": org }),
    );

    let ed25519 = ed25519_dalek::SigningKey::from_bytes(&[65u8; 32]);
    let principal_id = PrincipalId::mint();
    let body = by_admin(
        context::PRINCIPAL_KEY,
        json!({ "principal_id": principal_id, "public_key": spki_b64(&ed25519),
                "label": "ed25519 under a passkey", "issued_at": rfc3339(h.now()) }),
    );
    let (status, reply) = h.post("/v1/keys", body.clone()).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    verified(
        &h,
        &reply,
        "key.register",
        &body,
        json!({ "principal_id": principal_id, "org_id": org }),
    );
    let ed25519 = (registered(&reply), ed25519);
    let (status, reply) = h
        .put_secret("passkey-chain", &[app], b"chained", h.now(), &ed25519)
        .await;
    assert_eq!(status, StatusCode::OK, "{reply}");

    let path = format!("/v1/keys/{}/revoke", ed25519.0);
    let body = by_admin(
        context::CONTROL,
        json!({ "key_id": ed25519.0, "reason": "retired", "issued_at": rfc3339(h.now()) }),
    );
    let (status, first) = h.post(&path, body.clone()).await;
    assert_eq!(status, StatusCode::OK, "{first}");
    verified(
        &h,
        &first,
        "key.revoke",
        &body,
        json!({ "key_id": ed25519.0, "reason": "retired" }),
    );
    let (status, again) = h.post(&path, body.clone()).await;
    assert_eq!(status, StatusCode::OK, "{again}");
    verified(
        &h,
        &again,
        "key.revoke",
        &body,
        json!({ "key_id": ed25519.0, "revoked_at": first["revoked_at"] }),
    );
}
