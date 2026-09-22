//! The route contracts against a real Postgres (`DATABASE_URL`; skipped without it).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use std::fs;
use std::time::Duration;

use alpha_core::{AppId, KeyId, OrgId, PrincipalId, context};
use alpha_crypto::{INFO_NODE_BOOTSTRAP, INFO_UNSEAL_SHARE};
use alpha_kms::{certs, instance, platform, rfc3339};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use common::*;
use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::EncodePublicKey;
use reqwest::StatusCode;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[tokio::test]
async fn bootstrap_once_unseal_with_two_shares_and_sealed_gate() {
    let Some(h) = harness().await else {
        return;
    };
    assert!(h.ca_pem.starts_with("-----BEGIN CERTIFICATE-----"));
    assert_eq!(h.shares.len(), 3);
    let ready = send(client().get(format!("{}/ready", h.url))).await;
    assert_eq!(ready, (StatusCode::OK, json!({ "sealed": false })));

    let aad: [u8; 32] = Sha256::digest(&h.node.runtime_spki).into();
    let again =
        alpha_crypto::seal(&h.node.xwing_key.public(), INFO_NODE_BOOTSTRAP, &aad, b"{}").unwrap();
    let (status, reply) = h
        .post("/v1/node/bootstrap", json!({ "body_hpke": again }))
        .await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::CONFLICT, "already_exists")
    );

    // A second node over the same database comes up sealed and refuses everything but the Node API.
    let (node2, url2, _shutdown2) = start_node(
        h.pool.clone(),
        &h.release.url,
        &h.release.key,
        h.node.clock.clone(),
    )
    .await;
    assert!(node2.is_sealed());
    assert_eq!(
        send(client().get(format!("{url2}/ready"))).await,
        (StatusCode::SERVICE_UNAVAILABLE, json!({ "sealed": true }))
    );
    let r = client()
        .post(format!("{url2}/v1/attest/nonce"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(r.headers().get("retry-after").unwrap(), "30");
    assert_eq!(code(&r.json().await.unwrap()), "sealed");
    assert_eq!(
        send(client().get(format!("{url2}/healthz"))).await.0,
        StatusCode::OK
    );

    let aad2: [u8; 32] = Sha256::digest(&node2.runtime_spki).into();
    let unseal = |share: &Vec<u8>| json!({ "share_hpke": alpha_crypto::seal(&node2.xwing_key.public(), INFO_UNSEAL_SHARE, &aad2, share).unwrap() });
    let post = |body: Value| send(client().post(format!("{url2}/v1/node/unseal")).json(&body));
    let (status, reply) = post(unseal(&h.shares[2])).await;
    assert_eq!(
        (status, reply),
        (StatusCode::OK, json!({ "sealed": true, "shares": 1 }))
    );
    let (status, reply) = post(unseal(&h.shares[2])).await;
    assert_eq!(
        (status, reply),
        (StatusCode::OK, json!({ "sealed": true, "shares": 1 })),
        "the same share twice is one share"
    );
    assert!(node2.is_sealed());
    let wrong = alpha_crypto::seal(
        &node2.xwing_key.public(),
        INFO_NODE_BOOTSTRAP,
        &aad2,
        &h.shares[0],
    )
    .unwrap();
    let (status, reply) = post(json!({ "share_hpke": wrong })).await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::BAD_REQUEST, "malformed")
    );
    let (status, reply) = post(unseal(&h.shares[0])).await;
    assert_eq!(
        (status, reply),
        (StatusCode::OK, json!({ "sealed": false, "shares": 2 }))
    );
    assert!(!node2.is_sealed());
    assert_eq!(
        send(client().get(format!("{url2}/ready"))).await.0,
        StatusCode::OK
    );
    assert_eq!(
        node2.intermediates().unwrap().ca_cert_der,
        h.node.intermediates().unwrap().ca_cert_der
    );
    assert_eq!(
        *node2.intermediates().unwrap().tenant_kek_root,
        *h.node.intermediates().unwrap().tenant_kek_root
    );
}

/// Two organizations over one node see nothing of each other: a foreign object is absent, not
/// forbidden, and a secret does not decrypt under the neighbour's key.
#[tokio::test]
async fn two_organizations_live_side_by_side() {
    let Some(h) = harness().await else {
        return;
    };
    let compose =
        fs::read_to_string(testdata().join("manifest/05-deploy/app-compose.json")).unwrap();
    let expected: Value = serde_json::from_str(
        &fs::read_to_string(testdata().join("manifest/05-deploy/expected.json")).unwrap(),
    )
    .unwrap();
    let app_a: AppId = expected["app_id"].as_str().unwrap().parse().unwrap();

    let revision = |compose: &str| json!({ "app_id": app_a, "compose": compose });
    let admin_a = h.register_key(&h.root, 51).await;
    let (status, reply) = h
        .post(
            "/v1/revisions",
            h.signed(context::REVISION, revision(&compose), &admin_a),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let revision_a = reply["compose_hash"].as_str().unwrap().to_owned();
    let (status, reply) = h
        .put_secret("a-secret", &[app_a], b"a's value", h.now(), &admin_a)
        .await;
    assert_eq!(status, StatusCode::OK, "{reply}");

    // The second organization claims its own identifier and endorses its own key.
    let root_b_key = SigningKey::from_bytes(&[52u8; 32]);
    let org_b = trust_org(&root_b_key);
    let (status, reply) = h
        .post(
            "/v1/keys",
            root_key_registration(org_b, &root_b_key, h.now()),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["org_id"], json!(org_b));
    let root_b = (reply["id"].as_str().unwrap().parse().unwrap(), root_b_key);
    let admin_b = h.register_key(&root_b, 53).await;

    // A second, different Revision of the same App, so that the refusal below is the App's owner
    // and not the Revision already stored under the first one's hash.
    let other_bytes = compose.replace("\"public_logs\":false", "\"public_logs\":true");
    assert_ne!(other_bytes, compose);

    // Everything of the first organization is absent to the second, never forbidden.
    let foreign = [
        (
            "/v1/revisions".to_owned(),
            context::REVISION,
            revision(&compose),
        ),
        (
            "/v1/revisions".to_owned(),
            context::REVISION,
            revision(&other_bytes),
        ),
        (
            format!("/v1/revisions/{revision_a}/revoke"),
            context::CONTROL,
            json!({ "compose_hash": revision_a, "issued_at": rfc3339(h.now()) }),
        ),
        (
            format!("/v1/keys/{}/revoke", admin_a.0),
            context::CONTROL,
            json!({ "key_id": admin_a.0, "reason": "retired", "issued_at": rfc3339(h.now()) }),
        ),
    ];
    for (path, ctx, payload) in foreign {
        let (status, reply) = h.post(&path, h.signed(ctx, payload, &admin_b)).await;
        assert_eq!(
            (status, code(&reply)),
            (StatusCode::NOT_FOUND, "not_found"),
            "{path}: {reply}"
        );
    }
    let (status, reply) = h
        .put_secret("b-secret", &[app_a], b"b's value", h.now(), &admin_b)
        .await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::NOT_FOUND, "not_found"),
        "{reply}"
    );

    // Each organization's secrets are sealed under its own root key.
    let intermediates = h.node.intermediates().unwrap();
    let stored = sqlx::query!(
        "select id, ciphertext from secrets where org_id = $1 and name = 'a-secret'",
        Uuid::from(h.org)
    )
    .fetch_one(&h.pool)
    .await
    .unwrap();
    let org_key = |org, key: &SigningKey| {
        alpha_kms::keys::org_key(
            &intermediates.tenant_kek_root,
            org,
            key.verifying_key().to_public_key_der().unwrap().as_bytes(),
        )
        .unwrap()
    };
    let key_b = org_key(org_b, &root_b.1);
    let document: Value = sqlx::query_scalar("select document from secrets where id=$1")
        .bind(stored.id)
        .fetch_one(&h.pool)
        .await
        .unwrap();
    let aad = alpha_kms::keys::secret_aad(h.org, stored.id, &document).unwrap();
    let ciphertext = stored.ciphertext.strip_prefix(b"AKS2").unwrap();
    assert!(
        alpha_kms::keys::aead_open(&key_b, &aad, ciphertext).is_none(),
        "the neighbour's key opens the secret"
    );
    let key_a = org_key(h.org, &h.root.1);
    assert_eq!(
        alpha_kms::keys::aead_open(&key_a, &aad, ciphertext)
            .unwrap()
            .as_slice(),
        b"a's value"
    );
}

/// Nobody authorizes a root key: an `org_id` is claimed once, and re-sending the same document
/// is how the organization learns whose key the claim holds.
#[tokio::test]
async fn a_root_key_claims_its_organization_once() {
    let Some(h) = harness().await else {
        return;
    };
    let genesis = h.audit("node.bootstrap").await;
    assert_eq!(
        genesis.iter().map(|r| (&r.1, &r.2)).collect::<Vec<_>>(),
        vec![(&"ok".to_owned(), &json!({}))],
        "genesis names no organization"
    );

    let key = SigningKey::from_bytes(&[31u8; 32]);
    let org = trust_org(&key);
    let document = root_key_registration(org, &key, h.now());
    let (status, first) = h.post("/v1/keys", document.clone()).await;
    assert_eq!(status, StatusCode::OK, "{first}");
    assert_eq!(first["org_id"], json!(org));
    assert_eq!(first["public_key"], json!(spki_b64(&key)));
    let (status, again) = h.post("/v1/keys", document.clone()).await;
    assert_eq!(
        (status, &again["id"], &again["public_key"]),
        (StatusCode::OK, &first["id"], &first["public_key"]),
        "the same document again is the same row"
    );

    let stranger = SigningKey::from_bytes(&[32u8; 32]);
    let (status, reply) = h
        .post("/v1/keys", root_key_registration(org, &stranger, h.now()))
        .await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::CONFLICT, "already_exists"),
        "the claim is not reassigned"
    );
    let (status, reply) = h
        .post(
            "/v1/keys",
            root_key_registration(OrgId::mint(), &key, h.now()),
        )
        .await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::BAD_REQUEST, "signature_invalid"),
        "new organizations must derive their identity from the key"
    );

    // The signature is checked against the key inside the document, so naming another key fails.
    let mut forged = root_key_registration(OrgId::mint(), &key, h.now());
    forged["payload"]["public_key"] = json!(spki_b64(&stranger));
    let (status, reply) = h.post("/v1/keys", forged).await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::BAD_REQUEST, "signature_invalid")
    );
    // A claim signed under the context of an endorsed registration is not a claim: without a
    // separate context, a document signed for another purpose would register a root key.
    let elsewhere = SigningKey::from_bytes(&[33u8; 32]);
    let mut payload = document["payload"].clone();
    payload["org_id"] = json!(OrgId::mint());
    payload["public_key"] = json!(spki_b64(&elsewhere));
    let wrong_ctx =
        json!(alpha_client::sign_self(context::PRINCIPAL_KEY, payload, &elsewhere).unwrap());
    let (status, reply) = h.post("/v1/keys", wrong_ctx).await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::BAD_REQUEST, "signature_invalid")
    );

    // An identifier spelled in uppercase is the same identifier: the row keeps the parsed value,
    // so a claim made that way must go on signing rather than burning the identifier.
    let shouty_key = SigningKey::from_bytes(&[35u8; 32]);
    let shouty = trust_org(&shouty_key);
    let (status, reply) = h
        .post(
            "/v1/keys",
            root_key_registration(shouty.to_string().to_uppercase(), &shouty_key, h.now()),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["org_id"], json!(shouty));
    let shouty_root = (reply["id"].as_str().unwrap().parse().unwrap(), shouty_key);
    h.register_key(&shouty_root, 36).await;

    // The new root key endorses a key of its own, and that key's chain ends at it.
    let root = (first["id"].as_str().unwrap().parse().unwrap(), key);
    let admin = h.register_key(&root, 34).await;

    // Grafted onto the pilot organization's root by a superuser, the same row signs nothing:
    // its registration signature no longer verifies under its new parent.
    sqlx::query!(
        "update principal_keys set org_id = $1, registered_by_key = $2 where id = $3",
        Uuid::from(h.org),
        Uuid::from(h.root.0),
        Uuid::from(admin.0)
    )
    .execute(&h.pool)
    .await
    .unwrap();
    let payload = json!({ "key_id": admin.0, "reason": "retired", "issued_at": rfc3339(h.now()) });
    let (status, reply) = h
        .post(
            &format!("/v1/keys/{}/revoke", admin.0),
            h.signed(context::CONTROL, payload, &admin),
        )
        .await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::BAD_REQUEST, "signature_invalid")
    );
}

#[tokio::test]
async fn control_routes_register_revoke_and_put() {
    let Some(h) = harness().await else {
        return;
    };
    let admin = h.register_key(&h.root, 11).await;

    // Route 4 idempotency: the same public key again is already_exists; unknown signer is signature_invalid.
    let payload = json!({ "principal_id": PrincipalId::mint(), "public_key": b64(admin.1.verifying_key().to_public_key_der().unwrap().as_bytes()), "label": "dup", "issued_at": rfc3339(h.now()) });
    let (status, reply) = h
        .post(
            "/v1/keys",
            h.signed(context::PRINCIPAL_KEY, payload.clone(), &h.root),
        )
        .await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::CONFLICT, "already_exists")
    );
    let stranger = (KeyId::mint(), SigningKey::from_bytes(&[99u8; 32]));
    let (status, reply) = h
        .post(
            "/v1/keys",
            h.signed(context::PRINCIPAL_KEY, payload.clone(), &stranger),
        )
        .await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::BAD_REQUEST, "signature_invalid")
    );
    let mut wrong_ctx = h.signed(context::CONTROL, payload.clone(), &h.root);
    wrong_ctx["payload"]["label"] = json!("dup2");
    let (status, reply) = h.post("/v1/keys", wrong_ctx).await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::BAD_REQUEST, "signature_invalid")
    );
    let old = json!({ "principal_id": PrincipalId::mint(), "public_key": payload["public_key"], "label": "old", "issued_at": "2020-01-01T00:00:00Z" });
    let (status, reply) = h
        .post("/v1/keys", h.signed(context::PRINCIPAL_KEY, old, &h.root))
        .await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::BAD_REQUEST, "malformed")
    );

    // Route 1 with the canonical manifest vector, signed by the registered admin key.
    let compose =
        fs::read_to_string(testdata().join("manifest/05-deploy/app-compose.json")).unwrap();
    let expected: Value = serde_json::from_str(
        &fs::read_to_string(testdata().join("manifest/05-deploy/expected.json")).unwrap(),
    )
    .unwrap();
    let app_id = expected["app_id"].as_str().unwrap();
    let body = h.signed(
        context::REVISION,
        json!({ "app_id": app_id, "compose": compose }),
        &admin,
    );
    let (status, reply) = h.post("/v1/revisions", body.clone()).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["compose_hash"], expected["compose_hash"]);
    assert_eq!(reply["org_id"], json!(h.org));
    let (status, again) = h.post("/v1/revisions", body).await;
    assert_eq!(
        (status, &again["compose_hash"]),
        (StatusCode::OK, &reply["compose_hash"]),
        "a repeat is 200 with the same Revision"
    );
    let tag = fs::read_to_string(testdata().join("manifest/02-reject-image-tag/app-compose.json"))
        .unwrap();
    let (status, reply) = h
        .post(
            "/v1/revisions",
            h.signed(
                context::REVISION,
                json!({ "app_id": app_id, "compose": tag }),
                &admin,
            ),
        )
        .await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::BAD_REQUEST, "malformed")
    );
    let (status, reply) = h
        .post(
            "/v1/revisions",
            h.signed(
                context::REVISION,
                json!({ "app_id": AppId::mint(), "compose": compose }),
                &admin,
            ),
        )
        .await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::BAD_REQUEST, "malformed"),
        "name != app_id"
    );

    // A root row forged in the table with a random anchor_check: its keys never converge on a
    // real root key, whatever its own signature says.
    let other_org = OrgId::mint();
    let other_key = SigningKey::from_bytes(&[12u8; 32]);
    let other_id = Uuid::now_v7();
    let other_spki = other_key.verifying_key().to_public_key_der().unwrap();
    sqlx::query!("insert into principal_keys (id, org_id, principal_id, public_key, document, signature, anchor_check) values ($1, $2, $3, $4, '{}', '{}', $5)",
        other_id, Uuid::from(other_org), Uuid::now_v7(), other_spki.as_bytes(), &[0u8; 32][..])
        .execute(&h.pool).await.unwrap();
    let other = (KeyId::from(other_id), other_key);
    let (status, reply) = h
        .post(
            "/v1/revisions",
            h.signed(
                context::REVISION,
                json!({ "app_id": app_id, "compose": compose }),
                &other,
            ),
        )
        .await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::BAD_REQUEST, "signature_invalid"),
        "a row without the real anchor_check is not an anchor"
    );

    // Route 3: put, then a put with an older issued_at is already_exists; a forged signature is refused.
    let app: AppId = app_id.parse().unwrap();
    let (status, reply) = h
        .put_secret("api-key", &[app], b"s3cret", h.now(), &admin)
        .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let (status, reply) = h
        .put_secret("api-key", &[app], b"s3cret", h.now(), &admin)
        .await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::CONFLICT, "already_exists")
    );
    let foreign_app = AppId::mint();
    sqlx::query!("insert into revisions (compose_hash, app_id, org_id, compose, created_by_key, signature) values ($1, $2, $3, '{}', $4, '{}')",
        &[1u8; 32][..], Uuid::from(foreign_app), Uuid::from(other_org), other_id).execute(&h.pool).await.unwrap();
    let (status, reply) = h
        .put_secret(
            "api-key",
            &[app, foreign_app],
            b"newer",
            h.now() + Duration::from_secs(30),
            &admin,
        )
        .await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::NOT_FOUND, "not_found"),
        "an app of another organization"
    );
    let (status, reply) = h
        .put_secret(
            "api-key",
            &[app],
            b"newer",
            h.now() + Duration::from_secs(60),
            &admin,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let (status, reply) = h
        .put_secret(
            "api-key",
            &[app],
            b"forged",
            h.now() + Duration::from_secs(120),
            &(admin.0, SigningKey::from_bytes(&[13u8; 32])),
        )
        .await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::BAD_REQUEST, "signature_invalid")
    );
    let mut bad_hash = h.signed(context::SECRET, json!({ "name": "x", "app_ids": [app], "content_sha256": format!("sha256:{}", "0".repeat(64)), "issued_at": rfc3339(h.now()) }), &admin);
    bad_hash["value"] = json!(b64(b"v"));
    let (status, reply) = h
        .call(reqwest::Method::PUT, "/v1/secrets/x", bad_hash)
        .await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::BAD_REQUEST, "malformed")
    );

    // Route 2 and 5: revoke twice is 200 both times; objects of another organization are not_found.
    let hash = expected["compose_hash"].as_str().unwrap();
    let payload = json!({ "compose_hash": hash, "issued_at": rfc3339(h.now()) });
    let (status, r1) = h
        .post(
            &format!("/v1/revisions/{hash}/revoke"),
            h.signed(context::CONTROL, payload.clone(), &admin),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{r1}");
    let (status, r2) = h
        .post(
            &format!("/v1/revisions/{hash}/revoke"),
            h.signed(context::CONTROL, payload.clone(), &admin),
        )
        .await;
    assert_eq!((status, &r2), (StatusCode::OK, &r1));
    let (status, reply) = h
        .post(
            &format!("/v1/revisions/{hash}/revoke"),
            h.signed(context::CONTROL, payload, &other),
        )
        .await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::BAD_REQUEST, "signature_invalid")
    );
    let payload = json!({ "key_id": admin.0, "reason": "retired", "issued_at": rfc3339(h.now()) });
    let (status, r1) = h
        .post(
            &format!("/v1/keys/{}/revoke", admin.0),
            h.signed(context::CONTROL, payload.clone(), &h.root),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{r1}");
    let (status, r2) = h
        .post(
            &format!("/v1/keys/{}/revoke", admin.0),
            h.signed(context::CONTROL, payload, &h.root),
        )
        .await;
    assert_eq!((status, &r2), (StatusCode::OK, &r1));
    let (status, reply) = h.post("/v1/keys", h.signed(context::PRINCIPAL_KEY, json!({ "principal_id": PrincipalId::mint(), "public_key": b64(SigningKey::from_bytes(&[14u8; 32]).verifying_key().to_public_key_der().unwrap().as_bytes()), "label": "after", "issued_at": rfc3339(h.now()) }), &admin)).await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::BAD_REQUEST, "signature_invalid"),
        "a revoked key signs nothing"
    );
    let payload =
        json!({ "key_id": KeyId::mint(), "reason": "retired", "issued_at": rfc3339(h.now()) });
    let (status, reply) = h
        .post(
            &format!("/v1/keys/{}/revoke", payload["key_id"].as_str().unwrap()),
            h.signed(context::CONTROL, payload, &h.root),
        )
        .await;
    assert_eq!((status, code(&reply)), (StatusCode::NOT_FOUND, "not_found"));

    for action in [
        "key.register",
        "revision.register",
        "secret.put",
        "revision.revoke",
        "key.revoke",
    ] {
        assert!(
            h.audit(action)
                .await
                .iter()
                .any(|(_, outcome, _)| outcome == "ok"),
            "{action}"
        );
    }
}

#[tokio::test]
async fn attest_release_revoke_and_tamper() {
    let Some(h) = harness().await else {
        return;
    };
    let admin = h.register_key(&h.root, 21).await;
    let app = AppId::mint();
    let hash = h.insert_capture_revision(app, &admin).await;
    let (status, reply) = h
        .put_secret("model-key", &[app], b"the value", h.now(), &admin)
        .await;
    assert_eq!(status, StatusCode::OK, "{reply}");

    // Unknown compose_hash and an image without a reference value are refused.
    let (status, reply) = h.attest(DEV_KEYED).await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::FORBIDDEN, "attestation_unknown"),
        "dev image has no reference value"
    );
    let (status, reply) = h.post("/v1/attest", json!({ "runtime_pubkey": b64(&read(KEYED, "runtime_spki.der")), "nonce": b64(&[1u8; 32]), "evidence": evidence(KEYED, "instance") })).await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::BAD_REQUEST, "nonce_invalid")
    );
    let (status, reply) = h.post("/v1/attest", json!({ "runtime_pubkey": b64(&read(DEV_KEYED, "runtime_spki.der")), "nonce": h.nonce(), "evidence": evidence(KEYED, "instance") })).await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::FORBIDDEN, "attestation_failed"),
        "report_data binds the key"
    );

    // The real thing.
    let (status, reply) = h.attest(KEYED).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let result = &reply["attestation_result"];
    assert_eq!(result["verdict"], "verified");
    assert_eq!(
        result["revision"],
        json!({ "compose_hash": hash, "app_id": app, "org_id": h.org })
    );
    assert_eq!(result["os_image"], "dstack-0.5.9/1c-2g");
    let leaf_pem = reply["certificate_chain"][0].as_str().unwrap();
    assert_eq!(reply["certificate_chain"][1], json!(h.ca_pem));
    let leaf_der =
        <rustls::pki_types::CertificateDer as rustls::pki_types::pem::PemObject>::from_pem_slice(
            leaf_pem.as_bytes(),
        )
        .unwrap();
    let sans = certs::uri_sans(&leaf_der).unwrap();
    assert_eq!(
        sans,
        [
            format!(
                "alphacompute://{}/{app}/{}",
                h.org,
                result["runtime_pubkey_sha256"]
                    .as_str()
                    .unwrap()
                    .trim_start_matches("sha256:")
            ),
            format!("urn:alphacompute:revision:{hash}")
        ]
    );
    let attest_rows = h.audit("attest").await;
    let with_evidence: i64 = sqlx::query_scalar!(
        "select count(*) from audit_log where action = 'attest' and evidence_sha256 is not null"
    )
    .fetch_one(&h.pool)
    .await
    .unwrap()
    .unwrap();
    assert_eq!(with_evidence as usize, attest_rows.len());
    assert!(
        attest_rows
            .iter()
            .any(|(_, o, d)| o == "ok" && d["verdict"] == "verified")
    );
    assert!(
        attest_rows
            .iter()
            .any(|(_, o, d)| o == "denied" && d["code"] == "attestation_unknown")
    );

    let instance = h.instance_client().await;
    let secret_url = format!("{}/v1/secrets/model-key", h.url);
    let (status, secret) = send(instance.get(&secret_url)).await;
    assert_eq!(status, StatusCode::OK, "{secret}");
    assert_eq!(secret["value"], json!(b64(b"the value")));
    assert_eq!(
        secret["content_sha256"],
        json!(format!(
            "sha256:{}",
            hex::encode(Sha256::digest(b"the value"))
        ))
    );
    let (status, reply) = send(instance.get(format!("{}/v1/secrets/other", h.url))).await;
    assert_eq!((status, code(&reply)), (StatusCode::NOT_FOUND, "not_found"));

    // No certificate, or a self-signed one with the right SANs, is cert_invalid.
    let (status, reply) = send(client().get(&secret_url)).await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::UNAUTHORIZED, "cert_invalid")
    );
    let (status, reply) = send(forged_client(&h, &sans).get(&secret_url)).await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::UNAUTHORIZED, "cert_invalid")
    );

    // Revoke, then the next call on the issued certificate is revision_revoked.
    let payload = json!({ "compose_hash": hash, "issued_at": rfc3339(h.now()) });
    let (status, reply) = h
        .post(
            &format!("/v1/revisions/{hash}/revoke"),
            h.signed(context::CONTROL, payload, &admin),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let (status, reply) = send(instance.get(&secret_url)).await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::CONFLICT, "revision_revoked")
    );
    let (status, reply) = h.attest(KEYED).await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::CONFLICT, "revision_revoked")
    );
    sqlx::query!("update revisions set revoked_at = null")
        .execute(&h.pool)
        .await
        .unwrap();

    // The row is re-verified on every call.
    sqlx::query!("update revisions set app_id = $1", Uuid::now_v7())
        .execute(&h.pool)
        .await
        .unwrap();
    let (status, reply) = h.attest(KEYED).await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::BAD_REQUEST, "signature_invalid")
    );
    assert_eq!(
        send(instance.get(&secret_url)).await.0,
        StatusCode::NOT_FOUND,
        "the certificate's app no longer matches the row"
    );
    sqlx::query!("update revisions set app_id = $1", Uuid::from(app))
        .execute(&h.pool)
        .await
        .unwrap();
    sqlx::query!("update revisions set compose = compose || ' '")
        .execute(&h.pool)
        .await
        .unwrap();
    let (status, reply) = send(instance.get(&secret_url)).await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::BAD_REQUEST, "signature_invalid")
    );
    sqlx::query!("update revisions set compose = left(compose, length(compose) - 1)")
        .execute(&h.pool)
        .await
        .unwrap();
    assert_eq!(send(instance.get(&secret_url)).await.0, StatusCode::OK);

    // A retired registering key keeps old objects valid; compromised fails them closed.
    let payload = json!({ "key_id": admin.0, "reason": "retired", "issued_at": rfc3339(h.now() + Duration::from_secs(1)) });
    let (status, reply) = h
        .post(
            &format!("/v1/keys/{}/revoke", admin.0),
            h.signed(context::CONTROL, payload, &h.root),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(
        send(instance.get(&secret_url)).await.0,
        StatusCode::OK,
        "retired: objects signed before revoked_at stay valid"
    );
    sqlx::query!(
        "update principal_keys set revocation_reason = 'compromised' where id = $1",
        Uuid::from(admin.0)
    )
    .execute(&h.pool)
    .await
    .unwrap();
    let (status, reply) = send(instance.get(&secret_url)).await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::BAD_REQUEST, "signature_invalid")
    );
    let (status, reply) = h.attest(KEYED).await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::BAD_REQUEST, "signature_invalid")
    );

    // A delegated key's row must match its signed registration document: with the SPKI
    // swapped, the holder of the replacement key signs nothing.
    sqlx::query!(
        "update principal_keys set revoked_at = null, revocation_reason = null where id = $1",
        Uuid::from(admin.0)
    )
    .execute(&h.pool)
    .await
    .unwrap();
    let impostor = (admin.0, SigningKey::from_bytes(&[22u8; 32]));
    let other = impostor.1.verifying_key().to_public_key_der().unwrap();
    sqlx::query!(
        "update principal_keys set public_key = $1 where id = $2",
        other.as_bytes(),
        Uuid::from(admin.0)
    )
    .execute(&h.pool)
    .await
    .unwrap();
    let payload = json!({ "key_id": admin.0, "reason": "retired", "issued_at": rfc3339(h.now()) });
    let (status, reply) = h
        .post(
            &format!("/v1/keys/{}/revoke", admin.0),
            h.signed(context::CONTROL, payload, &impostor),
        )
        .await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::BAD_REQUEST, "signature_invalid"),
        "{reply}"
    );
    let genuine = admin.1.verifying_key().to_public_key_der().unwrap();
    sqlx::query!(
        "update principal_keys set public_key = $1 where id = $2",
        genuine.as_bytes(),
        Uuid::from(admin.0)
    )
    .execute(&h.pool)
    .await
    .unwrap();
    assert_eq!(send(instance.get(&secret_url)).await.0, StatusCode::OK);

    // Release follows the signed document, not the app_ids column.
    let (status, reply) = h
        .put_secret(
            "foreign",
            &[AppId::mint()],
            b"not for this app",
            h.now(),
            &admin,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let added = [Uuid::from(app)];
    sqlx::query!(
        "update secrets set app_ids = app_ids || $1 where name = 'foreign'",
        &added[..]
    )
    .execute(&h.pool)
    .await
    .unwrap();
    let (status, reply) = send(instance.get(format!("{}/v1/secrets/foreign", h.url))).await;
    assert_eq!((status, code(&reply)), (StatusCode::NOT_FOUND, "not_found"));

    // A swapped anchor SPKI leaves the organization's secrets undecryptable.
    sqlx::query!(
        "update principal_keys set public_key = $1 where registered_by_key is null",
        other.as_bytes()
    )
    .execute(&h.pool)
    .await
    .unwrap();
    let (status, reply) = send(instance.get(&secret_url)).await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::BAD_REQUEST, "signature_invalid")
    );

    // The service role cannot update or delete audit rows; seq is monotone.
    let rows = h.audit("secret.get").await;
    assert!(rows.windows(2).all(|w| w[0].0 < w[1].0) && rows.len() >= 3);
    let mut conn = h.pool.acquire().await.unwrap();
    sqlx::query("set role alpha_kms")
        .execute(&mut *conn)
        .await
        .unwrap();
    let e = sqlx::query("update audit_log set outcome = 'ok'")
        .execute(&mut *conn)
        .await
        .unwrap_err();
    assert!(e.to_string().contains("permission denied"), "{e}");
    let e = sqlx::query("delete from audit_log")
        .execute(&mut *conn)
        .await
        .unwrap_err();
    assert!(e.to_string().contains("permission denied"), "{e}");
    sqlx::query("insert into audit_log (actor_kind, actor, action, outcome) values ('node', 'node', 'test', 'ok')").execute(&mut *conn).await.unwrap();
}

/// A self-signed certificate carrying an Instance's SANs on a key we hold.
fn forged_client(h: &Harness, sans: &[String]) -> reqwest::Client {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = rcgen::CertificateParams::default();
    params.subject_alt_names = sans
        .iter()
        .map(|s| rcgen::SanType::URI(rcgen::string::Ia5String::try_from(s.as_str()).unwrap()))
        .collect();
    params.not_before = h.now().into();
    params.not_after = (h.now() + Duration::from_secs(3600)).into();
    let cert = params.self_signed(&key).unwrap();
    client_with(&format!("{}{}", key.serialize_pem(), cert.pem()))
}

#[tokio::test]
async fn join_hands_out_intermediates_only_to_an_attested_listed_requesting_node() {
    let Some(h) = harness().await else {
        return;
    };
    let pkcs8 = read(KEYED, "runtime.key.pkcs8.der");
    let cert = certs::self_signed(&certs::key_pair(&pkcs8).unwrap(), h.now()).unwrap();
    let joiner = client_with(&format!(
        "{}{}",
        text(KEYED, "runtime.key.pem"),
        certs::pem(&cert)
    ));
    let xwing = alpha_crypto::PrivateKey::from_seed(
        alpha_core::hex_bytes(
            fs::read_to_string(testdata().join("attest/capture/xwing_seed.hex"))
                .unwrap()
                .trim(),
        )
        .unwrap(),
    )
    .unwrap()
    .public();
    assert_eq!(
        xwing.as_bytes().as_slice(),
        read(KEYED, "node_xwing_pubkey.bin")
    );
    let body =
        json!({ "nonce": h.nonce(), "evidence": evidence(KEYED, "node"), "xwing_pubkey": xwing });
    let post = |client: &reqwest::Client, body: Value| {
        send(client.post(format!("{}/v1/node/join", h.url)).json(&body))
    };

    let (status, reply) = post(&joiner, body.clone()).await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::NOT_FOUND, "not_found"),
        "no node.join.request row"
    );
    let (status, reply) = post(&client(), body.clone()).await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::UNAUTHORIZED, "cert_invalid")
    );

    let runtime_sha = hex::encode(Sha256::digest(read(KEYED, "runtime_spki.der")));
    sqlx::query!("insert into audit_log (actor_kind, actor, action, outcome, details, ts) values ('node', 'node', 'node.join.request', 'ok', $1, now() - interval '11 minutes')", json!({ "runtime_pubkey_sha256": runtime_sha })).execute(&h.pool).await.unwrap();
    let (status, reply) = post(&joiner, body.clone()).await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::NOT_FOUND, "not_found"),
        "a stale request does not count"
    );
    sqlx::query!("insert into audit_log (actor_kind, actor, action, outcome, details) values ('node', 'node', 'node.join.request', 'ok', $1)", json!({ "runtime_pubkey_sha256": runtime_sha })).execute(&h.pool).await.unwrap();

    let mut wrong_key = body.clone();
    wrong_key["xwing_pubkey"] = json!(alpha_crypto::PrivateKey::generate().unwrap().public());
    let (status, reply) = post(&joiner, wrong_key).await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::FORBIDDEN, "attestation_failed"),
        "a substituted xwing_pubkey beside a genuine quote"
    );
    let forged = forged_client(&h, &["alphacompute://kms".into()]);
    let (status, reply) = post(&forged, body.clone()).await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::FORBIDDEN, "attestation_failed"),
        "the client key is not the one in report_data"
    );
    let mut doc = platform_document(KEYED);
    doc["version"] = json!(2);
    doc["kms_revisions"] = json!([]);
    h.release.set(doc);
    platform::reload(&h.node).await.unwrap();
    let (status, reply) = post(&joiner, body.clone()).await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::FORBIDDEN, "attestation_unknown"),
        "revision outside kms_revisions"
    );
    let mut doc = platform_document(KEYED);
    doc["version"] = json!(3);
    h.release.set(doc);
    platform::reload(&h.node).await.unwrap();

    let (status, reply) = post(&joiner, body).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let keys = h.node.intermediates().unwrap();
    assert_eq!(
        reply["tenant_kek_root"],
        json!(b64(keys.tenant_kek_root.as_slice()))
    );
    assert_eq!(reply["ca_cert"], json!(b64(&keys.ca_cert_der)));
    let joins = h.audit("node.join").await;
    assert!(
        joins
            .iter()
            .any(|(_, o, d)| o == "ok" && d["runtime_pubkey_sha256"] == json!(runtime_sha))
    );
    assert!(joins.iter().filter(|(_, o, _)| o == "denied").count() >= 4);
}

#[tokio::test]
async fn platform_document_is_monotone_and_audited_on_change() {
    let Some(h) = harness().await else {
        return;
    };
    assert_eq!(h.audit("platform.reload").await.len(), 1);
    platform::reload(&h.node).await.unwrap();
    assert_eq!(
        h.audit("platform.reload").await.len(),
        1,
        "same version: no row"
    );
    let mut doc = platform_document(KEYED);
    doc["version"] = json!(0);
    h.release.set(doc);
    assert!(
        platform::reload(&h.node).await.is_err(),
        "a lower version is refused"
    );
    assert_eq!(h.node.platform_document().unwrap().version, 1);
    let mut doc = platform_document(KEYED);
    doc["version"] = json!(5);
    h.release.set(doc);
    platform::reload(&h.node).await.unwrap();
    assert_eq!(h.node.platform_document().unwrap().version, 5);
    let rows = h.audit("platform.reload").await;
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[1].2, json!({ "version": 5, "previous": 1 }));
    let stored: i32 = sqlx::query_scalar!("select version from platform_document")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(stored, 5);
}

#[tokio::test]
async fn nonce_route_malformed_body_and_unknown_route() {
    let Some(h) = harness().await else {
        return;
    };
    let (status, reply) = h.post("/v1/attest/nonce", json!({})).await;
    assert_eq!(status, StatusCode::OK);
    let nonce = BASE64_URL_SAFE_NO_PAD
        .decode(reply["nonce"].as_str().unwrap())
        .unwrap();
    assert!(instance::check_nonce(&nonce_key(), &nonce.try_into().unwrap(), h.now()).is_ok());
    let (status, reply) = h
        .post(
            "/v1/attest",
            json!({ "runtime_pubkey": "", "nonce": "", "evidence": {}, "extra": 1 }),
        )
        .await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::BAD_REQUEST, "malformed")
    );
    assert!(Uuid::parse_str(reply["error"]["request_id"].as_str().unwrap()).is_ok());
    assert_eq!(
        send(client().get(format!("{}/v1/nope", h.url))).await.0,
        StatusCode::NOT_FOUND
    );
}
