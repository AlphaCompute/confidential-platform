//! PRD-06 "evidence to the customer", the Alpha side: an organization exports the KMS's
//! decisions about its own Instances, signed by the node, and an auditor checks the answer offline.
//! Needs `DATABASE_URL`; skipped without it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use std::time::Duration;

use alpha_core::{AppId, KeyId, OrgId, PrincipalId, context};
use alpha_kms::rfc3339;
use common::*;
use ed25519_dalek::SigningKey;
use reqwest::StatusCode;
use serde_json::{Value, json};

fn export_body(
    h: &Harness,
    key: &(KeyId, SigningKey),
    after_seq: i64,
    limit: i64,
    ctx: &str,
) -> Value {
    let payload = json!({ "after_seq": after_seq, "limit": limit, "issued_at": rfc3339(h.now()) });
    h.signed(ctx, payload, key)
}

async fn export(h: &Harness, body: Value) -> (StatusCode, Value) {
    h.post("/v1/decisions/export", body).await
}

fn checked(h: &Harness, reply: &Value) -> alpha_client::decisions::Decisions {
    alpha_client::decisions::verify(
        &serde_json::to_vec(reply).unwrap(),
        &h.ca_pem,
        &[h.node.compose_hash],
    )
    .unwrap()
}

#[tokio::test]
async fn an_organization_reads_its_own_decisions_signed_by_the_kms() {
    let Some(h) = harness().await else {
        return;
    };
    let admin = h.register_key(&h.root, 21).await;
    let app = AppId::mint();
    h.insert_capture_revision(app, &admin).await;
    let (status, reply) = h
        .put_secret("model-key", &[app], b"the value", h.now(), &admin)
        .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let instance = h.instance_client().await;
    let (status, _) = send(instance.get(format!("{}/v1/secrets/model-key", h.url))).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = send(instance.get(format!("{}/v1/secrets/not-declared", h.url))).await;
    assert_ne!(status, StatusCode::OK);
    let (status, _) = derive(&h, &instance, json!({ "purpose": "connectors" })).await;
    assert_eq!(status, StatusCode::OK);

    // Another organization's decisions never appear in this one's export.
    let other_root = SigningKey::from_bytes(&[9u8; 32]);
    let (status, reply) = h
        .post(
            "/v1/keys",
            root_key_registration(OrgId::mint(), &other_root, h.now()),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let other: (KeyId, SigningKey) = (reply["id"].as_str().unwrap().parse().unwrap(), other_root);
    let (status, theirs) = export(
        &h,
        export_body(&h, &other, 0, 500, context::DECISIONS_EXPORT),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{theirs}");
    assert!(checked(&h, &theirs).rows.is_empty());

    let (status, reply) = export(
        &h,
        export_body(&h, &admin, 0, 500, context::DECISIONS_EXPORT),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let decisions = checked(&h, &reply);
    assert_eq!(decisions.org_id, h.org);
    assert!(!decisions.more);
    let actions: Vec<(&str, &str)> = decisions
        .rows
        .iter()
        .map(|r| (r.action.as_str(), r.outcome.as_str()))
        .collect();
    assert!(actions.contains(&("attest", "ok")), "{actions:?}");
    assert!(actions.contains(&("secret.get", "ok")), "{actions:?}");
    assert!(actions.contains(&("secret.get", "denied")), "{actions:?}");
    assert!(actions.contains(&("key.derive", "ok")), "{actions:?}");
    // Control calls are not decisions about Instances (QUESTION(PRD-06 Q87)).
    assert!(!actions.iter().any(|(a, _)| a.starts_with("secret.put")));
    // The attest row carries the signed verifier claims of #90 and the evidence digest.
    let attest = decisions
        .rows
        .iter()
        .find(|r| r.action == "attest")
        .unwrap();
    assert!(attest.details.get("verifiers").is_some(), "{attest:?}");
    assert!(
        attest
            .evidence_sha256
            .as_deref()
            .unwrap()
            .starts_with("sha256:")
    );
    assert_eq!(decisions.next_after_seq, decisions.rows.last().unwrap().seq);

    // Paging, and each export is itself recorded.
    let (_, page) = export(&h, export_body(&h, &admin, 0, 1, context::DECISIONS_EXPORT)).await;
    let page = checked(&h, &page);
    assert_eq!(page.rows.len(), 1);
    assert!(page.more);
    let (_, rest) = export(
        &h,
        export_body(
            &h,
            &admin,
            decisions.next_after_seq,
            500,
            context::DECISIONS_EXPORT,
        ),
    )
    .await;
    let rest = checked(&h, &rest);
    assert!(rest.rows.iter().all(|r| r.action == "decisions.export"));
    assert_eq!(rest.rows.len(), 2, "{:?}", rest.rows);
}

#[tokio::test]
async fn a_tampered_answer_fails_the_offline_check() {
    let Some(h) = harness().await else {
        return;
    };
    let admin = h.register_key(&h.root, 21).await;
    h.insert_capture_revision(AppId::mint(), &admin).await;
    let (status, _) = h.attest(KEYED).await;
    assert_eq!(status, StatusCode::OK);
    let (_, reply) = export(
        &h,
        export_body(&h, &admin, 0, 500, context::DECISIONS_EXPORT),
    )
    .await;
    checked(&h, &reply);
    let verify = |reply: &Value, revisions: &[alpha_core::ComposeHash]| {
        alpha_client::decisions::verify(&serde_json::to_vec(reply).unwrap(), &h.ca_pem, revisions)
    };

    // The receipt's signed response is what counts; a reply edited around it still returns only
    // what was signed, but a forged request no longer matches the receipt.
    let mut forged = reply.clone();
    forged["request"]["payload"]["after_seq"] = json!(7);
    assert!(verify(&forged, &[h.node.compose_hash]).is_err());
    // The receipt's own document edited.
    let mut forged = reply.clone();
    forged["receipt"]["document"]["response"]["rows"] = json!([]);
    assert!(verify(&forged, &[h.node.compose_hash]).is_err());
    // A KMS Revision that is not listed.
    assert!(verify(&reply, &[alpha_core::compose_hash("another kms")]).is_err());
    // No receipt.
    let mut bare = reply.clone();
    bare.as_object_mut().unwrap().remove("receipt");
    assert!(verify(&bare, &[h.node.compose_hash]).is_err());
}

#[tokio::test]
async fn refusals_are_audited_and_carry_no_receipt() {
    let Some(h) = harness().await else {
        return;
    };
    let admin = h.register_key(&h.root, 21).await;
    for (body, code_) in [
        (
            export_body(&h, &admin, 0, 500, context::CONTROL),
            "signature_invalid",
        ),
        (
            export_body(&h, &admin, 0, 0, context::DECISIONS_EXPORT),
            "malformed",
        ),
        (
            export_body(&h, &admin, 0, 501, context::DECISIONS_EXPORT),
            "malformed",
        ),
        (
            export_body(&h, &admin, -1, 10, context::DECISIONS_EXPORT),
            "malformed",
        ),
        (
            h.signed(
                context::DECISIONS_EXPORT,
                json!({ "after_seq": 0, "limit": 1, "issued_at": rfc3339(h.now()), "org_id": OrgId::mint() }),
                &admin,
            ),
            "malformed",
        ),
        (
            h.signed(
                context::DECISIONS_EXPORT,
                json!({ "after_seq": 0, "limit": 1,
                        "issued_at": rfc3339(h.now() - Duration::from_secs(600)) }),
                &admin,
            ),
            "malformed",
        ),
    ] {
        let (status, reply) = export(&h, body).await;
        assert_ne!(status, StatusCode::OK, "{reply}");
        assert_eq!(code(&reply), code_, "{reply}");
        assert!(reply.get("receipt").is_none());
    }
    let denied = h.audit("decisions.export").await;
    assert_eq!(denied.len(), 6);
    assert!(denied.iter().all(|(_, outcome, _)| outcome != "ok"));
}

/// A member key registers `key` as a read-only auditor key (PRD-06 Q88).
async fn register_auditor(
    h: &Harness,
    signer: &(KeyId, SigningKey),
    seed: u8,
) -> ((KeyId, SigningKey), Value) {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let payload = json!({ "principal_id": PrincipalId::mint(), "public_key": spki_b64(&key),
                          "label": "the customer's auditor", "kind": "auditor",
                          "issued_at": rfc3339(h.now()) });
    let (status, reply) = h
        .post(
            "/v1/keys",
            h.signed(context::PRINCIPAL_KEY, payload, signer),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    ((reply["id"].as_str().unwrap().parse().unwrap(), key), reply)
}

/// `body` signed by `auditor` is refused as `forbidden` with no receipt; the same payload signed
/// by `member` then succeeds, so the refusal was the key's kind and nothing else.
async fn refused_then_allowed(
    h: &Harness,
    method: reqwest::Method,
    path: &str,
    ctx: &str,
    payload: Value,
    extra: Option<(&str, Value)>,
    (auditor, member): (&(KeyId, SigningKey), &(KeyId, SigningKey)),
) {
    let body = |key| {
        let mut body = h.signed(ctx, payload.clone(), key);
        if let Some((name, value)) = &extra {
            body[*name] = value.clone();
        }
        body
    };
    let (status, reply) = h.call(method.clone(), path, body(auditor)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{path}: {reply}");
    assert_eq!(code(&reply), "forbidden", "{reply}");
    assert!(reply.get("receipt").is_none());
    let (status, reply) = h.call(method, path, body(member)).await;
    assert_eq!(status, StatusCode::OK, "{path}: {reply}");
}

#[tokio::test]
async fn an_auditor_key_exports_and_is_refused_on_every_control_write() {
    let Some(h) = harness().await else {
        return;
    };
    let admin = h.register_key(&h.root, 21).await;

    // Registering one is an ordinary, audited Control write by a member key.
    let (auditor, reply) = register_auditor(&h, &admin, 41).await;
    assert_eq!(reply["kind"], "auditor");
    assert!(reply.get("receipt").is_some());
    let (_, outcome, details) = h.audit("key.register").await.pop().unwrap();
    assert_eq!(outcome, "ok");
    assert_eq!(details["kind"], "auditor");
    // A member key's registration says so too.
    let member = h.register_key(&h.root, 22).await;
    let (_, _, details) = h.audit("key.register").await.pop().unwrap();
    assert_eq!(details["kind"], "member");
    // An unknown kind is refused.
    let payload = json!({ "principal_id": PrincipalId::mint(),
                          "public_key": spki_b64(&SigningKey::from_bytes(&[42; 32])),
                          "label": "x", "kind": "admin", "issued_at": rfc3339(h.now()) });
    let (status, reply) = h
        .post(
            "/v1/keys",
            h.signed(context::PRINCIPAL_KEY, payload, &admin),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{reply}");
    assert_eq!(code(&reply), "malformed");

    // The auditor exports, and the export verifies offline and is recorded as an auditor's.
    h.insert_capture_revision(AppId::mint(), &admin).await;
    let (status, _) = h.attest(KEYED).await;
    assert_eq!(status, StatusCode::OK);
    let (status, reply) = export(
        &h,
        export_body(&h, &auditor, 0, 500, context::DECISIONS_EXPORT),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let decisions = checked(&h, &reply);
    assert_eq!(decisions.org_id, h.org);
    assert!(decisions.rows.iter().any(|r| r.action == "attest"));
    let (_, outcome, details) = h.audit("decisions.export").await.pop().unwrap();
    assert_eq!(
        (outcome.as_str(), &details["kind"]),
        ("ok", &json!("auditor"))
    );
    // A member key keeps the export.
    let (status, reply) = export(
        &h,
        export_body(&h, &member, 0, 500, context::DECISIONS_EXPORT),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let (_, _, details) = h.audit("decisions.export").await.pop().unwrap();
    assert_eq!(details["kind"], "member");

    // Every Control write, each refused for the auditor and then accepted from a member key.
    let compose =
        std::fs::read_to_string(testdata().join("manifest/01-canonical/app-compose.json")).unwrap();
    let expected: Value = serde_json::from_str(
        &std::fs::read_to_string(testdata().join("manifest/01-canonical/expected.json")).unwrap(),
    )
    .unwrap();
    let app: AppId = expected["app_id"].as_str().unwrap().parse().unwrap();
    let hash = expected["compose_hash"].as_str().unwrap();
    refused_then_allowed(
        &h,
        reqwest::Method::POST,
        "/v1/revisions",
        context::REVISION,
        json!({ "app_id": app, "compose": compose }),
        None,
        (&auditor, &member),
    )
    .await;
    refused_then_allowed(
        &h,
        reqwest::Method::PUT,
        "/v1/secrets/model-key",
        context::SECRET,
        put_payload("model-key", &[app], b"the value", h.now()),
        Some(("value", json!(b64(b"the value")))),
        (&auditor, &member),
    )
    .await;
    let new_key = SigningKey::from_bytes(&[43; 32]);
    refused_then_allowed(
        &h,
        reqwest::Method::POST,
        "/v1/keys",
        context::PRINCIPAL_KEY,
        json!({ "principal_id": PrincipalId::mint(), "public_key": spki_b64(&new_key),
                "label": "new", "issued_at": rfc3339(h.now()) }),
        None,
        (&auditor, &member),
    )
    .await;
    // Not even another auditor key.
    let payload = json!({ "principal_id": PrincipalId::mint(),
                          "public_key": spki_b64(&SigningKey::from_bytes(&[44; 32])),
                          "label": "x", "kind": "auditor", "issued_at": rfc3339(h.now()) });
    let (status, reply) = h
        .post(
            "/v1/keys",
            h.signed(context::PRINCIPAL_KEY, payload, &auditor),
        )
        .await;
    assert_eq!((status, code(&reply)), (StatusCode::FORBIDDEN, "forbidden"));
    refused_then_allowed(
        &h,
        reqwest::Method::POST,
        &format!("/v1/revisions/{hash}/revoke"),
        context::CONTROL,
        json!({ "compose_hash": hash, "issued_at": rfc3339(h.now()) }),
        None,
        (&auditor, &member),
    )
    .await;
    // Revoking a key last: the auditor cannot revoke another key, nor its own.
    for target in [admin.0, auditor.0] {
        let payload =
            json!({ "key_id": target, "reason": "retired", "issued_at": rfc3339(h.now()) });
        let (status, reply) = h
            .post(
                &format!("/v1/keys/{target}/revoke"),
                h.signed(context::CONTROL, payload, &auditor),
            )
            .await;
        assert_eq!(
            (status, code(&reply)),
            (StatusCode::FORBIDDEN, "forbidden"),
            "{reply}"
        );
    }
    refused_then_allowed(
        &h,
        reqwest::Method::POST,
        &format!("/v1/keys/{}/revoke", admin.0),
        context::CONTROL,
        json!({ "key_id": admin.0, "reason": "retired", "issued_at": rfc3339(h.now()) }),
        None,
        (&auditor, &member),
    )
    .await;

    // Each refusal is audited as a denied write by the auditor's key.
    for action in [
        "revision.register",
        "secret.put",
        "key.register",
        "revision.revoke",
        "key.revoke",
    ] {
        let forbidden: Vec<_> = h
            .audit(action)
            .await
            .into_iter()
            .filter(|(_, _, details)| details["code"] == "forbidden")
            .collect();
        assert!(!forbidden.is_empty(), "{action}");
        assert!(forbidden.iter().all(|(_, outcome, _)| outcome == "denied"));
    }
}

#[tokio::test]
async fn a_row_an_auditor_key_signed_anyway_is_refused_where_it_is_used() {
    let Some(h) = harness().await else {
        return;
    };
    let admin = h.register_key(&h.root, 21).await;
    let (auditor, _) = register_auditor(&h, &admin, 41).await;

    // A Revision the auditor signed, written straight into the table: the route never accepts it,
    // and the Instance-side re-check refuses it too.
    h.insert_capture_revision(AppId::mint(), &auditor).await;
    let (status, reply) = h.attest(KEYED).await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::FORBIDDEN, "forbidden"),
        "{reply}"
    );

    // A key the auditor "registered", written straight into the table, does not chain.
    let child = SigningKey::from_bytes(&[45; 32]);
    let document = json!({ "principal_id": PrincipalId::mint(), "public_key": spki_b64(&child),
                           "label": "smuggled", "issued_at": rfc3339(h.now()) });
    let signature =
        h.signed(context::PRINCIPAL_KEY, document.clone(), &auditor)["signature"].clone();
    let child_id = KeyId::mint();
    let child_spki =
        ed25519_dalek::pkcs8::EncodePublicKey::to_public_key_der(&child.verifying_key()).unwrap();
    sqlx::query!(
        "insert into principal_keys (id, org_id, principal_id, public_key, document, registered_by_key, signature)
         values ($1, $2, $3, $4, $5, $6, $7)",
        uuid::Uuid::from(child_id),
        uuid::Uuid::from(h.org),
        uuid::Uuid::from(PrincipalId::mint()),
        child_spki.as_bytes(),
        document,
        uuid::Uuid::from(auditor.0),
        signature,
    )
    .execute(&h.pool)
    .await
    .unwrap();
    let (status, reply) = export(
        &h,
        export_body(&h, &(child_id, child), 0, 10, context::DECISIONS_EXPORT),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{reply}");
    assert_eq!(code(&reply), "signature_invalid");
    assert!(
        reply["error"]["message"]
            .as_str()
            .unwrap()
            .contains("auditor"),
        "{reply}"
    );
}
