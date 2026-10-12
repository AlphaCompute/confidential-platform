//! PRD-06 "evidence to the customer", the Alpha side (draft): an organization exports the KMS's
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

use alpha_core::{AppId, KeyId, OrgId, context};
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
    // Control calls are not decisions about Instances (QUESTION(PRD-06 Q1)).
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
