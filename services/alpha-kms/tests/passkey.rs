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

use alpha_kms::platform;
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use common::*;
use reqwest::StatusCode;
use serde_json::{Value, json};
use uuid::Uuid;

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
