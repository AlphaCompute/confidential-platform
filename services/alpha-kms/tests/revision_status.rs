//! `GET /v1/revisions/{compose_hash}?app_id=` (PRD-05 M3 status tracking) against a real
//! Postgres (`DATABASE_URL`; skipped without it), through `alpha_client` pinned as an admin call:
//! a registered Revision is `registered` for its own App only, an unknown one is not, and a
//! revoked one says so; and, once an Instance of a Revision v2 attests, when its leaf expires
//! (PRD-05 Q66, "running on CoCo").

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use std::fs;
use std::sync::Arc;
use std::time::SystemTime;

use alpha_client::{Client, Pin, tls as client_tls};
use alpha_core::coco::CPU_RUNTIME_CLASS;
use alpha_core::{AppId, ComposeHash, context};
use alpha_kms::rfc3339;
use common::kata::*;
use common::*;
use reqwest::StatusCode;
use serde_json::{Value, json};

#[tokio::test]
async fn the_kms_says_whether_it_holds_an_apps_revision() {
    // The wall clock: the pinned client judges the node's one-hour leaf by it.
    let Some(h) = harness_with_clock(Arc::new(SystemTime::now)).await else {
        return;
    };
    let admin = h.register_key(&h.root, 11).await;
    let compose =
        fs::read_to_string(testdata().join("manifest/01-canonical/app-compose.json")).unwrap();
    let expected: Value = serde_json::from_str(
        &fs::read_to_string(testdata().join("manifest/01-canonical/expected.json")).unwrap(),
    )
    .unwrap();
    let app: AppId = expected["app_id"].as_str().unwrap().parse().unwrap();
    let hash: ComposeHash = expected["compose_hash"].as_str().unwrap().parse().unwrap();
    let ca = client_tls::cert_from_pem(&h.ca_pem).unwrap();
    let kms = Client::new(
        vec![h.url.clone()],
        Pin::CaAndRevisions(ca, vec![h.node.compose_hash]),
    )
    .unwrap();

    // Not yet approved: the KMS does not hold it.
    let before = kms.revision_status(hash, app).await.unwrap();
    assert!(!before.registered && !before.revoked);

    let body = h.signed(
        context::REVISION,
        json!({ "app_id": app, "compose": compose }),
        &admin,
    );
    let (status, reply) = h.post("/v1/revisions", body).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let after = kms.revision_status(hash, app).await.unwrap();
    assert_eq!((after.registered, after.revoked), (true, false));
    assert_eq!((after.compose_hash, after.app_id), (hash, app));

    // Asked for another App, the same hash is not that App's Revision.
    let other = AppId::mint();
    let foreign = kms.revision_status(hash, other).await.unwrap();
    assert!(!foreign.registered);
    assert_eq!(foreign.app_id, other);

    // Revoked by its organization.
    let payload = json!({ "compose_hash": hash, "issued_at": rfc3339(h.now()) });
    let (status, reply) = h
        .post(
            &format!("/v1/revisions/{hash}/revoke"),
            h.signed(context::CONTROL, payload, &admin),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let revoked = kms.revision_status(hash, app).await.unwrap();
    assert_eq!((revoked.registered, revoked.revoked), (true, true));

    // A malformed hash is refused, not answered.
    let (status, _) =
        send(client().get(format!("{}/v1/revisions/not-a-hash?app_id={app}", h.url))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// The KMS's answer about a Revision through the unpinned test client: the Kata harness's node
/// runs on the capture's clock, which a pinned client would judge its leaf by.
async fn status(h: &Harness, hash: ComposeHash, app: AppId) -> alpha_client::RevisionStatus {
    let (status, reply) =
        send(client().get(format!("{}/v1/revisions/{hash}?app_id={app}", h.url))).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    serde_json::from_value(reply).unwrap()
}

#[tokio::test]
async fn the_kms_says_when_the_latest_leaf_naming_a_revision_v2_expires() {
    let gpu = FakeGpu::new();
    let Some(h) = kata_harness(&gpu).await else {
        return;
    };
    let admin = h.register_key(&h.root, 12).await;
    let pod = Pod::cpu(AppId::mint());
    let hash = pod.register(&h, &admin).await;

    // Re-approved, and nothing running yet.
    let approved = status(&h, hash, pod.app).await;
    assert_eq!((approved.registered, approved.revoked), (true, false));
    assert_eq!(approved.leaf_not_after, None);

    // A refused attestation of the same App issues no leaf.
    let other_pod = Pod {
        initdata: initdata(
            pod.app,
            CPU_RUNTIME_CLASS,
            None,
            "package agent_policy\n# other\n",
        ),
        ..pod.clone()
    };
    assert!(other_pod.attest(&h).await.is_err());
    assert_eq!(status(&h, hash, pod.app).await.leaf_not_after, None);

    // The Instance attests: the KMS answers when its leaf expires, an hour after the audit row.
    let before = chrono::Utc::now();
    pod.attest(&h).await.unwrap();
    let after = chrono::Utc::now();
    let running = status(&h, hash, pod.app).await;
    let not_after =
        chrono::DateTime::parse_from_rfc3339(running.leaf_not_after.as_deref().unwrap())
            .unwrap()
            .to_utc();
    let hour = chrono::Duration::hours(1);
    let second = chrono::Duration::seconds(1);
    assert!(
        not_after >= before + hour - second && not_after <= after + hour + second,
        "{not_after} not an hour after {before}..{after}"
    );

    // Asked for another App, neither the Revision nor its leaf is that App's.
    let foreign = status(&h, hash, AppId::mint()).await;
    assert!(!foreign.registered);
    assert_eq!(foreign.leaf_not_after, None);

    // An unregistered Revision of the same App has no leaf either.
    let unregistered = Pod {
        initdata: initdata(
            pod.app,
            CPU_RUNTIME_CLASS,
            None,
            "package agent_policy\n# v3\n",
        ),
        ..pod.clone()
    };
    let none = status(&h, unregistered.hash(), pod.app).await;
    assert_eq!((none.registered, none.leaf_not_after), (false, None));
}
