//! The CLI's side of the contracts, through `alpha-cli`'s library functions against an
//! in-process node (`DATABASE_URL`; skipped without it). The node runs on the wall clock so
//! that a pinned TLS client accepts its one-hour leaf; nothing here attests with a quote.

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

use alpha_cli::call::Route;
use alpha_cli::{call, deploy, node as cli_node, sign};
use alpha_client::{Anchor, Client, Pin, tls};
use alpha_core::{AppId, KeyId, PrincipalId};
use alpha_kms::{certs, platform};
use common::*;
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

async fn wall_clock_harness() -> Option<Harness> {
    harness_with_clock(Arc::new(SystemTime::now)).await
}

fn pinned(h: &Harness, pin: Pin) -> Client {
    Client::new(vec![h.url.clone()], pin).unwrap()
}

fn ca_pin(h: &Harness) -> Pin {
    Pin::Ca(tls::cert_from_pem(&h.ca_pem).unwrap())
}

#[tokio::test]
async fn call_refuses_a_kms_whose_chain_does_not_end_in_the_pinned_ca() {
    let Some(h) = wall_clock_harness().await else {
        return;
    };
    let (_, other_ca) = certs::new_ca(SystemTime::now()).unwrap();
    let err = pinned(&h, Pin::Ca(other_ca.clone().into()))
        .ready()
        .await
        .unwrap_err();
    assert!(matches!(err, alpha_client::Error::Connect(_)), "{err}");
    assert!(pinned(&h, ca_pin(&h)).ready().await.is_ok());

    let ca = tls::cert_from_pem(&h.ca_pem).unwrap();
    let listed = Pin::CaAndRevisions(ca.clone(), vec![h.node.compose_hash]);
    assert!(pinned(&h, listed).ready().await.is_ok());
    let unlisted = Pin::CaAndRevisions(ca, vec![alpha_core::compose_hash("other")]);
    assert!(matches!(
        pinned(&h, unlisted).ready().await.unwrap_err(),
        alpha_client::Error::Connect(_)
    ));
    let spki = tls::spki_of(&h.node.intermediates().unwrap().ca_cert_der).unwrap();
    assert!(matches!(
        pinned(&h, Pin::Spki(spki)).ready().await.unwrap_err(),
        alpha_client::Error::Connect(_)
    ));

    // The runtime's pin: the CA taken from the presented chain by its SPKI hash.
    let ca_hash = tls::spki_sha256(&h.node.intermediates().unwrap().ca_cert_der).unwrap();
    let by_hash = |hash, revisions| Pin::CaSpkiAndRevisions(hash, revisions);
    assert!(
        pinned(&h, by_hash(ca_hash, vec![h.node.compose_hash]))
            .ready()
            .await
            .is_ok()
    );
    for pin in [
        by_hash(ca_hash, vec![alpha_core::compose_hash("other")]),
        by_hash(ca_hash, vec![]),
        by_hash(
            tls::spki_sha256(&other_ca).unwrap(),
            vec![h.node.compose_hash],
        ),
    ] {
        assert!(matches!(
            pinned(&h, pin).ready().await.unwrap_err(),
            alpha_client::Error::Connect(_)
        ));
    }
}

#[tokio::test]
async fn call_signs_all_five_control_routes() {
    let Some(h) = wall_clock_harness().await else {
        return;
    };
    let client = pinned(&h, ca_pin(&h));
    let now = h.now();
    let run = |route: Route, key: &(KeyId, SigningKey), payload: Value, value: Option<Vec<u8>>| {
        let (key_id, key) = (key.0, key.1.clone());
        let client = &client;
        async move {
            call::run(
                client,
                route,
                None,
                (key_id, &key),
                payload,
                value.as_deref(),
                now,
            )
            .await
        }
    };

    // Route 4 by the anchor, whose id the bootstrap reply handed out.
    let admin_key = SigningKey::from_bytes(&[21u8; 32]);
    let reply = run(
        Route::RegisterKey,
        &h.anchor,
        json!({ "principal_id": PrincipalId::mint(), "public_key": spki_b64(&admin_key), "label": "day-to-day" }),
        None,
    )
    .await
    .unwrap();
    let admin = (
        reply["id"].as_str().unwrap().parse::<KeyId>().unwrap(),
        admin_key,
    );
    assert_eq!(reply["org_id"], json!(h.org));

    // Route 1 with the canonical manifest vector.
    let compose =
        fs::read_to_string(testdata().join("manifest/01-canonical/app-compose.json")).unwrap();
    let expected: Value = serde_json::from_str(
        &fs::read_to_string(testdata().join("manifest/01-canonical/expected.json")).unwrap(),
    )
    .unwrap();
    let app_id: AppId = expected["app_id"].as_str().unwrap().parse().unwrap();
    let reply = run(
        Route::RegisterRevision,
        &admin,
        json!({ "app_id": app_id, "compose": compose }),
        None,
    )
    .await
    .unwrap();
    assert_eq!(reply["compose_hash"], expected["compose_hash"]);
    let stored: String = sqlx::query_scalar!(
        "select compose from revisions where app_id = $1",
        Uuid::from(app_id)
    )
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert_eq!(
        stored,
        fs::read_to_string(testdata().join("manifest/01-canonical/app-compose.json")).unwrap()
    );

    // Route 3: content_sha256 and issued_at filled in from the value and the clock.
    let reply = run(
        Route::PutSecret,
        &admin,
        json!({ "name": "api-key", "app_ids": [app_id] }),
        Some(b"s3cret".to_vec()),
    )
    .await
    .unwrap();
    assert_eq!(
        reply["content_sha256"],
        json!(format!("sha256:{}", hex::encode(Sha256::digest(b"s3cret"))))
    );
    assert_eq!(reply["name"], "api-key");
    let err = run(
        Route::PutSecret,
        &admin,
        json!({ "name": "api-key", "app_ids": [app_id] }),
        None,
    )
    .await
    .unwrap_err();
    assert!(err.contains("--value"), "{err}");
    let err = run(Route::RegisterKey, &admin, json!({}), Some(b"x".to_vec()))
        .await
        .unwrap_err();
    assert!(err.contains("only for put-secret"), "{err}");

    // Route 2: the path comes from the payload.
    let reply = run(
        Route::RevokeRevision,
        &admin,
        json!({ "compose_hash": expected["compose_hash"] }),
        None,
    )
    .await
    .unwrap();
    assert_eq!(reply["compose_hash"], expected["compose_hash"]);
    assert!(reply["revoked_at"].is_string());

    // Route 5, then the revoked key signs nothing.
    let reply = run(
        Route::RevokeKey,
        &h.anchor,
        json!({ "key_id": admin.0, "reason": "compromised" }),
        None,
    )
    .await
    .unwrap();
    assert_eq!(reply["reason"], "compromised");
    let err = run(
        Route::RevokeRevision,
        &admin,
        json!({ "compose_hash": expected["compose_hash"] }),
        None,
    )
    .await
    .unwrap_err();
    assert!(err.starts_with("signature_invalid"), "{err}");

    // A wrong context is refused by the KMS, not repaired by the CLI.
    let err = call::run(
        &client,
        Route::RevokeKey,
        Some(alpha_core::context::SECRET),
        (h.anchor.0, &h.anchor.1),
        json!({ "key_id": admin.0, "reason": "retired" }),
        None,
        now,
    )
    .await
    .unwrap_err();
    assert!(err.starts_with("signature_invalid"), "{err}");
    assert_eq!(h.audit("key.revoke").await.len(), 2);
}

#[tokio::test]
async fn deploy_register_only_registers_the_generated_compose() {
    let Some(h) = wall_clock_harness().await else {
        return;
    };
    let client = pinned(&h, ca_pin(&h));
    let admin = h.register_key(&h.anchor, 22).await;
    let vector = testdata().join("manifest/05-deploy");
    let spec = deploy::parse(&fs::read_to_string(vector.join("app.yaml")).unwrap()).unwrap();
    let expected: Value =
        serde_json::from_str(&fs::read_to_string(vector.join("expected.json")).unwrap()).unwrap();

    let reply = deploy::run(&client, &spec, admin.0, &admin.1, None)
        .await
        .unwrap();
    assert_eq!(reply["revision"]["compose_hash"], expected["compose_hash"]);
    assert_eq!(reply["revision"]["app_id"], json!(spec.app_id));
    assert!(
        reply.get("deploy").is_none(),
        "register-only stops before shroud-go"
    );
    let stored: String = sqlx::query_scalar!(
        "select compose from revisions where app_id = $1",
        Uuid::from(spec.app_id)
    )
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert_eq!(
        stored,
        fs::read_to_string(vector.join("app-compose.json")).unwrap()
    );

    let again = deploy::run(&client, &spec, admin.0, &admin.1, None)
        .await
        .unwrap();
    assert_eq!(
        again["revision"]["created_at"],
        reply["revision"]["created_at"]
    );
    assert_eq!(h.audit("revision.register").await.len(), 1);
}

#[tokio::test]
async fn sign_and_check_feed_the_node_and_the_admin_pin() {
    let Some(h) = wall_clock_harness().await else {
        return;
    };
    let mut document = platform_document(KEYED);
    document["version"] = json!(2);
    document["kms_ca_pem"] = json!(h.ca_pem);
    let artifact = sign::sign(document.clone(), &h.release.key).unwrap();
    let summary = sign::check(&artifact, &h.release.key.verifying_key(), h.now()).unwrap();
    let ca_der = h.node.intermediates().unwrap().ca_cert_der.clone();
    assert_eq!(
        summary.kms_ca_spki_sha256.as_deref(),
        Some(
            format!(
                "sha256:{}",
                hex::encode(Sha256::digest(tls::spki_of(&ca_der).unwrap()))
            )
            .as_str()
        )
    );
    assert_eq!(summary.kms_revisions, vec![h.node.compose_hash]);
    assert!(
        sign::check(&artifact, &alpha_cli::release_key().unwrap(), h.now()).is_err(),
        "not the pilot key"
    );

    h.release.set(document);
    platform::reload(&h.node).await.unwrap();
    assert_eq!(h.node.platform_document().unwrap().version, 2);
    let served =
        alpha_client::platform::fetch(&h.release.url, &h.release.key.verifying_key(), h.now())
            .await
            .unwrap();
    let client = pinned(&h, Pin::Ca(tls::cert_from_pem(&served.kms_ca_pem).unwrap()));
    assert!(client.ready().await.is_ok());
}

#[tokio::test]
async fn bootstrap_once_never_again_then_unseal_the_second_node() {
    let Some(h) = wall_clock_harness().await else {
        return;
    };
    assert!(!h.node.is_sealed());
    assert_eq!(h.ca_pem, h.node.intermediates().unwrap().ca_pem());
    assert_eq!(
        h.bootstrap["kms_ca_spki_sha256"],
        json!(sign::ca_spki_sha256(&h.ca_pem).unwrap().unwrap())
    );
    let anchor_id: Uuid =
        sqlx::query_scalar!("select id from principal_keys where registered_by_key is null")
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert_eq!(h.anchor.0, KeyId::from(anchor_id));
    let identity = node_identity(&h.node);
    let shares: Vec<std::path::PathBuf> =
        serde_json::from_value(h.bootstrap["shares"].clone()).unwrap();
    assert_eq!(shares.len(), 3);
    for path in &shares {
        let file = cli_node::ShareFile::read(path).unwrap();
        assert_eq!(file.platform_document_version, 1);
        assert_eq!(
            file.kms_node_spki_sha256,
            format!("sha256:{}", hex::encode(identity.aad()))
        );
    }

    // Never again: the serving node refuses, and so does a fresh sealed node over the same database.
    let pubs = custodian_pubs(&h.custodians);
    let anchor = Anchor {
        org_id: h.org,
        principal_id: PrincipalId::mint(),
        public_key: spki_b64(&h.anchor.1),
        label: "again".into(),
    };
    let client = spki_client(&h.url, &h.node);
    let err = cli_node::bootstrap(&client, &identity, pubs.clone(), anchor.clone(), 1, &h.dir)
        .await
        .unwrap_err();
    assert!(err.starts_with("already_exists"), "{err}");
    let (node2, url2, _shutdown2) = start_node(
        h.pool.clone(),
        &h.release.url,
        &h.release.key,
        Arc::new(SystemTime::now),
    )
    .await;
    assert!(node2.is_sealed());
    let identity2 = node_identity(&node2);
    let client2 = spki_client(&url2, &node2);
    let err = cli_node::bootstrap(&client2, &identity2, pubs, anchor, 1, &h.dir)
        .await
        .unwrap_err();
    assert!(err.starts_with("already_exists"), "{err}");
    assert!(node2.is_sealed());

    // The self-signed sealed listener is pinned by SPKI: another node's key is refused.
    let wrong = spki_client(&h.url, &node2);
    assert!(matches!(
        wrong.ready().await.unwrap_err(),
        alpha_client::Error::Connect(_)
    ));

    // Unseal through the CLI: one share leaves it sealed, the second opens it; the share file
    // remembers the higher document version it was verified against.
    let reply = cli_node::unseal(&client2, &identity2, &shares[2], &h.custodians[2], 3)
        .await
        .unwrap();
    assert!(reply.sealed);
    assert_eq!(reply.shares, 1);
    assert_eq!(
        cli_node::ShareFile::read(&shares[2])
            .unwrap()
            .platform_document_version,
        3
    );
    let err = cli_node::unseal(&client2, &identity2, &shares[0], &h.custodians[2], 1)
        .await
        .unwrap_err();
    assert!(err.contains("share file"), "{err}");
    let reply = cli_node::unseal(&client2, &identity2, &shares[0], &h.custodians[0], 1)
        .await
        .unwrap();
    assert!(!reply.sealed);
    assert!(!node2.is_sealed());
    assert_eq!(
        cli_node::ShareFile::read(&shares[0])
            .unwrap()
            .platform_document_version,
        1
    );
    assert_eq!(
        *node2.intermediates().unwrap().tenant_kek_root,
        *h.node.intermediates().unwrap().tenant_kek_root
    );
}
