//! PRD-06 I3 against a real Postgres (`DATABASE_URL`; skipped without it) and the stand-in for
//! our own DSM: the KMS root KEK's co-factor in DSM is needed in addition to two custodian shares,
//! never instead of them.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use std::sync::Arc;
use std::sync::atomic::Ordering;

use alpha_crypto::INFO_UNSEAL_SHARE;
use alpha_dsm::stand_in::{AES_KEY, API_KEY, StandIn};
use alpha_kms::Node;
use common::*;
use reqwest::StatusCode;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use vsss_rs::Gf256;
use zeroize::Zeroizing;

/// Posts `shares` to `node`'s unseal route; the last reply.
async fn unseal(node: &Arc<Node>, url: &str, shares: &[&Vec<u8>]) -> (StatusCode, Value) {
    let aad: [u8; 32] = Sha256::digest(&node.runtime_spki).into();
    let mut last = (StatusCode::OK, Value::Null);
    for share in shares {
        let body = json!({ "share_hpke": alpha_crypto::seal(&node.xwing_key.public(), INFO_UNSEAL_SHARE, &aad, share).unwrap() });
        last = send(client().post(format!("{url}/v1/node/unseal")).json(&body)).await;
    }
    last
}

#[tokio::test]
async fn the_root_needs_two_custodian_shares_and_our_dsm_never_one_without_the_other() {
    let dsm = StandIn::new();
    let (endpoint, ca) = dsm.serve().await;
    let config = StandIn::config(&endpoint, &ca, AES_KEY);
    let Some(h) = harness_with_root_dsm(config.clone(), Zeroizing::new(API_KEY.into())).await
    else {
        return;
    };
    // Bootstrap had the DSM encrypt the co-factor and decrypt it once, before storing anything.
    assert_eq!(dsm.calls.load(Ordering::SeqCst), 2);
    let rows = sqlx::query!("select details from audit_log where action = 'node.bootstrap'")
        .fetch_all(&h.pool)
        .await
        .unwrap();
    assert_eq!(rows[0].details, json!({ "root_dsm": true }));

    // The shares alone open nothing: the intermediates are under HKDF(root ‖ co-factor).
    let root = Gf256::combine_bytes(&h.shares[..2]).unwrap();
    let root: [u8; 32] = root.as_slice().try_into().unwrap();
    let ca_wrapped =
        sqlx::query_scalar!("select wrapped from intermediate_keys where purpose = 'ca'")
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert!(alpha_kms::keys::aead_open(&root, b"ca", &ca_wrapped).is_none());
    // Nor does the DSM alone: what it holds is the co-factor, and the API key that reaches it is
    // under the custodians' root.
    let stored = sqlx::query!("select api_key_wrapped from root_cofactor")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert!(
        !stored
            .api_key_wrapped
            .windows(API_KEY.len())
            .any(|w| w == API_KEY.as_bytes())
    );

    let second = |root_dsm: Option<alpha_dsm::OwnDsmConfig>| {
        start_node_with_root_dsm(
            h.pool.clone(),
            &h.release.url,
            &h.release.key,
            h.node.clock.clone(),
            root_dsm,
        )
    };

    // Two shares and the DSM: the node serves the same intermediates.
    let (node2, url2, _s2) = second(Some(config.clone())).await;
    let (status, reply) = unseal(&node2, &url2, &[&h.shares[1], &h.shares[2]]).await;
    assert_eq!(
        (status, reply),
        (StatusCode::OK, json!({ "sealed": false, "shares": 2 }))
    );
    assert_eq!(
        *node2.intermediates().unwrap().tenant_kek_root,
        *h.node.intermediates().unwrap().tenant_kek_root
    );

    // Two shares while the DSM's admin has disabled the key: still sealed, the shares dropped.
    let (node3, url3, _s3) = second(Some(config.clone())).await;
    dsm.disabled.store(true, Ordering::SeqCst);
    let (status, reply) = unseal(&node3, &url3, &[&h.shares[0], &h.shares[1]]).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{reply}");
    assert!(
        reply["error"]["message"]
            .as_str()
            .unwrap()
            .contains("root DSM"),
        "{reply}"
    );
    assert!(node3.is_sealed());
    dsm.disabled.store(false, Ordering::SeqCst);
    let (status, reply) = unseal(&node3, &url3, &[&h.shares[0], &h.shares[1]]).await;
    assert_eq!(
        (status, reply["sealed"].clone()),
        (StatusCode::OK, json!(false))
    );

    // A node whose measured configuration drops the DSM, or names another key, unseals nothing.
    let (node4, url4, _s4) = second(None).await;
    let (status, reply) = unseal(&node4, &url4, &[&h.shares[0], &h.shares[2]]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{reply}");
    assert!(
        reply["error"]["message"]
            .as_str()
            .unwrap()
            .contains("ALPHACOMPUTE_KMS_ROOT_DSM"),
        "{reply}"
    );
    assert!(node4.is_sealed());
    let (node5, url5, _s5) = second(Some(StandIn::config(&endpoint, &ca, "another-key"))).await;
    let (status, reply) = unseal(&node5, &url5, &[&h.shares[0], &h.shares[2]]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{reply}");
    assert!(node5.is_sealed());
    let denied = sqlx::query_scalar!(
        "select count(*) from audit_log where action = 'node.unseal' and outcome <> 'ok'"
    )
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert_eq!(denied, Some(3));
}

#[tokio::test]
async fn a_root_without_a_cofactor_is_not_unsealed_by_a_node_that_expects_one() {
    let Some(h) = harness().await else {
        return;
    };
    let dsm = StandIn::new();
    let (endpoint, ca) = dsm.serve().await;
    let (node2, url2, _s2) = start_node_with_root_dsm(
        h.pool.clone(),
        &h.release.url,
        &h.release.key,
        h.node.clock.clone(),
        Some(StandIn::config(&endpoint, &ca, AES_KEY)),
    )
    .await;
    let (status, reply) = unseal(&node2, &url2, &[&h.shares[0], &h.shares[1]]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{reply}");
    assert!(
        reply["error"]["message"]
            .as_str()
            .unwrap()
            .contains("bootstrapped without a DSM co-factor"),
        "{reply}"
    );
    assert_eq!(dsm.calls.load(Ordering::SeqCst), 0);
}
