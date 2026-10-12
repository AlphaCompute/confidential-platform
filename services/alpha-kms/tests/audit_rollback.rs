//! Andrei Pfau's review of #95: the operator restores the trust-zone Postgres from an older copy.
//! The copy is internally consistent, so its audit chain verifies and ends at an older head. Each
//! node therefore keeps the highest head it has seen committed, outside the database, and learns
//! heads from the node it joins, from its peers and from custodians' share files. A database that
//! does not hold one halts the node: not ready, nothing released, nothing appended.

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

use alpha_cli::node as cli_node;
use alpha_client::JoinReply;
use alpha_core::AppId;
use alpha_kms::audit::{self, Checkpoint, Halt};
use alpha_kms::{Node, node, platform};
use common::*;
use reqwest::StatusCode;
use serde_json::json;

/// What an operator's copy of the database holds: the audit chain up to `head`, and `secrets`.
struct Copy {
    head: i64,
}

async fn take_copy(h: &Harness) -> Copy {
    sqlx::query("create table secrets_copy as select * from secrets")
        .execute(&h.pool)
        .await
        .unwrap();
    Copy {
        head: sqlx::query_scalar("select max(seq) from audit_log")
            .fetch_one(&h.pool)
            .await
            .unwrap(),
    }
}

/// Restores the copy as an operator would: the audit rows after it gone, the sequence back where
/// the copy had it (so the next row reuses a `seq`), and `secrets` as the copy held them.
async fn restore(h: &Harness, copy: &Copy) {
    for sql in [
        "delete from audit_log where seq > $1",
        "select setval(pg_get_serial_sequence('audit_log', 'seq'), $1)",
        "delete from secrets where $1 = $1",
        "insert into secrets select * from secrets_copy where $1 = $1",
    ] {
        sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(copy.head)
            .execute(&h.pool)
            .await
            .unwrap();
    }
}

/// The reply `POST /v1/node/join` gives, from the serving node's memory.
fn join_reply(serving: &Node) -> JoinReply {
    let keys = serving.intermediates().unwrap();
    JoinReply {
        tenant_kek_root: b64(keys.tenant_kek_root.as_slice()),
        ca_key: b64(&keys.ca_key_der),
        ca_cert: b64(&keys.ca_cert_der),
        audit_head: serving.chain.floor().map(|f| f.to_wire()),
    }
}

#[tokio::test]
async fn a_database_restored_from_an_older_copy_is_refused_and_the_node_halts() {
    let Some(h) = harness().await else {
        return;
    };
    let admin = h.register_key(&h.root, 81).await;
    let app = AppId::mint();
    h.insert_capture_revision(app, &admin).await;
    let (status, reply) = h
        .put_secret("chained", &[app], b"old", h.now(), &admin)
        .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let instance = h.instance_client().await;
    let url = format!("{}/v1/secrets/chained", h.url);
    let copy = take_copy(&h).await;

    // After the copy: the Secret is replaced. The node remembers the head of that commit.
    let later = h.now() + std::time::Duration::from_secs(1);
    let (status, reply) = h.put_secret("chained", &[app], b"new", later, &admin).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let (status, reply) = send(instance.get(&url)).await;
    assert_eq!(
        (status, reply["value"].clone()),
        (StatusCode::OK, json!(b64(b"new")))
    );
    let floor = h.node.chain.floor().unwrap();
    assert!(floor.seq > copy.head);

    restore(&h, &copy).await;
    // The copy is consistent: its chain verifies on its own and ends where the copy was taken.
    let at = audit::verify(&h.pool, &h.metadata(), Checkpoint::default(), |_| {})
        .await
        .unwrap();
    assert_eq!(at.head().unwrap().seq, copy.head);

    // The next audit row would follow the copy's head; the node refuses it, and with it the
    // release of the old value.
    let (status, reply) = send(instance.get(&url)).await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::SERVICE_UNAVAILABLE, "halted"),
        "the copy's value is not released: {reply}"
    );
    assert_eq!(h.node.chain.halted(), Some(Halt::RolledBack));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("select max(seq) from audit_log")
            .fetch_one(&h.pool)
            .await
            .unwrap(),
        copy.head,
        "nothing appended to the copy"
    );
    assert_halted(&h, &instance, "audit_chain_rolled_back").await;
}

#[tokio::test]
async fn maintenance_finds_a_restored_copy_with_no_request_and_a_new_row_on_it() {
    let Some(h) = harness().await else {
        return;
    };
    let admin = h.register_key(&h.root, 82).await;
    h.insert_capture_revision(AppId::mint(), &admin).await;
    let instance = h.instance_client().await;
    let copy = take_copy(&h).await;
    h.register_key(&h.root, 84).await;
    h.node.maintain().await;
    assert_eq!(h.node.chain.halted(), None);

    // Restored, and a row appended on the copy by another node, so the head's `seq` exists again
    // with another link.
    restore(&h, &copy).await;
    let (other, _, _shutdown) = start_node(
        h.pool.clone(),
        &h.release.url,
        &h.release.key,
        h.node.clock.clone(),
    )
    .await;
    other
        .audit(audit::node("node.join.request", "ok", json!({})))
        .await
        .unwrap();
    h.node.maintain().await;
    assert_eq!(h.node.chain.halted(), Some(Halt::RolledBack));
    assert_halted(&h, &instance, "audit_chain_rolled_back").await;
}

#[tokio::test]
async fn a_joining_node_refuses_a_database_without_the_serving_nodes_head() {
    let Some(h) = harness().await else {
        return;
    };
    let copy = take_copy(&h).await;
    h.register_key(&h.root, 83).await;
    let reply = join_reply(&h.node);
    assert!(reply.audit_head.as_ref().unwrap().seq > copy.head);

    // On the database the serving node saw, the joining node serves from its head on.
    let (joined, _, _s1) = start_node(
        h.pool.clone(),
        &h.release.url,
        &h.release.key,
        h.node.clock.clone(),
    )
    .await;
    node::finish_join(&joined, &reply).await.unwrap();
    assert!(!joined.is_sealed());
    assert!(joined.chain.floor().unwrap().seq >= reply.audit_head.as_ref().unwrap().seq);

    // Pointed at an older copy, it halts instead of serving it.
    restore(&h, &copy).await;
    let (stray, stray_url, _s2) = start_node(
        h.pool.clone(),
        &h.release.url,
        &h.release.key,
        h.node.clock.clone(),
    )
    .await;
    let rows = audit_count(&h).await;
    let e = node::finish_join(&stray, &reply).await.unwrap_err();
    assert_eq!(e.code, "halted");
    assert!(stray.is_sealed());
    assert_eq!(stray.chain.halted(), Some(Halt::RolledBack));
    let (status, ready) = send(client().get(format!("{stray_url}/ready"))).await;
    assert_eq!(
        (status, ready),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            json!({ "sealed": true, "halted": "audit_chain_rolled_back" })
        )
    );
    assert_eq!(audit_count(&h).await, rows, "the halted node wrote nothing");
}

#[tokio::test]
async fn a_node_halts_when_a_peer_has_seen_a_head_its_database_lacks() {
    let Some(h) = harness_with_clock(Arc::new(SystemTime::now)).await else {
        return;
    };
    // The peers pin each other as a join does: the KMS CA and a listed KMS Revision.
    let mut document = platform_document(KEYED);
    document["version"] = json!(2);
    document["kms_ca_pem"] = json!(h.ca_pem);
    h.release.set(document);
    platform::reload(&h.node).await.unwrap();
    let (peer, _, _s) = start_node_with_peers(
        h.pool.clone(),
        &h.release.url,
        &h.release.key,
        h.node.clock.clone(),
        Vec::new(),
        vec![h.url.clone()],
    )
    .await;
    node::finish_join(&peer, &join_reply(&h.node))
        .await
        .unwrap();
    let copy = take_copy(&h).await;

    // Only the first node writes after the copy; the peer's own floor stays at or below the copy.
    h.node
        .audit(audit::node("node.fact", "ok", json!({})))
        .await
        .unwrap();
    let head = h.node.chain.floor().unwrap();
    assert!(head.seq > copy.head);
    assert!(peer.chain.floor().unwrap().seq <= copy.head);
    let (status, reply) = send(client().get(format!("{}/v1/node/audit-head", h.url))).await;
    assert_eq!(
        (status, reply),
        (StatusCode::OK, json!({ "head": head.to_wire() }))
    );
    peer.maintain().await;
    assert_eq!(
        peer.chain.halted(),
        None,
        "the database holds the peer's head"
    );

    restore(&h, &copy).await;
    peer.maintain().await;
    assert_eq!(
        peer.chain.halted(),
        Some(Halt::RolledBack),
        "the first node's head, read over the pinned channel, is not in the database"
    );
    assert_eq!(peer.intermediates().err().map(|e| e.code), Some("halted"));
}

#[tokio::test]
async fn custodians_share_files_carry_the_head_across_a_cold_start() {
    let Some(h) = harness().await else {
        return;
    };
    let copy = take_copy(&h).await;
    let shares: Vec<std::path::PathBuf> =
        serde_json::from_value(h.bootstrap["shares"].clone()).unwrap();
    let wall = || Arc::new(SystemTime::now);
    let start = || start_node(h.pool.clone(), &h.release.url, &h.release.key, wall());

    // A cold start: custodians 3 then 1 unseal a node; the second reply carries the head the node
    // serves from, and custodian 1's share file remembers it.
    let (second, url2, _s2) = start().await;
    let client2 = spki_client(&url2, &second);
    let identity2 = node_identity(&second);
    let reply = cli_node::unseal(&client2, &identity2, &shares[2], &h.custodians[2], 1, false)
        .await
        .unwrap();
    assert_eq!(reply.audit_head, None);
    let reply = cli_node::unseal(&client2, &identity2, &shares[0], &h.custodians[0], 1, false)
        .await
        .unwrap();
    let head = reply.audit_head.unwrap();
    assert!(head.seq > copy.head);
    assert_eq!(
        cli_node::ShareFile::read(&shares[0]).unwrap().audit_head,
        Some(head.clone())
    );
    assert_eq!(
        cli_node::ShareFile::read(&shares[2]).unwrap().audit_head,
        None
    );

    // Every node gone, the database restored from the copy: the next cold start sends custodian
    // 1's head, and the node halts instead of serving the copy.
    restore(&h, &copy).await;
    let (third, url3, _s3) = start().await;
    let client3 = spki_client(&url3, &third);
    let identity3 = node_identity(&third);
    let rows = audit_count(&h).await;
    let reply = cli_node::unseal(&client3, &identity3, &shares[0], &h.custodians[0], 1, false)
        .await
        .unwrap();
    assert!(reply.sealed);
    let e = cli_node::unseal(&client3, &identity3, &shares[1], &h.custodians[1], 1, false)
        .await
        .unwrap_err();
    assert!(e.contains("halted"), "{e}");
    assert!(third.is_sealed());
    assert_eq!(third.chain.halted(), Some(Halt::RolledBack));
    assert_eq!(audit_count(&h).await, rows, "the halted node wrote nothing");

    // Custodians who decide to accept the restore say so, explicitly, and their share files then
    // remember the restored head.
    let (fourth, url4, _s4) = start().await;
    let client4 = spki_client(&url4, &fourth);
    let identity4 = node_identity(&fourth);
    for (i, accept) in [(0, true), (1, false)] {
        cli_node::unseal(
            &client4,
            &identity4,
            &shares[i],
            &h.custodians[i],
            1,
            accept,
        )
        .await
        .unwrap();
    }
    assert!(!fourth.is_sealed());
    let restored = fourth.chain.floor().unwrap().to_wire();
    assert_ne!(
        restored, head,
        "the restored chain's head, not the one before the restore"
    );
    assert_eq!(
        cli_node::ShareFile::read(&shares[0]).unwrap().audit_head,
        None
    );
    assert_eq!(
        cli_node::ShareFile::read(&shares[1]).unwrap().audit_head,
        Some(restored)
    );
}
