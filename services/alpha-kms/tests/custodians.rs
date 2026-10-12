//! Custodian re-share with root rotation, against an in-process node on `DATABASE_URL` (skipped
//! without it): two current custodians rotate through `alpha-cli`'s library, one cannot, a wrong
//! or replayed nonce cannot, a rotation that fails before its commit changes nothing, the old shares
//! open nothing afterwards, joined nodes keep serving and later joins get the same keys, and every
//! sealed row stays readable.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use alpha_attest::PlatformDocument;
use alpha_cli::custodians;
use alpha_cli::node::{self as cli_node, NodeIdentity};
use alpha_client::{Client, RotateRequest, Rotation, RotationProposal};
use alpha_core::AppId;
use alpha_crypto::{INFO_CUSTODIAN_APPROVAL, PrivateKey, PublicKey};
use alpha_kms::{Clock, Node, audit, certs, instance, node, store};
use common::*;
use reqwest::StatusCode;
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// The capture's time plus a shared offset each proposal moves on by a second: the KMS's nonce is
/// a MAC of the second it was minted in, and a frozen clock would mint one nonce forever.
static TICKS: AtomicU64 = AtomicU64::new(0);

fn ticking() -> Clock {
    let base = captured_at(KEYED);
    Arc::new(move || base + Duration::from_secs(TICKS.load(Ordering::SeqCst)))
}

async fn harness() -> Option<Harness> {
    harness_with_clock(ticking()).await
}

async fn propose(client: &Client, node: &NodeIdentity, new: [PublicKey; 3]) -> RotationProposal {
    TICKS.fetch_add(1, Ordering::SeqCst);
    custodians::propose(client, node, new).await.unwrap()
}

fn doc_for(h: &Harness) -> PlatformDocument {
    let mut doc = platform_document(KEYED);
    doc["kms_ca_pem"] = json!(h.ca_pem);
    serde_json::from_value(doc).unwrap()
}

fn share_path(h: &Harness, i: usize) -> PathBuf {
    h.dir.join(format!("share-{i}.json"))
}

fn pubs(keys: &[&PrivateKey]) -> [PublicKey; 3] {
    keys.iter()
        .map(|k| k.public())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

async fn wrapped(h: &Harness) -> Vec<(String, Vec<u8>)> {
    sqlx::query_as("select purpose::text, wrapped from intermediate_keys order by purpose")
        .fetch_all(&h.pool)
        .await
        .unwrap()
}

async fn rotations(h: &Harness) -> i64 {
    sqlx::query_scalar!(r#"select count(*) as "n!" from custodian_rotations"#)
        .fetch_one(&h.pool)
        .await
        .unwrap()
}

/// An approval built by hand, as the CLI builds it, for refusals the CLI would not send.
fn approval(node: &NodeIdentity, digest: &[u8; 32], share: &[u8]) -> alpha_crypto::Sealed {
    let plain = [digest.as_slice(), share].concat();
    alpha_crypto::seal(&node.xwing, INFO_CUSTODIAN_APPROVAL, &node.aad(), &plain).unwrap()
}

async fn post(
    client: &Client,
    proposal: &RotationProposal,
    approval_hpke: alpha_crypto::Sealed,
) -> Result<alpha_client::RotateReply, alpha_client::Error> {
    client
        .rotate_custodians(&RotateRequest {
            proposal: proposal.clone(),
            approval_hpke,
        })
        .await
}

fn code_of(e: &alpha_client::Error) -> String {
    e.to_string()
}

/// Two current custodians (`approvers`, by share file index) rotate to `new` through the CLI's
/// library; returns the rotation.
async fn rotate(h: &Harness, new: [PublicKey; 3], approvers: [usize; 2]) -> Rotation {
    let client = spki_client(&h.url, &h.node);
    let identity = node_identity(&h.node);
    let doc = doc_for(h);
    let proposal = propose(&client, &identity, new).await;
    let [a, b] = approvers;
    let first = custodians::approve(
        &client,
        &identity,
        &proposal,
        &share_path(h, a),
        &h.custodians[a - 1],
        &doc,
    )
    .await
    .unwrap();
    assert_eq!((first.rotated, first.approvals), (false, 1));
    let second = custodians::approve(
        &client,
        &identity,
        &proposal,
        &share_path(h, b),
        &h.custodians[b - 1],
        &doc,
    )
    .await
    .unwrap();
    assert_eq!((second.rotated, second.approvals), (true, 2));
    second.rotation.unwrap()
}

/// Each new custodian's accept, into `dir`; returns the share files in the proposal's order.
fn accept_all(h: &Harness, rotation: &Rotation, keys: &[&PrivateKey], dir: &Path) -> Vec<PathBuf> {
    fs::create_dir_all(dir).unwrap();
    keys.iter()
        .enumerate()
        .map(|(i, key)| {
            let out = dir.join(format!("new-share-{}.json", i + 1));
            let accepted = custodians::accept(rotation, &doc_for(h), key, &out).unwrap();
            assert_eq!(accepted["custodian"], json!(i + 1));
            out
        })
        .collect()
}

async fn sealed_node(h: &Harness) -> (Arc<Node>, String, tokio::sync::oneshot::Sender<()>) {
    let started = start_node(h.pool.clone(), &h.release.url, &h.release.key, ticking()).await;
    assert!(started.0.is_sealed());
    started
}

/// `alpha unseal` with two share files on a fresh node: the second share's result.
async fn unseal_with(
    h: &Harness,
    shares: [(&Path, &PrivateKey); 2],
) -> (Arc<Node>, Result<alpha_client::UnsealReply, String>) {
    let (node, url, shutdown) = sealed_node(h).await;
    std::mem::forget(shutdown);
    let client = spki_client(&url, &node);
    let identity = node_identity(&node);
    let [(a, ka), (b, kb)] = shares;
    let first = cli_node::unseal(&client, &identity, a, ka, 1)
        .await
        .unwrap();
    assert!(first.sealed);
    let second = cli_node::unseal(&client, &identity, b, kb, 1).await;
    (node, second)
}

#[tokio::test]
async fn two_current_custodians_replace_one_and_the_old_shares_open_nothing() {
    let Some(h) = harness().await else {
        return;
    };
    let app = AppId::mint();
    let (status, reply) = h
        .put_secret("db-password", &[app], b"hunter2", h.now(), &h.root)
        .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let before = wrapped(&h).await;
    let serving = h.node.intermediates().unwrap();

    // Custodian 3 leaves: custodians 1 and 2 stay, with new shares, and `d3` joins.
    let d3 = PrivateKey::generate().unwrap();
    let new_keys = [&h.custodians[0], &h.custodians[1], &d3];
    let rotation = rotate(&h, pubs(&new_keys), [1, 3]).await;

    // Every wrapped row changed; what they wrap did not, and the node never stopped serving.
    let after = wrapped(&h).await;
    assert_eq!(
        before.iter().map(|r| &r.0).collect::<Vec<_>>(),
        ["ca", "tenant-kek-root"]
    );
    for ((purpose, old), (_, new)) in before.iter().zip(&after) {
        assert_ne!(old, new, "{purpose} was not re-wrapped");
    }
    assert!(!h.node.is_sealed());
    assert_eq!(
        *h.node.intermediates().unwrap().tenant_kek_root,
        *serving.tenant_kek_root
    );

    // The receipt verifies against the KMS CA and names the proposal and every share.
    let signed = custodians::verify_rotation(&rotation, &doc_for(&h)).unwrap();
    assert_eq!(signed["approved_by_shares"], json!([1, 3]));
    assert_eq!(signed["rewrapped"], json!(["tenant-kek-root", "ca"]));
    assert_eq!(
        signed["custodians_sha256"][2],
        json!(alpha_channel::sha256_label(d3.public().as_bytes()))
    );
    let mut forged = rotation.clone();
    forged.shares_hpke.swap(0, 1);
    assert!(
        custodians::verify_rotation(&forged, &doc_for(&h))
            .unwrap_err()
            .contains("shares_hpke_sha256")
    );
    let mut other_ca = platform_document(KEYED);
    other_ca["kms_ca_pem"] = json!(certs::pem(&certs::new_ca(h.now()).unwrap().1));
    assert!(
        custodians::verify_rotation(&rotation, &serde_json::from_value(other_ca).unwrap()).is_err()
    );

    // The new custodians accept; the departed custodian's key opens none of the new shares.
    let dir = h.dir.join("rotated");
    let new_shares = accept_all(&h, &rotation, &new_keys, &dir);
    let e = custodians::accept(
        &rotation,
        &doc_for(&h),
        &h.custodians[2],
        &dir.join("x.json"),
    )
    .unwrap_err();
    assert!(e.contains("not one of the rotation's three"), "{e}");
    let e = custodians::accept(&rotation, &doc_for(&h), &d3, &new_shares[2]).unwrap_err();
    assert!(
        e.contains("exists"),
        "an accepted share file is never overwritten: {e}"
    );

    // Old shares, alone or beside a new one, open nothing; two new ones open the same keys.
    let old = |i: usize| (share_path(&h, i), &h.custodians[i - 1]);
    let (o1, k1) = old(1);
    let (o3, k3) = old(3);
    let (stale, refused) = unseal_with(&h, [(&o1, k1), (&o3, k3)]).await;
    let refused = refused.unwrap_err();
    assert!(
        refused.contains("does not unwrap under this root"),
        "{refused}"
    );
    assert!(stale.is_sealed());
    let (mixed, refused) = unseal_with(&h, [(&o3, k3), (&new_shares[0], &h.custodians[0])]).await;
    assert!(refused.is_err());
    assert!(mixed.is_sealed());
    let (fresh, opened) = unseal_with(
        &h,
        [(&new_shares[2], &d3), (&new_shares[1], &h.custodians[1])],
    )
    .await;
    assert!(!opened.unwrap().sealed);
    let keys = fresh.intermediates().unwrap();
    assert_eq!(*keys.tenant_kek_root, *serving.tenant_kek_root);
    assert_eq!(keys.ca_cert_der, serving.ca_cert_der);

    // The metadata sealed before the rotation, and the audit chain across it, still open.
    let secret = store::load_secret(&h.pool, &keys.metadata, h.org.into(), "db-password")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(secret.record.app_ids, vec![Uuid::from(app)]);
    audit::verify(
        &h.pool,
        &keys.metadata,
        audit::Checkpoint::default(),
        |_| {},
    )
    .await
    .unwrap();
    let (status, reply) = h
        .put_secret(
            "db-password",
            &[app],
            b"hunter3",
            h.now() + Duration::from_secs(1),
            &h.root,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{reply}");

    // The node keeps the committed rotation, and the audit log has both approvals' rows.
    let stored = spki_client(&h.url, &h.node).last_rotation().await.unwrap();
    assert_eq!(
        serde_json::to_value(&stored).unwrap(),
        serde_json::to_value(&rotation).unwrap()
    );
    assert_eq!(h.audit("custodians.approve").await.len(), 1);
    let rotated = h.audit("custodians.rotate").await;
    assert_eq!(rotated.len(), 1);
    assert_eq!(rotated[0].1, "ok");
    assert_eq!(rotated[0].2["rotation_id"], json!(rotation.id));
}

#[tokio::test]
async fn all_three_custodians_replaced_and_the_new_ones_rotate_again() {
    let Some(h) = harness().await else {
        return;
    };
    let new: Vec<PrivateKey> = (0..3).map(|_| PrivateKey::generate().unwrap()).collect();
    let new_refs: Vec<&PrivateKey> = new.iter().collect();
    let rotation = rotate(&h, pubs(&new_refs), [2, 3]).await;
    let dir = h.dir.join("second");
    let shares = accept_all(&h, &rotation, &new_refs, &dir);

    // The new custodians are now the current ones: two of them rotate again, the old ones cannot.
    let client = spki_client(&h.url, &h.node);
    let identity = node_identity(&h.node);
    let doc = doc_for(&h);
    let next: Vec<PrivateKey> = (0..3).map(|_| PrivateKey::generate().unwrap()).collect();
    let proposal = propose(&client, &identity, pubs(&next.iter().collect::<Vec<_>>())).await;
    for (path, key) in [
        (share_path(&h, 1), &h.custodians[0]),
        (share_path(&h, 2), &h.custodians[1]),
    ] {
        let _ = custodians::approve(&client, &identity, &proposal, &path, key, &doc).await;
    }
    assert_eq!(rotations(&h).await, 1, "the old custodians rotated nothing");
    // The second old approval cleared the pending pair; two new custodians start afresh.
    for (i, rotated) in [(0, false), (1, true)] {
        let reply = custodians::approve(&client, &identity, &proposal, &shares[i], &new[i], &doc)
            .await
            .unwrap();
        assert_eq!(reply.rotated, rotated);
    }
    assert_eq!(rotations(&h).await, 2);
}

#[tokio::test]
async fn one_custodian_cannot_rotate_alone() {
    let Some(h) = harness().await else {
        return;
    };
    let before = wrapped(&h).await;
    let client = spki_client(&h.url, &h.node);
    let identity = node_identity(&h.node);
    let new: Vec<PrivateKey> = (0..3).map(|_| PrivateKey::generate().unwrap()).collect();
    let proposal = propose(&client, &identity, pubs(&new.iter().collect::<Vec<_>>())).await;
    let digest = proposal.digest().unwrap();

    // One approval, sent twice, is one approval.
    for _ in 0..2 {
        let reply = post(
            &client,
            &proposal,
            approval(&identity, &digest, &h.shares[0]),
        )
        .await
        .unwrap();
        assert_eq!((reply.rotated, reply.approvals), (false, 1));
    }
    // A second "share" the custodian made up combines into no root the database knows.
    let mut made_up = h.shares[0].clone();
    made_up[0] = 2;
    let e = post(&client, &proposal, approval(&identity, &digest, &made_up))
        .await
        .unwrap_err();
    assert!(code_of(&e).contains("signature_invalid"), "{e}");
    assert_eq!(wrapped(&h).await, before);
    assert_eq!(rotations(&h).await, 0);
    let refused = h.audit("custodians.rotate").await;
    assert_eq!(refused.len(), 1);
    assert_eq!(refused[0].1, "denied");

    // The refusal cleared the pending approval: one real approval is again only one.
    let reply = post(
        &client,
        &proposal,
        approval(&identity, &digest, &h.shares[1]),
    )
    .await
    .unwrap();
    assert_eq!((reply.rotated, reply.approvals), (false, 1));

    // A sealed node takes no approval at all.
    let (sealed, url, _shutdown) = sealed_node(&h).await;
    let sealed_client = spki_client(&url, &sealed);
    let sealed_id = node_identity(&sealed);
    let mut for_sealed = proposal.clone();
    for_sealed.kms_node_spki_sha256 = alpha_channel::sha256_label(&sealed.runtime_spki);
    let e = post(
        &sealed_client,
        &for_sealed,
        approval(&sealed_id, &for_sealed.digest().unwrap(), &h.shares[0]),
    )
    .await
    .unwrap_err();
    assert!(code_of(&e).contains("sealed"), "{e}");
}

#[tokio::test]
async fn a_wrong_nonce_another_node_another_proposal_or_a_replay_is_refused() {
    let Some(h) = harness().await else {
        return;
    };
    let client = spki_client(&h.url, &h.node);
    let identity = node_identity(&h.node);
    let new: Vec<PrivateKey> = (0..3).map(|_| PrivateKey::generate().unwrap()).collect();
    let new_pubs = pubs(&new.iter().collect::<Vec<_>>());
    let good = propose(&client, &identity, new_pubs.clone()).await;
    let send = |proposal: RotationProposal, share: usize| {
        let client = &client;
        let identity = &identity;
        let h = &h;
        async move {
            let digest = proposal.digest().unwrap();
            post(
                client,
                &proposal,
                approval(identity, &digest, &h.shares[share]),
            )
            .await
        }
    };
    let refused = |proposal: RotationProposal, expect: &'static str| {
        let send = &send;
        async move {
            let e = send(proposal, 0).await.unwrap_err().to_string();
            assert!(e.contains(expect), "{expect}: {e}");
        }
    };

    let mut p = good.clone();
    p.nonce = b64(&[7u8; 32]);
    refused(p, "nonce_invalid").await;
    let mut p = good.clone();
    let stale = instance::mint_nonce(&nonce_key(), h.now() - Duration::from_secs(600)).unwrap();
    p.nonce = b64(&stale);
    refused(p, "nonce is too old").await;
    let mut p = good.clone();
    p.kms_node_spki_sha256 = alpha_channel::sha256_label(b"another node");
    refused(p, "names another node").await;
    let mut p = good.clone();
    p.custodians[2] = p.custodians[0].clone();
    refused(p, "three keys").await;
    let mut p = good.clone();
    p.format = "alphacompute-custodian-rotation/0".into();
    refused(p, "format").await;
    // An approval of one proposal posted beside another.
    let e = post(
        &client,
        &good,
        approval(&identity, &[0u8; 32], &h.shares[0]),
    )
    .await
    .unwrap_err();
    assert!(e.to_string().contains("another proposal"), "{e}");
    // An approval sealed under the unseal info, as a captured unseal share would be.
    let unseal_like = alpha_crypto::seal(
        &identity.xwing,
        alpha_crypto::INFO_UNSEAL_SHARE,
        &identity.aad(),
        &[good.digest().unwrap().as_slice(), &h.shares[0]].concat(),
    )
    .unwrap();
    assert!(post(&client, &good, unseal_like).await.is_err());
    assert_eq!(rotations(&h).await, 0);

    // The good proposal rotates once.
    assert!(!send(good.clone(), 0).await.unwrap().rotated);
    let rotation = send(good.clone(), 1).await.unwrap().rotation.unwrap();
    let after = wrapped(&h).await;

    // Replaying both approvals: the old shares no longer make the current root.
    assert!(!send(good.clone(), 0).await.unwrap().rotated);
    let e = send(good.clone(), 1).await.unwrap_err();
    assert!(
        e.to_string()
            .contains("do not reconstruct the current root"),
        "{e}"
    );
    // The nonce rotates once, even for the custodians who now hold the current root.
    let dir = h.dir.join("replay");
    let shares = accept_all(&h, &rotation, &new.iter().collect::<Vec<_>>(), &dir);
    let doc = doc_for(&h);
    let first = custodians::approve(&client, &identity, &good, &shares[0], &new[0], &doc)
        .await
        .unwrap();
    assert!(!first.rotated);
    let e = custodians::approve(&client, &identity, &good, &shares[1], &new[1], &doc)
        .await
        .unwrap_err();
    assert!(e.contains("already rotated"), "{e}");
    assert_eq!(wrapped(&h).await, after);
    assert_eq!(rotations(&h).await, 1);
}

#[tokio::test]
async fn a_rotation_that_fails_before_its_commit_leaves_the_old_root_whole() {
    let Some(h) = harness().await else {
        return;
    };
    let before = wrapped(&h).await;
    // The last write of the rotation's transaction fails, after every row was re-wrapped in it.
    sqlx::query("create function fail_rotation() returns trigger language plpgsql as $$ begin raise exception 'simulated crash'; end $$")
        .execute(&h.pool)
        .await
        .unwrap();
    sqlx::query("create trigger fail_rotation before insert on custodian_rotations for each row execute function fail_rotation()")
        .execute(&h.pool)
        .await
        .unwrap();
    let client = spki_client(&h.url, &h.node);
    let identity = node_identity(&h.node);
    let doc = doc_for(&h);
    let new: Vec<PrivateKey> = (0..3).map(|_| PrivateKey::generate().unwrap()).collect();
    let new_refs: Vec<&PrivateKey> = new.iter().collect();
    let proposal = propose(&client, &identity, pubs(&new_refs)).await;
    custodians::approve(
        &client,
        &identity,
        &proposal,
        &share_path(&h, 1),
        &h.custodians[0],
        &doc,
    )
    .await
    .unwrap();
    let e = custodians::approve(
        &client,
        &identity,
        &proposal,
        &share_path(&h, 2),
        &h.custodians[1],
        &doc,
    )
    .await
    .unwrap_err();
    assert!(e.contains("simulated crash"), "{e}");
    assert_eq!(
        wrapped(&h).await,
        before,
        "nothing of the rotation was committed"
    );
    assert_eq!(rotations(&h).await, 0);
    assert!(!h.node.is_sealed());
    let (old_root_node, opened) = unseal_with(
        &h,
        [
            (&share_path(&h, 2), &h.custodians[1]),
            (&share_path(&h, 3), &h.custodians[2]),
        ],
    )
    .await;
    assert!(
        !opened.unwrap().sealed,
        "the old shares still open the database"
    );
    assert!(!old_root_node.is_sealed());
    assert_eq!(h.audit("custodians.rotate").await[0].1, "error");

    // Once the database takes the write, the same custodians rotate with a fresh proposal; the
    // reply is then lost, and a node started afterwards still serves the rotation it stored.
    sqlx::query("drop trigger fail_rotation on custodian_rotations")
        .execute(&h.pool)
        .await
        .unwrap();
    let rotation = rotate(&h, pubs(&new_refs), [1, 2]).await;
    let (later, url, _shutdown) = sealed_node(&h).await;
    let stored = spki_client(&url, &later).last_rotation().await.unwrap();
    assert_eq!(stored.id, rotation.id);
    let shares = accept_all(&h, &stored, &new_refs, &h.dir.join("lost-reply"));
    let (fresh, opened) = unseal_with(&h, [(&shares[0], &new[0]), (&shares[1], &new[1])]).await;
    assert!(!opened.unwrap().sealed);
    assert!(!fresh.is_sealed());
}

#[tokio::test]
async fn joined_nodes_keep_serving_and_later_joins_and_rotations_see_the_new_root() {
    let Some(h) = harness().await else {
        return;
    };
    // A second node joins before the rotation, as `try_join` would.
    let reply = join_reply(&h).await;
    let (joined, joined_url, _joined) = sealed_node(&h).await;
    node::finish_join(&joined, &reply).await.unwrap();
    assert!(!joined.is_sealed());

    let new: Vec<PrivateKey> = (0..3).map(|_| PrivateKey::generate().unwrap()).collect();
    let new_refs: Vec<&PrivateKey> = new.iter().collect();
    let rotation = rotate(&h, pubs(&new_refs), [1, 2]).await;

    // The joined node holds the same intermediates, so it keeps serving and reads every row.
    let keys = joined.intermediates().unwrap();
    assert_eq!(
        *keys.tenant_kek_root,
        *h.node.intermediates().unwrap().tenant_kek_root
    );
    joined.maintain().await;
    assert!(
        joined.audit_chain.lock().is_ok(),
        "the chain verifies across the rotation"
    );
    assert!(
        store::load_key(&h.pool, &keys.metadata, h.root.0.into())
            .await
            .unwrap()
            .is_some()
    );
    // A join after the rotation hands out the same intermediates.
    let later = join_reply(&h).await;
    assert_eq!(later.tenant_kek_root, reply.tenant_kek_root);
    assert_eq!(later.ca_key, reply.ca_key);

    // The joined node never held a root, but it reads the re-wrapped rows: the new custodians
    // rotate through it, and the shares of the first rotation open nothing after the second.
    let shares = accept_all(&h, &rotation, &new_refs, &h.dir.join("joined"));
    let client = spki_client(&joined_url, &joined);
    let identity = node_identity(&joined);
    let mut doc = platform_document(KEYED);
    doc["kms_ca_pem"] = json!(h.ca_pem);
    let doc: PlatformDocument = serde_json::from_value(doc).unwrap();
    let next: Vec<PrivateKey> = (0..3).map(|_| PrivateKey::generate().unwrap()).collect();
    let proposal = propose(&client, &identity, pubs(&next.iter().collect::<Vec<_>>())).await;
    for (i, rotated) in [(2, false), (0, true)] {
        let reply = custodians::approve(&client, &identity, &proposal, &shares[i], &new[i], &doc)
            .await
            .unwrap();
        assert_eq!(reply.rotated, rotated);
    }
    let (stale, refused) = unseal_with(&h, [(&shares[0], &new[0]), (&shares[1], &new[1])]).await;
    assert!(refused.is_err());
    assert!(stale.is_sealed());
}

/// The serving node's join reply to the keyed capture's node, as `db.rs` joins it.
async fn join_reply(h: &Harness) -> alpha_client::JoinReply {
    let pkcs8 = read(KEYED, "runtime.key.pkcs8.der");
    let cert = certs::self_signed(&certs::key_pair(&pkcs8).unwrap(), h.now()).unwrap();
    let joiner = client_with(&format!(
        "{}{}",
        text(KEYED, "runtime.key.pem"),
        certs::pem(&cert)
    ));
    let runtime_sha = hex::encode(Sha256::digest(read(KEYED, "runtime_spki.der")));
    sqlx::query!(
        "insert into audit_log (actor_kind, actor, action, outcome, details) values ('node', 'node', 'node.join.request', 'ok', $1)",
        json!({ "runtime_pubkey_sha256": runtime_sha })
    )
    .execute(&h.pool)
    .await
    .unwrap();
    let xwing = PublicKey::try_from(read(KEYED, "node_xwing_pubkey.bin").as_slice()).unwrap();
    let body =
        json!({ "nonce": h.nonce(), "evidence": evidence(KEYED, "node"), "xwing_pubkey": xwing });
    let (status, reply) = send(joiner.post(format!("{}/v1/node/join", h.url)).json(&body)).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    serde_json::from_value::<alpha_client::JoinReply>(reply).unwrap()
}
