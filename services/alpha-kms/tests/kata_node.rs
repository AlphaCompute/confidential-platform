//! A KMS node on Kata (PRD-05 M-C) against a real Postgres (`DATABASE_URL`; skipped without it):
//! its identity is the Revision v2 of its init-data, its evidence comes from the CoCo source and
//! is served by `GET /v1/node/evidence`, `alpha bootstrap` and `alpha unseal` seal to it only once
//! `alpha_attest::node` admits it, and it joins a prototype node over the existing join protocol,
//! keeping the CA. No B300 Kata capture exists before M1, so the node's evidence source returns
//! synthetic evidence v2 and the custodian's and the serving node's DCAP step is replaced by the
//! quote a TD running that init-data produces (`verify_kata_node`, `join_verified`); the route's
//! DCAP step is checked for evidence v2 with a quote that fails it.

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

use alpha_attest::{
    CpuEvidence, CpuKind, EVIDENCE_FORMAT_V2, EvidenceV2, VerifiedQuote, report_data,
};
use alpha_cli::node::{self as cli_node, AttestedNode};
use alpha_client::{JoinReply, NodeEvidence, Pin, tls as client_tls};
use alpha_core::coco::{CPU_RUNTIME_CLASS, GPU_RUNTIME_CLASS};
use alpha_core::{AppId, ComposeHash};
use alpha_crypto::PrivateKey;
use alpha_kms::{Clock, CollateralSource, Config, Node, NodeGuest, certs, node, platform, tls};
use common::kata::{POLICY, Pod, fresh_nonce, initdata, kata_document, publish};
use common::*;
use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

/// The KMS App's init-data on the CPU class: what `alpha coco render` makes of
/// `deploy/coco/platform/alpha-kms.yaml`.
fn kms_initdata() -> String {
    let app: AppId = "01a09f07-8d09-7640-94c1-bbdb74200a1e".parse().unwrap();
    initdata(app, CPU_RUNTIME_CLASS, None, POLICY)
}

fn kms_revision(initdata: &str) -> ComposeHash {
    alpha_core::coco::InitData::parse(initdata.as_bytes())
        .unwrap()
        .revision()
        .unwrap()
        .hash()
        .unwrap()
}

/// `doc` with the Kata KMS build listed as `kind`, beside the prototype build it already lists.
fn listing(mut doc: Value, revision: ComposeHash, kind: &str) -> Value {
    doc["kms_revisions"].as_array_mut().unwrap().push(
        json!({ "compose_hash": revision, "build": "kms kata", "source_url": "u", "kind": kind }),
    );
    doc
}

/// The synthetic evidence v2 a Kata pod with `initdata` sends; the quote is what its TD
/// produces over the same `report_data` ([`Pod::quote_of`]).
fn synthetic_source(initdata: String) -> alpha_kms::EvidenceSource {
    Arc::new(move |_report_data| {
        Ok(EvidenceV2 {
            format: EVIDENCE_FORMAT_V2.into(),
            cpu: CpuEvidence {
                kind: CpuKind::Tdx,
                quote: b"synthetic quote".to_vec(),
                event_log: Vec::new(),
            },
            gpus: Vec::new(),
            initdata: initdata.clone().into_bytes(),
            runtime_class: CPU_RUNTIME_CLASS.into(),
        }
        .into())
    })
}

/// A Kata KMS node on `pool`, sealed and listening, on the wall clock.
async fn start_kata_node(
    pool: PgPool,
    release: &ReleaseServer,
    initdata: &str,
) -> (Arc<Node>, String, tokio::sync::oneshot::Sender<()>) {
    let collateral = serde_json::from_slice(&read(KEYED, "collateral.json")).unwrap();
    let config = Config {
        kms_endpoints: vec![],
        platform_document_url: release.url.clone(),
        gpu_backends: Vec::new(),
        #[cfg(feature = "dev-root")]
        dev_root_kek: None,
    };
    let clock: Clock = Arc::new(SystemTime::now);
    let guest =
        NodeGuest::coco_with(initdata.as_bytes(), synthetic_source(initdata.to_owned())).unwrap();
    let node = Node::new(
        pool,
        config,
        clock,
        CollateralSource::Fixed(Box::new(collateral)),
        nonce_key(),
        guest,
        release.key.verifying_key(),
    )
    .unwrap();
    platform::start(&node).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("https://{}", listener.local_addr().unwrap());
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let app = alpha_kms::router(node.clone());
    let cert = node.server_cert.clone();
    tokio::spawn(async move {
        alpha_client::tls::serve(listener, tls::server_config(cert).unwrap(), app, async {
            let _ = rx.await;
        })
        .await
    });
    (node, base, tx)
}

/// What the custodian's CLI fetches from `url`: the evidence, the server's key and the quote the
/// node's TD produced for that nonce.
async fn fetch(url: &str, initdata: &str) -> ([u8; 32], NodeEvidence, Vec<u8>, VerifiedQuote) {
    let nonce: [u8; 32] = alpha_kms::random().unwrap();
    let (evidence, server_spki) = alpha_client::fetch_node_evidence(url, &nonce)
        .await
        .unwrap();
    let spki = evidence.runtime_spki().unwrap();
    let rd = report_data(&spki, &nonce, Some(evidence.xwing_pubkey.as_bytes()));
    let quote = Pod::quote_of(initdata, CPU_RUNTIME_CLASS, rd);
    (nonce, evidence, server_spki, quote)
}

fn doc_of(value: &Value) -> alpha_attest::PlatformDocument {
    serde_json::from_value(value.clone()).unwrap()
}

fn verify(
    fetched: &([u8; 32], NodeEvidence, Vec<u8>, VerifiedQuote),
    doc: &Value,
) -> Result<AttestedNode, String> {
    let (nonce, evidence, server_spki, quote) = fetched;
    cli_node::verify_kata_node(
        evidence,
        quote.clone(),
        nonce,
        server_spki,
        &doc_of(doc),
        None,
    )
}

#[tokio::test]
async fn a_kata_node_is_bootstrapped_by_three_custodians_and_a_second_one_unsealed() {
    let Some(pool) = fresh_database().await else {
        return;
    };
    let initdata = kms_initdata();
    let revision = kms_revision(&initdata);
    let doc = listing(kata_document(1), revision, "kata-tdx");
    let release = ReleaseServer::start(doc.clone()).await;
    let (first, first_url, _first) = start_kata_node(pool.clone(), &release, &initdata).await;
    assert_eq!(first.compose_hash, revision);

    // The node serves its evidence v2, init-data included, and nothing of the prototype form.
    let fetched = fetch(&first_url, &initdata).await;
    let served = &fetched.1;
    assert!(served.quote.is_empty() && served.event_log.is_empty());
    let v2 = served.evidence_v2.as_ref().unwrap();
    assert_eq!(v2.initdata, initdata.as_bytes());
    assert_eq!(v2.runtime_class, CPU_RUNTIME_CLASS);
    assert_eq!(served.compose_hash, revision);
    assert_eq!(fetched.2, first.runtime_spki);

    // What a custodian's CLI refuses: the build unlisted, listed as a prototype build, or the
    // evidence served by another TLS key.
    for (doc, reason) in [
        (
            kata_document(1),
            "attestation_unknown: no reference for the evidence: kms revision",
        ),
        (
            listing(kata_document(1), revision, "prototype-tdx"),
            "is not listed as a kata-tdx build",
        ),
    ] {
        let err = verify(&fetched, &doc).unwrap_err();
        assert!(err.contains(reason), "{err}");
    }
    let (nonce, evidence, _, quote) = fetched.clone();
    let err = cli_node::verify_kata_node(
        &evidence,
        quote,
        &nonce,
        b"someone else's key",
        &doc_of(&doc),
        None,
    )
    .unwrap_err();
    assert!(err.contains("not the attested runtime_pubkey"), "{err}");

    let attested = verify(&fetched, &doc).unwrap();
    let summary = attested.summary();
    assert_eq!(summary["profile"], "kata-tdx/1");
    assert_eq!(summary["revision"], json!(revision));
    assert_eq!(summary["os_image"], "kata-tdx/cpu-4c-8g");

    // Genesis with three custodians.
    let custodians: Vec<PrivateKey> = (0..3).map(|_| PrivateKey::generate().unwrap()).collect();
    let dir = std::env::temp_dir().join(format!("alpha-kata-genesis-{}", Uuid::now_v7()));
    fs::create_dir_all(&dir).unwrap();
    let client = spki_client(&first_url, &first);
    let out = cli_node::bootstrap(
        &client,
        &attested.identity,
        custodian_pubs(&custodians),
        1,
        &dir,
    )
    .await
    .unwrap();
    assert!(!first.is_sealed());
    let ca_pem = out["kms_ca_pem"].as_str().unwrap().to_owned();
    assert_eq!(ca_pem, first.intermediates().unwrap().ca_pem());

    // A second Kata node on the same database, unsealed by two custodians.
    let (second, second_url, _second) = start_kata_node(pool.clone(), &release, &initdata).await;
    let attested = verify(&fetch(&second_url, &initdata).await, &doc).unwrap();
    let client = spki_client(&second_url, &second);
    for i in [1usize, 3] {
        let reply = cli_node::unseal(
            &client,
            &attested.identity,
            &dir.join(format!("share-{i}.json")),
            &custodians[i - 1],
            1,
        )
        .await
        .unwrap();
        assert_eq!(reply.sealed, i == 1);
    }
    assert_eq!(second.intermediates().unwrap().ca_pem(), ca_pem);

    // A client pins the CA and the listed Revisions; the Kata node's leaf names its Revision v2.
    let ca = client_tls::cert_from_pem(&ca_pem).unwrap();
    let pinned = |revisions: Vec<ComposeHash>| {
        alpha_client::Client::new(
            vec![second_url.clone()],
            Pin::CaAndRevisions(ca.clone(), revisions),
        )
        .unwrap()
    };
    let prototype = doc_of(&doc).kms_revisions[0].compose_hash;
    assert!(
        !pinned(vec![prototype, revision])
            .ready()
            .await
            .unwrap()
            .sealed
    );
    assert!(pinned(vec![prototype]).ready().await.is_err());
    fs::remove_dir_all(&dir).unwrap();
}

/// The serving node's half of a join over a synthetic quote of `joiner`'s TD.
async fn join(
    h: &Harness,
    joiner: &Node,
    initdata: &str,
    xwing: Option<&[u8]>,
) -> Result<Value, alpha_kms::error::ApiError> {
    let nonce = fresh_nonce(h);
    let request = node::join_request(joiner, b64(&nonce), &h.url)
        .await
        .unwrap();
    let xwing = xwing.unwrap_or(request.xwing_pubkey.as_bytes()).to_vec();
    let quote = Pod::quote_of(
        initdata,
        CPU_RUNTIME_CLASS,
        report_data(&joiner.runtime_spki, &nonce, Some(xwing.as_slice())),
    );
    node::join_verified(&h.node, &joiner.runtime_spki, &request, quote).await
}

/// A document to publish first, the X-Wing key the TD's quote binds instead of the node's, and
/// the refusal's code and reason.
type Refusal<'a> = (Option<Value>, Option<&'a [u8]>, &'a str, &'a str);

async fn last_join(h: &Harness) -> (String, Value) {
    let (_, outcome, details) = h.audit("node.join").await.pop().unwrap();
    (outcome, details)
}

#[tokio::test]
async fn a_kata_node_joins_a_prototype_node_and_serves_under_the_same_ca() {
    let Some(h) = harness_with_clock(Arc::new(SystemTime::now)).await else {
        return;
    };
    let initdata = kms_initdata();
    let revision = kms_revision(&initdata);
    publish(&h, kata_document(2)).await;
    let (joiner, joiner_url, _joiner) =
        start_kata_node(h.pool.clone(), &h.release, &initdata).await;

    let refusals: [Refusal; 3] = [
        (None, None, "attestation_unknown", "kms revision"),
        (
            Some(listing(kata_document(3), revision, "prototype-tdx")),
            None,
            "attestation_unknown",
            "is not listed as a kata-tdx build",
        ),
        (
            Some(listing(kata_document(4), revision, "kata-tdx")),
            Some(b"the host's xwing key"),
            "attestation_failed",
            "report_data is not bound",
        ),
    ];
    for (doc, xwing, code, reason) in refusals {
        if let Some(doc) = doc {
            publish(&h, doc).await;
        }
        let error = join(&h, &joiner, &initdata, xwing).await.unwrap_err();
        assert_eq!(error.code, code, "{}", error.message);
        assert!(error.message.contains(reason), "{}", error.message);
        let (outcome, details) = last_join(&h).await;
        assert_eq!(outcome, "denied");
        assert_eq!(details, json!({ "code": code, "message": error.message }));
    }
    assert!(joiner.is_sealed());

    // Appraised but never asked for: no node.join.request row for this key.
    let nonce = fresh_nonce(&h);
    let request = node::join_request(&joiner, b64(&nonce), &h.url)
        .await
        .unwrap();
    let stranger = p256::ecdsa::SigningKey::from_bytes((&[5u8; 32]).into()).unwrap();
    let stranger_spki = p256::pkcs8::EncodePublicKey::to_public_key_der(stranger.verifying_key())
        .unwrap()
        .as_bytes()
        .to_vec();
    let quote = Pod::quote_of(
        &initdata,
        CPU_RUNTIME_CLASS,
        report_data(
            &stranger_spki,
            &nonce,
            Some(request.xwing_pubkey.as_bytes()),
        ),
    );
    let error = node::join_verified(&h.node, &stranger_spki, &request, quote)
        .await
        .unwrap_err();
    assert_eq!(error.code, "not_found", "{}", error.message);

    // Listed as a Kata build beside the prototype one: the join hands over the intermediates.
    let reply = join(&h, &joiner, &initdata, None).await.unwrap();
    let (outcome, details) = last_join(&h).await;
    assert_eq!(outcome, "ok");
    assert_eq!(details["compose_hash"], json!(revision));
    assert_eq!(details["coco"]["profile"], "kata-tdx/1");
    assert_eq!(details["coco"]["runtime_class"], CPU_RUNTIME_CLASS);
    let reply: JoinReply = serde_json::from_value(reply).unwrap();
    node::finish_join(&joiner, &reply).unwrap();
    assert!(!joiner.is_sealed());
    assert_eq!(joiner.intermediates().unwrap().ca_pem(), h.ca_pem);

    // Clients keep their CA pin; the listed Revisions now include the Kata build.
    let ca = client_tls::cert_from_pem(&h.ca_pem).unwrap();
    let client = alpha_client::Client::new(
        vec![joiner_url],
        Pin::CaAndRevisions(ca, vec![h.node.compose_hash, revision]),
    )
    .unwrap();
    assert!(!client.ready().await.unwrap().sealed);
}

#[tokio::test]
async fn kata_join_evidence_through_the_route_is_dcap_verified() {
    let Some(h) = harness_with_clock(Arc::new(SystemTime::now)).await else {
        return;
    };
    let initdata = kms_initdata();
    publish(
        &h,
        listing(kata_document(2), kms_revision(&initdata), "kata-tdx"),
    )
    .await;
    let pkcs8 = read(KEYED, "runtime.key.pkcs8.der");
    let cert = certs::self_signed(&certs::key_pair(&pkcs8).unwrap(), h.now()).unwrap();
    let identity = format!("{}{}", text(KEYED, "runtime.key.pem"), certs::pem(&cert));
    let request = json!({
        "nonce": b64(&fresh_nonce(&h)),
        "evidence": (synthetic_source(initdata))(&[0; 64]).unwrap(),
        "xwing_pubkey": PrivateKey::generate().unwrap().public(),
    });
    let (status, reply) = send(
        client_with(&identity)
            .post(format!("{}/v1/node/join", h.url))
            .json(&request),
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::FORBIDDEN, "{reply}");
    assert_eq!(code(&reply), "attestation_failed");
    assert!(reply["error"]["message"].as_str().unwrap().contains("dcap"));
    let (outcome, _) = last_join(&h).await;
    assert_eq!(outcome, "denied");
}

#[test]
fn a_kms_node_identity_is_the_revision_v2_of_cpu_class_init_data_only() {
    let initdata = kms_initdata();
    let guest =
        NodeGuest::coco_with(initdata.as_bytes(), synthetic_source(initdata.clone())).unwrap();
    assert_eq!(guest.compose_hash, kms_revision(&initdata));
    let app = AppId::mint();
    let gpu = common::kata::initdata(app, GPU_RUNTIME_CLASS, Some(1), POLICY);
    let err = NodeGuest::coco_with(gpu.as_bytes(), synthetic_source(gpu.clone()))
        .err()
        .unwrap();
    assert!(err.contains("a KMS node runs on kata-qemu-tdx"), "{err}");
    assert!(NodeGuest::coco_with(b"not toml", synthetic_source(String::new())).is_err());
}

/// `alpha kms migrate` (PRD-05 draft) over the join above: the baseline is the prototype node's
/// CA and tenant-kek-root identifiers, the join is marked done only once the Kata node serves
/// with the same ones, a node from another genesis never counts as serving, and a baseline that
/// differs stops every step.
#[tokio::test]
async fn kms_migrate_marks_a_join_that_kept_the_ca_and_keys_and_nothing_else() {
    use alpha_cli::kms_migrate as m;
    let Some(h) = harness_with_clock(Arc::new(SystemTime::now)).await else {
        return;
    };
    let initdata = kms_initdata();
    let revision = kms_revision(&initdata);
    let listed = listing(kata_document(2), revision, "kata-tdx");
    publish(&h, listed.clone()).await;
    // What the operator's CLI verifies: the document naming the CA genesis made.
    let mut doc = listed;
    doc["kms_ca_pem"] = json!(h.ca_pem);
    let doc: alpha_attest::PlatformDocument = serde_json::from_value(doc).unwrap();
    let (joiner, joiner_url, _joiner) =
        start_kata_node(h.pool.clone(), &h.release, &initdata).await;
    let inventory: m::Inventory = serde_json::from_value(json!({
        "format": m::INVENTORY_FORMAT,
        "quorum": 1,
        "nodes": [
            { "name": "proto-a", "endpoint": h.url, "kind": "prototype" },
            { "name": "kata-a", "endpoint": joiner_url, "kind": "kata" }
        ]
    }))
    .unwrap();

    let baseline = m::take_baseline(&inventory, &doc).await.unwrap();
    assert_eq!(
        Some(baseline.ca_spki_sha256.clone()),
        alpha_cli::sign::ca_spki_sha256(&h.ca_pem).unwrap()
    );
    assert!(baseline.tenant_kek_root_id.starts_with("hmac-sha256:"));

    // Nothing has joined: the join is pending and nothing is marked.
    let mut state = m::State::new();
    let out = m::step(&inventory, &baseline, &mut state, &doc)
        .await
        .unwrap();
    assert!(out.completed.is_none());
    assert_eq!(
        out.next.unwrap()["step"],
        json!({ "action": "join", "node": "kata-a" })
    );
    assert!(state.completed.is_empty());

    // The Kata node joins the prototype node: same CA, same keys, two serving.
    let reply = join(&h, &joiner, &initdata, None).await.unwrap();
    node::finish_join(&joiner, &serde_json::from_value(reply).unwrap()).unwrap();
    let report = m::verify(&inventory, &baseline, &doc).await.unwrap();
    assert!(report.ok, "{:?}", report.problems);
    assert_eq!(report.serving, 2);
    let out = m::step(&inventory, &baseline, &mut state, &doc)
        .await
        .unwrap();
    assert_eq!(out.completed, Some(m::Step::Join("kata-a".into())));
    assert_eq!(
        out.next.unwrap()["step"],
        json!({ "action": "stop", "node": "proto-a" })
    );
    // proto-a still serves, so the stop stays pending.
    let out = m::step(&inventory, &baseline, &mut state, &doc)
        .await
        .unwrap();
    assert!(out.completed.is_none());
    assert_eq!(state.completed.len(), 1);

    // A node from another genesis (another CA) fails the pinned handshake: never serving.
    let Some(other) = harness_with_clock(Arc::new(SystemTime::now)).await else {
        return;
    };
    let mut wider = inventory.clone();
    wider.nodes.push(m::InventoryNode {
        name: "kata-b".into(),
        endpoint: other.url.clone(),
        kind: m::NodeKind::Kata,
    });
    let report = m::verify(&wider, &baseline, &doc).await.unwrap();
    assert!(!report.serving("kata-b"));
    assert_eq!(report.serving, 2);

    // A baseline the nodes do not match: every serving node differs, and no step is marked.
    let mut moved = baseline.clone();
    moved.tenant_kek_root_id = "hmac-sha256:00".into();
    let report = m::verify(&inventory, &moved, &doc).await.unwrap();
    assert!(!report.ok);
    assert_eq!(report.problems.len(), 2, "{:?}", report.problems);
    let refused = m::step(&inventory, &moved, &mut state, &doc)
        .await
        .unwrap_err();
    assert!(refused.contains("verify failed"), "{refused}");
    assert_eq!(state.completed.len(), 1);
}

/// Waits until `verify` sees `name` serving (or not) through the baseline's pin.
async fn await_serving(
    inventory: &alpha_cli::kms_migrate::Inventory,
    baseline: &alpha_cli::kms_migrate::Baseline,
    doc: &alpha_attest::PlatformDocument,
    name: &str,
    serving: bool,
) {
    for _ in 0..100 {
        let report = alpha_cli::kms_migrate::verify(inventory, baseline, doc)
            .await
            .unwrap();
        if report.serving(name) == serving {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    panic!("{name} never became serving={serving}");
}

/// Serves `node` on `url`'s address again: the prototype node, restarted where it was.
async fn restart(node: &Arc<Node>, url: &str) -> tokio::sync::oneshot::Sender<()> {
    let addr: std::net::SocketAddr = url.trim_start_matches("https://").parse().unwrap();
    let mut listener = None;
    // The stopped listener lets go of the port once its connections drained.
    for _ in 0..100 {
        match tokio::net::TcpListener::bind(addr).await {
            Ok(l) => {
                listener = Some(l);
                break;
            }
            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(200)).await,
        }
    }
    let listener = listener.unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let app = alpha_kms::router(node.clone());
    let config = tls::server_config(node.server_cert.clone()).unwrap();
    tokio::spawn(async move {
        alpha_client::tls::serve(listener, config, app, async {
            let _ = rx.await;
        })
        .await
    });
    tx
}

/// `alpha kms migrate rollback` (Q61) over the same join: the stop of the last prototype node is
/// reversible only while the prototype build is listed, and is rolled back once that node serves
/// again with the same identifiers; the join is rolled back once the Kata node no longer serves,
/// the prototype node still serving with the baseline's identifiers. Nothing is started or
/// stopped by the tool: the test plays the operator.
#[tokio::test]
async fn kms_migrate_rolls_back_the_last_stop_and_then_the_join() {
    use alpha_cli::kms_migrate as m;
    let Some(mut h) = harness_with_clock(Arc::new(SystemTime::now)).await else {
        return;
    };
    let initdata = kms_initdata();
    let revision = kms_revision(&initdata);
    let listed = listing(kata_document(2), revision, "kata-tdx");
    publish(&h, listed.clone()).await;
    let mut doc = listed;
    doc["kms_ca_pem"] = json!(h.ca_pem);
    // The same document without the prototype build: what M-G would publish.
    let mut kata_only = doc.clone();
    kata_only["kms_revisions"]
        .as_array_mut()
        .unwrap()
        .retain(|r| r["kind"] == "kata-tdx");
    let doc: alpha_attest::PlatformDocument = serde_json::from_value(doc).unwrap();
    let kata_only: alpha_attest::PlatformDocument = serde_json::from_value(kata_only).unwrap();
    let (joiner, joiner_url, joiner_listener) =
        start_kata_node(h.pool.clone(), &h.release, &initdata).await;
    let inventory: m::Inventory = serde_json::from_value(json!({
        "format": m::INVENTORY_FORMAT,
        "quorum": 1,
        "nodes": [
            { "name": "proto-a", "endpoint": h.url, "kind": "prototype" },
            { "name": "kata-a", "endpoint": joiner_url, "kind": "kata" }
        ]
    }))
    .unwrap();
    let baseline = m::take_baseline(&inventory, &doc).await.unwrap();
    let mut state = m::State::new();
    let err = m::rollback(&inventory, &baseline, &mut state, &doc)
        .await
        .unwrap_err();
    assert!(err.contains("nothing to roll back"), "{err}");

    // Forward: kata-a joins, then proto-a, the last prototype node, stops.
    let reply = join(&h, &joiner, &initdata, None).await.unwrap();
    node::finish_join(&joiner, &serde_json::from_value(reply).unwrap()).unwrap();
    let out = m::step(&inventory, &baseline, &mut state, &doc)
        .await
        .unwrap();
    assert_eq!(out.completed, Some(m::Step::Join("kata-a".into())));
    h._shutdown = tokio::sync::oneshot::channel().0;
    await_serving(&inventory, &baseline, &doc, "proto-a", false).await;
    let out = m::step(&inventory, &baseline, &mut state, &doc)
        .await
        .unwrap();
    assert_eq!(out.completed, Some(m::Step::Stop("proto-a".into())));
    assert!(out.next.is_none());

    // With the prototype build delisted, proto-a could only come back by joining a Kata node
    // that would refuse it: refused, and the state is left alone.
    let before = state.clone();
    let err = m::rollback(&inventory, &baseline, &mut state, &kata_only)
        .await
        .unwrap_err();
    assert!(err.contains("last prototype node"), "{err}");
    assert!(err.contains("kms_revisions"), "{err}");
    assert_eq!(state, before);

    // Listed: the operator is told to restart proto-a; `step` waits for the rollback.
    let out = m::rollback(&inventory, &baseline, &mut state, &doc)
        .await
        .unwrap();
    assert!(!out.rolled_back);
    let action = out.next["action"].as_str().unwrap();
    assert!(
        action.starts_with("restart the prototype KMS node proto-a"),
        "{action}"
    );
    assert_eq!(state.rolling_back, Some(m::Step::Stop("proto-a".into())));
    let err = m::step(&inventory, &baseline, &mut state, &doc)
        .await
        .unwrap_err();
    assert!(err.contains("rollback"), "{err}");

    // proto-a serves again with the baseline's identifiers: the stop is rolled back.
    h._shutdown = restart(&h.node, &h.url).await;
    await_serving(&inventory, &baseline, &doc, "proto-a", true).await;
    let out = m::rollback(&inventory, &baseline, &mut state, &doc)
        .await
        .unwrap();
    assert!(out.rolled_back, "{:?}", out.report);
    assert_eq!(state.completed, [m::Step::Join("kata-a".into())]);
    assert_eq!(state.rolling_back, None);

    // Then the join: the operator stops kata-a; proto-a alone keeps the quorum of one.
    let out = m::rollback(&inventory, &baseline, &mut state, &doc)
        .await
        .unwrap();
    assert!(!out.rolled_back);
    let action = out.next["action"].as_str().unwrap();
    assert!(
        action.starts_with("stop the Kata KMS node kata-a"),
        "{action}"
    );
    drop(joiner_listener);
    await_serving(&inventory, &baseline, &doc, "kata-a", false).await;
    let out = m::rollback(&inventory, &baseline, &mut state, &doc)
        .await
        .unwrap();
    assert!(out.rolled_back);
    assert_eq!(state, m::State::new());
    let out = m::step(&inventory, &baseline, &mut state, &doc)
        .await
        .unwrap();
    assert!(out.completed.is_none());
    assert_eq!(
        out.next.unwrap()["step"],
        json!({ "action": "join", "node": "kata-a" })
    );
}
