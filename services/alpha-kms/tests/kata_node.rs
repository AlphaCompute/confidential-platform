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
use alpha_cli::custodians::{self, Baseline};
use alpha_cli::node::{self as cli_node, AttestedNode};
use alpha_client::{JoinReply, NodeEvidence, Pin, tls as client_tls};
use alpha_core::coco::{CPU_RUNTIME_CLASS, GPU_RUNTIME_CLASS};
use alpha_core::{AppId, ComposeHash};
use alpha_crypto::PrivateKey;
use alpha_kms::{
    Clock, CollateralSource, Config, Intermediates, Node, NodeGuest, audit, certs, db_auth,
    instance, node, platform, tls,
};
use common::kata::{POLICY, Pod, fresh_nonce, initdata, kata_document, publish};
use common::*;
use serde_json::{Value, json};
use sqlx::PgPool;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use uuid::Uuid;
use zeroize::Zeroizing;

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
    start_kata_node_with(pool, release, initdata, false).await
}

/// [`start_kata_node`], in client-cert mode (D10) when `client_cert`: as `main.rs` sets it up, on
/// a pool of its own whose connections carry no certificate until the node holds the volume key,
/// with `pool`'s options as the base.
async fn start_kata_node_with(
    pool: PgPool,
    release: &ReleaseServer,
    initdata: &str,
    client_cert: bool,
) -> (Arc<Node>, String, tokio::sync::oneshot::Sender<()>) {
    let base = (*pool.connect_options()).clone();
    let pool = if client_cert {
        PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(std::time::Duration::from_secs(10))
            .connect_lazy_with(base.clone())
    } else {
        pool
    };
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
    if client_cert {
        db_auth::enable(&node, base);
    }
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
            false,
        )
        .await
        .unwrap();
        assert_eq!(reply.sealed, i == 1);
    }
    assert_eq!(second.intermediates().unwrap().ca_pem(), ca_pem);

    // Custodians 2 and 3 replace custodian 1 on the second node. Each checks the node's agent
    // policy against the baseline first (D9): this build's checker refuses until #79/#83's is
    // wired, so the ceremony runs either with that checker or with the check skipped on record.
    assert_eq!(attested.policy.as_deref(), Some(POLICY));
    let refused = custodians::check_baseline(
        attested.policy.as_deref(),
        Baseline::Check(custodians::alpha_baseline),
    )
    .unwrap_err();
    assert!(refused.starts_with("policy_denied"), "{refused}");
    fn exec_and_logs_denied(policy: &str) -> Result<(), String> {
        let denied = |request: &str| policy.contains(&format!("default {request} := false"));
        (denied("ExecProcessRequest") && denied("ReadStreamRequest"))
            .then_some(())
            .ok_or_else(|| "exec or log reads allowed".into())
    }
    assert_eq!(
        custodians::check_baseline(
            attested.policy.as_deref(),
            Baseline::Check(exec_and_logs_denied)
        ),
        Ok("held")
    );
    let mut pinned = doc.clone();
    pinned["kms_ca_pem"] = json!(ca_pem);
    let pinned = doc_of(&pinned);
    let new: Vec<PrivateKey> = (0..3).map(|_| PrivateKey::generate().unwrap()).collect();
    let proposal = custodians::propose(&client, &attested.identity, custodian_pubs(&new))
        .await
        .unwrap();
    let mut rotation = None;
    for i in [2usize, 3] {
        let reply = custodians::approve(
            &client,
            &attested.identity,
            &proposal,
            &dir.join(format!("share-{i}.json")),
            &custodians[i - 1],
            &pinned,
        )
        .await
        .unwrap();
        rotation = reply.rotation;
    }
    let rotation = rotation.unwrap();
    // Each new custodian attests the node afresh, finds it is the one that rotated, and keeps
    // their share; two of those shares unseal a third Kata node.
    for (i, key) in new.iter().enumerate() {
        let live = verify(&fetch(&second_url, &initdata).await, &doc).unwrap();
        assert!(custodians::is_rotating_node(&rotation, &live.identity));
        let out = dir.join(format!("new-share-{}.json", i + 1));
        custodians::accept(&rotation, &pinned, key, &out).unwrap();
    }
    let (third, third_url, _third) = start_kata_node(pool.clone(), &release, &initdata).await;
    let attested = verify(&fetch(&third_url, &initdata).await, &doc).unwrap();
    assert!(!custodians::is_rotating_node(&rotation, &attested.identity));
    let client = spki_client(&third_url, &third);
    for (i, key) in [(1usize, &new[0]), (2, &new[1])] {
        cli_node::unseal(
            &client,
            &attested.identity,
            &dir.join(format!("new-share-{i}.json")),
            key,
            1,
            false,
        )
        .await
        .unwrap();
    }
    assert!(!third.is_sealed());
    assert_eq!(third.intermediates().unwrap().ca_pem(), ca_pem);

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

    // Appraised but never asked for: no node.join.request row for this key. In `url` mode the
    // joiner writes its own row and the request asks nothing of the serving node (D10).
    let nonce = fresh_nonce(&h);
    let request = node::join_request(&joiner, b64(&nonce), &h.url)
        .await
        .unwrap();
    assert!(!request.db_client_cert);
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
    // The serving node's audit head, its `node.join` row included, travels with the keys.
    let head = h.node.chain.floor().unwrap();
    assert_eq!(head.seq, h.audit_rows().await.last().unwrap().seq);
    assert_eq!(reply.audit_head, Some(head.to_wire()));
    let requests = h.audit("node.join.request").await;
    let (_, outcome, details) = requests.last().unwrap();
    assert_eq!(outcome, "ok");
    assert_eq!(details["endpoint"], json!(h.url));
    assert!(details.get("recorded_by").is_none(), "{details}");
    node::finish_join(&joiner, &reply).await.unwrap();
    assert!(!joiner.is_sealed());
    assert_eq!(joiner.chain.floor().unwrap().seq, head.seq);
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

/// The `node.join.request` rows that name `spki`.
fn requests_for(rows: &[(i64, String, Value)], spki: &[u8]) -> Vec<Value> {
    let actor = alpha_kms::keys::sha256_hex(spki);
    rows.iter()
        .filter(|(_, _, details)| details["runtime_pubkey_sha256"] == json!(actor))
        .map(|(_, _, details)| details.clone())
        .collect()
}

/// D10, PRD-05 Q46: a Kata node in client-cert mode cannot reach the database before the join
/// reply, so it writes no `node.join.request`; the serving node writes it once the joiner is
/// appraised as a listed kata-tdx build, and for nothing else. The shared Postgres takes no client
/// certificate, so the joiner pins the derived CA and never reaches it here; the cert-auth test
/// below runs the same join to a serving joiner.
#[tokio::test]
async fn a_client_cert_kata_node_has_its_join_request_written_by_the_serving_node() {
    let Some(h) = harness_with_clock(Arc::new(SystemTime::now)).await else {
        return;
    };
    let initdata = kms_initdata();
    let revision = kms_revision(&initdata);
    publish(&h, kata_document(2)).await;
    let (joiner, _joiner_url, _joiner) =
        start_kata_node_with(h.pool.clone(), &h.release, &initdata, true).await;
    // Refused by the database, it still holds the document in memory to pin the serving node.
    assert!(db_auth::client_cert_mode(&joiner));
    assert!(joiner.platform_document().is_some());

    // The build is not listed: the appraisal refuses it, and no row is written for it.
    let nonce = fresh_nonce(&h);
    let request = node::join_request(&joiner, b64(&nonce), &h.url)
        .await
        .unwrap();
    assert!(request.db_client_cert);
    assert!(requests_for(&h.audit("node.join.request").await, &joiner.runtime_spki).is_empty());
    let quote = Pod::quote_of(
        &initdata,
        CPU_RUNTIME_CLASS,
        report_data(
            &joiner.runtime_spki,
            &nonce,
            Some(request.xwing_pubkey.as_bytes()),
        ),
    );
    let error = node::join_verified(&h.node, &joiner.runtime_spki, &request, quote)
        .await
        .unwrap_err();
    assert_eq!(error.code, "attestation_unknown", "{}", error.message);
    assert!(requests_for(&h.audit("node.join.request").await, &joiner.runtime_spki).is_empty());
    assert_eq!(last_join(&h).await.0, "denied");

    // Prototype evidence asking the serving node to write its row is refused before appraisal:
    // a prototype node's env is not measured, so it writes its own.
    let pkcs8 = read(KEYED, "runtime.key.pkcs8.der");
    let cert = certs::self_signed(&certs::key_pair(&pkcs8).unwrap(), h.now()).unwrap();
    let identity = format!("{}{}", text(KEYED, "runtime.key.pem"), certs::pem(&cert));
    let (status, reply) = send(
        client_with(&identity)
            .post(format!("{}/v1/node/join", h.url))
            .json(&json!({
                "nonce": b64(&fresh_nonce(&h)),
                "evidence": evidence(KEYED, "node"),
                "xwing_pubkey": PrivateKey::generate().unwrap().public(),
                "db_client_cert": true,
            })),
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::FORBIDDEN, "{reply}");
    assert_eq!(code(&reply), "policy_denied");
    let spki = certs::spki_of(&cert).unwrap();
    assert!(requests_for(&h.audit("node.join.request").await, &spki).is_empty());

    // Listed as a Kata build: the serving node writes the row, then hands over the intermediates
    // with the volume key, from which the joiner's database certificate comes.
    publish(&h, listing(kata_document(3), revision, "kata-tdx")).await;
    let reply = join(&h, &joiner, &initdata, None).await.unwrap();
    let requests = requests_for(&h.audit("node.join.request").await, &joiner.runtime_spki);
    assert_eq!(
        requests,
        [json!({
            "runtime_pubkey_sha256": alpha_kms::keys::sha256_hex(&joiner.runtime_spki),
            "compose_hash": revision,
            "recorded_by": "serving node",
            "database_auth": "client-cert",
        })]
    );
    let (outcome, details) = last_join(&h).await;
    assert_eq!(outcome, "ok");
    assert_eq!(details["compose_hash"], json!(revision));
    let reply: JoinReply = serde_json::from_value(reply).unwrap();
    let volume = h.node.db_volume_key().unwrap();
    assert_eq!(reply.db_volume_key, Some(b64(volume.as_slice())));

    // The joiner pins the database to the CA derived from that key, which this Postgres does not
    // hold: it sends nothing and stays sealed.
    assert!(node::finish_join(&joiner, &reply).await.is_err());
    assert!(joiner.is_sealed());
}

/// The volume key `tests/db_auth.rs`'s `write_postgres_side` sets the cert-auth Postgres up for.
const CERT_PG_VOLUME_KEY: [u8; 32] = [0x5a; 32];

/// D10 end to end on a Postgres that admits KMS nodes by client certificate only, set up as
/// `docs/db-client-auth.md` says ("Trying it"; CI's db-tests job starts one): skipped unless
/// `ALPHACOMPUTE_DB_AUTH_ADMIN_URL` (a password login for migrations and for the prototype node,
/// in `url` mode as during the migration) and `ALPHACOMPUTE_DB_AUTH_URL` (`alpha_kms_node`) are
/// set. A client-cert Kata node joins a prototype node whose database has that volume key: the
/// serving node writes its `node.join.request`, and the joiner issues itself a leaf from the
/// derived CA and serves on that database. An unlisted Kata node gets no row and no key.
#[tokio::test]
async fn a_client_cert_kata_node_joins_and_serves_on_a_cert_auth_postgres() {
    let (Ok(admin_url), Ok(node_url)) = (
        std::env::var("ALPHACOMPUTE_DB_AUTH_ADMIN_URL"),
        std::env::var("ALPHACOMPUTE_DB_AUTH_URL"),
    ) else {
        eprintln!("ALPHACOMPUTE_DB_AUTH_ADMIN_URL or ALPHACOMPUTE_DB_AUTH_URL unset; skipped");
        return;
    };
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&admin_url)
        .await
        .unwrap();
    let name = format!("alpha_test_{}", Uuid::now_v7().simple());
    sqlx::query(sqlx::AssertSqlSafe(format!("create database {name}")))
        .execute(&admin)
        .await
        .unwrap();
    let on_test_db = |url: &str| url.parse::<PgConnectOptions>().unwrap().database(&name);
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect_with(on_test_db(&admin_url))
        .await
        .unwrap();
    alpha_kms::migrate(&pool).await.unwrap();

    // The serving prototype node, on a database whose volume key the Postgres's CA comes from.
    let initdata = kms_initdata();
    let revision = kms_revision(&initdata);
    let release = ReleaseServer::start(listing(kata_document(2), revision, "kata-tdx")).await;
    let (serving, serving_url, _serving) = start_node(
        pool.clone(),
        &release.url,
        &release.key,
        Arc::new(SystemTime::now),
    )
    .await;
    let (ca_key, ca_cert) = certs::new_ca(serving.now()).unwrap();
    let keys = Intermediates::new(
        Zeroizing::new(alpha_kms::random().unwrap()),
        Zeroizing::new(ca_key),
        ca_cert,
    )
    .unwrap()
    .with_db_volume(Some(Zeroizing::new(CERT_PG_VOLUME_KEY)));
    serving.start_serving(keys).await.unwrap();
    let keys = serving.intermediates().unwrap();
    let requests = || {
        let (pool, metadata) = (&pool, &keys.metadata);
        async move {
            let mut rows = Vec::new();
            audit::verify(pool, metadata, audit::Checkpoint::default(), |row| {
                if row.entry.action == "node.join.request" {
                    rows.push((row.seq, row.entry.outcome, row.entry.details));
                }
            })
            .await
            .unwrap();
            rows
        }
    };

    let node_pool = PgPoolOptions::new().connect_lazy_with(on_test_db(&node_url));
    let join_with = |joiner: Arc<Node>, initdata: String| {
        let (serving, serving_url) = (serving.clone(), serving_url.clone());
        async move {
            let nonce = instance::mint_nonce(&serving.nonce_key, serving.now()).unwrap();
            let request = node::join_request(&joiner, b64(&nonce), &serving_url)
                .await
                .unwrap();
            assert!(request.db_client_cert);
            let quote = Pod::quote_of(
                &initdata,
                CPU_RUNTIME_CLASS,
                report_data(
                    &joiner.runtime_spki,
                    &nonce,
                    Some(request.xwing_pubkey.as_bytes()),
                ),
            );
            node::join_verified(&serving, &joiner.runtime_spki, &request, quote).await
        }
    };

    // An unlisted Kata build: refused, no row, no key, and the database still refuses it.
    let app: AppId = "01a09f07-8d09-7640-94c1-bbdb74200a1f".parse().unwrap();
    let unlisted = common::kata::initdata(app, CPU_RUNTIME_CLASS, None, POLICY);
    let (stranger, _, _stranger) =
        start_kata_node_with(node_pool.clone(), &release, &unlisted, true).await;
    let error = join_with(stranger.clone(), unlisted).await.unwrap_err();
    assert_eq!(error.code, "attestation_unknown", "{}", error.message);
    assert!(requests_for(&requests().await, &stranger.runtime_spki).is_empty());
    assert!(stranger.is_sealed());
    assert!(
        sqlx::query("select 1")
            .execute(&stranger.pool)
            .await
            .is_err()
    );

    // The listed build joins: the serving node writes its row, the joiner's leaf from the derived
    // CA reaches Postgres as alpha_kms_node, and it serves under the same CA.
    let (joiner, _, _joiner) =
        start_kata_node_with(node_pool.clone(), &release, &initdata, true).await;
    assert!(joiner.platform_document().is_some());
    let reply = join_with(joiner.clone(), initdata.clone()).await.unwrap();
    let rows = requests_for(&requests().await, &joiner.runtime_spki);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["recorded_by"], "serving node");
    let reply: JoinReply = serde_json::from_value(reply).unwrap();
    node::finish_join(&joiner, &reply).await.unwrap();
    assert!(!joiner.is_sealed());
    assert_eq!(
        joiner.intermediates().unwrap().ca_pem(),
        serving.intermediates().unwrap().ca_pem()
    );
    let user: String = sqlx::query_scalar("select current_user::text")
        .fetch_one(&joiner.pool)
        .await
        .unwrap();
    assert_eq!(user, db_auth::ROLE);
    // It reads and locks the stored platform document as any serving node does.
    platform::reload(&joiner).await.unwrap();
}
