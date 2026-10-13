//! M2(a), the trust-zone Postgres's volume key, against an in-process node on `DATABASE_URL`
//! (skipped without it). The Postgres pod is a synthetic Kata pod, its quote taken as verified
//! (`db_volume::db_key_verified`) until B300 Kata captures exist (M1); the route's own DCAP step
//! is checked with a quote that fails it. The database is made unreachable by pointing a node's
//! pool at a closed port, and reachable again by opening a proxy on that port.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use alpha_attest::{AnyEvidence, EVIDENCE_FORMAT, Evidence};
use alpha_cli::node as cli_node;
use alpha_client::db_key::{self, pod_report_data};
use alpha_client::{DbKeyReply, DbKeyRequest};
use alpha_core::AppId;
use alpha_core::coco::CPU_RUNTIME_CLASS;
use alpha_crypto::PrivateKey;
use alpha_kms::error::ApiError;
use alpha_kms::{Node, audit, db_volume, platform};
use common::kata::{Pod, kata_document, publish};
use common::*;
use reqwest::StatusCode;
use serde_json::{Value, json};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

/// The Postgres pod's build listed in `db_revisions` (and, for the refusal, nothing else).
fn listing(version: u64, db: &[&Pod], kms: &[&Pod]) -> Value {
    let entry = |pod: &&Pod| {
        json!({ "compose_hash": pod.hash(), "build": "postgres",
                                     "source_url": "u", "kind": "kata-tdx" })
    };
    let mut doc = kata_document(version);
    doc["db_revisions"] = json!(db.iter().map(entry).collect::<Vec<_>>());
    doc["kms_revisions"]
        .as_array_mut()
        .unwrap()
        .extend(kms.iter().map(entry));
    doc
}

/// A request from `pod` over `nonce` with its evidence, and the quote its TD produces over
/// `report_data` (by default the one binding its X-Wing key and the nonce).
fn ask(pod: &Pod, nonce: &str, xwing: &PrivateKey) -> DbKeyRequest {
    // A CPU pod's evidence names no GPU, so nothing in it depends on the nonce.
    db_key::request(nonce, xwing, |_| Ok(pod.evidence(&[0; 32]).into())).unwrap()
}

fn quote(pod: &Pod, nonce: &str, xwing: &PrivateKey) -> alpha_attest::VerifiedQuote {
    let raw: [u8; 32] = alpha_client::decode("nonce", nonce)
        .unwrap()
        .try_into()
        .unwrap();
    Pod::quote_of(
        &pod.initdata,
        CPU_RUNTIME_CLASS,
        pod_report_data(xwing, &raw),
    )
}

async fn node_nonce(url: &str) -> String {
    let (status, reply) = send(client().post(format!("{url}/v1/node/nonce"))).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    reply["nonce"].as_str().unwrap().to_owned()
}

/// The listed pod asks `node` (at `url`) and opens the reply.
async fn release(node: &Node, url: &str, pod: &Pod) -> Result<[u8; 32], ApiError> {
    let xwing = PrivateKey::generate().unwrap();
    let nonce = node_nonce(url).await;
    let request = ask(pod, &nonce, &xwing);
    let reply = db_volume::db_key_verified(node, &request, quote(pod, &nonce, &xwing)).await?;
    Ok(*db_key::open(&reply, &xwing, &node.runtime_spki).unwrap())
}

fn refused(result: Result<impl std::fmt::Debug, ApiError>, code: &str, reason: &str) {
    let e = result.unwrap_err();
    assert_eq!(e.code, code, "{}", e.message);
    assert!(e.message.contains(reason), "{}", e.message);
}

#[tokio::test]
async fn the_volume_key_goes_only_to_the_listed_postgres_pod_of_an_unsealed_node() {
    let Some(h) = harness().await else {
        return;
    };
    let postgres = Pod::cpu(AppId::mint());
    let other = Pod::cpu(AppId::mint());
    publish(&h, listing(2, &[&postgres], &[&other])).await;
    let key = *h.node.intermediates().unwrap().db_volume.clone().unwrap();

    // Before unseal: a sealed node has no key to give, whatever asks.
    let (sealed, sealed_url, _sealed) = start_node(
        h.pool.clone(),
        &h.release.url,
        &h.release.key,
        h.node.clock.clone(),
    )
    .await;
    let xwing = PrivateKey::generate().unwrap();
    let nonce = node_nonce(&sealed_url).await;
    let (status, reply) = send(
        client()
            .post(format!("{sealed_url}/v1/node/db-key"))
            .json(&ask(&postgres, &nonce, &xwing)),
    )
    .await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::SERVICE_UNAVAILABLE, "sealed")
    );
    refused(
        release(&sealed, &sealed_url, &postgres).await,
        "sealed",
        "sealed",
    );

    // The listed Revision gets the key, sealed to its X-Wing key from this node.
    assert_eq!(release(&h.node, &h.url, &postgres).await.unwrap(), key);
    let xwing = PrivateKey::generate().unwrap();
    let nonce = node_nonce(&h.url).await;
    let reply: DbKeyReply = db_volume::db_key_verified(
        &h.node,
        &ask(&postgres, &nonce, &xwing),
        quote(&postgres, &nonce, &xwing),
    )
    .await
    .unwrap();
    assert!(
        db_key::open(
            &reply,
            &PrivateKey::generate().unwrap(),
            &h.node.runtime_spki
        )
        .is_err()
    );
    assert!(db_key::open(&reply, &xwing, &sealed.runtime_spki).is_err());

    // Any other Revision: unlisted, or listed as a KMS build only.
    refused(
        release(&h.node, &h.url, &Pod::cpu(AppId::mint())).await,
        "attestation_unknown",
        "db revision",
    );
    refused(
        release(&h.node, &h.url, &other).await,
        "attestation_unknown",
        "is not listed as a kata-tdx build",
    );

    // An unattested caller: a quote over another X-Wing key, another nonce, a nonce the node did
    // not mint, prototype evidence, and evidence v2 through the route, whose DCAP refuses it.
    let xwing = PrivateKey::generate().unwrap();
    let nonce = node_nonce(&h.url).await;
    let request = ask(&postgres, &nonce, &xwing);
    let substituted = quote(&postgres, &nonce, &PrivateKey::generate().unwrap());
    refused(
        db_volume::db_key_verified(&h.node, &request, substituted).await,
        "attestation_failed",
        "report_data is not bound",
    );
    let elsewhere = quote(&postgres, &b64(&[1u8; 32]), &xwing);
    refused(
        db_volume::db_key_verified(&h.node, &request, elsewhere).await,
        "attestation_failed",
        "report_data is not bound",
    );
    let forged = ask(&postgres, &b64(&[7u8; 32]), &xwing);
    refused(
        db_volume::db_key_verified(&h.node, &forged, quote(&postgres, &b64(&[7u8; 32]), &xwing))
            .await,
        "nonce_invalid",
        "nonce",
    );
    let prototype = DbKeyRequest {
        nonce: nonce.clone(),
        evidence: AnyEvidence::V1(Evidence {
            format: EVIDENCE_FORMAT.into(),
            quote: read(KEYED, "quote.node.hex"),
            event_log: Vec::new(),
        }),
        xwing_pubkey: xwing.public(),
    };
    refused(
        db_volume::db_key_verified(&h.node, &prototype, quote(&postgres, &nonce, &xwing)).await,
        "malformed",
        "alphacompute-evidence/2",
    );
    let (status, reply) = send(
        client()
            .post(format!("{}/v1/node/db-key", h.url))
            .json(&request),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{reply}");
    assert_eq!(code(&reply), "attestation_failed");

    // Every release and refusal is audited, naming the Revision released to.
    let rows = h.audit("db.key").await;
    let released: Vec<&Value> = rows
        .iter()
        .filter(|(_, o, _)| o == "ok")
        .map(|(_, _, d)| d)
        .collect();
    assert_eq!(released.len(), 2);
    assert_eq!(released[0]["revision"], json!(postgres.hash()));
    assert!(rows.iter().filter(|(_, o, _)| o == "denied").count() >= 6);
}

/// A database name and a pool for it through `port`, which nothing answers until [`proxy`].
async fn pool_via(h_pool: &PgPool, port: u16) -> PgPool {
    let name: String = sqlx::query_scalar("select current_database()")
        .fetch_one(h_pool)
        .await
        .unwrap();
    let mut url = reqwest::Url::parse(&std::env::var("DATABASE_URL").unwrap()).unwrap();
    url.set_host(Some("127.0.0.1")).unwrap();
    url.set_port(Some(port)).unwrap();
    url.set_path(&format!("/{name}"));
    PgPoolOptions::new()
        .max_connections(4)
        .acquire_timeout(Duration::from_millis(300))
        .connect_lazy(url.as_str())
        .unwrap()
}

async fn closed_port() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

/// Opens `port` and forwards every connection to the real database.
async fn proxy(port: u16) {
    let target = reqwest::Url::parse(&std::env::var("DATABASE_URL").unwrap()).unwrap();
    let upstream = format!(
        "{}:{}",
        target.host_str().unwrap(),
        target.port().unwrap_or(5432)
    );
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .unwrap();
    tokio::spawn(async move {
        while let Ok((mut inbound, _)) = listener.accept().await {
            let upstream = upstream.clone();
            tokio::spawn(async move {
                if let Ok(mut outbound) = tokio::net::TcpStream::connect(upstream).await {
                    let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                }
            });
        }
    });
}

async fn until_serving(node: &Node) {
    for _ in 0..150 {
        if node.is_serving() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the node did not serve once its database opened");
}

#[tokio::test]
async fn unseal_then_db_key_then_database_then_serve() {
    let Some(h) = harness().await else {
        return;
    };
    let postgres = Pod::cpu(AppId::mint());
    publish(&h, listing(2, &[&postgres], &[])).await;
    let key = *h.node.intermediates().unwrap().db_volume.clone().unwrap();

    // A node whose database is closed comes up sealed and still learns the platform document.
    let port = closed_port().await;
    let pool = pool_via(&h.pool, port).await;
    let (cold, cold_url, _cold) =
        start_node(pool, &h.release.url, &h.release.key, h.node.clock.clone()).await;
    assert!(cold.is_sealed());
    assert_eq!(cold.platform_document().unwrap().version, 2);

    // Two custodians unseal it with their share files, which carry the wrapped volume key; the
    // second verified the node against document 3, which the node has not seen yet.
    let custodian_cli = spki_client(&cold_url, &cold);
    let identity = node_identity(&cold);
    for (i, version) in [(1usize, 2u64), (2, 3)] {
        let path = h.dir.join(format!("share-{i}.json"));
        assert!(
            cli_node::ShareFile::read(&path)
                .unwrap()
                .db_volume_wrapped
                .is_some()
        );
        cli_node::unseal(
            &custodian_cli,
            &identity,
            &path,
            &h.custodians[i - 1],
            version,
            false,
        )
        .await
        .unwrap();
    }
    assert!(!cold.is_sealed() && !cold.is_serving());
    assert_eq!(
        send(client_get(&cold_url, "/ready")).await,
        (
            StatusCode::SERVICE_UNAVAILABLE,
            json!({ "sealed": false, "database": "waiting" })
        )
    );
    let (status, reply) = send(client().post(format!("{cold_url}/v1/attest/nonce"))).await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::SERVICE_UNAVAILABLE, "sealed")
    );
    refused(
        cold.intermediates().map(|_| ()),
        "sealed",
        "waits for its database",
    );

    // The key goes out only under a document at least as new as the custodians verified.
    refused(
        release(&cold, &cold_url, &postgres).await,
        "attestation_unknown",
        "below the 3 the custodians verified",
    );
    h.release.set(listing(3, &[&postgres], &[]));
    let _ = platform::reload(&cold).await;
    assert_eq!(release(&cold, &cold_url, &postgres).await.unwrap(), key);
    refused(
        release(&cold, &cold_url, &Pod::cpu(AppId::mint())).await,
        "attestation_unknown",
        "db revision",
    );

    // The database opens: the node unwraps everything under the root it held, and serves.
    proxy(port).await;
    until_serving(&cold).await;
    let keys = cold.intermediates().unwrap();
    assert_eq!(
        *keys.tenant_kek_root,
        *h.node.intermediates().unwrap().tenant_kek_root
    );
    assert_eq!(*keys.db_volume.clone().unwrap(), key);
    // What it did while waiting is in the chain now, sealed, marked with when it happened.
    let released: Vec<Value> = h
        .audit("db.key")
        .await
        .into_iter()
        .map(|(_, _, d)| d)
        .collect();
    assert!(
        released
            .iter()
            .any(|d| d["revision"] == json!(postgres.hash()) && d["held_at"].is_string())
    );
    assert!(
        h.audit("node.unseal")
            .await
            .iter()
            .any(|(_, o, d)| o == "ok" && d["database"] == "waiting")
    );
}

#[tokio::test]
async fn a_node_unsealed_with_the_database_closed_and_no_volume_key_stays_sealed() {
    let Some(h) = harness().await else {
        return;
    };
    let port = closed_port().await;
    let pool = pool_via(&h.pool, port).await;
    let (cold, cold_url, _cold) =
        start_node(pool, &h.release.url, &h.release.key, h.node.clock.clone()).await;
    let client = spki_client(&cold_url, &cold);
    let identity = node_identity(&cold);
    // Share files from before M2(a): no wrapped volume key.
    for i in [1usize, 2] {
        let path = h.dir.join(format!("share-{i}.json"));
        let mut file = cli_node::ShareFile::read(&path).unwrap();
        file.db_volume_wrapped = None;
        file.write(&path).unwrap();
    }
    cli_node::unseal(
        &client,
        &identity,
        &h.dir.join("share-1.json"),
        &h.custodians[0],
        1,
        false,
    )
    .await
    .unwrap();
    let e = cli_node::unseal(
        &client,
        &identity,
        &h.dir.join("share-2.json"),
        &h.custodians[1],
        1,
        false,
    )
    .await
    .unwrap_err();
    assert!(e.contains("no share file carried the db-volume key"), "{e}");
    assert!(cold.is_sealed());
}

/// #95's rollback check holds on the cold-start path too: the custodians' audit heads are checked
/// when the database opens, not at the unseal, which comes before it.
#[tokio::test]
async fn a_node_that_waited_for_its_database_halts_if_it_lacks_a_custodians_audit_head() {
    let Some(h) = harness().await else {
        return;
    };
    // Custodian 1's share file remembers a head this database does not hold, as it would after
    // the database was restored from a copy older than that custodian's last unseal.
    let path = h.dir.join("share-1.json");
    let mut file = cli_node::ShareFile::read(&path).unwrap();
    file.audit_head = Some(
        audit::Head {
            seq: 1_000_000,
            link: vec![7; 32],
        }
        .to_wire(),
    );
    file.write(&path).unwrap();
    let port = closed_port().await;
    let pool = pool_via(&h.pool, port).await;
    let (cold, cold_url, _cold) =
        start_node(pool, &h.release.url, &h.release.key, h.node.clock.clone()).await;
    let client = spki_client(&cold_url, &cold);
    let identity = node_identity(&cold);
    for i in [1usize, 2] {
        let path = h.dir.join(format!("share-{i}.json"));
        cli_node::unseal(&client, &identity, &path, &h.custodians[i - 1], 1, false)
            .await
            .unwrap();
    }
    assert!(!cold.is_sealed() && !cold.is_serving(), "waiting");
    let rows = audit_count(&h).await;

    proxy(port).await;
    for _ in 0..150 {
        if cold.chain.halted().is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(cold.chain.halted(), Some(audit::Halt::RolledBack));
    assert!(!cold.is_serving());
    assert_eq!(
        send(client_get(&cold_url, "/ready")).await,
        (
            StatusCode::SERVICE_UNAVAILABLE,
            json!({ "sealed": true, "halted": "audit_chain_rolled_back" })
        )
    );
    assert_eq!(cold.db_volume_key().err().map(|e| e.code), Some("halted"));
    assert_eq!(audit_count(&h).await, rows, "the halted node wrote nothing");
}

/// ACC-FD-107: while the database is closed, refused `db-key` calls cannot grow the held audit
/// queue without bound, nor crowd out the row of a release; what was dropped is counted in the
/// chain once the node serves.
#[tokio::test]
async fn the_held_audit_queue_is_bounded_while_the_database_is_closed() {
    let Some(h) = harness().await else {
        return;
    };
    let port = closed_port().await;
    let pool = pool_via(&h.pool, port).await;
    let (cold, cold_url, _cold) =
        start_node(pool, &h.release.url, &h.release.key, h.node.clock.clone()).await;
    let client = spki_client(&cold_url, &cold);
    let identity = node_identity(&cold);
    for i in [1usize, 2] {
        let path = h.dir.join(format!("share-{i}.json"));
        cli_node::unseal(&client, &identity, &path, &h.custodians[i - 1], 1, false)
            .await
            .unwrap();
    }
    assert!(!cold.is_sealed() && !cold.is_serving(), "waiting");

    // A flood of refusals, as unauthenticated `db-key` calls would write them, after the held
    // `node.unseal` row.
    let before = cold.held_audit.lock().len();
    assert_eq!(before, 1);
    let flood = alpha_kms::HELD_REFUSALS + 500;
    for _ in 0..flood {
        cold.audit_or_hold("db.key", "denied", json!({ "code": "nonce_invalid" }))
            .await
            .unwrap();
    }
    let held = cold.held_audit.lock().len();
    assert_eq!(
        held,
        alpha_kms::HELD_REFUSALS,
        "refusals stop at their share"
    );
    // A release still has room; once the whole queue is full, a release is refused rather than
    // sent unrecorded.
    for _ in held..alpha_kms::HELD_MAX {
        cold.audit_or_hold("db.key", "ok", json!({})).await.unwrap();
    }
    let e = cold
        .audit_or_hold("db.key", "ok", json!({}))
        .await
        .unwrap_err();
    assert_eq!(e.code, "rate_limited");
    assert_eq!(cold.held_audit.lock().len(), alpha_kms::HELD_MAX);

    // The database opens: the held rows go into the chain, and one row counts the rest.
    proxy(port).await;
    until_serving(&cold).await;
    assert_eq!(
        h.audit("audit.held_dropped").await[0].2,
        json!({ "refusals": flood - (alpha_kms::HELD_REFUSALS - before) })
    );
    assert!(cold.held_audit.lock().is_empty());
}

#[tokio::test]
async fn genesis_with_the_database_closed_writes_it_once_it_opens() {
    let Some(pool) = fresh_database().await else {
        return;
    };
    let release = ReleaseServer::start(platform_document(KEYED)).await;
    let port = closed_port().await;
    let clock: alpha_kms::Clock = {
        let now = captured_at(KEYED);
        Arc::new(move || now)
    };
    let (node, url, _node) = start_node(
        pool_via(&pool, port).await,
        &release.url,
        &release.key,
        clock.clone(),
    )
    .await;
    let custodians: Vec<PrivateKey> = (0..3).map(|_| PrivateKey::generate().unwrap()).collect();
    let dir = std::env::temp_dir().join(format!("alpha-db-genesis-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&dir).unwrap();
    let identity = node_identity(&node);
    alpha_cli::node::bootstrap(
        &spki_client(&url, &node),
        &identity,
        custodian_pubs(&custodians),
        1,
        &dir,
    )
    .await
    .unwrap();
    // The volume key exists before the database it opens: the node holds genesis and waits.
    assert!(!node.is_sealed() && !node.is_serving());
    let key = *node.db_volume_key().unwrap();
    let rows: i64 = sqlx::query_scalar("select count(*) from intermediate_keys")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rows, 0);

    proxy(port).await;
    until_serving(&node).await;
    let rows: Vec<String> =
        sqlx::query_scalar("select purpose::text from intermediate_keys order by purpose")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(rows, ["ca", "db-volume", "tenant-kek-root"]);

    // Two of the shares unseal another node on the open database, with the same keys.
    let (second, second_url, _second) =
        start_node(pool.clone(), &release.url, &release.key, clock).await;
    let client = spki_client(&second_url, &second);
    let second_identity = node_identity(&second);
    for (i, custodian) in [(1usize, &custodians[0]), (3, &custodians[2])] {
        cli_node::unseal(
            &client,
            &second_identity,
            &dir.join(format!("share-{i}.json")),
            custodian,
            1,
            false,
        )
        .await
        .unwrap();
    }
    assert!(second.is_serving());
    assert_eq!(*second.db_volume_key().unwrap(), key);
    assert_eq!(
        *second.intermediates().unwrap().tenant_kek_root,
        *node.intermediates().unwrap().tenant_kek_root
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

fn client_get(url: &str, path: &str) -> reqwest::RequestBuilder {
    client().get(format!("{url}{path}"))
}
