//! `alpha probe`, which the stand runs every fifteen minutes, against real KMS-issued leaves: URI
//! SANs only and an empty subject, reached at an IP address no certificate names, so a probe that
//! checked the host name would read every one of them as down.

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

use alpha_cli::probe::{self, AppTarget, Report, State, Targets};
use alpha_client::tls::cert_from_pem;
use alpha_client::{Pin, system_time_provider};
use alpha_core::{AppId, ComposeHash, OrgId, compose_hash};
use alpha_kms::certs;
use alpha_kms::tls::{self, ServerCert};
use axum::http::StatusCode;
use axum::routing::get;
use rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256, PublicKeyData};
use serde_json::{Value, json};

/// Port 1 on loopback: nothing of ours answers there.
const DEAD: &str = "https://127.0.0.1:1";

struct Ca {
    key: KeyPair,
    der: Vec<u8>,
}

impl Ca {
    fn new() -> Self {
        let (key, der) = certs::new_ca(SystemTime::now()).unwrap();
        Self {
            key: certs::key_pair(&key).unwrap(),
            der,
        }
    }

    fn pem(&self) -> String {
        certs::pem(&self.der)
    }

    /// The admin CLI's pin: this CA, a node leaf, one of `revisions`.
    fn pin(&self, revisions: Vec<ComposeHash>) -> Pin {
        Pin::CaAndRevisions(cert_from_pem(&self.pem()).unwrap(), revisions)
    }

    /// A listener presenting a one-hour leaf from this CA with `sans`, `router` behind it.
    async fn serving(&self, sans: [String; 2], router: axum::Router) -> String {
        let now = SystemTime::now();
        let runtime = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let pkcs8 = runtime.serialize_der();
        let leaf = certs::issue_leaf(
            &self.key,
            &self.der,
            &runtime.subject_public_key_info(),
            sans,
            now,
        )
        .unwrap();
        let server = ServerCert::sealed(&pkcs8, now).unwrap();
        server.serve(&pkcs8, leaf, self.der.clone()).unwrap();
        listen(server, router).await
    }

    async fn node(&self, revision: ComposeHash, status: StatusCode, body: Value) -> String {
        self.serving(certs::node_sans(revision), ready(status, body))
            .await
    }

    async fn instance(&self, app: AppId, revision: ComposeHash) -> String {
        let sans = certs::instance_sans(OrgId::mint(), app, &"ab".repeat(32), revision);
        self.serving(sans, axum::Router::new()).await
    }
}

async fn listen(server: ServerCert, router: axum::Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("https://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        alpha_client::tls::serve(
            listener,
            tls::server_config(Arc::new(server)).unwrap(),
            router,
            std::future::pending::<()>(),
        )
        .await
    });
    url
}

/// `/ready` answering `status` with `body`.
fn ready(status: StatusCode, body: Value) -> axum::Router {
    axum::Router::new().route(
        "/ready",
        get(move || async move { (status, axum::Json(body)) }),
    )
}

fn unsealed() -> Value {
    json!({ "sealed": false })
}

fn finding(report: &Report) -> &str {
    assert!(!report.serving, "{report:?}");
    report.finding.as_deref().unwrap()
}

#[tokio::test]
async fn a_node_leaf_with_only_uri_sans_is_ready_under_its_ca_and_revision() {
    let ca = Ca::new();
    let revision = compose_hash("{\"name\":\"kms\"}");
    let url = ca.node(revision, StatusCode::OK, unsealed()).await;

    let report = probe::kms_node(&url, &ca.pin(vec![revision]), &system_time_provider()).await;

    assert_eq!(report.state, State::Ready, "{report:?}");
    assert!(report.serving);
    assert_eq!(report.compose_hash, Some(revision.to_string()));
    assert!(report.finding.is_none());
}

#[tokio::test]
async fn a_node_outside_the_ca_or_the_revisions_is_down_though_it_answers_unsealed() {
    let ca = Ca::new();
    let revision = compose_hash("{\"name\":\"kms\"}");
    let url = ca.node(revision, StatusCode::OK, unsealed()).await;
    let time = system_time_provider();

    let unlisted = probe::kms_node(&url, &ca.pin(vec![compose_hash("other")]), &time).await;
    assert_eq!(unlisted.state, State::Down);
    let text = finding(&unlisted);
    assert!(text.contains("answers 200 OK"), "{text}");
    assert!(
        text.contains("but not under the platform document's KMS CA"),
        "{text}"
    );
    assert!(text.contains("no allowed KMS revision"), "{text}");

    let foreign = probe::kms_node(&url, &Ca::new().pin(vec![revision]), &time).await;
    assert_eq!(foreign.state, State::Down);
    assert!(finding(&foreign).contains("pinned ca"), "{foreign:?}");
}

/// The CA also issues Instance leaves with the server-auth EKU; the node pin names the KMS.
#[tokio::test]
async fn an_instance_leaf_standing_in_for_a_node_is_down() {
    let ca = Ca::new();
    let revision = compose_hash("{\"name\":\"tenant\"}");
    let sans = certs::instance_sans(OrgId::mint(), AppId::mint(), &"ab".repeat(32), revision);
    let url = ca.serving(sans, ready(StatusCode::OK, unsealed())).await;

    let report = probe::kms_node(&url, &ca.pin(vec![revision]), &system_time_provider()).await;

    assert_eq!(report.state, State::Down);
    assert!(finding(&report).contains("not a KMS node's"), "{report:?}");
}

#[tokio::test]
async fn a_sealed_node_reads_as_sealed_not_as_silent() {
    let runtime = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let server = ServerCert::sealed(&runtime.serialize_der(), SystemTime::now()).unwrap();
    let body = json!({ "sealed": true });
    let url = listen(server, ready(StatusCode::SERVICE_UNAVAILABLE, body)).await;
    let ca = Ca::new();

    let report = probe::kms_node(
        &url,
        &ca.pin(vec![compose_hash("kms")]),
        &system_time_provider(),
    )
    .await;

    assert_eq!(report.state, State::Sealed, "{report:?}");
    let text = finding(&report);
    assert!(text.contains("503"), "{text}");
    assert!(text.contains("custodians must unseal it"), "{text}");
}

#[tokio::test]
async fn a_node_whose_database_fails_is_down_with_the_reason() {
    let ca = Ca::new();
    let revision = compose_hash("{\"name\":\"kms\"}");
    let envelope = json!({ "error": { "code": "internal", "message": "database: refused",
                                      "request_id": "r" } });
    let url = ca
        .node(revision, StatusCode::INTERNAL_SERVER_ERROR, envelope)
        .await;

    let report = probe::kms_node(&url, &ca.pin(vec![revision]), &system_time_provider()).await;

    assert_eq!(report.state, State::Down);
    let text = finding(&report);
    assert!(text.contains("/ready answers 500"), "{text}");
    assert!(text.contains("internal: database: refused"), "{text}");
}

#[tokio::test]
async fn nothing_listening_is_down() {
    let report = probe::kms_node(
        DEAD,
        &Ca::new().pin(vec![compose_hash("kms")]),
        &system_time_provider(),
    )
    .await;
    assert_eq!(report.state, State::Down);
    assert!(finding(&report).contains("no answer under"), "{report:?}");
}

#[tokio::test]
async fn an_app_endpoint_serves_when_its_leaf_names_a_listed_revision() {
    let ca = Ca::new();
    let app = AppId::mint();
    let (running, next) = (compose_hash("{\"v\":1}"), compose_hash("{\"v\":2}"));
    let url = ca.instance(app, running).await;
    let time = system_time_provider();
    let target = |revisions| AppTarget {
        url: url.clone(),
        revisions,
    };

    for listed in [vec![running], vec![next, running]] {
        let report = probe::app_endpoint(&target(listed), &ca.pem(), &time).await;
        assert_eq!(report.state, State::Attested, "{report:?}");
        assert!(report.serving);
        assert_eq!(report.app_id, Some(app.to_string()));
        assert_eq!(report.compose_hash, Some(running.to_string()));
    }

    let report = probe::app_endpoint(&target(vec![next]), &ca.pem(), &time).await;
    assert_eq!(report.state, State::OtherRevision);
    let text = finding(&report);
    assert!(text.contains(&running.to_string()), "{text}");
    assert!(text.contains("not listed"), "{text}");
}

#[tokio::test]
async fn an_app_endpoint_without_a_leaf_from_the_ca_is_silent() {
    let revision = compose_hash("{\"v\":1}");
    let url = Ca::new().instance(AppId::mint(), revision).await;
    let time = system_time_provider();
    let target = |url: &str| AppTarget {
        url: url.to_owned(),
        revisions: vec![revision],
    };

    let foreign = probe::app_endpoint(&target(&url), &Ca::new().pem(), &time).await;
    assert_eq!(foreign.state, State::Silent);
    let text = finding(&foreign);
    assert!(text.contains("unpinned it answers 404 Not Found"), "{text}");
    assert!(!text.contains(&format!("{url}: {url}")), "{text}");

    let dead = probe::app_endpoint(&target(DEAD), &Ca::new().pem(), &time).await;
    assert_eq!(dead.state, State::Silent);
    let text = finding(&dead);
    assert!(text.contains("Connection refused"), "{text}");
    assert!(!text.contains("unpinned"), "{text}");
}

#[tokio::test]
async fn a_node_leaf_at_an_app_endpoint_is_down() {
    let ca = Ca::new();
    let revision = compose_hash("{\"name\":\"kms\"}");
    let url = ca.node(revision, StatusCode::OK, unsealed()).await;
    let target = AppTarget {
        url,
        revisions: vec![revision],
    };

    let report = probe::app_endpoint(&target, &ca.pem(), &system_time_provider()).await;

    assert_eq!(report.state, State::Down);
    assert!(finding(&report).contains("not an Instance's"), "{report:?}");
}

#[tokio::test]
async fn run_reports_every_target_and_fails_when_one_is_not_serving() {
    let ca = Ca::new();
    let node = compose_hash("{\"name\":\"kms\"}");
    let kms = ca.node(node, StatusCode::OK, unsealed()).await;
    let revision = compose_hash("{\"v\":1}");
    let app = AppTarget {
        url: ca.instance(AppId::mint(), revision).await,
        revisions: vec![revision],
    };
    let time = system_time_provider();

    let all = Targets {
        kms: vec![kms.clone()],
        apps: vec![app.clone()],
    };
    let (out, failed) = probe::run(&all, &ca.pem(), vec![node], time.clone())
        .await
        .unwrap();
    assert!(!failed, "{out}");
    assert_eq!(out["kms"][0]["state"], "ready");
    assert_eq!(out["kms"][0]["compose_hash"], node.to_string());
    assert_eq!(out["apps"][0]["state"], "attested");
    assert!(out["kms"][0].get("finding").is_none(), "{out}");

    let one_down = Targets {
        kms: vec![kms, DEAD.into()],
        apps: vec![app],
    };
    let (out, failed) = probe::run(&one_down, &ca.pem(), vec![node], time.clone())
        .await
        .unwrap();
    assert!(failed, "{out}");
    assert_eq!(out["kms"][1]["state"], "down");
    assert_eq!(out["kms"][1]["serving"], false);
    assert!(
        out["kms"][1]["finding"].as_str().unwrap().starts_with(DEAD),
        "{out}"
    );

    let err = probe::run(&one_down, "", vec![node], time)
        .await
        .unwrap_err();
    assert!(err.contains("kms_ca_pem"), "{err}");
}

/// A real node through its own `/ready` route and its own listener: unsealed after bootstrap, and
/// sealed again as a second node over the same database before any custodian unseals it.
#[tokio::test]
async fn a_real_node_is_ready_once_unsealed_and_sealed_before() {
    let Some(h) = common::harness_with_clock(Arc::new(SystemTime::now)).await else {
        return;
    };
    let time = system_time_provider();
    let pin = Pin::CaAndRevisions(cert_from_pem(&h.ca_pem).unwrap(), vec![h.node.compose_hash]);

    let report = probe::kms_node(&h.url, &pin, &time).await;
    assert_eq!(report.state, State::Ready, "{report:?}");
    assert_eq!(report.compose_hash, Some(h.node.compose_hash.to_string()));

    let (sealed, url, _shutdown) = common::start_node(
        h.pool.clone(),
        &h.release.url,
        &h.release.key,
        Arc::new(SystemTime::now),
    )
    .await;
    assert!(sealed.is_sealed());
    let report = probe::kms_node(&url, &pin, &time).await;
    assert_eq!(report.state, State::Sealed, "{report:?}");
    assert!(finding(&report).contains("503"), "{report:?}");

    // The route checks the database before it answers.
    h.pool.close().await;
    let report = probe::kms_node(&h.url, &pin, &time).await;
    assert_eq!(report.state, State::Down, "{report:?}");
    assert!(
        finding(&report).contains("/ready answers 500"),
        "{report:?}"
    );
}
