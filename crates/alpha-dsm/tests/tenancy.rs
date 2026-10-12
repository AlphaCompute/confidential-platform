//! The live DSM read of the tenancy check against a stand-in DSM that answers the endpoints
//! assumed under `dsm-listing` (F3): an auditor login, account selection, paged listings, and
//! the session ended afterwards. What a real DSM answers is PRD-06 Q4.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use alpha_client::tls::{certified, mtls_server_config, serve};
use alpha_dsm::KeyExchange;
use alpha_dsm::tenancy::{self, Account, Roster, Severity, Verdict, dsm};
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, SanType};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use serde_json::{Value, json};

struct Ca {
    pem: String,
    der: Vec<u8>,
    issuer: Issuer<'static, KeyPair>,
}

fn ca() -> Ca {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let cert = params.self_signed(&key).unwrap();
    Ca {
        pem: cert.pem(),
        der: cert.der().to_vec(),
        issuer: Issuer::new(params, key),
    }
}

#[derive(Debug)]
struct One(Arc<CertifiedKey>);

impl ResolvesServerCert for One {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

/// 150 customer users (so the read takes two pages), one AlphaCompute admin among them, and the
/// recorded workload App.
struct StandIn {
    mfa: AtomicBool,
    selected: AtomicBool,
    terminated: AtomicUsize,
    pages: AtomicUsize,
}

const BASIC: &str = "Basic YXVkaXRAYWxwaGFjb21wdXRlLmFpOnMzY3JldA=="; // audit@alphacompute.ai:s3cret

async fn auth(State(s): State<Arc<StandIn>>, headers: HeaderMap) -> impl IntoResponse {
    if headers.get("authorization").and_then(|v| v.to_str().ok()) != Some(BASIC) {
        return (StatusCode::UNAUTHORIZED, "bad login").into_response();
    }
    if s.mfa.load(Ordering::SeqCst) {
        return Json(json!({"mfa_challenge": {"u2f": "..."}})).into_response();
    }
    Json(json!({"access_token": "t-1", "expires_in": 600})).into_response()
}

fn bearer(headers: &HeaderMap) -> bool {
    headers.get("authorization").and_then(|v| v.to_str().ok()) == Some("Bearer t-1")
}

async fn select(
    State(s): State<Arc<StandIn>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    if !bearer(&headers) || body != json!({"acct_id": "acct-1"}) {
        return (StatusCode::FORBIDDEN, "no").into_response();
    }
    s.selected.store(true, Ordering::SeqCst);
    Json(json!({})).into_response()
}

fn page(all: Vec<Value>, q: &HashMap<String, usize>) -> Vec<Value> {
    let (limit, offset) = (q["limit"], q["offset"]);
    all.into_iter().skip(offset).take(limit).collect()
}

async fn users(
    State(s): State<Arc<StandIn>>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, usize>>,
) -> impl IntoResponse {
    if !bearer(&headers) || !s.selected.load(Ordering::SeqCst) {
        return (StatusCode::FORBIDDEN, "no").into_response();
    }
    s.pages.fetch_add(1, Ordering::SeqCst);
    let mut all: Vec<Value> = (0..150)
        .map(|n| {
            json!({"user_id": format!("u-{n}"), "user_email": format!("p{n}@acme.example"),
                   "account_role": ["ACCOUNTMEMBER"], "groups": {}})
        })
        .collect();
    all.push(
        json!({"user_id": "u-ops", "user_email": "ops@alphacompute.ai",
                    "account_role": ["ACCOUNTADMINISTRATOR"]}),
    );
    all.push(
        json!({"user_id": "u-audit", "user_email": "audit@alphacompute.ai",
                    "account_role": ["ACCOUNTAUDITOR"]}),
    );
    Json(page(all, &q)).into_response()
}

async fn apps(headers: HeaderMap, Query(q): Query<HashMap<String, usize>>) -> impl IntoResponse {
    if !bearer(&headers) {
        return (StatusCode::FORBIDDEN, "no").into_response();
    }
    let all = vec![json!({"app_id": "app-w", "name": "I1", "groups": {"g-1": ["EXPORT"]}})];
    Json(page(all, &q)).into_response()
}

async fn groups(headers: HeaderMap, Query(q): Query<HashMap<String, usize>>) -> impl IntoResponse {
    if !bearer(&headers) {
        return (StatusCode::FORBIDDEN, "no").into_response();
    }
    Json(page(vec![json!({"group_id": "g-1", "name": "pilot"})], &q)).into_response()
}

async fn terminate(State(s): State<Arc<StandIn>>) -> impl IntoResponse {
    s.terminated.fetch_add(1, Ordering::SeqCst);
    StatusCode::NO_CONTENT
}

async fn stand_in(dsm_ca: &Ca, state: Arc<StandIn>) -> String {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.subject_alt_names = vec![SanType::IpAddress([127, 0, 0, 1].into())];
    let leaf = params.signed_by(&key, &dsm_ca.issuer).unwrap();
    let certified = certified(
        vec![leaf.der().to_vec().into(), dsm_ca.der.clone().into()],
        &key.serialize_der(),
    )
    .unwrap();
    // Client certificates are not used here; any CA will do for the verifier.
    let config = mtls_server_config(Arc::new(One(certified)), dsm_ca.der.clone().into()).unwrap();
    let app = Router::new()
        .route("/sys/v1/session/auth", post(auth))
        .route("/sys/v1/session/select_account", post(select))
        .route("/sys/v1/session/terminate", post(terminate))
        .route("/sys/v1/users", get(users))
        .route("/sys/v1/apps", get(apps))
        .route("/sys/v1/groups", get(groups))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve(listener, config, app, std::future::pending()));
    format!("https://{addr}")
}

fn state() -> Arc<StandIn> {
    Arc::new(StandIn {
        mfa: AtomicBool::new(false),
        selected: AtomicBool::new(false),
        terminated: AtomicUsize::new(0),
        pages: AtomicUsize::new(0),
    })
}

fn account(endpoint: &str, ca_pem: &str) -> Account {
    Account::parse(
        json!({
            "format": "alphacompute-fortanix-account/1",
            "owner": "Acme",
            "tenancy": "customer",
            "dsm": {"endpoint": endpoint, "account_id": "acct-1", "ca_pem": ca_pem},
            "credentials": [
                {"service": "dsm", "id": "app-w", "purpose": "workload"},
                {"service": "dsm", "id": "u-audit", "purpose": "audit"}
            ]
        })
        .to_string()
        .as_bytes(),
    )
    .unwrap()
}

fn login() -> dsm::AuditorLogin {
    serde_json::from_str(r#"{"email":"audit@alphacompute.ai","password":"s3cret"}"#).unwrap()
}

fn roster() -> Roster {
    Roster::parse(
        br#"{"format":"alphacompute-sod-roster/1","domains":["alphacompute.ai"],"people":[
             {"name":"Ops","roles":["infrastructure-admin"],"emails":["ops@alphacompute.ai"]}]}"#,
    )
    .unwrap()
}

#[tokio::test]
async fn a_live_read_lists_every_page_and_the_check_flags_our_admin() {
    let dsm_ca = ca();
    let s = state();
    let endpoint = stand_in(&dsm_ca, s.clone()).await;
    let account = account(&endpoint, &dsm_ca.pem);
    let bytes = dsm::fetch(account.dsm.as_ref().unwrap(), &login(), KeyExchange::Hybrid)
        .await
        .unwrap();
    assert_eq!(s.pages.load(Ordering::SeqCst), 2);
    assert_eq!(s.terminated.load(Ordering::SeqCst), 1);
    let listing = dsm::parse_export(&bytes, format!("live:{endpoint}")).unwrap();
    assert_eq!(listing.principals.len(), 153);

    let report = tenancy::check(&account, &roster(), &[listing], "now".into());
    assert_eq!(report.verdict, Verdict::Fail);
    let violations: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Violation)
        .collect();
    // Only the infrastructure admin; the recorded audit login and workload App are within purpose.
    assert_eq!(violations.len(), 1, "{violations:?}");
    assert_eq!(violations[0].rule, "tenancy.alphacompute-admin");
    assert!(violations[0].detail.contains("ops@alphacompute.ai"));
}

#[tokio::test]
async fn a_login_asking_for_a_second_factor_is_refused_and_ends_nothing_open() {
    let dsm_ca = ca();
    let s = state();
    s.mfa.store(true, Ordering::SeqCst);
    let endpoint = stand_in(&dsm_ca, s.clone()).await;
    let account = account(&endpoint, &dsm_ca.pem);
    let e = dsm::fetch(account.dsm.as_ref().unwrap(), &login(), KeyExchange::Hybrid)
        .await
        .unwrap_err();
    assert!(e.to_string().contains("not implemented"), "{e}");
    assert_eq!(s.pages.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_dsm_under_another_ca_is_never_read() {
    let s = state();
    let endpoint = stand_in(&ca(), s.clone()).await;
    let account = account(&endpoint, &ca().pem);
    assert!(
        dsm::fetch(account.dsm.as_ref().unwrap(), &login(), KeyExchange::Hybrid)
            .await
            .is_err()
    );
    assert!(!s.selected.load(Ordering::SeqCst));
    assert_eq!(s.pages.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_live_read_needs_the_dsm_ca() {
    let account = Account::parse(
        br#"{"format":"alphacompute-fortanix-account/1","owner":"Acme","tenancy":"customer",
             "dsm":{"endpoint":"https://127.0.0.1:1","account_id":"acct-1"}}"#,
    )
    .unwrap();
    let e = dsm::fetch(account.dsm.as_ref().unwrap(), &login(), KeyExchange::Hybrid)
        .await
        .unwrap_err();
    assert!(e.to_string().contains("ca_pem"), "{e}");
}
