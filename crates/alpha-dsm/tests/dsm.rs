//! The client against a stand-in DSM: mTLS with the Instance leaf, one session reused across
//! keys, DSM's refusals surfaced, a DSM under any other CA never reached.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use alpha_client::tls::{PeerCerts, certified, mtls_server_config, serve};
use alpha_dsm::{Dsm, DsmConfig, Error};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Extension, Json, Router};
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use serde_json::{Value, json};

const KEY: &[u8] = b"customer data key, 32 bytes long";

struct Ca {
    pem: String,
    der: Vec<u8>,
    issuer: Issuer<'static, KeyPair>,
}

fn ca(name: &str) -> Ca {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    let cert = params.self_signed(&key).unwrap();
    Ca {
        pem: cert.pem(),
        der: cert.der().to_vec(),
        issuer: Issuer::new(params, key),
    }
}

fn leaf(ca: &Ca, sans: Vec<String>) -> (Vec<u8>, Vec<u8>) {
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(sans)
        .unwrap()
        .signed_by(&key, &ca.issuer)
        .unwrap();
    (cert.der().to_vec(), key.serialize_der())
}

#[derive(Debug)]
struct One(Arc<CertifiedKey>);

impl ResolvesServerCert for One {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

#[derive(Default)]
struct StandIn {
    sessions: AtomicUsize,
}

async fn auth(
    State(dsm): State<Arc<StandIn>>,
    Extension(peer): Extension<PeerCerts>,
    headers: HeaderMap,
) -> impl IntoResponse {
    // "app-1:" in basic auth, and a client certificate under the KMS CA.
    let basic = headers.get("authorization").and_then(|v| v.to_str().ok());
    if peer.0.is_empty() || basic != Some("Basic YXBwLTE6") {
        return (StatusCode::UNAUTHORIZED, Json(json!({"message": "no"}))).into_response();
    }
    dsm.sessions.fetch_add(1, Ordering::SeqCst);
    Json(json!({"token_type": "Bearer", "access_token": "t-1", "expires_in": 600, "entity_id": "app-1"}))
        .into_response()
}

async fn export(headers: HeaderMap, Json(body): Json<Value>) -> impl IntoResponse {
    if headers.get("authorization").and_then(|v| v.to_str().ok()) != Some("Bearer t-1") {
        return (StatusCode::UNAUTHORIZED, "bad token").into_response();
    }
    use base64::Engine;
    match body {
        b if b == json!({"kid": "k-1"}) => Json(json!({
            "kid": "k-1", "name": "data", "obj_type": "AES",
            "value": base64::prelude::BASE64_STANDARD.encode(KEY),
        }))
        .into_response(),
        _ => (StatusCode::FORBIDDEN, "operation EXPORT is not permitted").into_response(),
    }
}

/// A stand-in DSM under `dsm_ca`, accepting clients under `kms_ca`; returns its base URL.
async fn stand_in(dsm_ca: &Ca, kms_ca: &Ca, state: Arc<StandIn>) -> String {
    let (der, pkcs8) = leaf(dsm_ca, vec!["127.0.0.1".into()]);
    let key = certified(vec![der.into(), dsm_ca.der.clone().into()], &pkcs8).unwrap();
    let config = mtls_server_config(Arc::new(One(key)), kms_ca.der.clone().into()).unwrap();
    let app = Router::new()
        .route("/sys/v1/session/auth", post(auth))
        .route("/crypto/v1/keys/export", post(export))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve(listener, config, app, std::future::pending()));
    format!("https://{addr}")
}

fn config(endpoint: &str, dsm_ca: &Ca) -> DsmConfig {
    let text = json!({
        "endpoint": endpoint, "app_id": "app-1", "ca_pem": dsm_ca.pem,
        "keys": {"data": {"kid": "k-1"}, "index": {"name": "idx"}},
    })
    .to_string();
    DsmConfig::parse(Some(&text)).unwrap().unwrap()
}

fn instance(kms_ca: &Ca) -> InstanceKey {
    let (der, pkcs8) = leaf(kms_ca, vec!["instance.example".into()]);
    InstanceKey {
        chain: vec![der, kms_ca.der.clone()],
        pkcs8,
    }
}

struct InstanceKey {
    chain: Vec<Vec<u8>>,
    pkcs8: Vec<u8>,
}

#[tokio::test]
async fn fetches_declared_keys_over_mtls_with_one_session() {
    let (kms_ca, dsm_ca) = (ca("kms"), ca("dsm"));
    let state = Arc::new(StandIn::default());
    let url = stand_in(&dsm_ca, &kms_ca, state.clone()).await;
    let me = instance(&kms_ca);
    let dsm = Dsm::new(&config(&url, &dsm_ca), me.chain, &me.pkcs8).unwrap();

    let key = dsm.key("data").await.unwrap();
    assert_eq!(&key.value[..], KEY);
    assert_eq!(key.kid.as_deref(), Some("k-1"));
    assert!(!format!("{key:?}").contains("customer data key"));

    dsm.key("data").await.unwrap();
    assert_eq!(state.sessions.load(Ordering::SeqCst), 1);

    match dsm.key("index").await.unwrap_err() {
        Error::Refused { status, message } => {
            assert_eq!(status, 403);
            assert!(message.contains("EXPORT"));
        }
        other => panic!("{other}"),
    }
    assert!(matches!(dsm.key("other").await, Err(Error::Undeclared(_))));
    assert!(dsm.declares("data") && !dsm.declares("other"));
}

#[tokio::test]
async fn a_dsm_under_another_ca_is_never_trusted() {
    let (kms_ca, dsm_ca, pinned) = (ca("kms"), ca("dsm"), ca("pinned"));
    let url = stand_in(&dsm_ca, &kms_ca, Arc::new(StandIn::default())).await;
    let me = instance(&kms_ca);
    let dsm = Dsm::new(&config(&url, &pinned), me.chain, &me.pkcs8).unwrap();
    assert!(matches!(dsm.key("data").await, Err(Error::Transport(_))));
}

#[tokio::test]
async fn an_instance_without_a_kms_leaf_gets_no_session() {
    let (kms_ca, dsm_ca, other) = (ca("kms"), ca("dsm"), ca("other"));
    let state = Arc::new(StandIn::default());
    let url = stand_in(&dsm_ca, &kms_ca, state.clone()).await;
    let stranger = instance(&other);
    let dsm = Dsm::new(&config(&url, &dsm_ca), stranger.chain, &stranger.pkcs8).unwrap();
    // The stand-in's verifier rejects a chain under another CA during the handshake.
    assert!(dsm.key("data").await.is_err());
    assert_eq!(state.sessions.load(Ordering::SeqCst), 0);
}
