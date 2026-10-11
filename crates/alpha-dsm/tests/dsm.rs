//! The client against a stand-in DSM: mTLS with the Instance leaf, one session reused across
//! keys, DSM's refusals surfaced, a DSM under any other CA never reached. The stand-in's App
//! is a trusted-CA App as `docs/fortanix-dsm-keys.md` tells the customer to configure it: the
//! KMS CA plus one DNS name of the leaf, so another App's leaf under the same CA gets nothing.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use alpha_client::tls::{
    PeerCerts, app_dns_name, certified, dns_sans, mtls_server_config, revision_dns_name, serve,
};
use alpha_core::{AppId, ComposeHash, OrgId};
use alpha_dsm::{Dsm, DsmConfig, Error};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Extension, Json, Router};
use rcgen::string::Ia5String;
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, SanType};
use rustls::crypto::CryptoProvider;
use rustls::crypto::aws_lc_rs::{self, kx_group};
use rustls::pki_types::CertificateDer;
use rustls::server::{ClientHello, ResolvesServerCert, WebPkiClientVerifier};
use rustls::sign::CertifiedKey;
use rustls::{RootCertStore, ServerConfig};
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

/// A leaf under `ca` with these SANs; `(der, pkcs8)`.
fn leaf(ca: &Ca, sans: Vec<SanType>) -> (Vec<u8>, Vec<u8>) {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.subject_alt_names = sans;
    let cert = params.signed_by(&key, &ca.issuer).unwrap();
    (cert.der().to_vec(), key.serialize_der())
}

fn uri(s: String) -> SanType {
    SanType::URI(Ia5String::try_from(s).unwrap())
}

fn dns(s: String) -> SanType {
    SanType::DnsName(Ia5String::try_from(s).unwrap())
}

/// Who an Instance leaf names.
#[derive(Clone, Copy)]
struct Who {
    org: OrgId,
    app: AppId,
    revision: ComposeHash,
}

impl Who {
    fn new(compose: &str) -> Self {
        Self {
            org: OrgId::mint(),
            app: AppId::mint(),
            revision: alpha_core::compose_hash(compose),
        }
    }

    fn app_name(&self) -> String {
        app_dns_name(self.org, self.app)
    }

    fn revision_name(&self) -> String {
        revision_dns_name(self.org, self.app, self.revision)
    }

    fn uris(&self) -> Vec<SanType> {
        vec![
            uri(format!(
                "alphacompute://{}/{}/{}",
                self.org,
                self.app,
                "ab".repeat(32)
            )),
            uri(format!("urn:alphacompute:revision:{}", self.revision)),
        ]
    }

    /// The SANs the KMS issues an Instance: the two URIs and the two DNS names derived from them.
    fn kms_sans(&self) -> Vec<SanType> {
        let mut sans = self.uris();
        sans.extend([dns(self.app_name()), dns(self.revision_name())]);
        sans
    }
}

struct InstanceKey {
    chain: Vec<Vec<u8>>,
    pkcs8: Vec<u8>,
}

fn instance(kms_ca: &Ca, sans: Vec<SanType>) -> InstanceKey {
    let (der, pkcs8) = leaf(kms_ca, sans);
    InstanceKey {
        chain: vec![der, kms_ca.der.clone()],
        pkcs8,
    }
}

#[derive(Debug)]
struct One(Arc<CertifiedKey>);

impl ResolvesServerCert for One {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

/// A DSM whose App `app-1` trusts the KMS CA (checked in the handshake) and matches one DNS name
/// of the client certificate, as a DSM trusted-CA App does.
struct StandIn {
    matches: String,
    sessions: AtomicUsize,
    requests: AtomicUsize,
}

impl StandIn {
    fn matching(name: String) -> Arc<Self> {
        Arc::new(Self {
            matches: name,
            sessions: AtomicUsize::new(0),
            requests: AtomicUsize::new(0),
        })
    }
}

async fn auth(
    State(dsm): State<Arc<StandIn>>,
    Extension(peer): Extension<PeerCerts>,
    headers: HeaderMap,
) -> impl IntoResponse {
    dsm.requests.fetch_add(1, Ordering::SeqCst);
    // "app-1:" in basic auth, and a client certificate under the KMS CA carrying the App's name.
    let basic = headers.get("authorization").and_then(|v| v.to_str().ok());
    let named = peer
        .0
        .first()
        .and_then(|leaf| dns_sans(leaf).ok())
        .is_some_and(|names| names.contains(&dsm.matches));
    if !named || basic != Some("Basic YXBwLTE6") {
        return (StatusCode::UNAUTHORIZED, Json(json!({"message": "no"}))).into_response();
    }
    dsm.sessions.fetch_add(1, Ordering::SeqCst);
    Json(json!({"token_type": "Bearer", "access_token": "t-1", "expires_in": 600, "entity_id": "app-1"}))
        .into_response()
}

async fn export(
    State(dsm): State<Arc<StandIn>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    dsm.requests.fetch_add(1, Ordering::SeqCst);
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
    stand_in_speaking(dsm_ca, kms_ca, state, Kx::Hybrid).await
}

/// What a stand-in DSM's TLS offers.
enum Kx {
    /// The platform's listener: TLS 1.3, `X25519MLKEM768` only.
    Hybrid,
    /// A DSM without ML-KEM: TLS 1.2 or 1.3 over classical X25519 only.
    ClassicalOnly,
}

async fn stand_in_speaking(dsm_ca: &Ca, kms_ca: &Ca, state: Arc<StandIn>, kx: Kx) -> String {
    let (der, pkcs8) = leaf(dsm_ca, vec![SanType::IpAddress([127, 0, 0, 1].into())]);
    let key = certified(vec![der.into(), dsm_ca.der.clone().into()], &pkcs8).unwrap();
    let kms_ca: CertificateDer<'static> = kms_ca.der.clone().into();
    let config = match kx {
        Kx::Hybrid => mtls_server_config(Arc::new(One(key)), kms_ca).unwrap(),
        Kx::ClassicalOnly => {
            let provider = Arc::new(CryptoProvider {
                kx_groups: vec![kx_group::X25519],
                ..aws_lc_rs::default_provider()
            });
            let mut roots = RootCertStore::empty();
            roots.add(kms_ca).unwrap();
            let verifier =
                WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
                    .allow_unauthenticated()
                    .build()
                    .unwrap();
            Arc::new(
                ServerConfig::builder_with_provider(provider)
                    .with_safe_default_protocol_versions()
                    .unwrap()
                    .with_client_cert_verifier(verifier)
                    .with_cert_resolver(Arc::new(One(key))),
            )
        }
    };
    let app = Router::new()
        .route("/sys/v1/session/auth", post(auth))
        .route("/crypto/v1/keys/export", post(export))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve(listener, config, app, std::future::pending()));
    format!("https://{addr}")
}

fn settings(endpoint: &str, dsm_ca: &Ca, binding: &str) -> Value {
    json!({
        "endpoint": endpoint, "app_id": "app-1", "ca_pem": dsm_ca.pem,
        "keys": {"data": {"kid": "k-1"}, "index": {"name": "idx"}},
        "binding": binding,
    })
}

fn parse(settings: &Value) -> DsmConfig {
    DsmConfig::parse(Some(&settings.to_string()))
        .unwrap()
        .unwrap()
}

fn config(endpoint: &str, dsm_ca: &Ca, binding: &str) -> DsmConfig {
    parse(&settings(endpoint, dsm_ca, binding))
}

#[tokio::test]
async fn fetches_declared_keys_over_mtls_with_one_session() {
    let (kms_ca, dsm_ca) = (ca("kms"), ca("dsm"));
    let who = Who::new("{}");
    let state = StandIn::matching(who.revision_name());
    let url = stand_in(&dsm_ca, &kms_ca, state.clone()).await;
    let me = instance(&kms_ca, who.kms_sans());
    let dsm = Dsm::new(&config(&url, &dsm_ca, "revision"), me.chain, &me.pkcs8).unwrap();
    assert_eq!(dsm.bound_name().unwrap(), who.revision_name());

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

/// X15: the KMS CA signs every organization's leaves. Another App's leaf under that same CA —
/// another tenant's, or an App AlphaCompute staff deploy as an ordinary tenant — knows the
/// customer's DSM endpoint and App uuid (both are in the plaintext compose) but does not carry
/// the name the customer's DSM App matches, so it gets no session and no key.
#[tokio::test]
async fn a_foreign_leaf_under_the_same_kms_ca_gets_no_session() {
    let (kms_ca, dsm_ca) = (ca("kms"), ca("dsm"));
    let customer = Who::new("{}");

    // Bound to the customer's Revision.
    let state = StandIn::matching(customer.revision_name());
    let url = stand_in(&dsm_ca, &kms_ca, state.clone()).await;
    let same_org_other_revision = Who {
        revision: alpha_core::compose_hash("{ }"),
        ..customer
    };
    let same_org_other_app = Who {
        app: AppId::mint(),
        ..customer
    };
    for foreign in [Who::new("{}"), same_org_other_app, same_org_other_revision] {
        for binding in ["revision", "app"] {
            let them = instance(&kms_ca, foreign.kms_sans());
            let dsm = Dsm::new(&config(&url, &dsm_ca, binding), them.chain, &them.pkcs8).unwrap();
            match dsm.key("data").await.unwrap_err() {
                Error::Refused { status, message } => {
                    assert_eq!(status, 401);
                    assert!(message.contains("session for the leaf named"), "{message}");
                }
                other => panic!("{other}"),
            }
        }
    }
    assert_eq!(state.sessions.load(Ordering::SeqCst), 0);

    // Bound to the customer's App: any Revision of it, nothing of another App.
    let state = StandIn::matching(customer.app_name());
    let url = stand_in(&dsm_ca, &kms_ca, state.clone()).await;
    let next = instance(&kms_ca, same_org_other_revision.kms_sans());
    let dsm = Dsm::new(&config(&url, &dsm_ca, "app"), next.chain, &next.pkcs8).unwrap();
    assert_eq!(&dsm.key("data").await.unwrap().value[..], KEY);
    for foreign in [Who::new("{}"), same_org_other_app] {
        let them = instance(&kms_ca, foreign.kms_sans());
        let dsm = Dsm::new(&config(&url, &dsm_ca, "app"), them.chain, &them.pkcs8).unwrap();
        assert!(matches!(
            dsm.key("data").await,
            Err(Error::Refused { status: 401, .. })
        ));
    }
    assert_eq!(state.sessions.load(Ordering::SeqCst), 1);
}

/// The client side of X15: a leaf that does not name its App and Revision as the binding needs
/// (one from a KMS that predates the DNS names, a KMS node's, or one whose DNS names are another
/// App's) is never presented, so nothing reaches even a DSM App misconfigured as CA-only.
#[tokio::test]
async fn a_leaf_a_dsm_could_check_only_against_the_ca_is_never_presented() {
    let (kms_ca, dsm_ca) = (ca("kms"), ca("dsm"));
    let who = Who::new("{}");
    let other = Who::new("{ }");
    let state = StandIn::matching(who.revision_name());
    let url = stand_in(&dsm_ca, &kms_ca, state.clone()).await;

    let mut mismatched = who.uris();
    mismatched.extend([dns(other.app_name()), dns(other.revision_name())]);
    let mut app_only = who.uris();
    app_only.push(dns(who.app_name()));
    let node = vec![
        uri("alphacompute://kms".into()),
        uri(format!("urn:alphacompute:revision:{}", who.revision)),
    ];
    for (sans, binding) in [
        (who.uris(), "revision"),
        (who.uris(), "app"),
        (mismatched.clone(), "revision"),
        (mismatched, "app"),
        (app_only, "revision"),
        (node, "app"),
    ] {
        let me = instance(&kms_ca, sans);
        let dsm = Dsm::new(&config(&url, &dsm_ca, binding), me.chain, &me.pkcs8).unwrap();
        assert!(matches!(dsm.bound_name(), Err(Error::Unbound(_))));
        assert!(matches!(dsm.key("data").await, Err(Error::Unbound(_))));
        // An undeclared name is still a 404, whatever the leaf.
        assert!(matches!(dsm.key("other").await, Err(Error::Undeclared(_))));
    }
    assert_eq!(state.requests.load(Ordering::SeqCst), 0);
}

/// Y26: key release is post-quantum by default. A DSM that cannot do the hybrid gets no
/// handshake unless the tenant's measured compose allows classical key exchange (until F6).
#[tokio::test]
async fn classical_key_exchange_only_when_the_compose_allows_it() {
    let (kms_ca, dsm_ca) = (ca("kms"), ca("dsm"));
    let who = Who::new("{}");
    let state = StandIn::matching(who.revision_name());
    let url = stand_in_speaking(&dsm_ca, &kms_ca, state.clone(), Kx::ClassicalOnly).await;

    let me = instance(&kms_ca, who.kms_sans());
    let dsm = Dsm::new(&config(&url, &dsm_ca, "revision"), me.chain, &me.pkcs8).unwrap();
    assert!(matches!(dsm.key("data").await, Err(Error::Transport(_))));
    assert_eq!(state.requests.load(Ordering::SeqCst), 0);

    let mut allowed = settings(&url, &dsm_ca, "revision");
    allowed["key_exchange"] = json!("classical-allowed");
    let me = instance(&kms_ca, who.kms_sans());
    let dsm = Dsm::new(&parse(&allowed), me.chain, &me.pkcs8).unwrap();
    assert_eq!(&dsm.key("data").await.unwrap().value[..], KEY);

    // The hybrid is still what a classical-allowed client prefers.
    let hybrid = stand_in(&dsm_ca, &kms_ca, StandIn::matching(who.revision_name())).await;
    allowed["endpoint"] = json!(hybrid);
    let me = instance(&kms_ca, who.kms_sans());
    let dsm = Dsm::new(&parse(&allowed), me.chain, &me.pkcs8).unwrap();
    assert_eq!(&dsm.key("data").await.unwrap().value[..], KEY);
}

#[tokio::test]
async fn a_dsm_under_another_ca_is_never_trusted() {
    let (kms_ca, dsm_ca, pinned) = (ca("kms"), ca("dsm"), ca("pinned"));
    let who = Who::new("{}");
    let state = StandIn::matching(who.revision_name());
    let url = stand_in(&dsm_ca, &kms_ca, state.clone()).await;
    let me = instance(&kms_ca, who.kms_sans());
    let dsm = Dsm::new(&config(&url, &pinned, "revision"), me.chain, &me.pkcs8).unwrap();
    assert!(matches!(dsm.key("data").await, Err(Error::Transport(_))));
    assert_eq!(state.requests.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn an_instance_without_a_kms_leaf_gets_no_session() {
    let (kms_ca, dsm_ca, other) = (ca("kms"), ca("dsm"), ca("other"));
    let who = Who::new("{}");
    let state = StandIn::matching(who.revision_name());
    let url = stand_in(&dsm_ca, &kms_ca, state.clone()).await;
    // The right names, under a CA that is not the KMS's.
    let stranger = instance(&other, who.kms_sans());
    let dsm = Dsm::new(
        &config(&url, &dsm_ca, "revision"),
        stranger.chain,
        &stranger.pkcs8,
    )
    .unwrap();
    // The stand-in's verifier rejects a chain under another CA during the handshake.
    assert!(dsm.key("data").await.is_err());
    assert_eq!(state.sessions.load(Ordering::SeqCst), 0);
}
