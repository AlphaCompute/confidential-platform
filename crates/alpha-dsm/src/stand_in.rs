//! A stand-in for our own DSM, for tests here and in alpha-kms (feature `stand-in`): one App
//! with one API key, an AES-256 key and an Ed25519 key, the four calls [`crate::OwnDsm`] makes,
//! TLS 1.3 with the hybrid only, and switches to disable the keys or the App as a DSM admin
//! would.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::result_large_err
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use alpha_client::tls::{certified, mtls_server_config, serve};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use ed25519_dalek::Signer;
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, SanType};
use serde_json::{Value, json};

pub const API_KEY: &str = "c3RhbmQtaW46YXBwLXNlY3JldA";
pub const AES_KEY: &str = "kms-root-cofactor";
pub const SIGNING_KEY: &str = "release-ed25519";

pub struct StandIn {
    aes: [u8; 32],
    signing: ed25519_dalek::SigningKey,
    ivs: AtomicU64,
    sessions: AtomicUsize,
    /// Every crypto call answers 403, as a DSM whose admin disabled the keys.
    pub disabled: AtomicBool,
    /// Signing answers with another key's signature, as a misconfigured DSM key would.
    pub wrong_signer: AtomicBool,
    pub calls: AtomicUsize,
}

impl StandIn {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            aes: [0x42; 32],
            signing: ed25519_dalek::SigningKey::from_bytes(&[0x17; 32]),
            ivs: AtomicU64::new(1),
            sessions: AtomicUsize::new(0),
            disabled: AtomicBool::new(false),
            wrong_signer: AtomicBool::new(false),
            calls: AtomicUsize::new(0),
        })
    }

    pub fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.signing.verifying_key()
    }

    /// Serves on loopback under a fresh CA; returns `(endpoint, ca_pem)`.
    pub async fn serve(self: &Arc<Self>) -> (String, String) {
        let ca_key = KeyPair::generate().unwrap();
        let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_cert = ca.self_signed(&ca_key).unwrap();
        let issuer = Issuer::new(ca, ca_key);
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.subject_alt_names = vec![SanType::IpAddress([127, 0, 0, 1].into())];
        let cert = params.signed_by(&key, &issuer).unwrap();
        let certified = certified(
            vec![cert.der().clone(), ca_cert.der().clone()],
            &key.serialize_der(),
        )
        .unwrap();
        let config = mtls_server_config(Arc::new(One(certified)), ca_cert.der().clone()).unwrap();
        let app = Router::new()
            .route("/sys/v1/session/auth", post(auth))
            .route("/crypto/v1/encrypt", post(encrypt))
            .route("/crypto/v1/decrypt", post(decrypt))
            .route("/crypto/v1/sign", post(sign))
            .with_state(self.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, config, app, std::future::pending()));
        (format!("https://{addr}"), ca_cert.pem())
    }

    pub fn config(endpoint: &str, ca_pem: &str, key: &str) -> crate::OwnDsmConfig {
        crate::OwnDsmConfig {
            endpoint: endpoint.into(),
            ca_pem: ca_pem.into(),
            key: crate::KeyRef::Name(key.into()),
            key_exchange: crate::KeyExchange::Hybrid,
        }
    }
}

#[derive(Debug)]
struct One(Arc<rustls::sign::CertifiedKey>);

impl rustls::server::ResolvesServerCert for One {
    fn resolve(
        &self,
        _: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(self.0.clone())
    }
}

fn b64(bytes: &[u8]) -> String {
    BASE64_STANDARD.encode(bytes)
}

fn field(body: &Value, name: &str) -> Option<Vec<u8>> {
    body.get(name)
        .and_then(Value::as_str)
        .and_then(|s| BASE64_STANDARD.decode(s).ok())
}

fn refused(status: StatusCode, message: &str) -> Response {
    (status, message.to_owned()).into_response()
}

async fn auth(State(dsm): State<Arc<StandIn>>, headers: HeaderMap) -> Response {
    let basic = headers.get("authorization").and_then(|v| v.to_str().ok());
    if basic != Some(&format!("Basic {API_KEY}")) {
        return refused(StatusCode::UNAUTHORIZED, "bad API key");
    }
    let n = dsm.sessions.fetch_add(1, Ordering::SeqCst) + 1;
    Json(json!({"token_type": "Bearer", "access_token": format!("t-{n}"), "expires_in": 600, "entity_id": "app"}))
        .into_response()
}

/// The checks every crypto call shares: a live token, the keys enabled, the named object.
fn admit(dsm: &StandIn, headers: &HeaderMap, body: &Value, key: &str) -> Result<(), Response> {
    dsm.calls.fetch_add(1, Ordering::SeqCst);
    let live = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("Bearer t-"));
    if !live {
        return Err(refused(StatusCode::UNAUTHORIZED, "no session"));
    }
    if dsm.disabled.load(Ordering::SeqCst) {
        return Err(refused(
            StatusCode::FORBIDDEN,
            "security object is disabled",
        ));
    }
    if body["key"] != json!({ "name": key }) {
        return Err(refused(StatusCode::NOT_FOUND, "no such security object"));
    }
    Ok(())
}

fn gcm_ok(body: &Value) -> bool {
    body["alg"] == "AES" && body["mode"] == "GCM" && body["tag_len"] == 128
}

async fn encrypt(
    State(dsm): State<Arc<StandIn>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if let Err(r) = admit(&dsm, &headers, &body, AES_KEY) {
        return r;
    }
    let (Some(plain), Some(ad), true) = (field(&body, "plain"), field(&body, "ad"), gcm_ok(&body))
    else {
        return refused(StatusCode::BAD_REQUEST, "bad encrypt request");
    };
    let mut iv = [0u8; 12];
    iv[4..].copy_from_slice(&dsm.ivs.fetch_add(1, Ordering::SeqCst).to_be_bytes());
    let sealed = Aes256Gcm::new_from_slice(&dsm.aes)
        .unwrap()
        .encrypt(
            &Nonce::try_from(&iv[..]).unwrap(),
            Payload {
                msg: &plain,
                aad: &ad,
            },
        )
        .unwrap();
    let (cipher, tag) = sealed.split_at(sealed.len() - 16);
    Json(json!({"kid": "aes-kid", "cipher": b64(cipher), "iv": b64(&iv), "tag": b64(tag)}))
        .into_response()
}

async fn decrypt(
    State(dsm): State<Arc<StandIn>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if let Err(r) = admit(&dsm, &headers, &body, AES_KEY) {
        return r;
    }
    let (Some(cipher), Some(iv), Some(tag), Some(ad), true) = (
        field(&body, "cipher"),
        field(&body, "iv"),
        field(&body, "tag"),
        field(&body, "ad"),
        gcm_ok(&body),
    ) else {
        return refused(StatusCode::BAD_REQUEST, "bad decrypt request");
    };
    let Ok(nonce) = Nonce::try_from(iv.as_slice()) else {
        return refused(StatusCode::BAD_REQUEST, "bad iv");
    };
    let sealed = [cipher, tag].concat();
    match Aes256Gcm::new_from_slice(&dsm.aes).unwrap().decrypt(
        &nonce,
        Payload {
            msg: &sealed,
            aad: &ad,
        },
    ) {
        Ok(plain) => Json(json!({"kid": "aes-kid", "plain": b64(&plain)})).into_response(),
        Err(_) => refused(StatusCode::BAD_REQUEST, "tag does not verify"),
    }
}

async fn sign(
    State(dsm): State<Arc<StandIn>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if let Err(r) = admit(&dsm, &headers, &body, SIGNING_KEY) {
        return r;
    }
    let (Some(data), true) = (field(&body, "data"), body["hash_alg"] == "SHA512") else {
        return refused(StatusCode::BAD_REQUEST, "bad sign request");
    };
    let key = if dsm.wrong_signer.load(Ordering::SeqCst) {
        ed25519_dalek::SigningKey::from_bytes(&[0x18; 32])
    } else {
        dsm.signing.clone()
    };
    Json(json!({"kid": "ed-kid", "signature": b64(&key.sign(&data).to_bytes())})).into_response()
}
