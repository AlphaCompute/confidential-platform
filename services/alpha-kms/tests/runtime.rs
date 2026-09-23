//! `alpha-runtime` against the in-process node acting as the keyed capture's CVM: the runtime
//! holds the capture's P-256 key, its quote source hands out the captured quote for the
//! `report_data` that CVM quoted over, and both clocks are pinned to the instant the capture's
//! nonce was minted — so `POST /v1/attest/nonce` returns that nonce and the attestation is the
//! real one (`DATABASE_URL`; skipped without it).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alpha_client::runtime::RuntimeSocket;
use alpha_client::tls::{self, Pin};
use alpha_client::{Client, Error as ClientError};
use alpha_core::{AppId, ComposeHash, KeyId, context};
use alpha_kms::{certs, rfc3339};
use alpha_runtime::{Config, Error, EvidenceSource, Exit, Runtime};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use common::*;
use p256::ecdsa::SigningKey as P256Key;
use p256::pkcs8::DecodePrivateKey;
use rcgen::PublicKeyData;
use reqwest::StatusCode;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::aws_lc_rs;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::time_provider::TimeProvider;
use rustls::{ClientConfig, ServerConfig};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use x509_parser::prelude::{FromDer, GeneralName, ParsedExtension, X509Certificate};

#[derive(Debug)]
struct PinnedTime(SystemTime);

impl TimeProvider for PinnedTime {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(
            self.0.duration_since(UNIX_EPOCH).ok()?,
        ))
    }
}

fn pinned_time(t: SystemTime) -> alpha_client::TimeProvider {
    Arc::new(PinnedTime(t))
}

async fn nonce_clock_harness() -> Option<Harness> {
    let now = nonce_minted_at(KEYED);
    harness_with_clock(Arc::new(move || now)).await
}

fn ca_spki_sha256(ca_pem: &str) -> [u8; 32] {
    tls::spki_sha256(&tls::cert_from_pem(ca_pem).unwrap()).unwrap()
}

/// The capture's quote, handed out only for the `report_data` the capture's CVM quoted over.
fn capture_evidence() -> EvidenceSource {
    let quoted: Vec<u8> = hex::decode(text(KEYED, "report_data.instance.hex").trim()).unwrap();
    Arc::new(move |report_data| {
        if report_data.as_slice() != quoted.as_slice() {
            return Err("report_data is not what the capture's CVM quoted over".into());
        }
        Ok(evidence(KEYED, "instance"))
    })
}

fn config(h: &Harness, endpoints: Vec<String>) -> Config {
    Config {
        kms_ca_spki_sha256: ca_spki_sha256(&h.ca_pem),
        kms_revisions: vec![h.node.compose_hash],
        kms_endpoints: endpoints,
    }
}

/// A runtime holding the capture's key, its clock settable by the test.
fn start_runtime(h: &Harness, config: Config) -> (Arc<Runtime>, Arc<Mutex<SystemTime>>) {
    let key = P256Key::from_pkcs8_der(&read(KEYED, "runtime.key.pkcs8.der")).unwrap();
    let clock = Arc::new(Mutex::new(h.now()));
    let shared = clock.clone();
    let runtime = Runtime::new(
        config,
        &key,
        Arc::new(move || *shared.lock().unwrap()),
        capture_evidence(),
        pinned_time(h.now()),
    )
    .unwrap();
    (runtime, clock)
}

async fn app_with_secret(
    h: &Harness,
    value: &[u8],
) -> (AppId, ComposeHash, (KeyId, ed25519_dalek::SigningKey)) {
    let admin = h.register_key(&h.root, 21).await;
    let app = AppId::mint();
    let hash = h.insert_capture_revision(app, &admin).await;
    let (status, reply) = h
        .put_secret("model-key", &[app], value, h.now(), &admin)
        .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    (app, hash, admin)
}

/// The runtime served on a unix socket, as the tenant's containers see it.
struct Socket {
    path: PathBuf,
    task: tokio::task::JoinHandle<Exit>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Socket {
    fn start(runtime: Arc<Runtime>) -> Self {
        // Short: a unix socket path is capped at 104 bytes on macOS; the random tail of the
        // UUID, not the timestamp head, keeps parallel tests apart.
        let path = std::env::temp_dir().join(format!(
            "alpha-{}.sock",
            &uuid::Uuid::now_v7().simple().to_string()[24..]
        ));
        let listener = UnixListener::bind(&path).unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(runtime.run(listener, async move {
            let _ = rx.await;
        }));
        Self {
            path,
            task,
            shutdown: Some(tx),
        }
    }

    /// One HTTP/1.1 request by hand: status and JSON body.
    async fn get(&self, route: &str) -> (u16, Value) {
        let mut stream = UnixStream::connect(&self.path).await.unwrap();
        stream
            .write_all(
                format!("GET {route} HTTP/1.1\r\nHost: alpha\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).await.unwrap();
        let reply = String::from_utf8(bytes).unwrap();
        let (head, body) = reply.split_once("\r\n\r\n").unwrap();
        let status = head.split(' ').nth(1).unwrap().parse().unwrap();
        (status, serde_json::from_str(body).unwrap_or(Value::Null))
    }

    async fn stop(mut self) -> Exit {
        let _ = self.shutdown.take().unwrap().send(());
        (&mut self.task).await.unwrap()
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[tokio::test]
async fn runtime_attests_with_the_captures_key_and_serves_the_three_routes() {
    let Some(h) = nonce_clock_harness().await else {
        return;
    };
    let (app, hash, admin) = app_with_secret(&h, b"v1").await;
    let (runtime, clock) = start_runtime(&h, config(&h, vec![h.url.clone()]));
    let attested = runtime.attest().await.unwrap();
    assert_eq!(attested.identity.compose_hash, hash);
    assert_eq!(attested.not_after, h.now() + certs::LEAF_TTL);
    let socket = Socket::start(runtime.clone());

    let (status, identity) = socket.get("/v1/identity").await;
    assert_eq!(status, 200, "{identity}");
    assert_eq!(identity["app_id"], json!(app));
    assert_eq!(identity["org_id"], json!(h.org));
    assert_eq!(identity["compose_hash"], json!(hash));
    assert_eq!(identity["attestation_result"]["verdict"], "verified");
    assert_eq!(
        identity["attestation_result"]["revision"]["compose_hash"],
        json!(hash)
    );
    let chain = identity["certificate_chain"].as_array().unwrap();
    assert_eq!(chain.len(), 2);
    assert_eq!(chain[1], json!(h.ca_pem));
    let leaf = tls::cert_from_pem(chain[0].as_str().unwrap()).unwrap();
    let sans = tls::parse_instance_sans(&tls::uri_sans(&leaf).unwrap()).unwrap();
    assert_eq!(
        (sans.org_id, sans.app_id, sans.compose_hash),
        (h.org, app, hash)
    );
    assert_eq!(
        tls::spki_of(&leaf).unwrap(),
        read(KEYED, "runtime_spki.der")
    );
    assert_eq!(
        BASE64_URL_SAFE_NO_PAD
            .decode(identity["tls_private_key"].as_str().unwrap())
            .unwrap(),
        read(KEYED, "runtime.key.pkcs8.der")
    );

    let (status, health) = socket.get("/healthz").await;
    assert_eq!(status, 200);
    assert_eq!(
        health,
        json!({ "attested": true, "cert_not_after": rfc3339(h.now() + certs::LEAF_TTL) })
    );

    // Secrets over mTLS with the leaf, cached with it: a later put is not seen until renewal.
    let (status, secret) = socket.get("/v1/secrets/model-key").await;
    assert_eq!(status, 200, "{secret}");
    assert_eq!(secret["value"], json!(b64(b"v1")));
    let (status, reply) = h
        .put_secret(
            "model-key",
            &[app],
            b"v2",
            h.now() + Duration::from_secs(1),
            &admin,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let (_, secret) = socket.get("/v1/secrets/model-key").await;
    assert_eq!(secret["value"], json!(b64(b"v1")), "cached");
    let (status, reply) = socket.get("/v1/secrets/other").await;
    assert_eq!((status, code(&reply)), (404, "not_found"), "{reply}");
    assert!(reply["error"]["request_id"].is_string());
    let (status, reply) = socket.get("/nope").await;
    assert_eq!((status, code(&reply)), (404, "not_found"));

    // Past not_after nothing is served, cache included; a renewal brings a new leaf and cache.
    *clock.lock().unwrap() = h.now() + certs::LEAF_TTL + Duration::from_secs(1);
    let (_, health) = socket.get("/healthz").await;
    assert_eq!(health["attested"], false);
    for route in ["/v1/identity", "/v1/secrets/model-key"] {
        let (status, reply) = socket.get(route).await;
        assert_eq!((status, code(&reply)), (503, "not_attested"), "{route}");
    }
    *clock.lock().unwrap() = h.now();
    runtime.attest().await.unwrap();
    let (status, secret) = socket.get("/v1/secrets/model-key").await;
    assert_eq!(status, 200, "{secret}");
    assert_eq!(secret["value"], json!(b64(b"v2")));

    assert_eq!(socket.stop().await, Exit::Drained);
    assert_eq!(Exit::Drained.code(), 0);
}

/// The tenant's backend: the KMS CA as the only root, the host name unchecked, the Revision
/// read from the leaf's SAN URI after the handshake — rustls, webpki and x509-parser only.
#[derive(Debug)]
struct CaOnly(Vec<rustls::pki_types::TrustAnchor<'static>>);

impl ServerCertVerifier for CaOnly {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        webpki::EndEntityCert::try_from(end_entity)
            .map_err(|e| rustls::Error::General(e.to_string()))?
            .verify_for_usage(
                aws_lc_rs::default_provider()
                    .signature_verification_algorithms
                    .all,
                &self.0,
                intermediates,
                now,
                webpki::KeyUsage::server_auth(),
                None,
                None,
            )
            .map_err(|e| rustls::Error::General(e.to_string()))?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn backend_client(ca_der: &[u8], now: SystemTime) -> TlsConnector {
    let anchor = webpki::anchor_from_trusted_cert(&CertificateDer::from(ca_der.to_vec()))
        .unwrap()
        .to_owned();
    let config = ClientConfig::builder_with_details(
        Arc::new(aws_lc_rs::default_provider()),
        pinned_time(now),
    )
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(CaOnly(vec![anchor])))
    .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

fn revision_san(leaf: &[u8]) -> ComposeHash {
    let (_, cert) = X509Certificate::from_der(leaf).unwrap();
    cert.extensions()
        .iter()
        .filter_map(|ext| match ext.parsed_extension() {
            ParsedExtension::SubjectAlternativeName(san) => Some(&san.general_names),
            _ => None,
        })
        .flatten()
        .find_map(|name| match name {
            GeneralName::URI(uri) => uri
                .strip_prefix("urn:alphacompute:revision:")
                .map(|h| h.parse().unwrap()),
            _ => None,
        })
        .unwrap()
}

/// A TLS listener on `chain` and `key` that answers one line and counts completed handshakes.
async fn tls_listener(
    chain: Vec<CertificateDer<'static>>,
    pkcs8: Vec<u8>,
) -> (String, Arc<AtomicUsize>) {
    let mut config = ServerConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8)))
        .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let completed = Arc::new(AtomicUsize::new(0));
    let counter = completed.clone();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            let counter = counter.clone();
            tokio::spawn(async move {
                if let Ok(mut tls) = acceptor.accept(tcp).await {
                    counter.fetch_add(1, Ordering::SeqCst);
                    let _ = tls.write_all(b"hello from the app\n").await;
                    let _ = tls.shutdown().await;
                }
            });
        }
    });
    (format!("127.0.0.1:{}", addr.port()), completed)
}

#[tokio::test]
async fn tenant_backend_pins_the_kms_ca_and_reads_the_revision_from_the_san() {
    let Some(h) = nonce_clock_harness().await else {
        return;
    };
    let (_, hash, _) = app_with_secret(&h, b"v1").await;
    let (runtime, _) = start_runtime(&h, config(&h, vec![h.url.clone()]));
    runtime.attest().await.unwrap();
    let identity = alpha_runtime::socket::identity_json(&runtime).unwrap();

    // The App terminates TLS on the key and chain from the socket.
    let chain: Vec<CertificateDer<'static>> = identity["certificate_chain"]
        .as_array()
        .unwrap()
        .iter()
        .map(|pem| tls::cert_from_pem(pem.as_str().unwrap()).unwrap())
        .collect();
    let pkcs8 = BASE64_URL_SAFE_NO_PAD
        .decode(identity["tls_private_key"].as_str().unwrap())
        .unwrap();
    let (addr, _) = tls_listener(chain, pkcs8).await;

    let ca_der = tls::cert_from_pem(&h.ca_pem).unwrap().to_vec();
    let tcp = TcpStream::connect(&addr).await.unwrap();
    let mut tls = backend_client(&ca_der, h.now())
        .connect(ServerName::try_from("app.example").unwrap(), tcp)
        .await
        .unwrap();
    let leaf = tls.get_ref().1.peer_certificates().unwrap()[0].to_vec();
    assert_eq!(revision_san(&leaf), hash);
    let mut line = String::new();
    tls.read_to_string(&mut line).await.unwrap();
    assert_eq!(line, "hello from the app\n");

    // Another CA as the root, or the leaf's own hour over, and the backend does not connect.
    let (_, other_ca) = certs::new_ca(h.now()).unwrap();
    let tcp = TcpStream::connect(&addr).await.unwrap();
    assert!(
        backend_client(&other_ca, h.now())
            .connect(ServerName::try_from("app.example").unwrap(), tcp)
            .await
            .is_err()
    );
    let tcp = TcpStream::connect(&addr).await.unwrap();
    assert!(
        backend_client(&ca_der, h.now() + certs::LEAF_TTL + Duration::from_secs(1))
            .connect(ServerName::try_from("app.example").unwrap(), tcp)
            .await
            .is_err()
    );
}

/// A tenant-shaped caller: `RuntimeSocket` for identity and a Secret over the real socket,
/// `InstanceCert` and `server_config` to serve the Endpoint, the same CA-pinned client the
/// tenant backend above uses to accept a hybrid handshake and read the Revision back off it.
#[tokio::test]
async fn a_tenant_serves_its_endpoint_with_the_runtime_identity() {
    let Some(h) = nonce_clock_harness().await else {
        return;
    };
    let (app, hash, _) = app_with_secret(&h, b"v1").await;
    let (runtime, _) = start_runtime(&h, config(&h, vec![h.url.clone()]));
    runtime.attest().await.unwrap();
    let socket = Socket::start(runtime.clone());

    let client = RuntimeSocket::at(&socket.path);
    let identity = client.identity().await.unwrap();
    assert_eq!(identity.app_id, app);
    assert_eq!(identity.compose_hash, hash);

    let secret = client.secret("model-key").await.unwrap();
    assert_eq!(secret.as_slice(), b"v1");

    let health = client.healthz().await.unwrap();
    assert!(health.attested);

    // The App terminates TLS with `InstanceCert` and `server_config` — the new helpers.
    let cert = Arc::new(tls::InstanceCert::new(&identity).unwrap());
    let acceptor = TlsAcceptor::from(tls::server_config(cert).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(tcp).await.unwrap();
        let _ = tls.write_all(b"hello from the app\n").await;
        let _ = tls.shutdown().await;
    });

    let ca_der = tls::cert_from_pem(&h.ca_pem).unwrap().to_vec();
    let tcp = TcpStream::connect(addr).await.unwrap();
    let mut tls = backend_client(&ca_der, h.now())
        .connect(ServerName::try_from("app.example").unwrap(), tcp)
        .await
        .unwrap();
    let group = tls
        .get_ref()
        .1
        .negotiated_key_exchange_group()
        .unwrap()
        .name();
    assert_eq!(group, rustls::NamedGroup::X25519MLKEM768);
    let leaf = tls.get_ref().1.peer_certificates().unwrap()[0].to_vec();
    assert_eq!(revision_san(&leaf), hash);
    let mut line = String::new();
    tls.read_to_string(&mut line).await.unwrap();
    assert_eq!(line, "hello from the app\n");

    socket.stop().await;
}

/// The App's key comes from the KMS through the socket, one derivation per purpose while the
/// leaf lasts, and it is the key the KMS derives from the organization's anchor and the App.
#[tokio::test]
async fn a_tenant_receives_its_app_key_through_the_runtime() {
    let Some(h) = nonce_clock_harness().await else {
        return;
    };
    let (app, _, _) = app_with_secret(&h, b"v1").await;
    let (runtime, _) = start_runtime(&h, config(&h, vec![h.url.clone()]));
    runtime.attest().await.unwrap();
    let socket = Socket::start(runtime.clone());

    let client = RuntimeSocket::at(&socket.path);
    let first = client.key("connectors").await.unwrap();
    let second = client.key("connectors").await.unwrap();
    assert_eq!(*first, *second);
    assert_eq!(*first, h.app_key(app, "connectors"));
    let other = client.key("other").await.unwrap();
    assert_ne!(*other, *first);
    assert_eq!(*other, h.app_key(app, "other"));
    let derived = h.audit("key.derive").await;
    assert_eq!(derived.len(), 2, "the second read is served from the cache");
    assert!(derived.iter().all(|(_, outcome, _)| outcome == "ok"));

    socket.stop().await;
}

#[tokio::test]
async fn runtime_refuses_another_ca_or_an_unlisted_revision_and_tries_the_next_endpoint() {
    let Some(h) = nonce_clock_harness().await else {
        return;
    };
    app_with_secret(&h, b"v1").await;

    // An impostor: a listener under another CA whose leaf carries the real node's Revision.
    let (other_key, other_ca) = certs::new_ca(h.now()).unwrap();
    let server_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let leaf = certs::issue_leaf(
        &certs::key_pair(&other_key).unwrap(),
        &other_ca,
        &server_key.subject_public_key_info(),
        certs::node_sans(h.node.compose_hash),
        h.now(),
    )
    .unwrap();
    let (addr, handshakes) = tls_listener(
        vec![leaf.into(), other_ca.clone().into()],
        server_key.serialize_der(),
    )
    .await;
    let impostor = format!("https://{addr}");
    let connect_error = |result: Result<Arc<alpha_runtime::Attested>, Error>| {
        let Err(err) = result else {
            panic!("the runtime attested");
        };
        assert!(matches!(err, Error::Kms(ClientError::Connect(_))), "{err}");
    };

    // Pinned to the real CA, the impostor never completes a handshake ...
    let (runtime, _) = start_runtime(&h, config(&h, vec![impostor.clone()]));
    connect_error(runtime.attest().await);
    assert_eq!(handshakes.load(Ordering::SeqCst), 0);
    // ... and is walked past to the real node.
    let (runtime, _) = start_runtime(&h, config(&h, vec![impostor.clone(), h.url.clone()]));
    runtime.attest().await.unwrap();
    assert_eq!(handshakes.load(Ordering::SeqCst), 0);

    // An Instance leaf from the real CA whose Revision is the node's own: not a node's leaf.
    let keys = h.node.intermediates().unwrap();
    let posing_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let posing_leaf = certs::issue_leaf(
        &keys.ca_key().unwrap(),
        &keys.ca_cert_der,
        &posing_key.subject_public_key_info(),
        certs::instance_sans(
            alpha_core::OrgId::mint(),
            alpha_core::AppId::mint(),
            &"0".repeat(64),
            h.node.compose_hash,
        ),
        h.now(),
    )
    .unwrap();
    let (addr, posing_handshakes) = tls_listener(
        vec![posing_leaf.into(), keys.ca_cert_der.clone().into()],
        posing_key.serialize_der(),
    )
    .await;
    let (runtime, _) = start_runtime(&h, config(&h, vec![format!("https://{addr}")]));
    connect_error(runtime.attest().await);
    assert_eq!(posing_handshakes.load(Ordering::SeqCst), 0);

    // Pinned to the impostor's CA, the handshake completes (the pin anchors on the presented
    // chain by SPKI) and the real node is the one refused.
    let mut pinned_to_impostor = config(&h, vec![impostor.clone()]);
    pinned_to_impostor.kms_ca_spki_sha256 = tls::spki_sha256(&other_ca).unwrap();
    let (runtime, _) = start_runtime(&h, pinned_to_impostor.clone());
    connect_error(runtime.attest().await);
    assert!(handshakes.load(Ordering::SeqCst) >= 1);
    pinned_to_impostor.kms_endpoints = vec![h.url.clone()];
    let (runtime, _) = start_runtime(&h, pinned_to_impostor);
    connect_error(runtime.attest().await);

    // The right CA but the node's Revision unlisted: refused before any request.
    let mut unlisted = config(&h, vec![h.url.clone()]);
    unlisted.kms_revisions = vec![alpha_core::compose_hash("other")];
    let (runtime, _) = start_runtime(&h, unlisted);
    connect_error(runtime.attest().await);
    assert_eq!(
        h.audit("attest").await.len(),
        1,
        "one attestation reached the node"
    );
}

#[tokio::test]
async fn client_certificate_validity_follows_the_time_provider() {
    let Some(h) = nonce_clock_harness().await else {
        return;
    };
    let pin = || Pin::CaSpkiAndRevisions(ca_spki_sha256(&h.ca_pem), vec![h.node.compose_hash]);
    let at = |t: SystemTime| Client::configured(vec![h.url.clone()], pin(), None, pinned_time(t));
    assert!(at(h.now()).unwrap().ready().await.is_ok());
    assert!(
        at(h.now() + certs::LEAF_TTL - Duration::from_secs(1))
            .unwrap()
            .ready()
            .await
            .is_ok()
    );
    for t in [
        h.now() - Duration::from_secs(1),
        h.now() + certs::LEAF_TTL + Duration::from_secs(1),
    ] {
        assert!(matches!(
            at(t).unwrap().ready().await.unwrap_err(),
            ClientError::Connect(_)
        ));
    }
}

#[tokio::test]
async fn revoked_revision_ends_the_runtime_with_78() {
    let Some(h) = nonce_clock_harness().await else {
        return;
    };
    let (_, hash, admin) = app_with_secret(&h, b"v1").await;
    let (runtime, _) = start_runtime(&h, config(&h, vec![h.url.clone()]));
    runtime.attest().await.unwrap();
    let mut socket = Socket::start(runtime.clone());
    let (status, _) = socket.get("/v1/secrets/model-key").await;
    assert_eq!(status, 200);

    let payload = json!({ "compose_hash": hash, "issued_at": rfc3339(h.now()) });
    let (status, reply) = h
        .post(
            &format!("/v1/revisions/{hash}/revoke"),
            h.signed(context::CONTROL, payload, &admin),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{reply}");

    // The cached secret is still served; the next call that reaches the KMS is refused and
    // the runtime ends itself.
    let (status, _) = socket.get("/v1/secrets/model-key").await;
    assert_eq!(status, 200);
    let (status, reply) = socket.get("/v1/secrets/other").await;
    assert_eq!((status, code(&reply)), (409, "revision_revoked"), "{reply}");
    assert!(runtime.is_revoked());
    let exit = (&mut socket.task).await.unwrap();
    assert_eq!(exit, Exit::Revoked);
    assert_eq!(exit.code(), 78);

    // Revoked at birth: the first attestation is the decision.
    let (runtime, _) = start_runtime(&h, config(&h, vec![h.url.clone()]));
    let Err(err) = runtime.attest().await else {
        panic!("a revoked revision attested");
    };
    assert!(err.revoked(), "{err}");
    assert_eq!(err.exit_code(), 78);
    assert!(runtime.is_revoked());
}
