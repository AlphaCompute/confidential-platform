//! `alpha instances` against a stand-in shroud-go whose copies serve real Instance leaves: a
//! copy counts as attested only when its own handshake names the Revision.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use alpha_cli::deploy::Shroud;
use alpha_cli::instances;
use alpha_core::{AppId, ComposeHash, OrgId, compose_hash};
use alpha_kms::certs;
use alpha_kms::tls::{self, ServerCert};
use axum::http::{HeaderMap, Method, Uri};
use rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256, PublicKeyData};
use serde_json::{Value, json};

const API_KEY: &str = "sk_test_organization";

struct Ca {
    key_der: Vec<u8>,
    cert: Vec<u8>,
}

impl Ca {
    fn new() -> Self {
        let (key_der, cert) = certs::new_ca(SystemTime::now()).unwrap();
        Self { key_der, cert }
    }

    fn pem(&self) -> String {
        pem::encode(&pem::Pem::new("CERTIFICATE", self.cert.clone()))
    }

    /// A listener presenting a one-hour Instance leaf for `hash` issued by this CA.
    async fn instance_serving(&self, hash: ComposeHash) -> String {
        let now = SystemTime::now();
        let ca_key = certs::key_pair(&self.key_der).unwrap();
        let runtime = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let pkcs8 = runtime.serialize_der();
        let sans = certs::instance_sans(OrgId::mint(), AppId::mint(), &"ab".repeat(32), hash);
        let leaf = certs::issue_leaf(
            &ca_key,
            &self.cert,
            &runtime.subject_public_key_info(),
            sans,
            now,
        )
        .unwrap();
        let server = ServerCert::sealed(&pkcs8, now).unwrap();
        server.serve(&pkcs8, leaf, self.cert.clone()).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("https://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            alpha_client::tls::serve(
                listener,
                tls::server_config(Arc::new(server)).unwrap(),
                axum::Router::new(),
                std::future::pending::<()>(),
            )
            .await
        });
        url
    }
}

fn copy(app: AppId, hash: ComposeHash, url: &str) -> Value {
    json!({
        "id": "0199a1b2-0000-7000-8000-000000000001",
        "app_id": app.to_string(),
        "compose_hash": hash.to_string(),
        "url": url,
        "resources": { "cpu": 2, "memory_mib": 4096 },
        "state": "running",
        "started_at": "2026-09-25T10:00:00Z",
        "drain_deadline": null,
        "stopped_at": null,
    })
}

/// Every request as `METHOD path?query authorization body`.
type Seen = Arc<Mutex<Vec<String>>>;

/// shroud-go's instance routes: a list holding `copy`, and `copy` as the answer to anything else.
async fn shroud(copy: Value) -> (Shroud, Seen) {
    let seen = Seen::default();
    let recorded = seen.clone();
    let app = axum::Router::new().fallback(
        move |method: Method, uri: Uri, headers: HeaderMap, body: String| {
            let (seen, copy) = (recorded.clone(), copy.clone());
            async move {
                let auth = headers
                    .get("authorization")
                    .map(|v| v.to_str().unwrap().to_owned())
                    .unwrap_or_default();
                seen.lock()
                    .unwrap()
                    .push(format!("{method} {uri} {auth} {body}"));
                axum::Json(match method {
                    Method::GET => json!({ "instances": [copy] }),
                    _ => copy,
                })
            }
        },
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await });
    let shroud = Shroud {
        url,
        api_key: API_KEY.into(),
    };
    (shroud, seen)
}

#[tokio::test]
async fn add_waits_for_the_new_copy_to_attest() {
    let ca = Ca::new();
    let app = AppId::mint();
    let hash = compose_hash("{\"name\":\"worker\"}");
    let url = ca.instance_serving(hash).await;
    let (shroud, seen) = shroud(copy(app, hash, &url)).await;

    let out = instances::add(
        &shroud,
        app,
        Some(json!({ "cpu": 2, "memory_mib": 4096 })),
        Some((Duration::from_secs(10), &ca.pem())),
    )
    .await
    .unwrap();

    assert_eq!(out["attested"]["compose_hash"], hash.to_string());
    assert_eq!(out["attested"]["url"], url);
    assert_eq!(out["instance"]["url"], url);
    assert_eq!(
        *seen.lock().unwrap(),
        [format!(
            "POST /v1/apps/{app}/instances Bearer {API_KEY} {{\"resources\":{{\"cpu\":2,\"memory_mib\":4096}}}}"
        )]
    );
}

#[tokio::test]
async fn add_refuses_a_copy_that_attests_another_revision() {
    let ca = Ca::new();
    let app = AppId::mint();
    let claimed = compose_hash("{\"name\":\"worker\"}");
    let served = compose_hash("{\"name\":\"something else\"}");
    let url = ca.instance_serving(served).await;
    let (shroud, _) = shroud(copy(app, claimed, &url)).await;

    let message = instances::add(&shroud, app, None, Some((Duration::ZERO, &ca.pem())))
        .await
        .unwrap_err();

    assert!(message.contains("did not attest"), "{message}");
    assert!(message.contains(&served.to_string()), "{message}");
}

#[tokio::test]
async fn list_prints_the_copies_and_sends_the_key() {
    let app = AppId::mint();
    let hash = compose_hash("{}");
    let listed = copy(app, hash, "https://copy.example");
    let (shroud, seen) = shroud(listed.clone()).await;

    let out = instances::list(&shroud, app).await.unwrap();

    assert_eq!(out, json!({ "instances": [listed] }));
    assert_eq!(
        *seen.lock().unwrap(),
        [format!("GET /v1/apps/{app}/instances Bearer {API_KEY} ")]
    );
}
