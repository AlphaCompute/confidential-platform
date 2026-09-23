//! `alpha deploy --wait` asks nothing: it hands the KMS CA to a TLS handshake and reads the
//! Revision out of the leaf the Instance presents. These serve a real Instance leaf and check
//! that the three answers are told apart.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use alpha_client::tls::cert_from_pem;
use alpha_client::{Client, Pin, Probe, probe_instance, system_time_provider};
use alpha_core::{AppId, OrgId, compose_hash};
use alpha_kms::certs;
use alpha_kms::tls::{self, ServerCert};
use rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256, PublicKeyData};

/// A listener presenting a one-hour Instance leaf for `hash`, and the CA that issued it as PEM.
async fn instance_serving(hash: alpha_core::ComposeHash) -> (String, String) {
    let now = SystemTime::now();
    let (ca_key_der, ca_cert) = certs::new_ca(now).unwrap();
    let ca_key = certs::key_pair(&ca_key_der).unwrap();
    let runtime = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let pkcs8 = runtime.serialize_der();
    let sans = certs::instance_sans(OrgId::mint(), AppId::mint(), &"ab".repeat(32), hash);
    let leaf = certs::issue_leaf(
        &ca_key,
        &ca_cert,
        &runtime.subject_public_key_info(),
        sans,
        now,
    )
    .unwrap();
    let server = ServerCert::sealed(&pkcs8, now).unwrap();
    server.serve(&pkcs8, leaf, ca_cert.clone()).unwrap();
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
    (url, pem::encode(&pem::Pem::new("CERTIFICATE", ca_cert)))
}

#[tokio::test]
async fn a_leaf_from_the_ca_naming_the_revision_is_the_verdict() {
    let hash = compose_hash("{\"name\":\"deployed\"}");
    let (url, ca_pem) = instance_serving(hash).await;
    let Probe::Attested(sans) = probe_instance(&url, &ca_pem, &hash, system_time_provider())
        .await
        .unwrap()
    else {
        panic!("the Instance serving this Revision was not recognised");
    };
    assert_eq!(sans.compose_hash, hash);
}

#[tokio::test]
async fn the_previous_revision_still_serving_is_not_a_failure() {
    let running = compose_hash("{\"name\":\"previous\"}");
    let (url, ca_pem) = instance_serving(running).await;
    let deploying = compose_hash("{\"name\":\"next\"}");
    let Probe::OtherRevision(sans) =
        probe_instance(&url, &ca_pem, &deploying, system_time_provider())
            .await
            .unwrap()
    else {
        panic!("a different Revision must be told apart from the one deployed");
    };
    assert_eq!(sans.compose_hash, running);
}

#[tokio::test]
async fn nothing_listening_is_silence_and_the_wait_ends_at_its_deadline() {
    let hash = compose_hash("{}");
    let (_, ca_pem) = instance_serving(hash).await;
    // Port 1 on loopback: nothing of ours answers there.
    let dead = "https://127.0.0.1:1";
    assert!(matches!(
        probe_instance(dead, &ca_pem, &hash, system_time_provider())
            .await
            .unwrap(),
        Probe::Silent(_)
    ));
    let message = alpha_cli::deploy::wait_for_attestation(dead, &ca_pem, hash, Duration::ZERO)
        .await
        .unwrap_err();
    assert!(message.contains("did not attest"), "{message}");
}

#[tokio::test]
async fn a_certificate_from_another_ca_is_never_a_verdict() {
    let hash = compose_hash("{}");
    let (url, _) = instance_serving(hash).await;
    let (_, other_ca) = certs::new_ca(SystemTime::now()).unwrap();
    let other_pem = pem::encode(&pem::Pem::new("CERTIFICATE", other_ca));
    assert!(matches!(
        probe_instance(&url, &other_pem, &hash, system_time_provider())
            .await
            .unwrap(),
        Probe::Silent(_)
    ));
}

/// The CA that signs node leaves also signs Instance leaves, and both carry the server-auth EKU.
/// A client that pins only the CA therefore accepts an attested tenant Instance in place of a
/// node — which, for the admin's client, would hand it a secret value. The admin pin names the
/// KMS identity and the allowed node Revisions for exactly that reason.
#[tokio::test]
async fn the_admin_pin_refuses_an_instance_standing_in_for_a_node() {
    let hash = compose_hash("{\"name\":\"a tenant app\"}");
    let (url, ca_pem) = instance_serving(hash).await;
    let ca = cert_from_pem(&ca_pem).unwrap();

    // Pinning the CA alone: the handshake completes and the Instance answers the request, so the
    // failure is the 404 of a route it does not serve, not the certificate.
    let ca_only = Client::new(vec![url.clone()], Pin::Ca(ca.clone())).unwrap();
    assert!(
        matches!(ca_only.ready().await, Err(alpha_client::Error::Invalid(_))),
        "an Instance leaf passes a CA-only pin, which is what makes the admin pin necessary"
    );

    // The admin's pin: the same certificate never gets to answer.
    let admin = Client::new(vec![url], Pin::CaAndRevisions(ca, vec![hash])).unwrap();
    assert!(
        matches!(admin.ready().await, Err(alpha_client::Error::Connect(_))),
        "an Instance leaf must be refused during the handshake"
    );
}
