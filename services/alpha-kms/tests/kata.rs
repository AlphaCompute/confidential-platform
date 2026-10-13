//! Revisions of Kata init-data, and leaves for the Kata TDX pods that boot with them, against a
//! quote taken on our B300 over a fixed runtime key and a nonce of the test nonce key.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use alpha_attest::KATA_EVIDENCE_FORMAT;
use alpha_core::{AppId, ComposeHash, InitData, KeyId, compose_hash, context};
use alpha_kms::{certs, platform, rfc3339};
use common::*;
use ed25519_dalek::SigningKey;
use reqwest::StatusCode;
use serde_json::{Value, json};

fn t1() -> String {
    text(KATA, "t1-sha256.toml")
}

fn t1_digest() -> ComposeHash {
    InitData::parse(t1()).unwrap().digest()
}

fn registration(app: AppId, init_data: &str, digest: ComposeHash) -> Value {
    json!({ "app_id": app, "init_data": init_data, "digest": digest })
}

async fn register(h: &Harness, app: AppId, signer: &(KeyId, SigningKey)) -> (StatusCode, Value) {
    h.post(
        "/v1/revisions",
        h.signed(
            context::REVISION,
            registration(app, &t1(), t1_digest()),
            signer,
        ),
    )
    .await
}

fn attest_body(quote: &str, spki: &[u8]) -> Value {
    json!({
        "runtime_pubkey": b64(spki),
        "nonce": b64(&read(KATA, "nonce.bin")),
        "evidence": { "format": KATA_EVIDENCE_FORMAT, "quote": b64(&read(KATA, quote)) },
    })
}

async fn attest(h: &Harness, quote: &str) -> (StatusCode, Value) {
    h.post(
        "/v1/attest",
        attest_body(quote, &read(KATA, "runtime_spki.der")),
    )
    .await
}

/// Serves `change`d reference values as the next document version.
async fn republish(h: &Harness, change: impl FnOnce(&mut Value)) {
    let mut document = h.release.document.read().unwrap().clone();
    document["version"] = json!(document["version"].as_u64().unwrap() + 1);
    change(&mut document["kata_reference_values"]);
    h.release.set(document);
    platform::reload(&h.node).await.unwrap();
}

#[tokio::test]
async fn an_init_data_revision_is_registered_as_signed() {
    let Some(h) = kata_harness().await else {
        return;
    };
    let admin = h.register_key(&h.root, 31).await;
    let app = AppId::mint();

    let (status, reply) = register(&h, app, &admin).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["compose_hash"], json!(t1_digest()));
    assert_eq!(reply["app_id"], json!(app));
    assert_eq!(reply["org_id"], json!(h.org));
    let digest = t1_digest();
    let row = sqlx::query!(
        "select compose, init_data from revisions where compose_hash = $1",
        digest.as_bytes().as_slice()
    )
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert_eq!((row.compose, row.init_data), (None, Some(t1())));

    let off_by_one = t1().replace("probe A", "probe B");
    let refusals = [
        (
            registration(app, "not toml", compose_hash("not toml")),
            "TOML",
        ),
        (registration(app, &off_by_one, t1_digest()), "digest"),
        (
            json!({ "app_id": app, "init_data": t1(), "digest": t1_digest(), "compose": "{}" }),
            "unknown field",
        ),
    ];
    for (payload, fragment) in refusals {
        let (status, reply) = h
            .post(
                "/v1/revisions",
                h.signed(context::REVISION, payload, &admin),
            )
            .await;
        assert_eq!(
            (status, code(&reply)),
            (StatusCode::BAD_REQUEST, "malformed")
        );
        assert!(
            reply["error"]["message"]
                .as_str()
                .unwrap()
                .contains(fragment),
            "{reply}"
        );
    }

    let other_app = AppId::mint();
    let mut unsigned = h.signed(
        context::REVISION,
        registration(other_app, &off_by_one, compose_hash(&off_by_one)),
        &admin,
    );
    unsigned["payload"]["init_data"] = json!(off_by_one.replace("probe B", "probe C"));
    unsigned["payload"]["digest"] = json!(compose_hash(&off_by_one.replace("probe B", "probe C")));
    let (status, reply) = h.post("/v1/revisions", unsigned).await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::BAD_REQUEST, "signature_invalid")
    );
}

#[tokio::test]
async fn a_kata_pod_gets_a_leaf_naming_the_revision_in_its_mrconfigid() {
    let Some(h) = kata_harness().await else {
        return;
    };
    let admin = h.register_key(&h.root, 32).await;
    let app = AppId::mint();

    let (status, reply) = attest(&h, "k1-sha256.quote.bin").await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::FORBIDDEN, "attestation_unknown"),
        "{reply}"
    );
    assert!(
        reply["error"]["message"]
            .as_str()
            .unwrap()
            .contains(&t1_digest().to_string())
    );

    let (status, reply) = register(&h, app, &admin).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let (status, reply) = attest(&h, "k1-sha256.quote.bin").await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let result = &reply["attestation_result"];
    assert_eq!(result["verdict"], "verified");
    assert_eq!(result["os_image"], "kata-qemu-tdx");
    assert_eq!(
        result["revision"],
        json!({ "compose_hash": t1_digest(), "app_id": app, "org_id": h.org })
    );
    let runtime_sha = alpha_kms::keys::sha256_hex(&read(KATA, "runtime_spki.der"));
    assert_eq!(
        result["runtime_pubkey_sha256"],
        format!("sha256:{runtime_sha}")
    );
    assert_eq!(reply["not_after"], rfc3339(h.now() + certs::LEAF_TTL));
    let leaf =
        <rustls::pki_types::CertificateDer as rustls::pki_types::pem::PemObject>::from_pem_slice(
            reply["certificate_chain"][0].as_str().unwrap().as_bytes(),
        )
        .unwrap();
    assert_eq!(
        certs::uri_sans(&leaf).unwrap(),
        [
            format!("alphacompute://{}/{app}/{runtime_sha}", h.org),
            format!("urn:alphacompute:revision:{}", t1_digest()),
        ]
    );
    let audited = h.audit("attest").await;
    assert!(
        audited
            .iter()
            .any(|(_, o, d)| o == "ok" && d["os_image"] == "kata-qemu-tdx")
    );

    // The runtime key the quote binds is the P-256 scalar 0x4b repeated.
    let (status, put) = h
        .put_secret("model-key", &[app], b"for the pod", h.now(), &admin)
        .await;
    assert_eq!(status, StatusCode::OK, "{put}");
    let key_pem = {
        use p256::pkcs8::EncodePrivateKey;
        p256::SecretKey::from_bytes(&[0x4b; 32].into())
            .unwrap()
            .to_pkcs8_pem(Default::default())
            .unwrap()
    };
    let pod = client_with(&format!(
        "{}{}",
        key_pem.as_str(),
        reply["certificate_chain"][0].as_str().unwrap()
    ));
    let (status, secret) = send(pod.get(format!("{}/v1/secrets/model-key", h.url))).await;
    assert_eq!(status, StatusCode::OK, "{secret}");
    assert_eq!(secret["value"], json!(b64(b"for the pod")));

    let other = p256::SecretKey::from_bytes(&[0x4c; 32].into()).unwrap();
    let other_spki = {
        use p256::pkcs8::EncodePublicKey;
        other.public_key().to_public_key_der().unwrap().into_vec()
    };
    let (status, reply) = h
        .post(
            "/v1/attest",
            attest_body("k1-sha256.quote.bin", &other_spki),
        )
        .await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::FORBIDDEN, "attestation_failed")
    );
    assert!(
        reply["error"]["message"]
            .as_str()
            .unwrap()
            .contains("report_data")
    );

    let mut dstack = attest_body("k1-sha256.quote.bin", &read(KATA, "runtime_spki.der"));
    dstack["evidence"]["event_log"] = json!([]);
    let (status, reply) = h.post("/v1/attest", dstack).await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::BAD_REQUEST, "malformed"),
        "{reply}"
    );
}

#[tokio::test]
async fn a_class_passing_gpus_through_gets_no_leaf() {
    let Some(h) = kata_harness().await else {
        return;
    };
    let admin = h.register_key(&h.root, 34).await;
    register(&h, AppId::mint(), &admin).await;
    republish(&h, |classes| classes[0]["gpu"] = json!(true)).await;
    let (status, reply) = attest(&h, "k1-sha256.quote.bin").await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::FORBIDDEN, "policy_denied")
    );
    assert!(
        reply["error"]["message"].as_str().unwrap().contains("GPU"),
        "{reply}"
    );
}

#[tokio::test]
async fn a_revoked_init_data_revision_gets_no_leaf() {
    let Some(h) = kata_harness().await else {
        return;
    };
    let admin = h.register_key(&h.root, 35).await;
    register(&h, AppId::mint(), &admin).await;
    let payload = json!({ "compose_hash": t1_digest(), "issued_at": rfc3339(h.now()) });
    let (status, reply) = h
        .post(
            &format!("/v1/revisions/{}/revoke", t1_digest()),
            h.signed(context::CONTROL, payload, &admin),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let (status, reply) = attest(&h, "k1-sha256.quote.bin").await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::CONFLICT, "revision_revoked")
    );
}

#[tokio::test]
async fn a_compose_revision_is_not_an_init_data_one() {
    let Some(h) = kata_harness().await else {
        return;
    };
    let admin = h.register_key(&h.root, 36).await;
    let app = AppId::mint();
    let document = json!({ "app_id": app, "compose": t1() });
    let signature = h.signed(context::REVISION, document, &admin)["signature"].clone();
    let hash = h
        .insert_signed_revision(h.org, app, t1(), admin.0, signature)
        .await;
    assert_eq!(hash, t1_digest());
    let (status, reply) = attest(&h, "k1-sha256.quote.bin").await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::FORBIDDEN, "attestation_unknown")
    );
}
