//! The KBS routes a guest's data hub calls for its registry credential, on a Kata node with the
//! B300 capture's collateral and clock.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit};
use alpha_core::{AppId, ComposeHash, InitData, context};
use alpha_kms::kbs::{self, Claims};
use alpha_kms::rfc3339;
use base64::Engine;
use base64::prelude::{BASE64_STANDARD, BASE64_URL_SAFE_NO_PAD};
use common::*;
use reqwest::StatusCode;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const VALUE: &[u8] = br#"{"auths":{"registry.example":{"auth":"dXNlcjpwYXNz"}}}"#;

fn kata_app() -> AppId {
    "0199e000-0000-7000-8000-00000000a11d".parse().unwrap()
}

fn tee_secret() -> p256::SecretKey {
    p256::SecretKey::from_bytes(&[0x11u8; 32].into()).unwrap()
}

fn tee_pubkey() -> Value {
    let point = tee_secret().public_key().to_sec1_bytes();
    json!({
        "kty": "EC", "crv": "P-256", "alg": "ECDH-ES+A256KW",
        "x": b64(&point[1..33]), "y": b64(&point[33..]),
    })
}

/// The B300 capture's init-data with the registry credential `regcred` under the document's CA.
fn init_data(h: &Harness) -> String {
    let ca = h.release.document.read().unwrap()["kms_ca_pem"]
        .as_str()
        .unwrap()
        .to_owned();
    let (aa, cdh) = alpha_core::registry_auth("regcred", &ca);
    text(KATA, "k3-app.toml").replace(
        "[data]\n",
        &format!("[data]\n\"aa.toml\" = '''\n{aa}'''\n\"cdh.toml\" = '''\n{cdh}'''\n"),
    )
}

async fn register(
    h: &Harness,
    admin: &(alpha_core::KeyId, ed25519_dalek::SigningKey),
) -> ComposeHash {
    let init_data = init_data(h);
    let digest = InitData::parse(init_data.clone()).unwrap().digest();
    let payload = json!({ "app_id": kata_app(), "init_data": init_data, "digest": digest });
    let (status, reply) = h
        .post("/v1/revisions", h.signed(context::REVISION, payload, admin))
        .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    digest
}

/// A token of the KMS that expires `ttl` seconds from now.
fn token(h: &Harness, revision: ComposeHash, ttl: u64) -> String {
    let claims: Claims = serde_json::from_value(json!({
        "exp": h.now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + ttl,
        "org_id": h.org, "revision": revision,
        "tee-pubkey": tee_pubkey(),
    }))
    .unwrap();
    kbs::issue_token(&h.node.intermediates().unwrap().tenant_kek_root, &claims).unwrap()
}

async fn resource(h: &Harness, path: &str, bearer: Option<&str>) -> (StatusCode, Value) {
    let mut request = client().get(format!("{}/kbs/v0/resource/{path}", h.url));
    if let Some(bearer) = bearer {
        request = request.bearer_auth(bearer);
    }
    send(request).await
}

/// Opens the JWE as the guest does: ECDH-ES with Concat KDF, AES key unwrap, A256GCM over the
/// protected header.
fn open(jwe: &Value) -> Vec<u8> {
    let field = |k: &str| {
        BASE64_URL_SAFE_NO_PAD
            .decode(jwe[k].as_str().unwrap())
            .unwrap()
    };
    let header: Value = serde_json::from_slice(&field("protected")).unwrap();
    assert_eq!(
        (&header["alg"], &header["enc"]),
        (&json!("ECDH-ES+A256KW"), &json!("A256GCM"))
    );
    let coordinate = |k: &str| {
        BASE64_URL_SAFE_NO_PAD
            .decode(header["epk"][k].as_str().unwrap())
            .unwrap()
    };
    let epk = p256::PublicKey::from_sec1_bytes(
        &[&[4u8][..], &coordinate("x"), &coordinate("y")].concat(),
    )
    .unwrap();
    let z = p256::ecdh::diffie_hellman(tee_secret().to_nonzero_scalar(), epk.as_affine());
    let kek = Sha256::new()
        .chain_update(1u32.to_be_bytes())
        .chain_update(z.raw_secret_bytes())
        .chain_update(14u32.to_be_bytes())
        .chain_update(b"ECDH-ES+A256KW")
        .chain_update([0u8; 8])
        .chain_update(256u32.to_be_bytes())
        .finalize();
    let mut cek = [0u8; 32];
    aes_kw::KwAes256::new(&kek)
        .unwrap_key(&field("encrypted_key"), &mut cek)
        .unwrap();
    let sealed = [field("ciphertext"), field("tag")].concat();
    let iv: [u8; 12] = field("iv").try_into().unwrap();
    Aes256Gcm::new(&cek.into())
        .decrypt(
            &iv.into(),
            Payload {
                msg: &sealed,
                aad: jwe["protected"].as_str().unwrap().as_bytes(),
            },
        )
        .unwrap()
}

#[tokio::test]
async fn a_token_fetches_the_revisions_registry_credential_and_nothing_else() {
    let Some(h) = kata_harness().await else {
        return;
    };
    let admin = h.register_key(&h.root, 41).await;
    let revision = register(&h, &admin).await;
    let bearer = token(&h, revision, 300);

    let (status, reply) = resource(&h, "alpha/secret/regcred", Some(&bearer)).await;
    assert_eq!(
        (status, reply["type"].as_str()),
        (StatusCode::NOT_FOUND, Some("not_found")),
        "{reply}"
    );

    let (status, put) = h
        .put_secret("regcred", &[kata_app()], VALUE, h.now(), &admin)
        .await;
    assert_eq!(status, StatusCode::OK, "{put}");
    let (status, other) = h
        .put_secret(
            "other",
            &[kata_app()],
            b"not for the data hub",
            h.now(),
            &admin,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{other}");

    let (status, jwe) = resource(&h, "alpha/secret/regcred", Some(&bearer)).await;
    assert_eq!(status, StatusCode::OK, "{jwe}");
    assert_eq!(open(&jwe), VALUE);

    for path in [
        "alpha/secret/other",
        "default/secret/regcred",
        "alpha/credential/regcred",
    ] {
        let (status, reply) = resource(&h, path, Some(&bearer)).await;
        assert_eq!(
            (status, reply["type"].as_str()),
            (StatusCode::NOT_FOUND, Some("not_found")),
            "{path}: {reply}"
        );
    }
    let expired = token(&h, revision, 0);
    for bearer in [None, Some(expired.as_str()), Some("a.b.c")] {
        let (status, reply) = resource(&h, "alpha/secret/regcred", bearer).await;
        assert_eq!(
            (status, reply["type"].as_str()),
            (StatusCode::UNAUTHORIZED, Some("token_invalid")),
            "{reply}"
        );
    }
    let audited = h.audit("kbs.resource").await;
    assert!(audited.iter().any(|(_, outcome, _)| outcome == "ok"));

    let payload = json!({ "compose_hash": revision, "issued_at": rfc3339(h.now()) });
    let (status, reply) = h
        .post(
            &format!("/v1/revisions/{revision}/revoke"),
            h.signed(context::CONTROL, payload, &admin),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let (status, reply) = resource(&h, "alpha/secret/regcred", Some(&bearer)).await;
    assert_eq!(
        (status, reply["type"].as_str()),
        (StatusCode::CONFLICT, Some("revision_revoked"))
    );
}

#[tokio::test]
async fn attest_binds_the_quote_to_the_nonce_and_tee_key_of_the_handshake() {
    let Some(h) = kata_harness().await else {
        return;
    };
    let (status, reply) = h
        .post(
            "/kbs/v0/auth",
            json!({ "version": "0.3.0", "tee": "tdx", "extra-params": {} }),
        )
        .await;
    assert_eq!(
        (status, reply["type"].as_str()),
        (StatusCode::BAD_REQUEST, Some("malformed"))
    );
    let request = json!({
        "version": "0.4.0", "tee": "tdx",
        "extra-params": { "supported-hash-algorithms": ["sha384", "sha256"] },
    });
    let (status, challenge) = h.post("/kbs/v0/auth", request).await;
    assert_eq!(status, StatusCode::OK, "{challenge}");
    assert_eq!(
        challenge["extra-params"]["selected-hash-algorithm"],
        "sha384"
    );
    let nonce = challenge["nonce"].as_str().unwrap();

    let attestation = |nonce: &str, tee_pubkey: Value| {
        json!({
            "init-data": { "format": "toml", "body": text(KATA, "k3-app.toml") },
            "runtime-data": { "nonce": nonce, "tee-pubkey": tee_pubkey },
            "tee-evidence": {
                "primary_evidence": { "quote": BASE64_STANDARD.encode(read(KATA, "k3-app.quote.bin")), "cc_eventlog": null },
                "additional_evidence": "",
            },
        })
    };
    // The capture's quote binds a runtime key, not this handshake.
    let (status, reply) = h
        .post("/kbs/v0/attest", attestation(nonce, tee_pubkey()))
        .await;
    assert_eq!(
        (status, reply["type"].as_str()),
        (StatusCode::FORBIDDEN, Some("attestation_failed")),
        "{reply}"
    );
    assert!(
        reply["detail"].as_str().unwrap().contains("report_data"),
        "{reply}"
    );

    let mut forged = BASE64_URL_SAFE_NO_PAD.decode(nonce).unwrap();
    forged[31] ^= 1;
    let (status, reply) = h
        .post("/kbs/v0/attest", attestation(&b64(&forged), tee_pubkey()))
        .await;
    assert_eq!(
        (status, reply["type"].as_str()),
        (StatusCode::BAD_REQUEST, Some("nonce_invalid"))
    );

    let mut rsa = tee_pubkey();
    rsa["kty"] = json!("RSA");
    let (status, reply) = h.post("/kbs/v0/attest", attestation(nonce, rsa)).await;
    assert_eq!(
        (status, reply["type"].as_str()),
        (StatusCode::BAD_REQUEST, Some("malformed"))
    );

    let audited = h.audit("kbs.attest").await;
    assert_eq!(audited.len(), 3);
    assert!(audited.iter().all(|(_, outcome, _)| outcome == "denied"));
}
