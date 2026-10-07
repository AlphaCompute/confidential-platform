#![cfg(target_arch = "wasm32")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::collections::BTreeMap;

use alpha_channel::handshake;
use alpha_channel::secret::{self, Sealed};
use alpha_channel::wasm::{
    Initiator, KmsSecretSealer, Responder, body_sha256, compose_services, signable, verify_grant,
    verify_kms_receipt, verify_member_request, verify_platform,
};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::EncodePublicKey;
use serde_json::value::RawValue;
use serde_json::{Value, json};
use wasm_bindgen::{JsCast, JsError, JsValue};
use wasm_bindgen_test::wasm_bindgen_test;

const CA: &str = include_str!("../../../testdata/channel/ca.pem");
const LEAF: &str = include_str!("../../../testdata/channel/leaf.pem");
const LEAF_KEY: &str = include_str!("../../../testdata/channel/leaf-key.pem");
const COMPOSE: &str = include_str!("../../../testdata/channel/app-compose.json");
const PLATFORM_DOCUMENT: &str = include_str!("../../../testdata/channel/platform-document.json");
const KMS_LEAF: &str = include_str!("../../../testdata/channel/kms-leaf.pem");
const KMS_LEAF_KEY: &str = include_str!("../../../testdata/channel/kms-leaf-key.pem");
const KMS_COMPOSE: &str = include_str!("../../../testdata/manifest/06-kms-node/app-compose.json");

/// 2026-06-01T00:00:00Z.
const NOW_MS: f64 = 1_780_272_000_000.0;

const RECEIPT_CA: &str = include_str!("../../../testdata/receipt/ca.pem");
macro_rules! r {
    ($n:literal) => {
        (
            $n,
            include_str!(concat!("../../../testdata/receipt/", $n, ".json")),
        )
    };
}

const RECEIPT_VECTORS: &[(&str, &str)] = &[
    r!("valid"),
    r!("wrong-ca"),
    r!("instance-leaf"),
    r!("wrong-route"),
    r!("wrong-request"),
    r!("other-response"),
    r!("tampered-response"),
    r!("issued-at-outside"),
    r!("duplicate-key"),
];

fn expected() -> String {
    json!({
        "org_id": "01920000-0000-7000-8000-000000000001",
        "app_id": "01920000-0000-7000-8000-000000000002",
        "revisions": [alpha_core::compose_hash(COMPOSE)],
    })
    .to_string()
}

fn der(pem: &str) -> Vec<u8> {
    x509_parser::pem::parse_x509_pem(pem.as_bytes())
        .unwrap()
        .1
        .contents
}

fn responder() -> Responder {
    Responder::new(vec![LEAF.into(), CA.into()], &der(LEAF_KEY), COMPOSE.into())
        .map_err(message)
        .unwrap()
}

/// What `verifyPlatform` returns, built by hand: the signed fixture document pins another CA and
/// cannot be re-signed here.
fn platform(kms_ca_pem: &str, revisions: &[String]) -> String {
    let revisions: Vec<Value> = revisions
        .iter()
        .map(|h| json!({"compose_hash": h, "build": "test", "source_url": "https://example.com/kms"}))
        .collect();
    json!({
        "version": 1,
        "issued_at": "2026-06-01T00:00:00Z",
        "kms_ca_pem": kms_ca_pem,
        "kms_revisions": revisions,
    })
    .to_string()
}

fn kms_revision() -> String {
    alpha_core::compose_hash(KMS_COMPOSE).to_string()
}

/// The KMS node's reply to `client_hello` with the ticket `"t"`, its channel id and `c2s`.
fn kms_reply(client_hello: &str) -> (String, [u8; 16], [u8; 32]) {
    let node =
        handshake::Responder::kms(vec![KMS_LEAF.into(), CA.into()], &der(KMS_LEAF_KEY)).unwrap();
    let client_hello: handshake::ClientHello = serde_json::from_str(client_hello).unwrap();
    let (mut reply, id, c2s) = node
        .respond_detached(
            &client_hello,
            std::time::UNIX_EPOCH + std::time::Duration::from_millis(NOW_MS as u64),
        )
        .unwrap();
    reply.ticket = Some("t".into());
    (serde_json::to_string(&reply).unwrap(), id, *c2s)
}

fn put_payload(value: &[u8]) -> Value {
    json!({
        "name": "db_password",
        "app_ids": ["01920000-0000-7000-8000-000000000002"],
        "content_sha256": body_sha256(value),
        "issued_at": "2026-06-01T00:00:00Z",
    })
}

fn message(e: JsError) -> String {
    JsValue::from(e)
        .unchecked_into::<js_sys::Error>()
        .message()
        .into()
}

#[wasm_bindgen_test]
fn the_exported_initiator_and_responder_share_a_channel() {
    let mut responder = responder();
    let mut initiator = Initiator::new().map_err(message).unwrap();
    let server_hello = responder
        .respond(&initiator.hello(), NOW_MS)
        .map_err(message)
        .unwrap();
    let mut server = responder.channel().map_err(message).unwrap();
    let mut client = initiator
        .finish(&server_hello, CA, &expected(), NOW_MS)
        .map_err(message)
        .unwrap();

    let verified: Value =
        serde_json::from_str(&initiator.verified().map_err(message).unwrap()).unwrap();
    assert_eq!(verified["compose"], COMPOSE);
    assert_eq!(verified["now"], "2026-06-01T00:00:00Z");
    assert_eq!(verified["aud"].as_str().unwrap().len(), 64);

    let frame = client
        .seal_request("POST", "/sessions", b"{}")
        .map_err(message)
        .unwrap();
    let seq = serde_json::from_str::<Value>(&frame).unwrap()["seq"]
        .as_u64()
        .unwrap() as u32;
    let body = server
        .open_request(&frame, "POST", "/sessions")
        .map_err(message)
        .unwrap();
    assert_eq!(body, b"{}");

    let mut reader = client.response(seq);
    for (end, text) in [(false, b"one"), (true, b"two")] {
        let line = server
            .seal_response(seq, end, text)
            .map_err(message)
            .unwrap();
        let opened = reader.open_line(&line).map_err(message).unwrap();
        assert_eq!(opened.unwrap(), text);
    }
    reader.finish().map_err(message).unwrap();

    let again = initiator.finish(&server_hello, CA, &expected(), NOW_MS);
    assert!(message(again.err().unwrap()).starts_with("malformed: "));
}

#[wasm_bindgen_test]
fn a_clock_before_the_leaf_is_refused_not_trapped() {
    let mut responder = responder();
    let mut initiator = Initiator::new().map_err(message).unwrap();
    let server_hello = responder
        .respond(&initiator.hello(), NOW_MS)
        .map_err(message)
        .unwrap();
    // 2025-12-31T23:59:59Z, a second before the leaf's notBefore.
    let err = initiator
        .finish(&server_hello, CA, &expected(), 1_767_225_599_000.0)
        .err()
        .unwrap();
    assert!(message(err).starts_with("certificate_expired: "));

    for bad in [-1.0, f64::NAN, f64::INFINITY, f64::MAX] {
        let err = responder.respond(&initiator.hello(), bad).err().unwrap();
        assert!(message(err).starts_with("malformed: "));
    }
}

#[wasm_bindgen_test]
fn the_sealer_seals_a_put_that_only_the_node_opens() {
    let value = b"correct horse battery staple";
    let payload = put_payload(value);
    let mut sealer = KmsSecretSealer::new().map_err(message).unwrap();
    let (reply, id, c2s) = kms_reply(&sealer.hello());
    let sealed: Sealed = serde_json::from_str(
        &sealer
            .seal(
                &reply,
                &platform(CA, &[kms_revision()]),
                &payload.to_string(),
                value,
                NOW_MS,
            )
            .map_err(message)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(sealed.ticket, "t");
    let opened = secret::open(&id, &c2s, &sealed.frame, "db_password", &payload).unwrap();
    assert_eq!(opened.as_slice(), value);
}

#[wasm_bindgen_test]
fn the_sealer_refuses_a_node_the_view_does_not_list() {
    let value = b"v";
    let payload = put_payload(value).to_string();
    let listed = platform(CA, &[kms_revision()]);
    let seal = |reply: &dyn Fn(&str) -> String, platform: &str, now_ms: f64| {
        let mut sealer = KmsSecretSealer::new().map_err(message).unwrap();
        let reply = reply(&sealer.hello());
        message(
            sealer
                .seal(&reply, platform, &payload, value, now_ms)
                .err()
                .unwrap(),
        )
    };
    let node = |hello: &str| kms_reply(hello).0;
    let instance = |hello: &str| {
        let mut reply: Value =
            serde_json::from_str(&responder().respond(hello, NOW_MS).map_err(message).unwrap())
                .unwrap();
        reply["ticket"] = json!("t");
        reply.to_string()
    };
    let foreign_ca = include_str!("../../../testdata/channel/foreign-ca.pem");
    let unlisted = alpha_core::compose_hash(COMPOSE).to_string();

    for (code, m) in [
        ("foreign_certificate", seal(&instance, &listed, NOW_MS)),
        (
            "foreign_certificate",
            seal(&node, &platform(foreign_ca, &[kms_revision()]), NOW_MS),
        ),
        (
            "unknown_revision",
            seal(&node, &platform(CA, &[unlisted]), NOW_MS),
        ),
        ("malformed", seal(&node, &listed, f64::NAN)),
    ] {
        assert!(m.starts_with(&format!("{code}: ")), "{code}: {m}");
    }

    let mut sealer = KmsSecretSealer::new().map_err(message).unwrap();
    let reply = node(&sealer.hello());
    sealer
        .seal(&reply, &listed, &payload, value, NOW_MS)
        .map_err(message)
        .unwrap();
    let again = sealer.seal(&reply, &listed, &payload, value, NOW_MS);
    assert!(message(again.err().unwrap()).starts_with("malformed: "));
}

#[wasm_bindgen_test]
fn the_platform_document_verifies_through_the_export() {
    let view: Value = serde_json::from_str(
        &verify_platform(PLATFORM_DOCUMENT, 1_790_208_000_000.0)
            .map_err(message)
            .unwrap(),
    )
    .unwrap();
    assert!(
        view["kms_ca_pem"]
            .as_str()
            .unwrap()
            .contains("BEGIN CERTIFICATE")
    );
    let revisions = view["kms_revisions"].as_array().unwrap();
    assert!(!revisions.is_empty());
    for r in revisions {
        assert!(r["compose_hash"].as_str().unwrap().starts_with("sha256:"));
    }
    assert!(view.get("signer").is_none());
    assert!(view.get("catalog_key").is_none());
    let err = verify_platform(PLATFORM_DOCUMENT, 0.0).err().unwrap();
    assert!(message(err).starts_with("platform_signature: "));
}

#[wasm_bindgen_test]
fn member_documents_from_signable_verify_through_the_exports() {
    let key = SigningKey::from_slice(&[7u8; 32]).unwrap();
    let spki = BASE64_URL_SAFE_NO_PAD.encode(key.verifying_key().to_public_key_der().unwrap());
    let sign = |digest: &[u8]| {
        let signature: Signature = key.sign(digest);
        BASE64_URL_SAFE_NO_PAD.encode(signature.to_bytes())
    };

    let list = signable(
        "alphacompute/connector-request/v1",
        r#"{"op":"list"}"#,
        NOW_MS,
    )
    .map_err(message)
    .unwrap();
    let signature = json!({"algorithm": "ecdsa-p256", "signature": sign(&list.digest)});
    let signer = verify_member_request(
        "alphacompute/connector-request/v1",
        &list.document,
        &spki,
        &signature.to_string(),
        NOW_MS + 30_000.0,
    )
    .map_err(message)
    .unwrap();
    assert_eq!(signer.len(), 64);
    let stale = verify_member_request(
        "alphacompute/connector-request/v1",
        &list.document,
        &spki,
        &signature.to_string(),
        NOW_MS + 61_000.0,
    );
    assert!(message(stale.err().unwrap()).starts_with("request_stale: "));

    let fields = json!({"aud": "sha256:00", "connections": [], "exp": "2026-06-01T00:15:00Z"});
    let grant = signable(
        "alphacompute/connector-grant/v1",
        &fields.to_string(),
        NOW_MS,
    )
    .map_err(message)
    .unwrap();
    let wire = format!(
        "{}.{}",
        BASE64_URL_SAFE_NO_PAD.encode(&grant.document),
        sign(&grant.digest)
    );
    let verified: Value =
        serde_json::from_str(&verify_grant(&wire, &spki).map_err(message).unwrap()).unwrap();
    assert_eq!(verified["exp"], "2026-06-01T00:15:00Z");

    let services: Value =
        serde_json::from_str(&compose_services(COMPOSE).map_err(message).unwrap()).unwrap();
    assert!(
        services["app"]["image"]
            .as_str()
            .unwrap()
            .contains("@sha256:")
    );
}

#[wasm_bindgen_test]
fn kms_receipt_vectors_give_their_recorded_result_through_the_export() {
    for (name, text) in RECEIPT_VECTORS {
        let v: Value = serde_json::from_str(text).unwrap();
        let raw: BTreeMap<String, Box<RawValue>> = serde_json::from_str(text).unwrap();
        let out = verify_kms_receipt(
            raw["receipt"].get(),
            RECEIPT_CA,
            &v["kms_revisions"].to_string(),
            &v["expected"].to_string(),
        );
        match (out, v["result"].as_str().unwrap()) {
            (Ok(json), "ok") => assert_eq!(
                serde_json::from_str::<Value>(&json).unwrap(),
                v["receipt"]["document"]["response"],
                "{name}"
            ),
            (Err(e), result) => {
                let m = message(e);
                assert!(m.starts_with(&format!("{result}:")), "{name}: {m}");
            }
            (Ok(_), result) => panic!("{name}: accepted, expected {result}"),
        }
    }
}
