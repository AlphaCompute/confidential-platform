#![cfg(target_arch = "wasm32")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use alpha_channel::wasm::{Initiator, Responder, verify_platform};
use serde_json::{Value, json};
use wasm_bindgen::{JsCast, JsError, JsValue};
use wasm_bindgen_test::wasm_bindgen_test;

const CA: &str = include_str!("../../../testdata/channel/ca.pem");
const LEAF: &str = include_str!("../../../testdata/channel/leaf.pem");
const LEAF_KEY: &str = include_str!("../../../testdata/channel/leaf-key.pem");
const COMPOSE: &str = include_str!("../../../testdata/channel/app-compose.json");
const PLATFORM_DOCUMENT: &str = include_str!("../../../testdata/channel/platform-document.json");

/// 2026-06-01T00:00:00Z.
const NOW_MS: f64 = 1_780_272_000_000.0;

fn expected() -> String {
    json!({
        "org_id": "01920000-0000-7000-8000-000000000001",
        "app_id": "01920000-0000-7000-8000-000000000002",
        "revisions": [alpha_core::compose_hash(COMPOSE)],
    })
    .to_string()
}

fn responder() -> Responder {
    let key = x509_parser::pem::parse_x509_pem(LEAF_KEY.as_bytes())
        .unwrap()
        .1
        .contents;
    Responder::new(vec![LEAF.into(), CA.into()], &key, COMPOSE.into())
        .map_err(message)
        .unwrap()
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
    let seq = client.last_seq().unwrap();
    let body = server
        .open_request(&frame, "POST", "/sessions")
        .map_err(message)
        .unwrap();
    assert_eq!(body, b"{}");

    let mut reader = client.response(seq);
    for (index, end, text) in [(0, false, b"one"), (1, true, b"two")] {
        let line = server
            .seal_response(seq, index, end, text)
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
    let err = verify_platform(PLATFORM_DOCUMENT, 0.0).err().unwrap();
    assert!(message(err).starts_with("platform_signature: "));
}
