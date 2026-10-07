#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::time::SystemTime;

use alpha_channel::Error;
use alpha_channel::handshake::{Initiator, Responder, ServerHello};
use alpha_channel::secret::{self, Sealed};
use alpha_core::{ComposeHash, OrgId};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use serde_json::{Value, json};

const CA: &str = include_str!("../../../testdata/channel/ca.pem");
const FOREIGN_CA: &str = include_str!("../../../testdata/channel/foreign-ca.pem");
const LEAF: &str = include_str!("../../../testdata/channel/leaf.pem");
const LEAF_KEY: &str = include_str!("../../../testdata/channel/leaf-key.pem");
const KMS_LEAF: &str = include_str!("../../../testdata/channel/kms-leaf.pem");
const KMS_LEAF_KEY: &str = include_str!("../../../testdata/channel/kms-leaf-key.pem");
const COMPOSE: &str = include_str!("../../../testdata/channel/app-compose.json");
const KMS_COMPOSE: &str = include_str!("../../../testdata/manifest/06-kms-node/app-compose.json");

const NOW: &str = "2026-06-01T00:00:00Z";
const VALUE: &[u8] = b"correct horse battery staple";

fn org() -> OrgId {
    "01920000-0000-7000-8000-000000000001".parse().unwrap()
}

fn at(rfc3339: &str) -> SystemTime {
    chrono::DateTime::parse_from_rfc3339(rfc3339)
        .unwrap()
        .into()
}

fn der(pem: &str) -> Vec<u8> {
    x509_parser::pem::parse_x509_pem(pem.as_bytes())
        .unwrap()
        .1
        .contents
}

fn node() -> Responder {
    Responder::kms(vec![KMS_LEAF.into(), CA.into()], &der(KMS_LEAF_KEY)).unwrap()
}

fn instance() -> Responder {
    Responder::new(vec![LEAF.into(), CA.into()], &der(LEAF_KEY), COMPOSE.into()).unwrap()
}

fn revisions() -> Vec<ComposeHash> {
    vec![alpha_core::compose_hash(KMS_COMPOSE)]
}

fn payload(name: Option<&str>) -> Value {
    let mut payload = json!({
        "app_ids": ["01920000-0000-7000-8000-000000000002"],
        "content_sha256": alpha_channel::sha256_label(VALUE),
        "issued_at": NOW,
    });
    if let Some(name) = name {
        payload["name"] = json!(name);
    }
    payload
}

fn with_ticket(hello: &mut Value) {
    hello["ticket"] = json!("t");
}

/// `responder`'s reply to a fresh initiator, passed through `tamper` as JSON: the initiator, the
/// reply, and the responder's channel id and `c2s`.
fn exchange(
    responder: &Responder,
    tamper: impl FnOnce(&mut Value),
) -> (Initiator, ServerHello, [u8; 16], [u8; 32]) {
    let (initiator, client_hello) = Initiator::new().unwrap();
    let (reply, id, c2s) = responder.respond_detached(&client_hello, at(NOW)).unwrap();
    let mut json = serde_json::to_value(reply).unwrap();
    tamper(&mut json);
    (initiator, serde_json::from_value(json).unwrap(), id, *c2s)
}

fn seal_to(
    responder: &Responder,
    tamper: impl FnOnce(&mut Value),
    kms_ca_pem: &str,
    kms_revisions: &[ComposeHash],
    payload: &Value,
    now: &str,
) -> Result<Sealed, Error> {
    let (initiator, hello, _, _) = exchange(responder, tamper);
    let (mut channel, ticket) = initiator.finish_kms(&hello, kms_ca_pem, kms_revisions, at(now))?;
    secret::seal(&mut channel, ticket, payload, org(), VALUE)
}

fn refused(
    responder: &Responder,
    tamper: impl FnOnce(&mut Value),
    kms_ca_pem: &str,
    kms_revisions: &[ComposeHash],
    now: &str,
) -> &'static str {
    seal_to(
        responder,
        tamper,
        kms_ca_pem,
        kms_revisions,
        &payload(Some("db_password")),
        now,
    )
    .unwrap_err()
    .code()
}

fn flip_first_byte(field: &mut Value) {
    let mut bytes = BASE64_URL_SAFE_NO_PAD
        .decode(field.as_str().unwrap())
        .unwrap();
    bytes[0] ^= 1;
    *field = json!(BASE64_URL_SAFE_NO_PAD.encode(bytes));
}

#[wasm_bindgen_test::wasm_bindgen_test(unsupported = test)]
fn a_value_sealed_to_a_kms_node_opens_there() {
    let payload = payload(Some("db_password"));
    let (initiator, hello, id, c2s) = exchange(&node(), with_ticket);
    assert!(hello.compose.is_empty());
    let (mut channel, ticket) = initiator
        .finish_kms(&hello, CA, &revisions(), at(NOW))
        .unwrap();
    let sealed = secret::seal(&mut channel, ticket, &payload, org(), VALUE).unwrap();
    assert_eq!(sealed.ticket, "t");
    let (sealed_for, opened) =
        secret::open(&id, &c2s, &sealed.frame, "db_password", &payload).unwrap();
    assert_eq!(sealed_for, org());
    assert_eq!(opened.as_slice(), VALUE);

    let (initiator, hello, _, _) = exchange(&node(), with_ticket);
    let (_, ticket) = initiator
        .finish_kms(&hello, CA, &revisions(), at(NOW))
        .unwrap();
    assert_eq!(ticket, "t");
}

#[wasm_bindgen_test::wasm_bindgen_test(unsupported = test)]
fn a_leaf_or_ca_the_view_does_not_list_is_refused() {
    let instance_with_ticket = refused(&instance(), with_ticket, CA, &revisions(), NOW);
    assert_eq!(instance_with_ticket, "foreign_certificate");

    let other = [alpha_core::compose_hash(COMPOSE)];
    assert_eq!(
        refused(&node(), with_ticket, CA, &other, NOW),
        "unknown_revision"
    );
    assert_eq!(
        refused(&node(), with_ticket, CA, &[], NOW),
        "unknown_revision"
    );
    assert_eq!(
        refused(&node(), with_ticket, FOREIGN_CA, &revisions(), NOW),
        "foreign_certificate"
    );
    assert_eq!(
        refused(
            &node(),
            with_ticket,
            CA,
            &revisions(),
            "2036-01-01T00:00:00Z"
        ),
        "certificate_expired"
    );
}

#[wasm_bindgen_test::wasm_bindgen_test(unsupported = test)]
fn a_responder_refuses_a_chain_of_the_other_kind() {
    let kms_over_instance = Responder::kms(vec![LEAF.into(), CA.into()], &der(LEAF_KEY));
    assert_eq!(kms_over_instance.unwrap_err().code(), "foreign_certificate");
    let instance_over_kms = Responder::new(
        vec![KMS_LEAF.into(), CA.into()],
        &der(KMS_LEAF_KEY),
        KMS_COMPOSE.into(),
    );
    assert_eq!(instance_over_kms.unwrap_err().code(), "foreign_certificate");
}

#[wasm_bindgen_test::wasm_bindgen_test(unsupported = test)]
fn a_kms_reply_with_a_changed_signature_or_no_ticket_is_refused() {
    let flipped = |hello: &mut Value| {
        with_ticket(hello);
        flip_first_byte(&mut hello["signature"]["signature"]);
    };
    let (initiator, hello, _, _) = exchange(&node(), flipped);
    let err = initiator
        .finish_kms(&hello, CA, &revisions(), at(NOW))
        .unwrap_err();
    assert_eq!(err.code(), "handshake_signature");

    assert_eq!(refused(&node(), |_| {}, CA, &revisions(), NOW), "malformed");
}

#[wasm_bindgen_test::wasm_bindgen_test(unsupported = test)]
fn a_frame_opens_only_for_its_name_key_channel_and_payload() {
    let payload = payload(Some("db_password"));
    let (initiator, hello, id, c2s) = exchange(&node(), with_ticket);
    let (mut channel, ticket) = initiator
        .finish_kms(&hello, CA, &revisions(), at(NOW))
        .unwrap();
    let sealed = secret::seal(&mut channel, ticket, &payload, org(), VALUE).unwrap();
    let open = |id: &[u8; 16], c2s: &[u8; 32], frame, name, payload| {
        secret::open(id, c2s, frame, name, payload)
            .unwrap_err()
            .code()
    };

    assert_eq!(open(&id, &c2s, &sealed.frame, "api_key", &payload), "open");
    assert_eq!(
        open(&id, &[7; 32], &sealed.frame, "db_password", &payload),
        "open"
    );
    let mut moved = sealed.frame.clone();
    moved.channel = BASE64_URL_SAFE_NO_PAD.encode([9u8; 16]);
    assert_eq!(open(&id, &c2s, &moved, "db_password", &payload), "open");
    let mut later = payload.clone();
    later["issued_at"] = json!("2026-06-01T00:00:01Z");
    assert_eq!(
        open(&id, &c2s, &sealed.frame, "db_password", &later),
        "malformed"
    );
}

#[wasm_bindgen_test::wasm_bindgen_test(unsupported = test)]
fn a_plaintext_without_its_organization_is_malformed() {
    let payload = payload(Some("db_password"));
    let digest = alpha_core::signing_digest(alpha_core::context::SECRET, &payload).unwrap();
    for plaintext in [digest.to_vec(), [digest.as_slice(), &[1; 15]].concat()] {
        let (initiator, hello, id, c2s) = exchange(&node(), with_ticket);
        let (mut channel, _) = initiator
            .finish_kms(&hello, CA, &revisions(), at(NOW))
            .unwrap();
        let frame = channel
            .seal_request("PUT", "/v1/secrets/db_password", &plaintext)
            .unwrap();
        let err = secret::open(&id, &c2s, &frame, "db_password", &payload).unwrap_err();
        assert_eq!(err.code(), "malformed");
    }
}

#[wasm_bindgen_test::wasm_bindgen_test(unsupported = test)]
fn a_payload_name_that_is_not_a_secret_name_is_refused() {
    for name in [Some("../x"), Some("A"), None] {
        let err = seal_to(&node(), with_ticket, CA, &revisions(), &payload(name), NOW).unwrap_err();
        assert_eq!(err.code(), "malformed", "{name:?}");
    }
}

/// A pk of the right length whose ML-KEM coefficients are all 4095, past the modulus 3329.
#[wasm_bindgen_test::wasm_bindgen_test(unsupported = test)]
fn a_pk_that_cannot_be_encapsulated_to_is_malformed() {
    let (_, mut hello) = Initiator::new().unwrap();
    hello.pk = BASE64_URL_SAFE_NO_PAD.encode([0xff; 1216]);
    let err = node().respond_detached(&hello, at(NOW)).unwrap_err();
    assert_eq!(err.code(), "malformed");
}

#[wasm_bindgen_test::wasm_bindgen_test(unsupported = test)]
fn an_instance_reply_carries_no_ticket_key() {
    let (_, client_hello) = Initiator::new().unwrap();
    let (reply, _) = instance().respond(&client_hello, at(NOW)).unwrap();
    let json = serde_json::to_value(reply).unwrap();
    assert!(json.get("ticket").is_none());
}
