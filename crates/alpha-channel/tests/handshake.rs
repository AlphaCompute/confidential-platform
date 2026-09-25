#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::time::SystemTime;

use alpha_channel::Error;
use alpha_channel::cert::{pem_to_der, spki_sha256};
use alpha_channel::handshake::{Expected, Initiator, Responder, ServerHello, Verified};
use alpha_channel::platform::{SignedDocument, release_key, verify};
use alpha_core::{AppId, OrgId};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use serde_json::{Value, json};

const CA: &str = include_str!("../../../testdata/channel/ca.pem");
const LEAF: &str = include_str!("../../../testdata/channel/leaf.pem");
const LEAF_KEY: &str = include_str!("../../../testdata/channel/leaf-key.pem");
const FOREIGN_CA: &str = include_str!("../../../testdata/channel/foreign-ca.pem");
const FOREIGN_LEAF: &str = include_str!("../../../testdata/channel/foreign-leaf.pem");
const OTHER_APP_LEAF: &str = include_str!("../../../testdata/channel/other-app-leaf.pem");
const COMPOSE: &str = include_str!("../../../testdata/channel/app-compose.json");
const PLATFORM_DOCUMENT: &str = include_str!("../../../testdata/channel/platform-document.json");

const ORG: &str = "01920000-0000-7000-8000-000000000001";
const APP: &str = "01920000-0000-7000-8000-000000000002";
const NOW: &str = "2026-06-01T00:00:00Z";

fn at(rfc3339: &str) -> SystemTime {
    chrono::DateTime::parse_from_rfc3339(rfc3339)
        .unwrap()
        .into()
}

fn leaf_key() -> Vec<u8> {
    x509_parser::pem::parse_x509_pem(LEAF_KEY.as_bytes())
        .unwrap()
        .1
        .contents
}

fn expected() -> Expected {
    Expected {
        org_id: ORG.parse::<OrgId>().unwrap(),
        app_id: APP.parse::<AppId>().unwrap(),
        revisions: vec![alpha_core::compose_hash(COMPOSE)],
    }
}

/// A handshake with a responder presenting `leaf` then `ca`, its reply's JSON passed through
/// `tamper` on the way, finished by the initiator at `now`.
fn handshake(
    leaf: &str,
    ca: &str,
    tamper: impl FnOnce(&mut Value),
    expected: &Expected,
    now: &str,
) -> Result<Verified, Error> {
    let responder = Responder::new(vec![leaf.into(), ca.into()], &leaf_key(), COMPOSE.into())?;
    let (initiator, client_hello) = Initiator::new()?;
    let (server_hello, _) = responder.respond(&client_hello, at(NOW))?;
    let mut json = serde_json::to_value(server_hello).unwrap();
    tamper(&mut json);
    let server_hello: ServerHello = serde_json::from_value(json).unwrap();
    initiator
        .finish(&server_hello, CA, expected, at(now))
        .map(|(_, verified)| verified)
}

fn refused(
    leaf: &str,
    ca: &str,
    tamper: impl FnOnce(&mut Value),
    expected: &Expected,
    now: &str,
) -> &'static str {
    handshake(leaf, ca, tamper, expected, now)
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

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn a_responder_and_an_initiator_share_a_channel() {
    let now = at(NOW);
    let responder =
        Responder::new(vec![LEAF.into(), CA.into()], &leaf_key(), COMPOSE.into()).unwrap();
    let (initiator, client_hello) = Initiator::new().unwrap();
    let (server_hello, mut server) = responder.respond(&client_hello, now).unwrap();
    let (mut client, verified) = initiator
        .finish(&server_hello, CA, &expected(), now)
        .unwrap();

    assert_eq!(verified.org_id.to_string(), ORG);
    assert_eq!(verified.app_id.to_string(), APP);
    assert_eq!(verified.compose_hash, alpha_core::compose_hash(COMPOSE));
    assert_eq!(verified.compose, COMPOSE);
    assert_eq!(Some(verified.aud), spki_sha256(&pem_to_der(LEAF).unwrap()));
    assert_eq!(verified.now, now);
    assert_eq!(client.id(), server.id());

    let request = client
        .seal_request("POST", "/sessions", br#"{"hello":1}"#)
        .unwrap();
    let seq = request.seq;
    let body = server.open_request(&request, "POST", "/sessions").unwrap();
    assert_eq!(body.as_slice(), br#"{"hello":1}"#);

    let first = server.seal_response(seq, 0, false, b"one").unwrap();
    let last = server.seal_response(seq, 1, true, b"two").unwrap();
    let mut reader = client.response(seq);
    assert!(reader.finish().is_err());
    assert_eq!(
        reader.open_line(&first).unwrap().unwrap().as_slice(),
        b"one"
    );
    assert_eq!(reader.open_line(&last).unwrap().unwrap().as_slice(), b"two");
    reader.finish().unwrap();
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn a_ca_that_is_not_the_platforms_is_foreign() {
    let code = refused(LEAF, FOREIGN_CA, |_| {}, &expected(), NOW);
    assert_eq!(code, "foreign_certificate");
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn a_leaf_the_pinned_ca_did_not_sign_is_foreign() {
    let code = refused(FOREIGN_LEAF, CA, |_| {}, &expected(), NOW);
    assert_eq!(code, "foreign_certificate");
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn a_leaf_for_another_app_is_foreign() {
    let code = refused(OTHER_APP_LEAF, CA, |_| {}, &expected(), NOW);
    assert_eq!(code, "foreign_certificate");
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn a_leaf_for_another_organization_is_foreign() {
    let mut other = expected();
    other.org_id = "01920000-0000-7000-8000-0000000000ff".parse().unwrap();
    assert_eq!(
        refused(LEAF, CA, |_| {}, &other, NOW),
        "foreign_certificate"
    );
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn a_compose_hash_outside_the_allowlist_is_unknown() {
    let mut other = expected();
    other.revisions = vec![alpha_core::compose_hash("{}")];
    assert_eq!(refused(LEAF, CA, |_| {}, &other, NOW), "unknown_revision");
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn an_empty_allowlist_knows_no_revision() {
    let mut other = expected();
    other.revisions.clear();
    assert_eq!(refused(LEAF, CA, |_| {}, &other, NOW), "unknown_revision");
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn a_compose_with_one_byte_changed_does_not_match_the_revision() {
    let tamper = |hello: &mut Value| {
        let compose = hello["compose"].as_str().unwrap().replacen('{', "[", 1);
        hello["compose"] = json!(compose);
    };
    assert_eq!(
        refused(LEAF, CA, tamper, &expected(), NOW),
        "compose_mismatch"
    );
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn an_enc_changed_after_signing_breaks_the_signature() {
    let tamper = |hello: &mut Value| flip_first_byte(&mut hello["enc"]);
    assert_eq!(
        refused(LEAF, CA, tamper, &expected(), NOW),
        "handshake_signature"
    );
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn a_channel_id_changed_after_signing_breaks_the_signature() {
    let tamper = |hello: &mut Value| flip_first_byte(&mut hello["channel"]);
    assert_eq!(
        refused(LEAF, CA, tamper, &expected(), NOW),
        "handshake_signature"
    );
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn a_responder_time_changed_after_signing_breaks_the_signature() {
    let tamper = |hello: &mut Value| hello["now"] = json!("2026-06-01T00:00:01Z");
    assert_eq!(
        refused(LEAF, CA, tamper, &expected(), NOW),
        "handshake_signature"
    );
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn a_changed_signature_does_not_verify() {
    let tamper = |hello: &mut Value| flip_first_byte(&mut hello["signature"]["signature"]);
    assert_eq!(
        refused(LEAF, CA, tamper, &expected(), NOW),
        "handshake_signature"
    );
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn a_signature_algorithm_other_than_ecdsa_p256_is_refused() {
    let tamper = |hello: &mut Value| hello["signature"]["algorithm"] = json!("ed25519");
    assert_eq!(
        refused(LEAF, CA, tamper, &expected(), NOW),
        "handshake_signature"
    );
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn a_leaf_before_its_not_before_is_expired() {
    let code = refused(LEAF, CA, |_| {}, &expected(), "2025-12-31T23:59:59Z");
    assert_eq!(code, "certificate_expired");
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn a_leaf_at_its_not_after_is_expired() {
    let code = refused(LEAF, CA, |_| {}, &expected(), "2036-01-01T00:00:00Z");
    assert_eq!(code, "certificate_expired");
    handshake(LEAF, CA, |_| {}, &expected(), "2035-12-31T23:59:59Z").unwrap();
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn a_chain_of_one_certificate_is_foreign() {
    let tamper = |hello: &mut Value| hello["certificate_chain"] = json!([LEAF]);
    assert_eq!(
        refused(LEAF, CA, tamper, &expected(), NOW),
        "foreign_certificate"
    );
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn a_chain_of_three_certificates_is_foreign() {
    let tamper = |hello: &mut Value| hello["certificate_chain"] = json!([LEAF, CA, CA]);
    assert_eq!(
        refused(LEAF, CA, tamper, &expected(), NOW),
        "foreign_certificate"
    );
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn the_stands_platform_document_verifies_under_the_compiled_in_release_key() {
    let signed: SignedDocument = serde_json::from_str(PLATFORM_DOCUMENT).unwrap();
    let view = verify(&signed, &release_key().unwrap(), at("2026-09-24T00:00:00Z")).unwrap();
    assert!(view.version >= 1);
    assert!(view.kms_ca_pem.contains("BEGIN CERTIFICATE"));
    pem_to_der(&view.kms_ca_pem).unwrap();
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn a_platform_document_with_a_changed_ca_is_refused_platform_signature() {
    let mut signed: SignedDocument = serde_json::from_str(PLATFORM_DOCUMENT).unwrap();
    let ca = signed.document["kms_ca_pem"].as_str().unwrap();
    let at_char = ca.find("-----\n").unwrap() + 6;
    let mut tampered = ca.to_owned();
    let original = tampered.remove(at_char);
    tampered.insert(at_char, if original == 'A' { 'B' } else { 'A' });
    signed.document["kms_ca_pem"] = json!(tampered);
    let err = verify(&signed, &release_key().unwrap(), at("2026-09-24T00:00:00Z")).unwrap_err();
    assert_eq!(err.code(), "platform_signature");
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn a_platform_document_is_refused_before_it_was_issued() {
    let signed: SignedDocument = serde_json::from_str(PLATFORM_DOCUMENT).unwrap();
    let issued_at = signed.document["issued_at"].as_str().unwrap();
    let before = at(issued_at) - std::time::Duration::from_secs(1);
    let err = verify(&signed, &release_key().unwrap(), before).unwrap_err();
    assert_eq!(err.code(), "platform_signature");
}
