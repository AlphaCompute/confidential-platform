#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::time::{Duration, SystemTime};

use alpha_channel::Error;
use alpha_channel::NamedSignature;
use alpha_channel::member::{check_fresh, parse_grant, signable, verify_request};
use alpha_core::{context, signing_digest};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::EncodePublicKey;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const VECTORS: &str = include_str!("../../../testdata/member/webcrypto.json");

fn vectors() -> Value {
    serde_json::from_str(VECTORS).unwrap()
}

fn at(rfc3339: &str) -> SystemTime {
    chrono::DateTime::parse_from_rfc3339(rfc3339)
        .unwrap()
        .into()
}

fn verify(entry: &Value) -> Result<[u8; 32], Error> {
    let signature: NamedSignature = serde_json::from_value(entry["signature"].clone()).unwrap();
    verify_request(
        entry["context"].as_str().unwrap(),
        &entry["document"],
        entry["member_key"].as_str().unwrap(),
        &signature,
    )
}

fn other_key() -> SigningKey {
    SigningKey::from_slice(&[7u8; 32]).unwrap()
}

fn spki(key: &SigningKey) -> Vec<u8> {
    key.verifying_key()
        .to_public_key_der()
        .unwrap()
        .as_bytes()
        .to_vec()
}

fn b64(bytes: &[u8]) -> String {
    BASE64_URL_SAFE_NO_PAD.encode(bytes)
}

#[wasm_bindgen_test::wasm_bindgen_test(unsupported = test)]
fn every_webcrypto_signature_verifies_high_s_included() {
    let vectors = vectors();
    let entries = vectors["entries"].as_array().unwrap();
    assert!(entries.iter().any(|e| e["high_s"] == true));
    for entry in entries {
        let spki = BASE64_URL_SAFE_NO_PAD
            .decode(entry["member_key"].as_str().unwrap())
            .unwrap();
        assert_eq!(
            verify(entry).unwrap(),
            <[u8; 32]>::from(Sha256::digest(&spki))
        );
    }
}

#[wasm_bindgen_test::wasm_bindgen_test(unsupported = test)]
fn another_context_field_key_or_algorithm_is_signature_invalid() {
    let entry = vectors()["entries"][0].clone();

    let mut other = entry.clone();
    other["context"] = json!(context::CONNECTOR_WRITE);
    assert_eq!(verify(&other).unwrap_err().code(), "signature_invalid");

    let mut other = entry.clone();
    other["document"]["provider"] = json!("dropbox");
    assert_eq!(verify(&other).unwrap_err().code(), "signature_invalid");

    let mut other = entry.clone();
    other["member_key"] = json!(b64(&spki(&other_key())));
    assert_eq!(verify(&other).unwrap_err().code(), "signature_invalid");

    let mut other = entry.clone();
    other["signature"]["algorithm"] = json!("ecdsa-p384");
    assert_eq!(verify(&other).unwrap_err().code(), "signature_invalid");

    let mut other = entry;
    other["signature"]["signature"] = json!("AAAA");
    assert_eq!(verify(&other).unwrap_err().code(), "signature_invalid");
}

#[wasm_bindgen_test::wasm_bindgen_test(unsupported = test)]
fn a_member_key_that_is_not_p256_is_malformed() {
    let ed25519 = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32])
        .verifying_key()
        .to_public_key_der()
        .unwrap();
    for key in [b64(ed25519.as_bytes()), "not base64!".into()] {
        let mut entry = vectors()["entries"][0].clone();
        entry["member_key"] = json!(key);
        assert_eq!(verify(&entry).unwrap_err().code(), "malformed");
    }
}

#[wasm_bindgen_test::wasm_bindgen_test(unsupported = test)]
fn the_webcrypto_grant_verifies_as_received_and_only_under_its_key() {
    let vectors = vectors();
    let member = BASE64_URL_SAFE_NO_PAD
        .decode(vectors["entries"][3]["member_key"].as_str().unwrap())
        .unwrap();
    let signed = parse_grant(vectors["grant_wire"].as_str().unwrap()).unwrap();
    let grant = signed.verify(&member).unwrap();
    assert_eq!(grant.aud, format!("sha256:{}", "ab".repeat(32)));
    assert_eq!(grant.connections.len(), 2);
    assert_eq!(grant.exp, "2026-09-25T12:15:00Z");
    assert_eq!(
        signed.verify(&spki(&other_key())).unwrap_err().code(),
        "signature_invalid"
    );
}

#[wasm_bindgen_test::wasm_bindgen_test(unsupported = test)]
fn a_grant_wire_without_a_dot_or_with_bad_base64url_is_malformed() {
    let wire = vectors()["grant_wire"].as_str().unwrap().to_owned();
    let (document, signature) = wire.split_once('.').unwrap();
    for bad in [
        document.to_owned(),
        format!("{document}!.{signature}"),
        format!("{document}.{signature}="),
        format!("{document}.{}", b64(&[1u8; 63])),
    ] {
        assert_eq!(parse_grant(&bad).unwrap_err().code(), "malformed", "{bad}");
    }
}

#[wasm_bindgen_test::wasm_bindgen_test(unsupported = test)]
fn a_grant_reencoded_on_the_way_no_longer_verifies() {
    let vectors = vectors();
    let member = BASE64_URL_SAFE_NO_PAD
        .decode(vectors["entries"][3]["member_key"].as_str().unwrap())
        .unwrap();
    let wire = vectors["grant_wire"].as_str().unwrap();
    let (document, signature) = wire.split_once('.').unwrap();
    let pretty = serde_json::to_vec_pretty(
        &serde_json::from_slice::<Value>(&BASE64_URL_SAFE_NO_PAD.decode(document).unwrap())
            .unwrap(),
    )
    .unwrap();
    let reencoded = format!("{}.{signature}", b64(&pretty));
    let err = parse_grant(&reencoded)
        .unwrap()
        .verify(&member)
        .unwrap_err();
    assert_eq!(err.code(), "signature_invalid");
}

/// A grant whose document is `fields` plus the filled `v`, `nonce` and `issued_at`, signed by `key`.
fn grant_wire(key: &SigningKey, fields: Value) -> String {
    let (document, digest) =
        signable(context::CONNECTOR_GRANT, fields, at("2026-09-25T12:00:00Z")).unwrap();
    let signature: Signature = key.sign(&digest);
    format!(
        "{}.{}",
        b64(document.as_bytes()),
        b64(&signature.to_bytes())
    )
}

#[wasm_bindgen_test::wasm_bindgen_test(unsupported = test)]
fn an_unknown_grant_field_is_malformed_only_after_the_signature_verifies() {
    let key = other_key();
    let fields = json!({
        "aud": format!("sha256:{}", "cd".repeat(32)),
        "connections": [],
        "exp": "2026-09-25T12:15:00Z",
        "scope": "write",
    });
    let signed = parse_grant(&grant_wire(&key, fields)).unwrap();
    assert_eq!(signed.verify(&spki(&key)).unwrap_err().code(), "malformed");
    let stranger = SigningKey::from_slice(&[9u8; 32]).unwrap();
    assert_eq!(
        signed.verify(&spki(&stranger)).unwrap_err().code(),
        "signature_invalid"
    );
}

#[wasm_bindgen_test::wasm_bindgen_test(unsupported = test)]
fn issued_at_more_than_sixty_seconds_away_is_stale() {
    let now = at("2026-09-25T12:00:00Z");
    for issued_at in ["2026-09-25T11:58:59Z", "2026-09-25T12:01:01Z"] {
        assert_eq!(
            check_fresh(issued_at, now).unwrap_err().code(),
            "request_stale"
        );
    }
    for issued_at in [
        "2026-09-25T11:59:01Z",
        "2026-09-25T12:00:59Z",
        "2026-09-25T12:01:00Z",
    ] {
        check_fresh(issued_at, now).unwrap();
    }
    assert_eq!(
        check_fresh("yesterday", now).unwrap_err().code(),
        "malformed"
    );
}

#[wasm_bindgen_test::wasm_bindgen_test(unsupported = test)]
fn signable_returns_a_jcs_document_and_its_digest() {
    let now = at("2026-09-25T12:00:00Z") + Duration::from_millis(900);
    let fields = json!({"exp": "2026-09-25T12:15:00Z", "connections": [], "aud": "sha256:00"});
    let (document, digest) = signable(context::CONNECTOR_GRANT, fields, now).unwrap();
    let value: Value = serde_json::from_str(&document).unwrap();
    assert_eq!(alpha_core::jcs(&value).unwrap(), document.as_bytes());
    assert_eq!(
        digest,
        signing_digest(context::CONNECTOR_GRANT, &value).unwrap()
    );
    assert_eq!(value["v"], 1);
    assert_eq!(value["issued_at"], "2026-09-25T12:00:00Z");
    let nonce = BASE64_URL_SAFE_NO_PAD
        .decode(value["nonce"].as_str().unwrap())
        .unwrap();
    assert_eq!(nonce.len(), 32);

    let again = signable(context::CONNECTOR_GRANT, json!({}), now).unwrap();
    assert_ne!(
        again.0,
        signable(context::CONNECTOR_GRANT, json!({}), now)
            .unwrap()
            .0
    );

    for (ctx, fields) in [
        (context::INNER_CHANNEL, json!({})),
        (context::CONNECTOR_REQUEST, json!({"nonce": "mine"})),
        (context::CONNECTOR_WRITE, json!({"v": 2})),
        (context::CONNECTOR_REQUEST, json!(["op"])),
    ] {
        assert_eq!(signable(ctx, fields, now).unwrap_err().code(), "malformed");
    }
}
