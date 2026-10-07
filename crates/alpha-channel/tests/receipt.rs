#![cfg(not(target_arch = "wasm32"))]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::fs;
use std::path::PathBuf;
use std::time::SystemTime;

use alpha_channel::cert::KMS_SAN;
use alpha_channel::receipt::{self, Expected, Receipt};
use alpha_core::ComposeHash;
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use p256::ecdsa::signature::Signer;
use rcgen::string::Ia5String;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyUsagePurpose, PublicKeyData, SanType, SerialNumber,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const DEPLOY_COMPOSE: &str = include_str!("../../../testdata/manifest/05-deploy/app-compose.json");
const DEPLOY_EXPECTED: &str = include_str!("../../../testdata/manifest/05-deploy/expected.json");
const NODE_COMPOSE: &str = include_str!("../../../testdata/manifest/06-kms-node/app-compose.json");
const ORG: &str = "01920000-0000-7000-8000-000000000003";
const OTHER_APP: &str = "01920000-0000-7000-8000-000000000004";
const OTHER_ORG: &str = "01920000-0000-7000-8000-000000000005";
const ROUTE: &str = "revision.register";
const NOT_BEFORE: &str = "2026-06-01T00:00:00Z";
const NOT_AFTER: &str = "2026-06-01T01:00:00Z";

/// rcgen's own key pairs sign with randomized ECDSA; p256 signs per RFC 6979, so the same seed
/// gives the same certificate bytes on every run.
struct FixedKey {
    key: p256::ecdsa::SigningKey,
    point: Vec<u8>,
}

impl FixedKey {
    fn new(seed: u8) -> Self {
        let key = p256::ecdsa::SigningKey::from_bytes((&[seed; 32]).into()).unwrap();
        let point = key.verifying_key().to_sec1_point(false).as_bytes().to_vec();
        Self { key, point }
    }
}

impl PublicKeyData for FixedKey {
    fn der_bytes(&self) -> &[u8] {
        &self.point
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

impl rcgen::SigningKey for FixedKey {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        let signature: p256::ecdsa::Signature = self
            .key
            .try_sign(msg)
            .map_err(|_| rcgen::Error::RemoteKeyError)?;
        Ok(signature.to_der().as_bytes().to_vec())
    }
}

fn at(rfc3339: &str) -> SystemTime {
    chrono::DateTime::parse_from_rfc3339(rfc3339)
        .unwrap()
        .into()
}

struct Ca {
    key: FixedKey,
    params: CertificateParams,
    pem: String,
}

fn ca(seed: u8, serial: u64) -> Ca {
    let key = FixedKey::new(seed);
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "alpha-kms ca");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.not_before = at("2026-01-01T00:00:00Z").into();
    params.not_after = at("2046-01-01T00:00:00Z").into();
    params.serial_number = Some(SerialNumber::from(serial));
    let pem = params.self_signed(&key).unwrap().pem();
    Ca { key, params, pem }
}

/// The KMS's one-hour leaf profile, for a node or an Instance depending on `sans`.
fn leaf(issuer: &Ca, key: &FixedKey, sans: [String; 2], serial: u64) -> String {
    let issuer = Issuer::new(issuer.params.clone(), &issuer.key);
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params.subject_alt_names = sans
        .into_iter()
        .map(|s| SanType::URI(Ia5String::try_from(s).unwrap()))
        .collect();
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ClientAuth,
        ExtendedKeyUsagePurpose::ServerAuth,
    ];
    params.use_authority_key_identifier_extension = true;
    params.not_before = at(NOT_BEFORE).into();
    params.not_after = at(NOT_AFTER).into();
    params.serial_number = Some(SerialNumber::from(serial));
    params.signed_by(key, &issuer).unwrap().pem()
}

fn revision() -> ComposeHash {
    alpha_core::compose_hash(NODE_COMPOSE)
}

fn revision_san() -> String {
    format!("urn:alphacompute:revision:{}", revision())
}

fn deploy(field: &str) -> Value {
    serde_json::from_str::<Value>(DEPLOY_EXPECTED).unwrap()[field].clone()
}

fn request_for(app_id: Value) -> Value {
    json!({
        "payload": {"app_id": app_id, "compose": DEPLOY_COMPOSE},
        "signature": {
            "key_id": "01920000-0000-7000-8000-000000000001",
            "algorithm": "ed25519",
            "signature": BASE64_URL_SAFE_NO_PAD.encode([7u8; 64]),
        },
    })
}

fn request() -> Value {
    request_for(deploy("app_id"))
}

fn response() -> Value {
    json!({
        "compose_hash": deploy("compose_hash"),
        "app_id": deploy("app_id"),
        "org_id": ORG,
        "created_at": NOT_BEFORE,
    })
}

fn expected(request: &Value) -> Value {
    json!({
        "route": ROUTE,
        "request_sha256": receipt::request_sha256(request).unwrap(),
        "response": {
            "compose_hash": deploy("compose_hash"),
            "app_id": deploy("app_id"),
            "org_id": ORG,
        },
    })
}

fn typed(expected: &Value) -> Expected {
    serde_json::from_value(expected.clone()).unwrap()
}

/// The real CA, the node key and the node's leaf under that CA.
struct Node {
    ca: Ca,
    key: FixedKey,
    leaf: String,
}

fn node() -> Node {
    let ca = ca(1, 1);
    let key = FixedKey::new(2);
    let leaf = leaf(&ca, &key, [KMS_SAN.to_owned(), revision_san()], 2);
    Node { ca, key, leaf }
}

fn issue(key: &FixedKey, leaf: String, issued_at: &str) -> Receipt {
    receipt::issue(&key.key, leaf, ROUTE, &request(), response(), at(issued_at)).unwrap()
}

fn vector(request: &Value, expected: &Value, receipt: &Receipt, result: &str) -> Value {
    json!({
        "expected": expected,
        "kms_revisions": [revision()],
        "receipt": receipt,
        "request": request,
        "result": result,
    })
}

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/receipt")
}

/// Every file under `testdata/receipt`, each different from `valid.json` in one respect only.
fn vectors() -> Vec<(&'static str, Vec<u8>)> {
    let node = node();
    let request = request();
    let matching = expected(&request);
    let valid = issue(&node.key, node.leaf.clone(), NOT_BEFORE);

    let foreign_ca = ca(3, 3);
    let foreign_key = FixedKey::new(4);
    let foreign_leaf = leaf(
        &foreign_ca,
        &foreign_key,
        [KMS_SAN.to_owned(), revision_san()],
        4,
    );

    let instance_key = FixedKey::new(5);
    let instance_identity = format!(
        "alphacompute://{ORG}/{}/{}",
        deploy("app_id").as_str().unwrap(),
        hex::encode(Sha256::digest(instance_key.subject_public_key_info())),
    );
    let instance_leaf = leaf(
        &node.ca,
        &instance_key,
        [instance_identity, revision_san()],
        5,
    );

    let mut wrong_route = matching.clone();
    wrong_route["route"] = json!("revision.revoke");

    let other_request = request_for(json!(OTHER_APP));
    let other_request_expected = expected(&other_request);

    let mut other_response = matching.clone();
    other_response["response"]["org_id"] = json!(OTHER_ORG);

    let mut tampered = valid.clone();
    tampered.document["response"]["org_id"] = json!(OTHER_ORG);

    let files = [
        ("valid.json", vector(&request, &matching, &valid, "ok")),
        (
            "wrong-ca.json",
            vector(
                &request,
                &matching,
                &issue(&foreign_key, foreign_leaf, NOT_BEFORE),
                "foreign_certificate",
            ),
        ),
        (
            "instance-leaf.json",
            vector(
                &request,
                &matching,
                &issue(&instance_key, instance_leaf, NOT_BEFORE),
                "foreign_certificate",
            ),
        ),
        (
            "wrong-route.json",
            vector(&request, &wrong_route, &valid, "receipt_mismatch"),
        ),
        (
            "wrong-request.json",
            vector(
                &other_request,
                &other_request_expected,
                &valid,
                "receipt_mismatch",
            ),
        ),
        (
            "other-response.json",
            vector(&request, &other_response, &valid, "receipt_mismatch"),
        ),
        (
            "tampered-response.json",
            vector(&request, &other_response, &tampered, "signature_invalid"),
        ),
        (
            "issued-at-outside.json",
            vector(
                &request,
                &matching,
                &issue(&node.key, node.leaf.clone(), NOT_AFTER),
                "certificate_expired",
            ),
        ),
    ];
    let mut out = vec![("ca.pem", node.ca.pem.into_bytes())];
    // Canonical form keeps the bytes identical whether or not serde_json's `preserve_order` is
    // on, and the workspace build turns it on through other crates.
    out.extend(files.into_iter().map(|(name, v)| {
        let mut bytes = alpha_core::jcs(&v).unwrap();
        bytes.push(b'\n');
        (name, bytes)
    }));
    out
}

fn checked_in() -> Vec<(String, Value)> {
    let mut out: Vec<(String, Value)> = fs::read_dir(vectors_dir())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.ends_with(".json"))
        .map(|name| {
            let bytes = fs::read(vectors_dir().join(&name)).unwrap();
            (name, serde_json::from_slice(&bytes).unwrap())
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn ca_pem() -> String {
    fs::read_to_string(vectors_dir().join("ca.pem")).unwrap()
}

fn verify_vector(v: &Value) -> Result<Value, alpha_channel::Error> {
    let receipt: Receipt = serde_json::from_value(v["receipt"].clone()).unwrap();
    let revisions: Vec<ComposeHash> = serde_json::from_value(v["kms_revisions"].clone()).unwrap();
    receipt::verify(&receipt, &ca_pem(), &revisions, &typed(&v["expected"]))
}

#[test]
fn a_receipt_verifies_against_its_ca_with_the_matching_expectation() {
    let node = node();
    let issued = issue(&node.key, node.leaf, NOT_BEFORE);
    let verified = receipt::verify(
        &issued,
        &node.ca.pem,
        &[revision()],
        &typed(&expected(&request())),
    )
    .unwrap();
    assert_eq!(verified, response());
}

#[test]
fn receipt_vectors_regenerate_byte_for_byte() {
    let files = vectors();
    let dir = vectors_dir();
    if std::env::var_os("WRITE_VECTORS").is_some() {
        fs::create_dir_all(&dir).unwrap();
        for (name, bytes) in &files {
            fs::write(dir.join(name), bytes).unwrap();
        }
        return;
    }
    for (name, bytes) in &files {
        let on_disk = fs::read(dir.join(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(on_disk == *bytes, "{name} does not regenerate");
    }
    let mut listed: Vec<String> = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    listed.sort();
    let mut generated: Vec<String> = files.iter().map(|(n, _)| (*n).to_owned()).collect();
    generated.sort();
    assert_eq!(listed, generated);
}

#[test]
fn every_receipt_vector_gives_its_recorded_result() {
    let vectors = checked_in();
    assert_eq!(vectors.len(), 8);
    for (name, v) in &vectors {
        assert_eq!(
            receipt::request_sha256(&v["request"]).unwrap(),
            v["expected"]["request_sha256"],
            "{name}"
        );
        match (verify_vector(v), v["result"].as_str().unwrap()) {
            (Ok(response), "ok") => assert_eq!(response, v["receipt"]["document"]["response"]),
            (Err(e), result) => assert_eq!(e.code(), result, "{name}: {e}"),
            (Ok(_), result) => panic!("{name}: accepted, expected {result}"),
        }
    }
}

#[test]
fn receipt_checks_at_the_edges_of_the_vectors() {
    let valid: Value =
        serde_json::from_slice(&fs::read(vectors_dir().join("valid.json")).unwrap()).unwrap();
    let code = |v: &Value| verify_vector(v).map(|_| "ok").unwrap_or_else(|e| e.code());

    let mut v = valid.clone();
    v["expected"]["response"] = json!({});
    assert_eq!(code(&v), "ok");

    let mut v = valid.clone();
    v["expected"]["response"]["missing"] = json!("x");
    assert_eq!(code(&v), "receipt_mismatch");

    let mut v = valid.clone();
    v["kms_revisions"] = json!([]);
    assert_eq!(code(&v), "unknown_revision");

    let mut v = valid.clone();
    v["receipt"]["certificate_chain"] = json!([]);
    assert_eq!(code(&v), "foreign_certificate");

    let mut v = valid.clone();
    let leaf_pem = v["receipt"]["certificate_chain"][0].clone();
    v["receipt"]["certificate_chain"] = json!([leaf_pem, ca_pem()]);
    assert_eq!(code(&v), "foreign_certificate");

    let node = node();
    let mut v = valid.clone();
    v["receipt"] = json!(issue(&node.key, node.leaf.clone(), "2026-05-31T23:59:59Z"));
    assert_eq!(code(&v), "certificate_expired");
    v["receipt"] = json!(issue(&node.key, node.leaf.clone(), "2026-06-01T00:59:59Z"));
    assert_eq!(code(&v), "ok");

    let numeric = receipt::issue(
        &node.key.key,
        node.leaf,
        ROUTE,
        &request(),
        json!({"n": 1}),
        at(NOT_BEFORE),
    )
    .unwrap();
    v["receipt"] = json!(numeric);
    v["expected"]["response"] = json!({"n": 1.0});
    assert_eq!(code(&v), "ok");
}
