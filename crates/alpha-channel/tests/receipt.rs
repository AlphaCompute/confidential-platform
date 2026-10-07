#![cfg(not(target_arch = "wasm32"))]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::time::SystemTime;

use alpha_channel::cert::KMS_SAN;
use alpha_channel::receipt::{self, Expected};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use p256::ecdsa::signature::Signer;
use rcgen::string::Ia5String;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyUsagePurpose, PublicKeyData, SanType, SerialNumber,
};
use serde_json::{Value, json};

const DEPLOY_COMPOSE: &str = include_str!("../../../testdata/manifest/05-deploy/app-compose.json");
const DEPLOY_EXPECTED: &str = include_str!("../../../testdata/manifest/05-deploy/expected.json");
const NODE_COMPOSE: &str = include_str!("../../../testdata/manifest/06-kms-node/app-compose.json");
const ORG: &str = "01920000-0000-7000-8000-000000000003";
const ROUTE: &str = "revision.register";

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

fn ca_params(serial: u64) -> CertificateParams {
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
    params
}

struct Ca {
    key: FixedKey,
    params: CertificateParams,
    pem: String,
}

fn ca(seed: u8, serial: u64) -> Ca {
    let key = FixedKey::new(seed);
    let params = ca_params(serial);
    let pem = params.self_signed(&key).unwrap().pem();
    Ca { key, params, pem }
}

fn node_leaf(issuer: &Ca, key: &FixedKey, sans: [String; 2], serial: u64) -> String {
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
    params.not_before = at("2026-06-01T00:00:00Z").into();
    params.not_after = at("2026-06-01T01:00:00Z").into();
    params.serial_number = Some(SerialNumber::from(serial));
    params.signed_by(key, &issuer).unwrap().pem()
}

fn revision() -> alpha_core::ComposeHash {
    alpha_core::compose_hash(NODE_COMPOSE)
}

fn node_sans() -> [String; 2] {
    [
        KMS_SAN.to_owned(),
        format!("urn:alphacompute:revision:{}", revision()),
    ]
}

fn deploy(field: &str) -> Value {
    serde_json::from_str::<Value>(DEPLOY_EXPECTED).unwrap()[field].clone()
}

fn request() -> Value {
    json!({
        "payload": {"app_id": deploy("app_id"), "compose": DEPLOY_COMPOSE},
        "signature": {
            "key_id": "01920000-0000-7000-8000-000000000001",
            "algorithm": "ed25519",
            "signature": BASE64_URL_SAFE_NO_PAD.encode([7u8; 64]),
        },
    })
}

fn response() -> Value {
    json!({
        "compose_hash": deploy("compose_hash"),
        "app_id": deploy("app_id"),
        "org_id": ORG,
        "created_at": "2026-06-01T00:00:00Z",
    })
}

fn expected(request: &Value) -> Expected {
    Expected {
        route: ROUTE.into(),
        request_sha256: receipt::request_sha256(request).unwrap(),
        response: json!({
            "compose_hash": deploy("compose_hash"),
            "app_id": deploy("app_id"),
            "org_id": ORG,
        })
        .as_object()
        .unwrap()
        .clone(),
    }
}

#[test]
fn a_receipt_verifies_against_its_ca_with_the_matching_expectation() {
    let ca = ca(1, 1);
    let node = FixedKey::new(2);
    let leaf = node_leaf(&ca, &node, node_sans(), 2);
    let request = request();
    let issued = receipt::issue(
        &node.key,
        leaf,
        ROUTE,
        &request,
        response(),
        at("2026-06-01T00:00:00Z"),
    )
    .unwrap();
    let verified = receipt::verify(&issued, &ca.pem, &[revision()], &expected(&request)).unwrap();
    assert_eq!(verified, response());
}
