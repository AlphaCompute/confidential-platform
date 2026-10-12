//! PRD-06 I5 against a real Postgres (`DATABASE_URL`; skipped without it): a Fortanix
//! CCM-attested workload gets a leaf of its own kind only inside a zone the platform document pins
//! and for an identity its organization allow-listed, and that leaf is never an Instance's.
//! Until Fortanix names the CCM certificate's identity fields (F5, F8) the route refuses every
//! CCM certificate; the steps after it run through `ccm::attest_ccm_verified`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use alpha_attest::ccm::{
    CCM_EVIDENCE_FORMAT, CcmAppraised, CcmCertificate, CcmEvidence, possession_digest,
};
use alpha_channel::cert::{parse_ccm_sans, parse_instance_sans};
use alpha_channel::receipt::{self, Expected};
use alpha_core::{OrgId, context};
use alpha_kms::ccm::{self, AttestCcmRequest};
use alpha_kms::{certs, instance, rfc3339};
use common::kata::publish;
use common::*;
use p256::ecdsa::signature::Signer;
use p256::pkcs8::DecodePrivateKey;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, PublicKeyData,
};
use reqwest::StatusCode;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

struct Zone {
    key: KeyPair,
    params: CertificateParams,
    cert: rcgen::Certificate,
}

impl Zone {
    fn new() -> Self {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "ccm zone root");
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let cert = params.self_signed(&key).unwrap();
        Self { key, params, cert }
    }

    fn spki_sha256(&self) -> String {
        format!(
            "sha256:{}",
            hex::encode(Sha256::digest(self.key.subject_public_key_info()))
        )
    }
}

/// The workload: its P-256 key the leaf certifies, and what CCM appraised.
struct Workload {
    key: KeyPair,
}

impl Workload {
    fn new() -> Self {
        Self {
            key: KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap(),
        }
    }

    fn spki(&self) -> Vec<u8> {
        self.key.subject_public_key_info()
    }

    fn request(&self, h: &Harness, org: OrgId, evidence: CcmEvidence) -> AttestCcmRequest {
        let nonce = instance::mint_nonce(&h.node.nonce_key, h.now()).unwrap();
        AttestCcmRequest {
            runtime_pubkey: b64(&self.spki()),
            nonce: b64(&nonce),
            org_id: org,
            evidence,
        }
    }

    /// An HTTPS client presenting `leaf_pem` with this workload's key.
    fn client(&self, leaf_pem: &str) -> reqwest::Client {
        client_with(&format!("{}{leaf_pem}", self.key.serialize_pem()))
    }
}

fn appraised(zone: &Zone, identity: &str) -> CcmAppraised {
    CcmAppraised {
        zone_ca_spki_sha256: zone.spki_sha256(),
        identity: identity.into(),
        certificate_sha256: format!("sha256:{}", "cc".repeat(32)),
    }
}

/// Evidence nothing reads on the seam's path.
fn placeholder() -> CcmEvidence {
    CcmEvidence {
        format: CCM_EVIDENCE_FORMAT.into(),
        certificate_chain: vec![],
        signature: vec![],
    }
}

async fn pin(h: &Harness, zones: &[&Zone]) {
    let mut doc = platform_document(KEYED);
    doc["version"] = json!(2);
    doc["fortanix_ccm"] =
        json!({ "zone_cas": zones.iter().map(|z| z.cert.pem()).collect::<Vec<_>>() });
    publish(h, doc).await;
}

fn allow(zone: &Zone, identity: &str) -> Value {
    json!({ "name": "inference-front", "zone_ca_spki_sha256": zone.spki_sha256(), "identity": identity })
}

async fn refused(
    h: &Harness,
    result: Result<Value, alpha_kms::error::ApiError>,
    code: &str,
    reason: &str,
) {
    let error = match result {
        Ok(reply) => panic!("issued: {reply}"),
        Err(e) => e,
    };
    assert_eq!(error.code, code, "{}", error.message);
    assert!(error.message.contains(reason), "{}", error.message);
    let (_, outcome, details) = h.audit("attest.ccm").await.pop().unwrap();
    assert_eq!(outcome, "denied");
    assert_eq!(details["code"], code);
}

#[tokio::test]
async fn an_allow_listed_ccm_identity_gets_a_leaf_of_its_own_kind_and_nothing_else_does() {
    let Some(h) = harness().await else {
        return;
    };
    let zone = Zone::new();
    let workload = Workload::new();
    let identity = "ccm-app:inference-front";

    // No `fortanix_ccm` in the platform document: every CCM evidence is refused.
    refused(
        &h,
        ccm::attest_ccm_verified(
            &h.node,
            &workload.request(&h, h.org, placeholder()),
            appraised(&zone, identity),
        )
        .await,
        "attestation_unknown",
        "pins no Fortanix CCM zone",
    )
    .await;

    pin(&h, &[&zone]).await;
    // Pinned, but the organization allow-listed nothing.
    refused(
        &h,
        ccm::attest_ccm_verified(
            &h.node,
            &workload.request(&h, h.org, placeholder()),
            appraised(&zone, identity),
        )
        .await,
        "attestation_unknown",
        "has not allow-listed this CCM identity",
    )
    .await;

    // The organization allow-lists the identity (route, receipt, idempotent).
    let admin = h.register_key(&h.root, 41).await;
    let body = h.signed(context::CCM_IDENTITY, allow(&zone, identity), &admin);
    let mut id = None;
    for _ in 0..2 {
        let (status, reply) = h.post("/v1/ccm-identities", body.clone()).await;
        assert_eq!(status, StatusCode::OK, "{reply}");
        verified(
            &h,
            &reply,
            "ccm_identity.register",
            &body,
            json!({ "org_id": h.org, "identity": identity, "zone_ca_spki_sha256": zone.spki_sha256() }),
        );
        let this = reply["id"].as_str().unwrap().to_owned();
        assert_eq!(id.get_or_insert(this.clone()), &this);
    }
    let id = id.unwrap();

    let request = workload.request(&h, h.org, placeholder());
    let reply = ccm::attest_ccm_verified(&h.node, &request, appraised(&zone, identity))
        .await
        .unwrap();
    let result = &reply["attestation_result"];
    assert_eq!(result["format"], "alphacompute-ccm-attestation-result/1");
    assert_eq!(result["org_id"], json!(h.org));
    assert_eq!(result["ccm_identity_id"], json!(id));
    assert_eq!(
        result["verifiers"],
        json!({
            "format": "alphacompute-verifiers/1",
            "attested_by": ["fortanix"],
            "composite": [{
                "verifier": "fortanix-ccm",
                "zone_ca_spki_sha256": zone.spki_sha256(),
                "certificate_sha256": format!("sha256:{}", "cc".repeat(32)),
            }],
        })
    );
    assert!(result.get("revision").is_none());

    // The leaf: a CCM identity's SANs, under the KMS CA, never an Instance's.
    let leaf_pem = reply["certificate_chain"][0].as_str().unwrap();
    let leaf = alpha_channel::cert::pem_to_der(leaf_pem).unwrap();
    let sans = certs::uri_sans(&leaf).unwrap();
    let ccm_sans = parse_ccm_sans(&sans).unwrap();
    assert_eq!(ccm_sans.org_id, h.org);
    assert_eq!(ccm_sans.ccm_identity_id.to_string(), id);
    assert_eq!(ccm_sans.zone_ca_spki_sha256, zone.spki_sha256());
    assert_eq!(
        ccm_sans.runtime_pubkey_sha256_hex,
        hex::encode(Sha256::digest(workload.spki()))
    );
    assert!(parse_instance_sans(&sans).is_err());
    assert_eq!(reply["certificate_chain"][1], json!(h.ca_pem));

    // The KMS's signature over the request, the result and the leaf.
    let signed = receipt::verify(
        &serde_json::to_vec(&reply["attestation_receipt"]).unwrap(),
        &h.ca_pem,
        &[h.node.compose_hash],
        &Expected {
            route: ccm::ATTEST_CCM_ROUTE.into(),
            request_sha256: receipt::request_sha256(&json!(request)).unwrap(),
            response: serde_json::Map::new(),
        },
    )
    .unwrap();
    assert_eq!(signed["attestation_result"], *result);
    assert_eq!(
        signed["certificate_sha256"],
        json!(format!("sha256:{}", hex::encode(Sha256::digest(&leaf))))
    );
    let (_, outcome, details) = h.audit("attest.ccm").await.pop().unwrap();
    assert_eq!(outcome, "ok");
    assert_eq!(&details, result);

    // Alpha's own Instance API does not take the CCM leaf: no Secret, no derived key.
    let client = workload.client(leaf_pem);
    let (status, reply) = send(client.get(format!("{}/v1/secrets/anything", h.url))).await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::UNAUTHORIZED, "cert_invalid"),
        "{reply}"
    );
    let (status, reply) = derive(&h, &client, json!({ "purpose": "connectors" })).await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::UNAUTHORIZED, "cert_invalid"),
        "{reply}"
    );

    // Another organization's name does not borrow this allow-listing.
    let other_org = OrgId::mint();
    let other_root = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
    let (status, reply) = h
        .post(
            "/v1/keys",
            root_key_registration(other_org, &other_root, h.now()),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    refused(
        &h,
        ccm::attest_ccm_verified(
            &h.node,
            &workload.request(&h, other_org, placeholder()),
            appraised(&zone, identity),
        )
        .await,
        "attestation_unknown",
        "has not allow-listed this CCM identity",
    )
    .await;

    // The same identity from a zone the platform document does not pin.
    let foreign = Zone::new();
    refused(
        &h,
        ccm::attest_ccm_verified(
            &h.node,
            &workload.request(&h, h.org, placeholder()),
            appraised(&foreign, identity),
        )
        .await,
        "attestation_unknown",
        "is not pinned",
    )
    .await;

    // Another identity in the pinned zone.
    refused(
        &h,
        ccm::attest_ccm_verified(
            &h.node,
            &workload.request(&h, h.org, placeholder()),
            appraised(&zone, "ccm-app:another"),
        )
        .await,
        "attestation_unknown",
        "has not allow-listed",
    )
    .await;

    // A row edited in the database no longer verifies under its signature.
    sqlx::query(
        "update ccm_identities set document = jsonb_set(document, '{name}', '\"renamed\"')",
    )
    .execute(&h.pool)
    .await
    .unwrap();
    refused(
        &h,
        ccm::attest_ccm_verified(
            &h.node,
            &workload.request(&h, h.org, placeholder()),
            appraised(&zone, identity),
        )
        .await,
        "signature_invalid",
        "",
    )
    .await;
    sqlx::query(
        "update ccm_identities set document = jsonb_set(document, '{name}', '\"inference-front\"')",
    )
    .execute(&h.pool)
    .await
    .unwrap();

    // Revoked by the organization: no more leaves.
    let revoke = h.signed(
        context::CONTROL,
        json!({ "id": id, "issued_at": rfc3339(h.now()) }),
        &admin,
    );
    let (status, reply) = h
        .post(&format!("/v1/ccm-identities/{id}/revoke"), revoke)
        .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    refused(
        &h,
        ccm::attest_ccm_verified(
            &h.node,
            &workload.request(&h, h.org, placeholder()),
            appraised(&zone, identity),
        )
        .await,
        "policy_denied",
        "revoked",
    )
    .await;
    // Registering it again does not bring it back.
    let (status, reply) = h.post("/v1/ccm-identities", body).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert!(reply["revoked_at"].is_string(), "{reply}");
}

/// The route runs the real CCM appraisal: a valid chain to the pinned zone and a valid
/// possession signature still end at the identity step, which refuses until F5 and F8.
#[tokio::test]
async fn the_route_refuses_every_ccm_certificate_until_fortanix_names_its_identity_fields() {
    let Some(h) = harness().await else {
        return;
    };
    let zone = Zone::new();
    pin(&h, &[&zone]).await;
    let ccm_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::ExplicitNoCa;
    let cert = params
        .signed_by(&ccm_key, &Issuer::from_params(&zone.params, &zone.key))
        .unwrap();
    let workload = Workload::new();
    let nonce = instance::mint_nonce(&h.node.nonce_key, h.now()).unwrap();
    let signing = p256::ecdsa::SigningKey::from_pkcs8_der(&ccm_key.serialize_der()).unwrap();
    let signature: p256::ecdsa::Signature =
        signing.sign(&possession_digest(&nonce, &workload.spki()).unwrap());
    let body = json!({
        "runtime_pubkey": b64(&workload.spki()),
        "nonce": b64(&nonce),
        "org_id": h.org,
        "evidence": {
            "format": CCM_EVIDENCE_FORMAT,
            "certificate_chain": [CcmCertificate(cert.der().to_vec())],
            "signature": b64(&signature.to_der().to_bytes()),
        },
    });
    let (status, reply) = h.post("/v1/attest/ccm", body.clone()).await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::FORBIDDEN, "attestation_unknown"),
        "{reply}"
    );
    assert!(
        reply["error"]["message"]
            .as_str()
            .unwrap()
            .contains("(F5, F8)"),
        "{reply}"
    );
    let rows = h.audit("attest.ccm").await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].1, "denied");

    // Signed for another key: refused before the identity step.
    let mut other = body.clone();
    other["runtime_pubkey"] = json!(b64(&Workload::new().spki()));
    let (status, reply) = h.post("/v1/attest/ccm", other).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{reply}");
    assert!(
        reply["error"]["message"]
            .as_str()
            .unwrap()
            .contains("did not sign"),
        "{reply}"
    );
    // A stale nonce never reaches the CCM steps.
    let mut stale = body;
    stale["nonce"] = json!(b64(&[0u8; 32]));
    let (status, reply) = h.post("/v1/attest/ccm", stale).await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::BAD_REQUEST, "nonce_invalid"),
        "{reply}"
    );
}
