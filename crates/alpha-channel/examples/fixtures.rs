//! Writes the certificates under `testdata/channel/` that the tests read: a CA and an Instance
//! leaf in the KMS's profile for the compose in `app-compose.json`, a leaf with the same SANs
//! under another CA, and a leaf for another App under the same CA. Run once, commit the output.

#![allow(clippy::unwrap_used, clippy::expect_used)]

#[cfg(target_arch = "wasm32")]
fn main() {}

#[cfg(not(target_arch = "wasm32"))]
fn main() {
    use std::path::Path;

    use rcgen::string::Ia5String;
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
        IsCa, Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, PublicKeyData, SanType,
        date_time_ymd,
    };
    use sha2::{Digest, Sha256};

    const ORG: &str = "01920000-0000-7000-8000-000000000001";
    const APP: &str = "01920000-0000-7000-8000-000000000002";
    const OTHER_APP: &str = "01920000-0000-7000-8000-000000000003";

    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/channel");
    let compose = std::fs::read_to_string(dir.join("app-compose.json")).unwrap();
    let revision = format!(
        "urn:alphacompute:revision:{}",
        alpha_core::compose_hash(&compose)
    );

    let ca = |cn: &str| {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, cn);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.not_before = date_time_ymd(2026, 1, 1);
        params.not_after = date_time_ymd(2046, 1, 1);
        let cert = params.self_signed(&key).unwrap();
        (key, cert)
    };
    let leaf = |ca_key: &KeyPair, ca_cert: &rcgen::Certificate, key: &KeyPair, app: &str| {
        let spki_sha256 = hex::encode(Sha256::digest(key.subject_public_key_info()));
        let issuer = Issuer::from_ca_cert_der(ca_cert.der(), ca_key).unwrap();
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params.subject_alt_names = [
            format!("alphacompute://{ORG}/{app}/{spki_sha256}"),
            revision.clone(),
        ]
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
        params.not_before = date_time_ymd(2026, 1, 1);
        params.not_after = date_time_ymd(2036, 1, 1);
        params.signed_by(key, &issuer).unwrap().pem()
    };

    let (ca_key, ca_cert) = ca("alpha-kms ca");
    let (foreign_key, foreign_cert) = ca("alpha-kms ca");
    let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let write = |name: &str, text: String| std::fs::write(dir.join(name), text).unwrap();
    write("ca.pem", ca_cert.pem());
    write("leaf.pem", leaf(&ca_key, &ca_cert, &leaf_key, APP));
    write("leaf-key.pem", leaf_key.serialize_pem());
    write("foreign-ca.pem", foreign_cert.pem());
    write(
        "foreign-leaf.pem",
        leaf(&foreign_key, &foreign_cert, &leaf_key, APP),
    );
    write(
        "other-app-leaf.pem",
        leaf(&ca_key, &ca_cert, &leaf_key, OTHER_APP),
    );
}
