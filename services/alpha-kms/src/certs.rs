//! P-256 certificates: the node's self-signed sealed-phase certificate, the `ca` root, the
//! one-hour leaves with exactly two URI SANs, and the checks the extractors run on them.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use alpha_core::{AppId, ComposeHash, OrgId};
use rcgen::string::Ia5String;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, SanType, SubjectPublicKeyInfo,
};
use rustls::RootCertStore;
use rustls::server::WebPkiClientVerifier;
use rustls::server::danger::ClientCertVerifier;
use rustls_pki_types::{CertificateDer, UnixTime};
use x509_parser::prelude::{FromDer, GeneralName, ParsedExtension, X509Certificate};

use crate::error::ApiError;

pub const LEAF_TTL: Duration = Duration::from_secs(3600);
pub const KMS_SAN: &str = "alphacompute://kms";

fn offset(t: SystemTime) -> time::OffsetDateTime {
    time::OffsetDateTime::from(t)
}

fn serial() -> rcgen::SerialNumber {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("the system RNG never fails");
    bytes[0] &= 0x7f;
    rcgen::SerialNumber::from(bytes.to_vec())
}

fn subject(cn: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn);
    dn
}

pub fn key_pair(pkcs8_der: &[u8]) -> KeyPair {
    KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8_der.into(), &PKCS_ECDSA_P256_SHA256)
        .expect("a P-256 key we generated")
}

/// Sealed phase: the listener speaks with the runtime key itself.
pub fn self_signed(key: &KeyPair, now: SystemTime) -> Vec<u8> {
    let mut params = CertificateParams::default();
    params.distinguished_name = subject("alpha-kms sealed node");
    params.subject_alt_names = vec![SanType::URI(Ia5String::try_from(KMS_SAN).unwrap())];
    params.not_before = offset(now);
    params.not_after = offset(now + Duration::from_secs(365 * 86400));
    params.serial_number = Some(serial());
    params
        .self_signed(key)
        .expect("self-signing cannot fail")
        .der()
        .to_vec()
}

/// The `ca` intermediate: a self-signed P-256 root; returns (PKCS#8 DER, certificate DER).
pub fn new_ca(now: SystemTime) -> (Vec<u8>, Vec<u8>) {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("key generation");
    let mut params = CertificateParams::default();
    params.distinguished_name = subject("alpha-kms ca");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.not_before = offset(now);
    params.not_after = offset(now + Duration::from_secs(20 * 365 * 86400));
    params.serial_number = Some(serial());
    let cert = params.self_signed(&key).expect("self-signing cannot fail");
    (key.serialize_der(), cert.der().to_vec())
}

/// A one-hour leaf from `ca` over a foreign SPKI with the two URI SANs and both EKUs.
pub fn issue_leaf(
    ca_key: &KeyPair,
    ca_cert_der: &[u8],
    spki_der: &[u8],
    sans: [String; 2],
    now: SystemTime,
) -> Result<Vec<u8>, ApiError> {
    let spki = SubjectPublicKeyInfo::from_der(spki_der)
        .map_err(|e| ApiError::malformed(format!("runtime_pubkey: {e}")))?;
    let issuer = Issuer::from_ca_cert_der(&ca_cert_der.into(), ca_key)
        .map_err(|e| ApiError::internal(format!("ca certificate: {e}")))?;
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params.subject_alt_names = sans
        .into_iter()
        .map(|s| Ia5String::try_from(s).map(SanType::URI))
        .collect::<Result<_, _>>()
        .map_err(|e| ApiError::internal(format!("san: {e}")))?;
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ClientAuth,
        ExtendedKeyUsagePurpose::ServerAuth,
    ];
    params.use_authority_key_identifier_extension = true;
    params.not_before = offset(now);
    params.not_after = offset(now + LEAF_TTL);
    params.serial_number = Some(serial());
    Ok(params
        .signed_by(&spki, &issuer)
        .map_err(|e| ApiError::internal(format!("leaf: {e}")))?
        .der()
        .to_vec())
}

pub fn instance_sans(
    org_id: OrgId,
    app_id: AppId,
    runtime_pubkey_sha256_hex: &str,
    compose_hash: ComposeHash,
) -> [String; 2] {
    [
        format!("alphacompute://{org_id}/{app_id}/{runtime_pubkey_sha256_hex}"),
        format!("urn:alphacompute:revision:{compose_hash}"),
    ]
}

pub fn node_sans(compose_hash: ComposeHash) -> [String; 2] {
    [
        KMS_SAN.to_owned(),
        format!("urn:alphacompute:revision:{compose_hash}"),
    ]
}

pub fn pem(der: &[u8]) -> String {
    use base64::Engine;
    let body = base64::prelude::BASE64_STANDARD.encode(der);
    let lines: Vec<&str> = body
        .as_bytes()
        .chunks(64)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect();
    format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        lines.join("\n")
    )
}

pub fn ca_verifier(ca_cert_der: &[u8]) -> Arc<dyn ClientCertVerifier> {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(ca_cert_der.to_vec()))
        .expect("the ca certificate parses");
    WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .expect("a verifier over one root")
}

/// Verifies `chain` to `ca` at `now` and returns the leaf's URI SANs.
pub fn verify_to_ca(
    verifier: &dyn ClientCertVerifier,
    chain: &[CertificateDer<'static>],
    now: SystemTime,
) -> Result<Vec<String>, ApiError> {
    let (leaf, intermediates) = chain
        .split_first()
        .ok_or_else(|| ApiError::new("cert_invalid", "no client certificate"))?;
    let now = UnixTime::since_unix_epoch(
        now.duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| ApiError::internal("clock before the epoch"))?,
    );
    verifier
        .verify_client_cert(leaf, intermediates, now)
        .map_err(|e| ApiError::new("cert_invalid", format!("client certificate: {e}")))?;
    uri_sans(leaf)
}

pub fn uri_sans(cert: &[u8]) -> Result<Vec<String>, ApiError> {
    let (_, cert) = X509Certificate::from_der(cert)
        .map_err(|e| ApiError::new("cert_invalid", format!("client certificate: {e}")))?;
    Ok(cert
        .extensions()
        .iter()
        .filter_map(|ext| match ext.parsed_extension() {
            ParsedExtension::SubjectAlternativeName(san) => Some(&san.general_names),
            _ => None,
        })
        .flatten()
        .filter_map(|name| match name {
            GeneralName::URI(uri) => Some((*uri).to_owned()),
            _ => None,
        })
        .collect())
}

pub fn spki_of(cert: &[u8]) -> Result<Vec<u8>, ApiError> {
    let (_, cert) = X509Certificate::from_der(cert)
        .map_err(|e| ApiError::new("cert_invalid", format!("client certificate: {e}")))?;
    Ok(cert.public_key().raw.to_vec())
}

/// The identity an Instance certificate carries: `alphacompute://<org>/<app>/<key sha256>`
/// and `urn:alphacompute:revision:sha256:<hex>`, nothing else.
pub struct InstanceIdentity {
    pub org_id: OrgId,
    pub app_id: AppId,
    pub runtime_pubkey_sha256_hex: String,
    pub compose_hash: ComposeHash,
}

pub fn parse_instance_sans(sans: &[String]) -> Result<InstanceIdentity, ApiError> {
    let invalid = || ApiError::new("cert_invalid", "certificate SANs are not an Instance's");
    let [a, b] = sans else {
        return Err(invalid());
    };
    let (identity, revision) = if a.starts_with("alphacompute://") {
        (a, b)
    } else {
        (b, a)
    };
    let parts: Vec<&str> = identity
        .strip_prefix("alphacompute://")
        .ok_or_else(invalid)?
        .split('/')
        .collect();
    let [org, app, key] = parts[..] else {
        return Err(invalid());
    };
    let compose_hash = revision
        .strip_prefix("urn:alphacompute:revision:")
        .and_then(|s| s.parse().ok())
        .ok_or_else(invalid)?;
    Ok(InstanceIdentity {
        org_id: org.parse().map_err(|_| invalid())?,
        app_id: app.parse().map_err(|_| invalid())?,
        runtime_pubkey_sha256_hex: alpha_core::hex_bytes::<32>(key)
            .map(|_| key.to_owned())
            .ok_or_else(invalid)?,
        compose_hash,
    })
}

#[cfg(test)]
mod tests {
    use rcgen::PublicKeyData;

    use super::*;

    #[test]
    fn leaf_chains_to_ca_and_carries_the_two_sans() {
        let now = SystemTime::now();
        let (ca_key_der, ca_cert) = new_ca(now);
        let ca_key = key_pair(&ca_key_der);
        let runtime = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let org = OrgId::mint();
        let app = AppId::mint();
        let hash = alpha_core::compose_hash("{}");
        let sans = instance_sans(org, app, &"ab".repeat(32), hash);
        let leaf = issue_leaf(
            &ca_key,
            &ca_cert,
            &runtime.subject_public_key_info(),
            sans.clone(),
            now,
        )
        .unwrap();
        let verifier = ca_verifier(&ca_cert);
        let chain = vec![CertificateDer::from(leaf.clone())];
        let got = verify_to_ca(verifier.as_ref(), &chain, now + Duration::from_secs(60)).unwrap();
        assert_eq!(got, sans);
        let id = parse_instance_sans(&got).unwrap();
        assert_eq!((id.org_id, id.app_id, id.compose_hash), (org, app, hash));
        assert!(
            verify_to_ca(
                verifier.as_ref(),
                &chain,
                now + LEAF_TTL + Duration::from_secs(1)
            )
            .is_err()
        );
        assert_eq!(spki_of(&leaf).unwrap(), runtime.subject_public_key_info());

        let (_, other_ca) = new_ca(now);
        assert_eq!(
            verify_to_ca(ca_verifier(&other_ca).as_ref(), &chain, now)
                .unwrap_err()
                .code,
            "cert_invalid"
        );
        let self_signed = self_signed(&runtime, now);
        assert_eq!(
            verify_to_ca(verifier.as_ref(), &[CertificateDer::from(self_signed)], now)
                .unwrap_err()
                .code,
            "cert_invalid"
        );
        assert!(parse_instance_sans(&node_sans(hash)).is_err());
        assert!(parse_instance_sans(&[sans[0].clone()]).is_err());
    }
}
