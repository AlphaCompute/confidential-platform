//! P-256 certificates: the node's self-signed sealed-phase certificate, the `ca` root, the
//! one-hour leaves with two URI SANs and an Instance's appraisal, and the checks the extractors run on them.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use alpha_channel::cert::{APPRAISAL_OID, LeafAppraisal};
use alpha_core::{AppId, ComposeHash, OrgId};
use rcgen::string::Ia5String;
use rcgen::{
    BasicConstraints, CertificateParams, CustomExtension, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
    SanType, SubjectPublicKeyInfo,
};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::WebPkiClientVerifier;
use rustls::server::danger::ClientCertVerifier;

use crate::error::ApiError;

pub const LEAF_TTL: Duration = Duration::from_secs(3600);
/// A node's leaf also names the `kms` Service: a guest's data hub reaches the KMS by it and
/// checks the name.
const KMS_DNS_NAMES: [&str; 2] = ["kms.alpha-kms.svc", "kms.alpha-kms.svc.cluster.local"];
pub use alpha_client::tls::KMS_SAN;

fn serial() -> Result<rcgen::SerialNumber, ApiError> {
    let mut bytes = crate::random::<16>()?;
    if let Some(first) = bytes.first_mut() {
        *first &= 0x7f;
    }
    Ok(rcgen::SerialNumber::from(bytes.to_vec()))
}

use crate::later;

fn subject(cn: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn);
    dn
}

pub fn key_pair(pkcs8_der: &[u8]) -> Result<KeyPair, ApiError> {
    KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8_der.into(), &PKCS_ECDSA_P256_SHA256)
        .map_err(|e| ApiError::internal(format!("key pair: {e}")))
}

/// Sealed phase: the listener speaks with the runtime key itself.
pub fn self_signed(key: &KeyPair, now: SystemTime) -> Result<Vec<u8>, ApiError> {
    let mut params = CertificateParams::default();
    params.distinguished_name = subject("alpha-kms sealed node");
    params.subject_alt_names = vec![SanType::URI(
        Ia5String::try_from(KMS_SAN).map_err(|e| ApiError::internal(format!("san: {e}")))?,
    )];
    params.not_before = now.into();
    params.not_after = later(now, Duration::from_secs(365 * 86400))?.into();
    params.serial_number = Some(serial()?);
    Ok(params
        .self_signed(key)
        .map_err(|e| ApiError::internal(format!("self-signed certificate: {e}")))?
        .der()
        .to_vec())
}

/// The `ca` intermediate: a self-signed P-256 root; returns (PKCS#8 DER, certificate DER).
pub fn new_ca(now: SystemTime) -> Result<(Vec<u8>, Vec<u8>), ApiError> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .map_err(|e| ApiError::internal(format!("ca key: {e}")))?;
    let mut params = CertificateParams::default();
    params.distinguished_name = subject("alpha-kms ca");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.not_before = now.into();
    params.not_after = later(now, Duration::from_secs(20 * 365 * 86400))?.into();
    params.serial_number = Some(serial()?);
    let cert = params
        .self_signed(&key)
        .map_err(|e| ApiError::internal(format!("ca certificate: {e}")))?;
    Ok((key.serialize_der(), cert.der().to_vec()))
}

/// A one-hour leaf from `ca` over a foreign SPKI with the two URI SANs, [`KMS_DNS_NAMES`] for a
/// node, both EKUs and, for an Instance, its appraisal.
pub fn issue_leaf(
    ca_key: &KeyPair,
    ca_cert_der: &[u8],
    spki_der: &[u8],
    sans: [String; 2],
    appraisal: Option<&LeafAppraisal>,
    now: SystemTime,
) -> Result<Vec<u8>, ApiError> {
    let spki = SubjectPublicKeyInfo::from_der(spki_der)
        .map_err(|e| ApiError::malformed(format!("runtime_pubkey: {e}")))?;
    let issuer = Issuer::from_ca_cert_der(&ca_cert_der.into(), ca_key)
        .map_err(|e| ApiError::internal(format!("ca certificate: {e}")))?;
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    let dns_names = match sans.first() {
        Some(san) if san == KMS_SAN => &KMS_DNS_NAMES[..],
        _ => &[],
    };
    params.subject_alt_names = sans
        .into_iter()
        .map(|s| Ia5String::try_from(s).map(SanType::URI))
        .chain(
            dns_names
                .iter()
                .map(|d| Ia5String::try_from(*d).map(SanType::DnsName)),
        )
        .collect::<Result<_, _>>()
        .map_err(|e| ApiError::internal(format!("san: {e}")))?;
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ClientAuth,
        ExtendedKeyUsagePurpose::ServerAuth,
    ];
    params.use_authority_key_identifier_extension = true;
    params.not_before = now.into();
    params.not_after = later(now, LEAF_TTL)?.into();
    params.serial_number = Some(serial()?);
    if let Some(appraisal) = appraisal {
        let der = appraisal
            .to_der()
            .map_err(|e| ApiError::internal(e.to_string()))?;
        params.custom_extensions = vec![CustomExtension::from_oid_content(&APPRAISAL_OID, der)];
    }
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
    pem::encode(&pem::Pem::new("CERTIFICATE", der))
}

pub fn ca_verifier(ca_cert_der: &[u8]) -> Result<Arc<dyn ClientCertVerifier>, ApiError> {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(ca_cert_der.to_vec()))
        .map_err(|e| ApiError::internal(format!("ca certificate: {e}")))?;
    WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|e| ApiError::internal(format!("client verifier: {e}")))
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
    alpha_client::tls::uri_sans(cert).map_err(|e| ApiError::new("cert_invalid", e.to_string()))
}

pub fn spki_of(cert: &[u8]) -> Result<Vec<u8>, ApiError> {
    alpha_client::tls::spki_of(cert).map_err(|e| ApiError::new("cert_invalid", e.to_string()))
}

pub use alpha_client::tls::InstanceSans as InstanceIdentity;

pub fn parse_instance_sans(sans: &[String]) -> Result<InstanceIdentity, ApiError> {
    alpha_client::tls::parse_instance_sans(sans)
        .map_err(|e| ApiError::new("cert_invalid", e.to_string()))
}

#[cfg(test)]
mod tests {
    use rcgen::PublicKeyData;

    use super::*;

    #[test]
    fn leaf_chains_to_ca_and_carries_the_two_sans_and_the_appraisal() {
        let now = SystemTime::now();
        let (ca_key_der, ca_cert) = new_ca(now).unwrap();
        let ca_key = key_pair(&ca_key_der).unwrap();
        let runtime = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let org = OrgId::mint();
        let app = AppId::mint();
        let hash = alpha_core::compose_hash("{}");
        let sans = instance_sans(org, app, &"ab".repeat(32), hash);
        let appraisal = LeafAppraisal {
            tcb_status: "OutOfDate".into(),
            advisories: vec!["INTEL-SA-01397".into()],
            policy_version: 7,
            os_image: "kata-b300/32c-256g".into(),
            gpu_count: 1,
        };
        let leaf = issue_leaf(
            &ca_key,
            &ca_cert,
            &runtime.subject_public_key_info(),
            sans.clone(),
            Some(&appraisal),
            now,
        )
        .unwrap();
        let (_, cert) = x509_parser::parse_x509_certificate(&leaf).unwrap();
        let ext = cert
            .extensions()
            .iter()
            .find(|e| e.oid.to_id_string() == "2.25.1858292143.1688857791.1295186308")
            .unwrap();
        assert!(!ext.critical);
        let json = r#"{"advisories":["INTEL-SA-01397"],"format":"alphacompute-appraisal/1","gpu_count":1,"os_image":"kata-b300/32c-256g","policy_version":7,"tcb_status":"OutOfDate"}"#;
        let mut utf8_string = vec![0x0c, 0x81, json.len() as u8];
        utf8_string.extend_from_slice(json.as_bytes());
        assert_eq!(ext.value, utf8_string);
        let mut first = CertificateParams::default();
        first.custom_extensions = vec![CustomExtension::from_oid_content(
            &[2, 25, 7686831627720934303],
            utf8_string,
        )];
        let first = first.self_signed(&runtime).unwrap();
        assert_eq!(
            alpha_channel::cert::leaf_appraisal(first.der()).unwrap(),
            Some(appraisal.clone())
        );
        assert_eq!(
            alpha_channel::cert::leaf_appraisal(&leaf).unwrap(),
            Some(appraisal)
        );
        let verifier = ca_verifier(&ca_cert).unwrap();
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

        let (_, other_ca) = new_ca(now).unwrap();
        assert_eq!(
            verify_to_ca(ca_verifier(&other_ca).unwrap().as_ref(), &chain, now)
                .unwrap_err()
                .code,
            "cert_invalid"
        );
        let self_signed = self_signed(&runtime, now).unwrap();
        assert_eq!(
            alpha_channel::cert::leaf_appraisal(&self_signed).unwrap(),
            None
        );
        assert_eq!(
            verify_to_ca(verifier.as_ref(), &[CertificateDer::from(self_signed)], now)
                .unwrap_err()
                .code,
            "cert_invalid"
        );
        assert!(parse_instance_sans(&node_sans(hash)).is_err());

        let node_leaf = issue_leaf(
            &ca_key,
            &ca_cert,
            &runtime.subject_public_key_info(),
            node_sans(hash),
            None,
            now,
        )
        .unwrap();
        let named = |leaf: &[u8], name: &'static str| {
            let der = CertificateDer::from(leaf.to_vec());
            let parsed = rustls::server::ParsedCertificate::try_from(&der).unwrap();
            let name = rustls::pki_types::ServerName::try_from(name).unwrap();
            rustls::client::verify_server_name(&parsed, &name).is_ok()
        };
        assert!(named(&node_leaf, "kms.alpha-kms.svc"));
        let (aa, _) = alpha_core::registry_auth("regcred", "");
        assert!(aa.contains(&format!("url = \"https://{}:8443\"", KMS_DNS_NAMES[0])));
        assert!(named(&node_leaf, "kms.alpha-kms.svc.cluster.local"));
        assert!(!named(&node_leaf, "kms.other.svc"));
        assert!(!named(&leaf, "kms.alpha-kms.svc"));
        assert_eq!(uri_sans(&node_leaf).unwrap(), node_sans(hash));
        assert!(parse_instance_sans(&[sans[0].clone()]).is_err());
    }
}
