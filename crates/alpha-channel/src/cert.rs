//! Instance and KMS node certificates: their two URI SANs, their SPKI, and the check that a leaf
//! was signed by the pinned KMS CA and is valid at a given time. The chain is exactly leaf then CA, so there is
//! no path to build.

use std::time::SystemTime;

use alpha_core::{AppId, ComposeHash, OrgId};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;
use sha2::{Digest, Sha256};
use x509_parser::oid_registry::OID_SIG_ECDSA_WITH_SHA256;
use x509_parser::prelude::{FromDer, GeneralName, ParsedExtension, X509Certificate};

use crate::{Error, from_unix_seconds, unix_seconds};

/// The URI SAN every KMS node's leaf carries beside its Revision.
pub const KMS_SAN: &str = "alphacompute://kms";

pub fn uri_sans(cert: &[u8]) -> Result<Vec<String>, Error> {
    let (_, cert) = X509Certificate::from_der(cert)
        .map_err(|e| Error::Malformed(format!("certificate: {e}")))?;
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

/// The DNS-name SANs, in certificate order. An Instance leaf carries the two of
/// [`app_dns_name`] and [`revision_dns_name`]; a KMS node's leaf carries none.
pub fn dns_sans(cert: &[u8]) -> Result<Vec<String>, Error> {
    let (_, cert) = X509Certificate::from_der(cert)
        .map_err(|e| Error::Malformed(format!("certificate: {e}")))?;
    Ok(cert
        .extensions()
        .iter()
        .filter_map(|ext| match ext.parsed_extension() {
            ParsedExtension::SubjectAlternativeName(san) => Some(&san.general_names),
            _ => None,
        })
        .flatten()
        .filter_map(|name| match name {
            GeneralName::DNSName(dns) => Some((*dns).to_owned()),
            _ => None,
        })
        .collect())
}

/// The suffix of an Instance leaf's DNS names. `.invalid` (RFC 6761) never resolves, so the names
/// identify an App or a Revision and can never be a host a client connects to.
pub const INSTANCE_DNS_SUFFIX: &str = "alphacompute.invalid";

/// `<app id>.<org id>.app.alphacompute.invalid`: the App, for a peer that can match a client
/// certificate only by a DNS name (a Fortanix DSM trusted-CA App, PRD-06 I1). It says nothing the
/// first URI SAN does not; the KMS derives it from the same ids.
pub fn app_dns_name(org_id: OrgId, app_id: AppId) -> String {
    format!("{app_id}.{org_id}.app.{INSTANCE_DNS_SUFFIX}")
}

/// `<hex 1-32>.<hex 33-64>.<app id>.<org id>.revision.alphacompute.invalid`: the Revision of that
/// App, the compose hash split in two because a DNS label holds at most 63 characters.
pub fn revision_dns_name(org_id: OrgId, app_id: AppId, compose_hash: ComposeHash) -> String {
    let halves: Vec<String> = compose_hash
        .as_bytes()
        .chunks(16)
        .map(hex::encode)
        .collect();
    format!(
        "{}.{app_id}.{org_id}.revision.{INSTANCE_DNS_SUFFIX}",
        halves.join(".")
    )
}

pub fn spki_of(cert: &[u8]) -> Result<Vec<u8>, Error> {
    let (_, cert) = X509Certificate::from_der(cert)
        .map_err(|e| Error::Malformed(format!("certificate: {e}")))?;
    Ok(cert.public_key().raw.to_vec())
}

pub fn spki_sha256(cert: &[u8]) -> Option<[u8; 32]> {
    spki_of(cert).ok().map(|spki| Sha256::digest(spki).into())
}

/// The identity an Instance certificate carries: `alphacompute://<org>/<app>/<key sha256>`
/// then `urn:alphacompute:revision:sha256:<hex>`, in the order the KMS issues them.
#[derive(Clone, Debug)]
pub struct InstanceSans {
    pub org_id: OrgId,
    pub app_id: AppId,
    pub runtime_pubkey_sha256_hex: String,
    pub compose_hash: ComposeHash,
}

pub fn parse_instance_sans(sans: &[String]) -> Result<InstanceSans, Error> {
    let invalid = || Error::ForeignCertificate("certificate SANs are not an Instance's".into());
    let [identity, revision] = sans else {
        return Err(invalid());
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
    Ok(InstanceSans {
        org_id: org.parse().map_err(|_| invalid())?,
        app_id: app.parse().map_err(|_| invalid())?,
        runtime_pubkey_sha256_hex: alpha_core::hex_bytes::<32>(key)
            .map(|_| key.to_owned())
            .ok_or_else(invalid)?,
        compose_hash,
    })
}

/// A KMS node's leaf: `alphacompute://kms` then `urn:alphacompute:revision:sha256:<hex>`; returns
/// the Revision, which the caller checks against its allowlist.
pub fn parse_kms_sans(sans: &[String]) -> Result<ComposeHash, Error> {
    let not_node = || Error::ForeignCertificate("the leaf is not a KMS node's".into());
    let [kms, revision] = sans else {
        return Err(not_node());
    };
    if kms != KMS_SAN {
        return Err(not_node());
    }
    revision
        .strip_prefix("urn:alphacompute:revision:")
        .and_then(|s| s.parse().ok())
        .ok_or_else(not_node)
}

/// One PEM `CERTIFICATE` block and nothing else.
pub fn pem_to_der(pem: &str) -> Result<Vec<u8>, Error> {
    let (rest, pem) = x509_parser::pem::parse_x509_pem(pem.as_bytes())
        .map_err(|e| Error::Malformed(format!("certificate PEM: {e}")))?;
    if pem.label != "CERTIFICATE" || !rest.iter().all(u8::is_ascii_whitespace) {
        return Err(Error::Malformed(
            "certificate PEM is not exactly one CERTIFICATE block".into(),
        ));
    }
    Ok(pem.contents)
}

/// The leaf is signed with ecdsa-with-SHA256 by the CA's key and `notBefore ≤ now < notAfter`;
/// returns `(notBefore, notAfter)`.
pub fn verify_leaf(
    leaf_der: &[u8],
    ca_der: &[u8],
    now: SystemTime,
) -> Result<(SystemTime, SystemTime), Error> {
    let foreign = |m: &str| Error::ForeignCertificate(format!("leaf: {m}"));
    let (_, leaf) =
        X509Certificate::from_der(leaf_der).map_err(|_| foreign("not an X.509 certificate"))?;
    let (_, ca) = X509Certificate::from_der(ca_der)
        .map_err(|e| Error::Malformed(format!("CA certificate: {e}")))?;
    if leaf.signature_algorithm.algorithm != OID_SIG_ECDSA_WITH_SHA256 {
        return Err(foreign("not signed with ecdsa-with-SHA256"));
    }
    let key = VerifyingKey::from_public_key_der(ca.public_key().raw)
        .map_err(|_| Error::Malformed("the CA key is not P-256".into()))?;
    let signature = Signature::from_der(&leaf.signature_value.data)
        .map_err(|_| foreign("signature is not DER ECDSA"))?;
    key.verify(leaf.tbs_certificate.as_ref(), &signature)
        .map_err(|_| foreign("not signed by the KMS CA"))?;
    let now = unix_seconds(now)?;
    let validity = leaf.validity();
    let (not_before, not_after) = (
        validity.not_before.timestamp(),
        validity.not_after.timestamp(),
    );
    if now < not_before || now >= not_after {
        return Err(Error::CertificateExpired);
    }
    from_unix_seconds(not_before)
        .zip(from_unix_seconds(not_after))
        .ok_or_else(|| foreign("validity starts before 1970"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ORG: &str = "01920000-0000-7000-8000-000000000001";
    const APP: &str = "01920000-0000-7000-8000-000000000002";

    fn revision() -> String {
        format!(
            "urn:alphacompute:revision:{}",
            alpha_core::compose_hash("{}")
        )
    }

    #[wasm_bindgen_test::wasm_bindgen_test(unsupported = test)]
    fn instance_sans_parse_and_others_are_foreign() {
        let key = "ab".repeat(32);
        let sans = [format!("alphacompute://{ORG}/{APP}/{key}"), revision()];
        let id = parse_instance_sans(&sans).unwrap();
        assert_eq!(id.org_id.to_string(), ORG);
        assert_eq!(id.app_id.to_string(), APP);
        assert_eq!(id.runtime_pubkey_sha256_hex, key);
        assert_eq!(id.compose_hash, alpha_core::compose_hash("{}"));

        let node = ["alphacompute://kms".to_owned(), revision()];
        assert_eq!(
            parse_instance_sans(&node).unwrap_err().code(),
            "foreign_certificate"
        );
        assert!(parse_instance_sans(&[sans[0].clone()]).is_err());
        let short_key = [format!("alphacompute://{ORG}/{APP}/abcd"), revision()];
        assert!(parse_instance_sans(&short_key).is_err());
    }

    #[wasm_bindgen_test::wasm_bindgen_test(unsupported = test)]
    fn kms_sans_parse_and_others_are_foreign() {
        let node = [KMS_SAN.to_owned(), revision()];
        assert_eq!(
            parse_kms_sans(&node).unwrap(),
            alpha_core::compose_hash("{}")
        );

        let key = "ab".repeat(32);
        let instance = [format!("alphacompute://{ORG}/{APP}/{key}"), revision()];
        let three = [KMS_SAN.to_owned(), revision(), revision()];
        let wrong_first = ["alphacompute://kms/".to_owned(), revision()];
        let not_a_hash = [
            KMS_SAN.to_owned(),
            "urn:alphacompute:revision:sha256:abcd".to_owned(),
        ];
        for sans in [
            &instance[..],
            &node[..1],
            &three[..],
            &wrong_first[..],
            &not_a_hash[..],
        ] {
            assert_eq!(
                parse_kms_sans(sans).unwrap_err().code(),
                "foreign_certificate",
                "{sans:?}"
            );
        }
    }

    #[wasm_bindgen_test::wasm_bindgen_test(unsupported = test)]
    fn instance_dns_names_name_the_app_and_the_revision() {
        let (org, app) = (ORG.parse().unwrap(), APP.parse().unwrap());
        let hash = alpha_core::compose_hash("{}");
        let hex = hash.to_string().replace("sha256:", "");
        assert_eq!(
            app_dns_name(org, app),
            format!("{APP}.{ORG}.app.alphacompute.invalid")
        );
        let revision = revision_dns_name(org, app, hash);
        assert_eq!(
            revision,
            format!(
                "{}.{}.{APP}.{ORG}.revision.alphacompute.invalid",
                &hex[..32],
                &hex[32..]
            )
        );
        // Every label fits DNS's 63 characters and the name its 253.
        assert!(revision.len() <= 253);
        assert!(revision.split('.').all(|l| !l.is_empty() && l.len() <= 63));
        let other: AppId = "01920000-0000-7000-8000-000000000003".parse().unwrap();
        assert_ne!(app_dns_name(org, other), app_dns_name(org, app));
        assert_ne!(
            revision_dns_name(org, app, alpha_core::compose_hash("{ }")),
            revision
        );
    }

    #[wasm_bindgen_test::wasm_bindgen_test(unsupported = test)]
    fn pem_to_der_takes_one_certificate_block() {
        let pem = "-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n";
        assert_eq!(pem_to_der(pem).unwrap(), [1, 2, 3]);
        assert!(pem_to_der(&format!("{pem}{pem}")).is_err());
        assert!(pem_to_der(&pem.replace("CERTIFICATE", "PRIVATE KEY")).is_err());
        assert!(pem_to_der("").is_err());
    }
}
