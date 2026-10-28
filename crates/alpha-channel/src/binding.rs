//! The statement that ties a browser-trusted certificate to an attested Instance. Whoever
//! controls a zone can get a public certificate for its names, so such a certificate alone says
//! nothing about where its key lives; the Instance signs, with its leaf key, the hash of the key
//! it serves a name with. The layout is shroud-go's edge binding, so either side verifies both.

use std::time::SystemTime;

use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use p256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::pkcs8::DecodePublicKey;
use sha2::{Digest, Sha256};

use crate::cert::{self, InstanceSans};
use crate::{Error, rfc3339, sha256_label};

/// Where the Endpoint serves its [`SignedBinding`] on its public name.
pub const PATH: &str = "/.well-known/alphacompute/binding";
const FORMAT: &str = "alphacompute-edge-binding/1";
/// Keeps a binding's signature apart from every other one the Instance key makes.
const CONTEXT: &[u8] = b"alphacompute/edge-binding/v1\n";

/// The Instance serves `name` with the key whose SubjectPublicKeyInfo hashes to `spki_sha256`
/// until `not_after`.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub format: String,
    pub name: String,
    pub spki_sha256: String,
    pub not_after: String,
}

/// The [`Binding`]'s JSON as signed, the base64url DER ECDSA signature over
/// `SHA-256(CONTEXT || statement)` by the Instance leaf's key, and the leaf then the KMS CA in PEM.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct SignedBinding {
    pub statement: String,
    pub signature: String,
    pub chain_pem: String,
}

/// What lets a verifier appraise the TD without the KMS: the evidence the leaf's key was attested
/// with, whose `report_data` binds that key and `nonce` as [`alpha_attest::report_data`] lays
/// out, the init-data `MRCONFIGID` names, and Intel's collateral for the quote. Intel signs the
/// collateral, so it comes through the App unharmed or not at all.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attestation {
    pub evidence: alpha_attest::KataEvidence,
    /// base64url, 32 bytes.
    pub nonce: String,
    pub init_data: String,
    pub collateral: alpha_attest::Collateral,
}

fn digest(statement: &str) -> [u8; 32] {
    Sha256::new()
        .chain_update(CONTEXT)
        .chain_update(statement)
        .finalize()
        .into()
}

/// Signs that `key`'s Instance, whose leaf and CA are `chain_pem`, serves `name` with `served`.
pub fn sign(
    key: &SigningKey,
    chain_pem: String,
    name: &str,
    served: &[u8],
) -> Result<SignedBinding, Error> {
    let statement = serde_json::to_string(&Binding {
        format: FORMAT.into(),
        name: name.into(),
        spki_sha256: sha256_label(&cert::spki_of(served)?),
        not_after: rfc3339(cert::not_after(served)?)?,
    })
    .map_err(|e| Error::Malformed(e.to_string()))?;
    let signature: Signature = key
        .sign_prehash(&digest(&statement))
        .map_err(|e| Error::SignatureInvalid(format!("binding: {e}")))?;
    Ok(SignedBinding {
        statement,
        signature: BASE64_URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes()),
        chain_pem,
    })
}

/// The Instance that signed `signed` under `kms_ca` and its statement, refused unless the
/// statement names `name` and the key of `served`, the certificate that connection presented, and
/// is current at `now`.
pub fn verify(
    signed: &SignedBinding,
    name: &str,
    served: &[u8],
    kms_ca: &[u8],
    now: SystemTime,
) -> Result<(InstanceSans, Binding), Error> {
    let leaf = leaf(signed)?;
    cert::verify_leaf(&leaf, kms_ca, now)?;
    let instance = cert::parse_instance_sans(&cert::uri_sans(&leaf)?)?;
    let binding = open(signed, &leaf, name, now)?;
    if binding.spki_sha256 != sha256_label(&cert::spki_of(served)?) {
        return Err(Error::ForeignCertificate(
            "the name is served with a key the Instance did not sign for".into(),
        ));
    }
    Ok((instance, binding))
}

/// The statement, refused unless the key of `leaf`, the binding's [`leaf`], signed it, it names
/// `name` and it is current at `now`. Neither the leaf's issuer nor the served certificate is checked: a
/// caller that trusts the key for another reason, a quote that binds it, checks what it needs.
pub(crate) fn open(
    signed: &SignedBinding,
    leaf: &[u8],
    name: &str,
    now: SystemTime,
) -> Result<Binding, Error> {
    let key = VerifyingKey::from_public_key_der(&cert::spki_of(leaf)?)
        .map_err(|_| Error::ForeignCertificate("the binding leaf is not P-256".into()))?;
    let signature = BASE64_URL_SAFE_NO_PAD
        .decode(&signed.signature)
        .ok()
        .and_then(|der| Signature::from_der(&der).ok())
        .ok_or_else(|| Error::Malformed("binding signature is not base64url DER".into()))?;
    key.verify_prehash(&digest(&signed.statement), &signature)
        .map_err(|_| Error::SignatureInvalid("the binding is not signed by its leaf".into()))?;
    let binding: Binding = serde_json::from_str(&signed.statement)
        .map_err(|e| Error::Malformed(format!("binding statement: {e}")))?;
    if binding.format != FORMAT {
        return Err(Error::Malformed(format!(
            "binding format {:?}",
            binding.format
        )));
    }
    if !binding.name.eq_ignore_ascii_case(name) {
        return Err(Error::ForeignCertificate(format!(
            "the binding is for {}, not {name}",
            binding.name
        )));
    }
    let expires = chrono::DateTime::parse_from_rfc3339(&binding.not_after)
        .map_err(|e| Error::Malformed(format!("binding not_after: {e}")))?;
    if chrono::DateTime::<chrono::Utc>::from(now) >= expires {
        return Err(Error::CertificateExpired);
    }
    Ok(binding)
}

/// The DER of the binding's leaf, unchecked.
pub(crate) fn leaf(signed: &SignedBinding) -> Result<Vec<u8>, Error> {
    let (_, leaf) = x509_parser::pem::parse_x509_pem(signed.chain_pem.as_bytes())
        .map_err(|e| Error::Malformed(format!("binding chain: {e}")))?;
    Ok(leaf.contents)
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use std::time::Duration;

    use p256::pkcs8::EncodePrivateKey;

    use super::*;

    const ORG: &str = "01920000-0000-7000-8000-000000000001";
    const APP: &str = "01920000-0000-7000-8000-000000000002";
    const NAME: &str = "hello.alphacompute.cc";

    struct Instance {
        key: SigningKey,
        chain_pem: String,
        ca: Vec<u8>,
    }

    fn instance() -> Instance {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca = rcgen::CertificateParams::default();
        ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca = ca.self_signed(&ca_key).unwrap();
        let issuer = rcgen::Issuer::new(rcgen::CertificateParams::default(), &ca_key);
        let key = SigningKey::from_bytes(&[7u8; 32].into()).unwrap();
        let leaf_key = rcgen::KeyPair::try_from(key.to_pkcs8_der().unwrap().as_bytes()).unwrap();
        let mut leaf = rcgen::CertificateParams::default();
        leaf.subject_alt_names = [
            format!("alphacompute://{ORG}/{APP}/{}", "ab".repeat(32)),
            format!(
                "urn:alphacompute:revision:{}",
                alpha_core::compose_hash("{}")
            ),
        ]
        .into_iter()
        .map(|uri| rcgen::SanType::URI(uri.try_into().unwrap()))
        .collect();
        let leaf = leaf.signed_by(&leaf_key, &issuer).unwrap();
        Instance {
            key,
            chain_pem: format!("{}{}", leaf.pem(), ca.pem()),
            ca: ca.der().to_vec(),
        }
    }

    fn public_cert() -> Vec<u8> {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec![NAME.into()]).unwrap();
        params.not_after = rcgen::date_time_ymd(2100, 1, 1);
        params.self_signed(&key).unwrap().der().to_vec()
    }

    #[test]
    fn a_binding_verifies_only_for_its_name_served_key_and_kms_ca() {
        let now = SystemTime::now();
        let id = instance();
        let served = public_cert();
        let signed = sign(&id.key, id.chain_pem.clone(), NAME, &served).unwrap();
        let (sans, _) = verify(&signed, NAME, &served, &id.ca, now).unwrap();
        assert_eq!(sans.app_id.to_string(), APP);
        assert_eq!(sans.compose_hash, alpha_core::compose_hash("{}"));

        let refused = |signed: &SignedBinding, name: &str, served: &[u8], ca: &[u8]| {
            verify(signed, name, served, ca, now).unwrap_err().code()
        };
        assert_eq!(
            refused(&signed, "other.alphacompute.cc", &served, &id.ca),
            "foreign_certificate"
        );
        assert_eq!(
            refused(&signed, NAME, &public_cert(), &id.ca),
            "foreign_certificate"
        );
        assert_eq!(
            refused(&signed, NAME, &served, &instance().ca),
            "foreign_certificate"
        );
        let forged = SignedBinding {
            statement: signed.statement.replace(NAME, "evil.example"),
            ..sign(&id.key, id.chain_pem.clone(), NAME, &served).unwrap()
        };
        assert_eq!(
            refused(&forged, "evil.example", &served, &id.ca),
            "signature_invalid"
        );
        let other_key = SignedBinding {
            chain_pem: instance().chain_pem,
            ..sign(&id.key, id.chain_pem.clone(), NAME, &served).unwrap()
        };
        assert_eq!(
            refused(&other_key, NAME, &served, &id.ca),
            "foreign_certificate"
        );
        let later = SystemTime::UNIX_EPOCH + Duration::from_secs(4_102_444_800);
        assert_eq!(
            verify(&signed, NAME, &served, &id.ca, later)
                .unwrap_err()
                .code(),
            "certificate_expired"
        );
    }
}
