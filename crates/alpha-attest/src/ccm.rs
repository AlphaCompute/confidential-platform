//! A Fortanix CCM attestation as evidence (PRD-06 I5): a workload that Fortanix Confidential
//! Computing Manager attested asks alpha-kms for a leaf, so it can call Alpha services.
//!
//! What CCM hands an attested workload, per Fortanix's public documentation, is an X.509
//! application certificate signed by the CCM zone's Root CA, which "issues certificates only to
//! enclaves presenting a valid attestation" (support.fortanix.com, "What is the structure of Cert
//! Chain?" and "Fortanix Confidential Computing Manager Usage Workflow"). So the evidence here is
//! that certificate chain, plus the workload's signature with the certificate's key over the KMS
//! nonce and the key it wants certified, which makes the evidence fresh and ties it to that key.
//!
//! Trust is pinned, never fetched: a zone's Root CA counts only if the release-signed platform
//! document names it in `fortanix_ccm.zone_cas`. Absent that field, every CCM evidence is refused.
//!
//! Which fields of a CCM certificate name the attested application and its image is not
//! published (vendor questions F5 and F8), so [`ccm_identity`] refuses every certificate until
//! Fortanix answers. Everything before it (the pinned zone, the chain, the validity, the
//! possession signature) runs and is tested now.

use std::time::SystemTime;

use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, SignatureVerificationAlgorithm, UnixTime};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use webpki::{EndEntityCert, KeyUsage, anchor_from_trusted_cert};

use crate::{AppraisalError, base64url};

pub const CCM_EVIDENCE_FORMAT: &str = "alphacompute-ccm-evidence/1";

/// The most certificates a chain may carry: the workload's and its intermediates.
const MAX_CHAIN: usize = 4;

/// The platform document's `fortanix_ccm`. Release-signed, so alpha-kms trusts exactly the CCM
/// zones AlphaCompute's release names; an organization then allow-lists identities within them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "CcmPolicyFields")]
pub struct CcmPolicy {
    /// PEM Root CA certificates of the CCM zones whose attestations count. Empty refuses all.
    pub zone_cas: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CcmPolicyFields {
    zone_cas: Vec<String>,
}

/// Refused at parse, so `alpha sign` never signs a zone no KMS could use.
impl TryFrom<CcmPolicyFields> for CcmPolicy {
    type Error = String;

    fn try_from(f: CcmPolicyFields) -> Result<Self, Self::Error> {
        for pem in &f.zone_cas {
            let der = CertificateDer::from_pem_slice(pem.as_bytes())
                .map_err(|e| format!("fortanix_ccm.zone_cas: not a PEM certificate: {e}"))?;
            anchor_from_trusted_cert(&der)
                .map_err(|e| format!("fortanix_ccm.zone_cas: not a trust anchor: {e}"))?;
            crate::spki_of(&der)?;
        }
        Ok(Self {
            zone_cas: f.zone_cas,
        })
    }
}

/// `alphacompute-ccm-evidence/1`: what a CCM-attested workload sends to `POST /v1/attest/ccm`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CcmEvidence {
    pub format: String,
    /// DER certificates, the workload's CCM certificate first, then any intermediates; the zone's
    /// Root CA itself need not be sent.
    pub certificate_chain: Vec<CcmCertificate>,
    /// The CCM certificate key's signature over [`possession_digest`], in that key's own scheme
    /// (ECDSA P-256 or P-384, RSA-PSS or Ed25519).
    #[serde(with = "base64url")]
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CcmCertificate(#[serde(with = "base64url")] pub Vec<u8>);

/// What the KMS established about a CCM-attested workload. Part of the CCM attestation result, so
/// it accepts fields it does not know.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CcmAppraised {
    /// `sha256:<hex>` of the SubjectPublicKeyInfo of the pinned zone Root CA the chain ends at.
    pub zone_ca_spki_sha256: String,
    /// The attested application as CCM's certificate names it (see [`ccm_identity`]).
    pub identity: String,
    /// `sha256:<hex>` of the workload's CCM certificate.
    pub certificate_sha256: String,
}

/// What the CCM certificate's key signs: the KMS nonce and the key the workload wants certified,
/// so the evidence is fresh and the leaf goes to the key the CCM-attested workload chose.
pub fn possession_digest(
    nonce: &[u8; 32],
    runtime_pubkey_spki: &[u8],
) -> Result<[u8; 32], AppraisalError> {
    alpha_core::signing_digest(
        alpha_core::context::CCM_POSSESSION,
        &json!({
            "nonce": BASE64_URL_SAFE_NO_PAD.encode(nonce),
            "runtime_pubkey": BASE64_URL_SAFE_NO_PAD.encode(runtime_pubkey_spki),
        }),
    )
    .map_err(|e| AppraisalError::Failed(format!("possession digest: {e}")))
}

const POSSESSION_ALGS: &[&dyn SignatureVerificationAlgorithm] = &[
    webpki::aws_lc_rs::ECDSA_P256_SHA256,
    webpki::aws_lc_rs::ECDSA_P384_SHA384,
    webpki::aws_lc_rs::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
    webpki::aws_lc_rs::ED25519,
];

fn sha256_label(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

/// A zone Root CA from the policy, with the SHA-256 of its SubjectPublicKeyInfo.
fn zone_cas(
    policy: Option<&CcmPolicy>,
) -> Result<Vec<(CertificateDer<'static>, String)>, AppraisalError> {
    let policy = policy.filter(|p| !p.zone_cas.is_empty()).ok_or_else(|| {
        AppraisalError::Unknown(
            "the platform document pins no Fortanix CCM zone (fortanix_ccm)".into(),
        )
    })?;
    policy
        .zone_cas
        .iter()
        .map(|pem| {
            let der = CertificateDer::from_pem_slice(pem.as_bytes()).map_err(|e| {
                AppraisalError::Unknown(format!(
                    "fortanix_ccm.zone_cas: not a PEM certificate: {e}"
                ))
            })?;
            let spki = crate::spki_of(&der).map_err(AppraisalError::Unknown)?;
            Ok((der, sha256_label(&spki)))
        })
        .collect()
}

/// `sha256:<hex>` of every pinned zone Root CA's SubjectPublicKeyInfo; refuses as
/// [`appraise_ccm`] does when the platform document pins none.
pub fn pinned_zones(policy: Option<&CcmPolicy>) -> Result<Vec<String>, AppraisalError> {
    Ok(zone_cas(policy)?.into_iter().map(|(_, sha)| sha).collect())
}

/// The CCM part of PRD-06 I5, in order: a pinned zone exists → the format → the chain verifies
/// to one pinned zone Root CA at `now` (signatures, validity, CA constraints, and the client-auth
/// key purpose if the certificate lists purposes) → the certificate's key signed this nonce and
/// key → the identity the certificate names, which refuses until F5/F8 (see [`ccm_identity`]).
pub fn appraise_ccm(
    evidence: &CcmEvidence,
    nonce: &[u8; 32],
    runtime_pubkey_spki: &[u8],
    policy: Option<&CcmPolicy>,
    now: SystemTime,
) -> Result<CcmAppraised, AppraisalError> {
    use AppraisalError::*;

    let zones = zone_cas(policy)?;
    if evidence.format != CCM_EVIDENCE_FORMAT {
        return Err(Unknown(format!(
            "ccm evidence format {:?}",
            evidence.format
        )));
    }
    let (leaf, intermediates) = evidence
        .certificate_chain
        .split_first()
        .ok_or_else(|| Failed("ccm evidence carries no certificate".into()))?;
    if evidence.certificate_chain.len() > MAX_CHAIN {
        return Err(Failed(format!(
            "ccm evidence carries more than {MAX_CHAIN} certificates"
        )));
    }
    let leaf_der = CertificateDer::from(leaf.0.as_slice());
    let ee =
        EndEntityCert::try_from(&leaf_der).map_err(|e| Failed(format!("ccm certificate: {e}")))?;
    let intermediates: Vec<CertificateDer<'_>> = intermediates
        .iter()
        .map(|c| CertificateDer::from(c.0.as_slice()))
        .collect();
    let time = UnixTime::since_unix_epoch(
        now.duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| Failed("now is before the epoch".into()))?,
    );
    let mut zone = None;
    let mut last = None;
    for (ca, spki_sha256) in &zones {
        let anchor = anchor_from_trusted_cert(ca)
            .map_err(|e| Unknown(format!("fortanix_ccm.zone_cas: {e}")))?;
        match ee.verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &[anchor],
            &intermediates,
            time,
            KeyUsage::client_auth(),
            None,
            None,
        ) {
            Ok(_) => {
                zone = Some(spki_sha256.clone());
                break;
            }
            Err(e) => last = Some(e),
        }
    }
    let zone_ca_spki_sha256 = zone.ok_or_else(|| {
        Failed(format!(
            "the ccm certificate does not chain to a pinned CCM zone: {}",
            last.map_or_else(|| "no zone".into(), |e| e.to_string())
        ))
    })?;

    let digest = possession_digest(nonce, runtime_pubkey_spki)?;
    if !POSSESSION_ALGS.iter().any(|alg| {
        ee.verify_signature(*alg, &digest, &evidence.signature)
            .is_ok()
    }) {
        return Err(Failed(
            "the ccm certificate's key did not sign this nonce and key".into(),
        ));
    }

    Ok(CcmAppraised {
        zone_ca_spki_sha256,
        identity: ccm_identity(&leaf.0)?,
        certificate_sha256: sha256_label(&leaf.0),
    })
}

/// The application and image a CCM certificate attests, as one string an organization can
/// allow-list.
// ponytail: F5, F8 — Fortanix has not published which fields of a CCM application certificate
// name the attested application, its image and its CCM account, nor whether they cover a Kata pod
// (F1). Guessing (the subject CN, say) could let any application of a zone pass for another, so
// every certificate is refused here until Fortanix names the fields.
pub fn ccm_identity(_certificate_der: &[u8]) -> Result<String, AppraisalError> {
    Err(AppraisalError::Unknown(
        "Fortanix has not named the CCM certificate fields that identify the attested application \
         (F5, F8); no CCM identity is accepted yet"
            .into(),
    ))
}

#[cfg(test)]
mod tests {
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
        IsCa, Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
    };
    use std::time::Duration;

    use super::*;

    const NONCE: [u8; 32] = [9; 32];

    struct Zone {
        key: KeyPair,
        params: CertificateParams,
        cert: rcgen::Certificate,
    }

    fn zone(name: &str) -> Zone {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, name);
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let cert = params.self_signed(&key).unwrap();
        Zone { key, params, cert }
    }

    fn app_cert(zone: &Zone, eku: ExtendedKeyUsagePurpose) -> (KeyPair, Vec<u8>) {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::ExplicitNoCa;
        params.extended_key_usages = vec![eku];
        params.not_after = (SystemTime::now() + Duration::from_secs(90 * 86_400)).into();
        let issuer = Issuer::from_params(&zone.params, &zone.key);
        let cert = params.signed_by(&key, &issuer).unwrap();
        (key, cert.der().to_vec())
    }

    fn sign(key: &KeyPair, nonce: &[u8; 32], spki: &[u8]) -> Vec<u8> {
        use p256::ecdsa::signature::Signer;
        use p256::pkcs8::DecodePrivateKey;
        let signing = p256::ecdsa::SigningKey::from_pkcs8_der(&key.serialize_der()).unwrap();
        let signature: p256::ecdsa::Signature =
            signing.sign(&possession_digest(nonce, spki).unwrap());
        signature.to_der().as_bytes().to_vec()
    }

    fn evidence(cert: Vec<u8>, signature: Vec<u8>) -> CcmEvidence {
        CcmEvidence {
            format: CCM_EVIDENCE_FORMAT.into(),
            certificate_chain: vec![CcmCertificate(cert)],
            signature,
        }
    }

    fn policy(zones: &[&Zone]) -> CcmPolicy {
        CcmPolicy {
            zone_cas: zones.iter().map(|z| z.cert.pem()).collect(),
        }
    }

    fn refusal(result: Result<CcmAppraised, AppraisalError>) -> (String, String) {
        let e = result.unwrap_err();
        (e.code().to_owned(), e.to_string())
    }

    #[test]
    fn a_valid_ccm_chain_and_possession_reach_the_identity_step_which_refuses_until_f5() {
        let ours = zone("ccm zone");
        let (key, cert) = app_cert(&ours, ExtendedKeyUsagePurpose::ClientAuth);
        let spki = b"runtime key".as_slice();
        let good = evidence(cert.clone(), sign(&key, &NONCE, spki));
        let now = SystemTime::now();

        let (code, reason) = refusal(appraise_ccm(
            &good,
            &NONCE,
            spki,
            Some(&policy(&[&ours])),
            now,
        ));
        assert_eq!(code, "attestation_unknown");
        assert!(reason.contains("(F5, F8)"), "{reason}");

        // Every earlier step refuses on its own, before the identity step.
        let other = zone("another zone");
        for (case, result, expect) in [
            (
                "no fortanix_ccm",
                appraise_ccm(&good, &NONCE, spki, None, now),
                "pins no Fortanix CCM zone",
            ),
            (
                "empty zone list",
                appraise_ccm(&good, &NONCE, spki, Some(&policy(&[])), now),
                "pins no Fortanix CCM zone",
            ),
            (
                "another zone",
                appraise_ccm(&good, &NONCE, spki, Some(&policy(&[&other])), now),
                "does not chain to a pinned CCM zone",
            ),
            (
                "expired",
                appraise_ccm(
                    &good,
                    &NONCE,
                    spki,
                    Some(&policy(&[&ours])),
                    now + Duration::from_secs(91 * 86_400),
                ),
                "does not chain to a pinned CCM zone",
            ),
            (
                "another nonce",
                appraise_ccm(&good, &[8; 32], spki, Some(&policy(&[&ours])), now),
                "did not sign this nonce and key",
            ),
            (
                "another key",
                appraise_ccm(&good, &NONCE, b"other key", Some(&policy(&[&ours])), now),
                "did not sign this nonce and key",
            ),
        ] {
            let (_, reason) = refusal(result);
            assert!(reason.contains(expect), "{case}: {reason}");
        }

        // Signed by another key than the certificate's.
        let (stranger, _) = app_cert(&ours, ExtendedKeyUsagePurpose::ClientAuth);
        let forged = evidence(cert.clone(), sign(&stranger, &NONCE, spki));
        let (_, reason) = refusal(appraise_ccm(
            &forged,
            &NONCE,
            spki,
            Some(&policy(&[&ours])),
            now,
        ));
        assert!(reason.contains("did not sign"), "{reason}");

        // A certificate issued only for another purpose.
        let (code_key, code_cert) = app_cert(&ours, ExtendedKeyUsagePurpose::CodeSigning);
        let signing_only = evidence(code_cert, sign(&code_key, &NONCE, spki));
        let (_, reason) = refusal(appraise_ccm(
            &signing_only,
            &NONCE,
            spki,
            Some(&policy(&[&ours])),
            now,
        ));
        assert!(reason.contains("does not chain"), "{reason}");

        // The zone's own Root CA is not a workload certificate.
        let root = evidence(ours.cert.der().to_vec(), sign(&ours.key, &NONCE, spki));
        assert!(appraise_ccm(&root, &NONCE, spki, Some(&policy(&[&ours])), now).is_err());

        let mut wrong_format = good.clone();
        wrong_format.format = "alphacompute-evidence/2".into();
        let (code, _) = refusal(appraise_ccm(
            &wrong_format,
            &NONCE,
            spki,
            Some(&policy(&[&ours])),
            now,
        ));
        assert_eq!(code, "attestation_unknown");
        let mut long = good.clone();
        long.certificate_chain = vec![CcmCertificate(cert); MAX_CHAIN + 1];
        let (_, reason) = refusal(appraise_ccm(
            &long,
            &NONCE,
            spki,
            Some(&policy(&[&ours])),
            now,
        ));
        assert!(reason.contains("more than"), "{reason}");
    }

    #[test]
    fn the_policy_refuses_unknown_fields_and_anything_but_certificates() {
        assert!(
            serde_json::from_value::<CcmPolicy>(json!({ "zone_cas": [], "token_url": "x" }))
                .is_err()
        );
        assert!(serde_json::from_value::<CcmPolicy>(json!({ "zone_cas": ["not pem"] })).is_err());
        let pem = zone("z").cert.pem();
        let parsed: CcmPolicy = serde_json::from_value(json!({ "zone_cas": [pem] })).unwrap();
        assert_eq!(parsed.zone_cas.len(), 1);
    }
}
