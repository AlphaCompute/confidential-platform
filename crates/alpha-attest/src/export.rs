//! Evidence export (PRD-06 I2): the TDX quote and GPU reports `alpha-runtime` collects, bound to
//! a nonce a second verifier chose, so that verifier (Fortanix CCM, or an auditor) can appraise
//! the same pod alpha-kms appraised without a second workload.
//!
//! The quote is taken over `report_data(runtime key, export_nonce(caller nonce))`. The KMS's own
//! rules apply unchanged with the derived nonce: [`crate::kata::appraise_any`] (or
//! [`crate::appraise`]) over [`EvidenceExport::effective_nonce`]. The derived nonce is a hash, so
//! it is never a nonce alpha-kms minted, and an export can never be replayed to alpha-kms as an
//! attestation, whatever the caller passes.

use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{AnyEvidence, AppraisalError, report_data};

pub const EXPORT_FORMAT: &str = "alphacompute-evidence-export/1";
const EXPORT_DOMAIN: &[u8] = b"alphacompute/evidence-export/v1";

/// The nonce the quote is actually over: SHA-256 of the domain, a zero byte and the caller's
/// nonce.
pub fn export_nonce(caller_nonce: &[u8; 32]) -> [u8; 32] {
    Sha256::new()
        .chain_update(EXPORT_DOMAIN)
        .chain_update([0u8])
        .chain_update(caller_nonce)
        .finalize()
        .into()
}

/// The `report_data` an export's quote binds: the KMS's layout over the derived nonce.
pub fn export_report_data(runtime_pubkey_spki: &[u8], caller_nonce: &[u8; 32]) -> [u8; 64] {
    report_data(runtime_pubkey_spki, &export_nonce(caller_nonce), None)
}

/// `alphacompute-evidence-export/1`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceExport {
    pub format: String,
    /// The caller's nonce, base64url, as it was asked for.
    pub nonce: String,
    /// The runtime's P-256 SubjectPublicKeyInfo, base64url: the key `report_data` binds and the
    /// key of the runtime's Alpha leaf.
    pub runtime_pubkey: String,
    /// `alphacompute-evidence/2` from a Kata pod, `/1` from a prototype CVM: the same evidence
    /// the runtime sends alpha-kms, over [`export_report_data`].
    pub evidence: AnyEvidence,
    /// The runtime's current `[leaf, KMS CA]`, when it holds one, so the verifier can tie the
    /// pod it appraised to the Alpha identity it serves under. Unsigned by this export; check it
    /// against a pinned KMS CA.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub certificate_chain: Vec<String>,
}

impl EvidenceExport {
    /// Refuses an export that is not for `caller_nonce`, and returns the nonce and the key its
    /// evidence must be appraised against.
    pub fn binding(&self, caller_nonce: &[u8; 32]) -> Result<([u8; 32], Vec<u8>), AppraisalError> {
        use AppraisalError::*;
        if self.format != EXPORT_FORMAT {
            return Err(Unknown(format!("export format {:?}", self.format)));
        }
        let nonce = BASE64_URL_SAFE_NO_PAD
            .decode(&self.nonce)
            .ok()
            .and_then(|n| <[u8; 32]>::try_from(n).ok())
            .ok_or_else(|| Failed("export nonce is not 32 bytes base64url".into()))?;
        if nonce != *caller_nonce {
            return Err(Failed("the export is for another nonce".into()));
        }
        let spki = BASE64_URL_SAFE_NO_PAD
            .decode(&self.runtime_pubkey)
            .map_err(|_| Failed("export runtime_pubkey is not base64url".into()))?;
        Ok((export_nonce(caller_nonce), spki))
    }
}

/// The CCM input built from an export, once Fortanix says what CCM appraises.
// ponytail: F8 — whether CCM can appraise evidence alpha-runtime collected, and in which request
// format (quote and GPU reports as sent here, an Intel/NVIDIA-native bundle, or CCM's own agent
// output), is Fortanix's answer to F8. Until then nothing is sent in a CCM format.
pub fn ccm_input(_export: &EvidenceExport) -> Result<serde_json::Value, AppraisalError> {
    Err(AppraisalError::Unknown(
        "Fortanix has not said what evidence format CCM appraises (F8); use the \
         alphacompute-evidence-export/1 format"
            .into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EVIDENCE_FORMAT, Evidence};

    fn export(nonce: &[u8; 32]) -> EvidenceExport {
        EvidenceExport {
            format: EXPORT_FORMAT.into(),
            nonce: BASE64_URL_SAFE_NO_PAD.encode(nonce),
            runtime_pubkey: BASE64_URL_SAFE_NO_PAD.encode(b"spki"),
            evidence: Evidence {
                format: EVIDENCE_FORMAT.into(),
                quote: vec![1],
                event_log: vec![],
            }
            .into(),
            certificate_chain: vec![],
        }
    }

    #[test]
    fn the_quote_is_over_a_derived_nonce_never_the_callers() {
        let caller = [5u8; 32];
        let derived = export_nonce(&caller);
        assert_ne!(derived, caller);
        assert_ne!(export_nonce(&[6u8; 32]), derived);
        // Never the bytes a KMS attestation with the same nonce would bind.
        assert_ne!(
            export_report_data(b"spki", &caller),
            report_data(b"spki", &caller, None)
        );
        assert_eq!(
            export_report_data(b"spki", &caller),
            report_data(b"spki", &derived, None)
        );
    }

    #[test]
    fn an_export_binds_its_callers_nonce_and_key() {
        let caller = [5u8; 32];
        let (nonce, spki) = export(&caller).binding(&caller).unwrap();
        assert_eq!(
            (nonce, spki.as_slice()),
            (export_nonce(&caller), b"spki".as_slice())
        );
        assert!(export(&caller).binding(&[6u8; 32]).is_err());
        let mut other = export(&caller);
        other.format = "alphacompute-evidence/2".into();
        assert_eq!(
            other.binding(&caller).unwrap_err().code(),
            "attestation_unknown"
        );
        assert!(
            ccm_input(&export(&caller))
                .unwrap_err()
                .to_string()
                .contains("F8")
        );
    }
}
