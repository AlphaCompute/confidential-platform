//! A KMS node's evidence, as the two parties that hand a node key material appraise it: the
//! serving node before a `join`, and a custodian's CLI before `bootstrap` or `unseal`. Both call
//! this one function, so neither can admit a node the other would refuse.
//!
//! A prototype node is appraised by [`crate::appraise`], a Kata node by `kata-tdx/1`'s TD checks
//! ([`kata::appraise_kata_cpu`]), exactly as an Instance is, with the node's X-Wing key bound in
//! `report_data[32..64]`. Then, for both: the node's Revision is listed in `kms_revisions` for
//! the profile it was appraised under. A Kata node runs on the CPU runtime class, so no GPU
//! backend is ever called for one, and one on the GPU class is refused.

use std::time::SystemTime;

use alpha_core::KmsRevisionKind;
use alpha_core::coco::{CPU_RUNTIME_CLASS, RuntimeClass};

use crate::kata::{self, AnyEvidence, EvidenceV2};
use crate::{AppraisalError, Appraised, Collateral, PlatformDocument, VerifiedQuote};

/// The whole appraisal of a node's evidence of either format, DCAP included.
pub fn appraise_node(
    evidence: &AnyEvidence,
    nonce: &[u8; 32],
    runtime_pubkey_spki: &[u8],
    xwing: &[u8],
    doc: &PlatformDocument,
    collateral: &Collateral,
    now: SystemTime,
) -> Result<Appraised, AppraisalError> {
    match evidence {
        AnyEvidence::V1(e) => {
            let appraised = crate::appraise(
                e,
                nonce,
                runtime_pubkey_spki,
                Some(xwing),
                doc,
                collateral,
                now,
            )?;
            listed(doc, appraised, KmsRevisionKind::PrototypeTdx)
        }
        AnyEvidence::V2(e) => {
            kata::check_cpu_kind(e)?;
            let verified = crate::verify_quote(&e.cpu.quote, collateral, &doc.policy, now)?;
            appraise_kata_node(e, verified, nonce, runtime_pubkey_spki, xwing, doc)
        }
    }
}

/// A Kata node over a quote [`crate::verify_quote`] has already verified: every step after DCAP.
/// Pure, so the cases are tests over synthetic quotes until B300 Kata captures exist (M1).
pub fn appraise_kata_node(
    evidence: &EvidenceV2,
    verified: VerifiedQuote,
    nonce: &[u8; 32],
    runtime_pubkey_spki: &[u8],
    xwing: &[u8],
    doc: &PlatformDocument,
) -> Result<Appraised, AppraisalError> {
    let cpu = kata::appraise_kata_cpu(
        evidence,
        verified,
        nonce,
        runtime_pubkey_spki,
        Some(xwing),
        doc,
    )?;
    if cpu.runtime_class() != RuntimeClass::Cpu {
        return Err(AppraisalError::Failed(format!(
            "a KMS node runs on the runtime class {CPU_RUNTIME_CLASS}"
        )));
    }
    // The CPU class: no GPU evidence and no backend, so the GPU decision needs no verdicts.
    let appraised = cpu.finish(doc.gpu_policy.as_ref(), &[])?;
    listed(doc, appraised, KmsRevisionKind::KataTdx)
}

/// The node's Revision is listed for the profile it was appraised under. The appraisal has
/// already found the hash in `kms_revisions`; this holds it to the entry's `kind` too, so a
/// prototype CVM whose compose were a Revision v2's bytes, or the reverse, is not a node.
fn listed(
    doc: &PlatformDocument,
    appraised: Appraised,
    kind: KmsRevisionKind,
) -> Result<Appraised, AppraisalError> {
    if doc
        .kms_revisions
        .iter()
        .any(|r| r.compose_hash == appraised.compose_hash && r.kind == kind)
    {
        return Ok(appraised);
    }
    Err(AppraisalError::Unknown(format!(
        "kms revision {} is not listed as a {} build",
        appraised.compose_hash,
        match kind {
            KmsRevisionKind::PrototypeTdx => "prototype-tdx",
            KmsRevisionKind::KataTdx => "kata-tdx",
        }
    )))
}

#[cfg(test)]
mod tests;
