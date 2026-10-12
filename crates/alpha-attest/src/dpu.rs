//! NIC/DPU evidence (`nvidia-dpu/1`) for composite attestation: what a pod sends for every
//! BlueField DPU its Revision expects, the platform document's `dpu_policy`, and the seam between
//! them, shaped as the GPU's ([`crate::gpu`]).
//!
//! The evidence is what a BlueField BMC's Redfish `ComponentIntegrity.SPDMGetSignedMeasurements`
//! returns for our nonce: the SPDM `GET_MEASUREMENTS`/`MEASUREMENTS` transcript whose last response
//! is signed by the device's DICE leaf key, and the device's certificate chain (SPDM slot 0). A
//! [`DpuVerifier`] backend proves what it can of that and reduces it to [`VerifiedDpu`] claims;
//! [`check_dpus`] applies the Revision's DPU shape and the nonce, and is the step that decides.
//! What is and is not verified is listed in `docs/dpu-attestation.md`.

pub mod spdm;

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use alpha_core::coco::{DpuShape, MAX_DPUS};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{AppraisalError, base64url};

/// One DPU's evidence, as the BMC's Redfish answers it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DpuEvidence {
    /// Redfish `Version`: the SPDM version the transcript was made under, e.g. `1.1.0`.
    pub spdm_version: String,
    /// Redfish `HashingAlgorithm` (SPDM `BaseHashAlgo`), e.g. `TPM_ALG_SHA_512`.
    pub hashing_algorithm: String,
    /// Redfish `SigningAlgorithm` (SPDM `BaseAsymAlgo`), e.g. `TPM_ALG_ECDSA_ECC_NIST_P384`.
    pub signing_algorithm: String,
    /// Redfish `SignedMeasurements`: the SPDM transcript.
    #[serde(with = "base64url")]
    pub signed_measurements: Vec<u8>,
    /// The SPDM slot 0 certificate chain (Redfish `.../Certificates/CertChain`), PEM.
    pub certificate_chain: String,
}

/// Which backend verifies DPU evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DpuVerifierKind {
    /// The KMS's own SPDM verifier ([`spdm::LocalDpu`]).
    Local,
}

/// The platform document's `dpu_policy`. Absent, no Revision that expects a DPU can attest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DpuPolicy {
    /// By model name, as a Revision's `dpu.model` names it.
    pub models: BTreeMap<String, DpuModel>,
    /// Every backend listed must verify every DPU.
    pub verifiers: Vec<DpuVerifierKind>,
}

/// One DPU model's trust anchors and reference measurements.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DpuModel {
    /// The roots the device's certificate chain must end at, PEM, copied from NVIDIA when the
    /// document is prepared. Empty, every DPU of the model is refused.
    pub roots_pem: Vec<String>,
    // ponytail: dpu-corim — transcribed from NVIDIA's CoRIM by whoever prepares the document;
    // reading COSE-signed CoRIMs from NVIDIA's RIM service is not built.
    /// SPDM measurement index (decimal) to the DMTF measurement values allowed for it, hex
    /// (value type byte, then the value). Every index listed must be measured with one of its
    /// values; indices not listed are recorded, not judged. Empty, every DPU of the model is
    /// refused.
    pub measurements: BTreeMap<String, Vec<String>>,
    /// Whether to accept a device whose certificates' revocation was not checked: no revocation
    /// source for BlueField certificates is built yet, so without this every DPU is refused.
    #[serde(default)]
    pub accept_unchecked_revocation: bool,
}

/// What a backend proved about one DPU.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedDpu {
    /// Position in the evidence's `nic`.
    pub index: u32,
    /// `sha256:<hex>` of the device identity key (the DICE DeviceID certificate's public key).
    pub device_id: String,
    pub model: String,
    /// Every measurement block of the transcript, by index: DMTF value type and value, hex.
    pub measurements: BTreeMap<u8, String>,
    /// The nonce the signed request carried.
    #[serde(with = "hex::serde")]
    pub nonce: [u8; 32],
    pub revocation_checked: bool,
}

/// What one backend returns over all of a pod's DPUs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DpuAppraisal {
    pub verifier: DpuVerifierKind,
    pub dpus: Vec<VerifiedDpu>,
}

/// The 32-byte nonce every DPU transcript must be over, bound to the CPU evidence's
/// `report_data` like the GPU nonce, under its own label.
pub fn dpu_nonce(report_data: &[u8; 64]) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"alphacompute/dpu-nonce/v1")
        .chain_update(report_data)
        .finalize()
        .into()
}

pub type DpuFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Vec<VerifiedDpu>, AppraisalError>> + Send + 'a>>;

/// A DPU verifier backend. It must fail rather than return a DPU it could not fully verify.
pub trait DpuVerifier: Send + Sync {
    fn kind(&self) -> DpuVerifierKind;
    fn verify<'a>(
        &'a self,
        dpus: &'a [DpuEvidence],
        nonce: &'a [u8; 32],
        model: &'a str,
        policy: &'a DpuModel,
    ) -> DpuFuture<'a>;
}

/// The checks that need no backend: the policy exists, lists a verifier and knows the model, and
/// the pod sent one evidence entry per expected DPU.
pub fn precheck<'a>(
    policy: Option<&'a DpuPolicy>,
    shape: &DpuShape,
    evidence_count: usize,
) -> Result<(&'a DpuPolicy, &'a DpuModel), AppraisalError> {
    use AppraisalError::*;

    if !(1..=MAX_DPUS).contains(&shape.count) {
        return Err(Failed(format!(
            "the Revision expects {} DPUs, not 1 to {MAX_DPUS}",
            shape.count
        )));
    }
    let policy = policy.ok_or_else(|| Unknown("the platform document has no dpu_policy".into()))?;
    if policy.verifiers.is_empty() {
        return Err(PolicyDenied("dpu_policy lists no verifier".into()));
    }
    let model = policy
        .models
        .get(&shape.model)
        .ok_or_else(|| PolicyDenied(format!("dpu model {} is not allowed", shape.model)))?;
    if usize::try_from(shape.count).ok() != Some(evidence_count) {
        return Err(Failed(format!(
            "{evidence_count} DPUs attested, the Revision expects {}",
            shape.count
        )));
    }
    Ok((policy, model))
}

/// Runs every backend the policy lists, failing closed on one that is not configured or fails.
pub async fn verify_dpus(
    backends: &[Arc<dyn DpuVerifier>],
    dpus: &[DpuEvidence],
    nonce: &[u8; 32],
    shape: &DpuShape,
    policy: &DpuPolicy,
    model: &DpuModel,
) -> Result<Vec<DpuAppraisal>, AppraisalError> {
    let mut out = Vec::with_capacity(policy.verifiers.len());
    for kind in &policy.verifiers {
        let backend = backends.iter().find(|b| b.kind() == *kind).ok_or_else(|| {
            AppraisalError::Unknown(format!("dpu verifier {kind:?} is not configured"))
        })?;
        out.push(DpuAppraisal {
            verifier: *kind,
            dpus: backend.verify(dpus, nonce, &shape.model, model).await?,
        });
    }
    Ok(out)
}

/// The decision over the backends' results: every listed backend verified exactly the Revision's
/// DPUs, each once, of its model, over this nonce, no two the same device. Returns the first
/// listed backend's claims in index order.
// ponytail: dpu-binding — nothing here proves a DPU is the pod's host's; a relayed nonce answered
// by a healthy BlueField elsewhere passes. Needs a per-node device inventory.
pub fn check_dpus(
    policy: Option<&DpuPolicy>,
    shape: &DpuShape,
    evidence_count: usize,
    appraisals: &[DpuAppraisal],
    nonce: &[u8; 32],
) -> Result<Vec<VerifiedDpu>, AppraisalError> {
    use AppraisalError::*;

    let (policy, _) = precheck(policy, shape, evidence_count)?;
    let count = usize::try_from(shape.count).map_err(|_| Failed("dpu count".into()))?;
    for kind in &policy.verifiers {
        let appraisal = appraisals
            .iter()
            .find(|a| a.verifier == *kind)
            .ok_or_else(|| Failed(format!("dpu verifier {kind:?} did not run")))?;
        if appraisal.dpus.len() != count {
            return Err(Failed(format!(
                "dpu verifier {kind:?} verified {} DPUs, the Revision expects {count}",
                appraisal.dpus.len()
            )));
        }
        let mut seen = vec![false; count];
        let mut devices = BTreeSet::new();
        for dpu in &appraisal.dpus {
            let i = dpu.index;
            let slot = usize::try_from(i)
                .ok()
                .and_then(|i| seen.get_mut(i))
                .ok_or_else(|| Failed(format!("dpu index {i} is out of range")))?;
            if std::mem::replace(slot, true) {
                return Err(Failed(format!("dpu index {i} verified twice")));
            }
            if dpu.device_id.is_empty() || !devices.insert(dpu.device_id.as_str()) {
                return Err(Failed(format!(
                    "dpu {i}: device {:?} is missing or reported for another DPU of this pod too",
                    dpu.device_id
                )));
            }
            if dpu.nonce != *nonce {
                return Err(Failed(format!(
                    "dpu {i}: transcript is not over this nonce"
                )));
            }
            if dpu.model != shape.model {
                return Err(Failed(format!(
                    "dpu {i}: model {} is not the Revision's {}",
                    dpu.model, shape.model
                )));
            }
        }
    }
    let first = policy
        .verifiers
        .first()
        .ok_or_else(|| Failed("no verifier".into()))?;
    let mut dpus = appraisals
        .iter()
        .find(|a| a.verifier == *first)
        .map(|a| a.dpus.clone())
        .unwrap_or_default();
    dpus.sort_by_key(|d| d.index);
    Ok(dpus)
}

#[cfg(test)]
mod tests;
