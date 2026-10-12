//! `alphacompute-evidence/2` and the `kata-tdx/1` profile: a Kata confidential pod on TDX, either
//! CPU-only (`kata-qemu-tdx`) or with the NVIDIA guest image and passed-through GPUs
//! (`kata-qemu-nvidia-gpu-tdx`).
//!
//! The steps, in the plan's order (PRD-02 R5), after DCAP and the TCB policy that
//! [`crate::verify_quote`] already runs: (event log replay, when sent) → the pod's runtime class
//! is one a Revision v2 may name → MRTD and RTMR0..2 match a reference value of kind `kata-tdx`
//! captured for that runtime class → MRCONFIGID equals the init-data's digest → the init-data
//! parses, carries a policy and our entry → the evidence's runtime class is the init-data's →
//! report_data binds this key and nonce, last of the TD checks → the Revision v2 rebuilt from the
//! init-data (for a KMS node, found in `kms_revisions`) → GPUs by runtime class: on the GPU class
//! every expected GPU passed, on the CPU class no GPU was presented or verified. Every step is
//! mandatory; the order only decides which reason a refusal of evidence with several faults names.

use std::sync::Arc;
use std::time::SystemTime;

use alpha_core::ComposeHash;
use alpha_core::coco::{CPU_RUNTIME_CLASS, GpuShape, InitData, RuntimeClass};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::gpu::{
    self, CheckedGpus, GpuAppraisal, GpuEvidence, GpuPolicy, GpuVerifier, GpuVouch, VerifiedGpu,
};
use crate::{
    AppraisalError, Appraised, Collateral, EVIDENCE_FORMAT, EVIDENCE_FORMAT_V2, EventLogEntry,
    Evidence, Measurement, PlatformDocument, ReferenceKind, VerifiedQuote, base64url, event_log,
    report_data,
};

pub const PROFILE_KATA_TDX: &str = "kata-tdx/1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CpuKind {
    Tdx,
    Snp,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CpuEvidence {
    pub kind: CpuKind,
    #[serde(with = "base64url")]
    pub quote: Vec<u8>,
    /// The CCEL boot events, when the guest exposes them; RTMR0..2 must then replay from them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub event_log: Vec<EventLogEntry>,
}

/// `alphacompute-evidence/2`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceV2 {
    pub format: String,
    pub cpu: CpuEvidence,
    #[serde(default)]
    pub gpus: Vec<GpuEvidence>,
    /// The exact init-data document the pod booted with.
    #[serde(with = "base64url")]
    pub initdata: Vec<u8>,
    /// Reported by the pod; refused unless it is the runtime class the measured init-data names.
    pub runtime_class: String,
}

/// Either evidence format, dispatched on `format`; anything else is refused when parsed.
#[derive(Clone, Debug)]
pub enum AnyEvidence {
    V1(Evidence),
    V2(EvidenceV2),
}

impl AnyEvidence {
    /// The TDX quote, for fetching its collateral.
    pub fn quote(&self) -> &[u8] {
        match self {
            Self::V1(e) => &e.quote,
            Self::V2(e) => &e.cpu.quote,
        }
    }

    pub fn gpus(&self) -> &[GpuEvidence] {
        match self {
            Self::V1(_) => &[],
            Self::V2(e) => &e.gpus,
        }
    }
}

impl From<Evidence> for AnyEvidence {
    fn from(e: Evidence) -> Self {
        Self::V1(e)
    }
}

impl From<EvidenceV2> for AnyEvidence {
    fn from(e: EvidenceV2) -> Self {
        Self::V2(e)
    }
}

impl Serialize for AnyEvidence {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::V1(e) => e.serialize(serializer),
            Self::V2(e) => e.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for AnyEvidence {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        let value = Value::deserialize(deserializer)?;
        match value.get("format").and_then(Value::as_str) {
            Some(EVIDENCE_FORMAT) => serde_json::from_value(value).map(Self::V1),
            Some(EVIDENCE_FORMAT_V2) => serde_json::from_value(value).map(Self::V2),
            other => return Err(D::Error::custom(format!("evidence format {other:?}"))),
        }
        .map_err(D::Error::custom)
    }
}

/// What `kata-tdx/1` found, reported in the attestation result. Like the rest of the result it
/// accepts fields it does not know, so a runtime built before a KMS upgrade that adds one keeps
/// renewing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CocoAppraised {
    pub profile: String,
    pub initdata_sha256: ComposeHash,
    pub policy_sha256: ComposeHash,
    pub runtime_class: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gpus: Vec<VerifiedGpu>,
    /// Who vouched for `gpus`: every GPU backend the `gpu_policy` lists, each with the digest of
    /// the signed result it verified (e.g. NRAS's overall EAT). Empty for a CPU-only pod.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gpu_verifiers: Vec<GpuVouch>,
}

/// The appraisal of either evidence format. For `alphacompute-evidence/2` every TD check runs
/// first; the GPU backends (the one network step, e.g. NRAS) are called only after they all pass
/// and only for a pod on the GPU runtime class, so evidence that fails on the CPU side never costs
/// a verifier call and a CPU-class pod never causes one. v1 evidence has no GPUs and never calls a
/// backend.
#[allow(clippy::too_many_arguments)]
pub async fn appraise_any(
    evidence: &AnyEvidence,
    nonce: &[u8; 32],
    runtime_pubkey_spki: &[u8],
    node_xwing_spki: Option<&[u8]>,
    doc: &PlatformDocument,
    collateral: &Collateral,
    gpu_backends: &[Arc<dyn GpuVerifier>],
    now: SystemTime,
) -> Result<Appraised, AppraisalError> {
    match evidence {
        AnyEvidence::V1(e) => crate::appraise(
            e,
            nonce,
            runtime_pubkey_spki,
            node_xwing_spki,
            doc,
            collateral,
            now,
        ),
        AnyEvidence::V2(e) => {
            check_cpu_kind(e)?;
            let verified = crate::verify_quote(&e.cpu.quote, collateral, &doc.policy, now)?;
            appraise_kata_tdx(
                e,
                verified,
                nonce,
                runtime_pubkey_spki,
                node_xwing_spki,
                doc,
                gpu_backends,
            )
            .await
        }
    }
}

/// The format and CPU kind `kata-tdx/1` appraises: refused before any collateral is fetched or
/// quote verified, so SEV-SNP evidence is named for what it is.
pub fn check_cpu_kind(evidence: &EvidenceV2) -> Result<(), AppraisalError> {
    if evidence.format != EVIDENCE_FORMAT_V2 {
        return Err(AppraisalError::Unknown(format!(
            "evidence format {:?}",
            evidence.format
        )));
    }
    match evidence.cpu.kind {
        CpuKind::Tdx => Ok(()),
        CpuKind::Snp => Err(AppraisalError::Unknown(
            "no kata-snp/1 profile yet; SEV-SNP evidence is not appraised".into(),
        )),
    }
}

/// Whether a quote's `report_data` binds `expected`: byte for byte (configfs-tsm), or as the
/// CoCo attestation agent carries runtime data, the 64 ASCII bytes of lowercase hex
/// SHA-256(`expected`). Either form needs the same preimage, so accepting both adds no forgery.
pub fn report_data_binds(quoted: &[u8; 64], expected: &[u8; 64]) -> bool {
    if quoted == expected {
        return true;
    }
    let digest = hex::encode(Sha256::digest(expected));
    quoted.as_slice() == digest.as_bytes()
}

/// What the quote's `report_data` must bind and what every GPU report must be over: the one
/// input on which the two protocols a pod attests through differ. Every other `kata-tdx/1` step
/// is the same for both.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    report_data: [u8; 64],
    agent_hex: bool,
    gpu_nonce: [u8; 32],
    key_sha256: [u8; 32],
    kms_node: bool,
}

impl Binding {
    /// `POST /v1/attest`'s: [`report_data`] of the runtime key, the KMS nonce and, for a KMS node,
    /// its X-Wing key, in either form [`report_data_binds`] accepts; GPU reports over
    /// [`gpu::gpu_nonce`] of it. A KMS node's Revision must also be in `kms_revisions`.
    pub fn runtime(
        runtime_pubkey_spki: &[u8],
        nonce: &[u8; 32],
        node_xwing_spki: Option<&[u8]>,
    ) -> Self {
        let report_data = report_data(runtime_pubkey_spki, nonce, node_xwing_spki);
        Self {
            report_data,
            agent_hex: true,
            gpu_nonce: gpu::gpu_nonce(&report_data),
            key_sha256: Sha256::digest(runtime_pubkey_spki).into(),
            kms_node: node_xwing_spki.is_some(),
        }
    }

    /// The KBS protocol's: `report_data` byte for byte only (the attestation agent's TDX attester
    /// writes the runtime-data digest there itself), GPU reports over `gpu_nonce`, certifying the
    /// key whose SHA-256 is `key_sha256`. Never a KMS node.
    pub fn exact(report_data: [u8; 64], gpu_nonce: [u8; 32], key_sha256: [u8; 32]) -> Self {
        Self {
            report_data,
            agent_hex: false,
            gpu_nonce,
            key_sha256,
            kms_node: false,
        }
    }

    fn binds(&self, quoted: &[u8; 64]) -> bool {
        if self.agent_hex {
            report_data_binds(quoted, &self.report_data)
        } else {
            *quoted == self.report_data
        }
    }
}

/// `kata-tdx/1` over a quote [`crate::verify_quote`] has already verified: [`appraise_kata_cpu`],
/// then, only if it passed and the pod is on the GPU runtime class, every backend the
/// `gpu_policy` lists, then [`CpuAppraised::finish`].
pub async fn appraise_kata_tdx(
    evidence: &EvidenceV2,
    verified: VerifiedQuote,
    nonce: &[u8; 32],
    runtime_pubkey_spki: &[u8],
    node_xwing_spki: Option<&[u8]>,
    doc: &PlatformDocument,
    gpu_backends: &[Arc<dyn GpuVerifier>],
) -> Result<Appraised, AppraisalError> {
    let binding = Binding::runtime(runtime_pubkey_spki, nonce, node_xwing_spki);
    appraise_kata_tdx_bound(evidence, verified, &binding, doc, gpu_backends).await
}

/// [`appraise_kata_tdx`] under any [`Binding`].
pub async fn appraise_kata_tdx_bound(
    evidence: &EvidenceV2,
    verified: VerifiedQuote,
    binding: &Binding,
    doc: &PlatformDocument,
    gpu_backends: &[Arc<dyn GpuVerifier>],
) -> Result<Appraised, AppraisalError> {
    let cpu = appraise_kata_cpu_bound(evidence, verified, binding, doc)?;
    let gpus = match cpu.gpu_shape() {
        None => Vec::new(),
        Some(shape) => {
            let policy = gpu::precheck(doc.gpu_policy.as_ref(), shape, evidence.gpus.len())?;
            gpu::verify_gpus(gpu_backends, &evidence.gpus, cpu.gpu_nonce(), policy).await?
        }
    };
    cpu.finish(doc.gpu_policy.as_ref(), &gpus)
}

/// What `kata-tdx/1` established about the TD before any GPU backend ran: everything but the GPU
/// decision. Only [`CpuAppraised::finish`] turns it into an [`Appraised`].
#[derive(Debug)]
pub struct CpuAppraised {
    appraised: Appraised,
    gpus: ClassGpus,
    gpu_evidence: usize,
    gpu_nonce: [u8; 32],
}

/// The GPUs the pod's runtime class (from the measured init-data) allows: none on the CPU class,
/// exactly the Revision's on the GPU class. No other combination can be built.
#[derive(Debug)]
enum ClassGpus {
    Cpu,
    Gpu(GpuShape),
}

impl CpuAppraised {
    /// The pod's runtime class, as its measured init-data names it.
    pub fn runtime_class(&self) -> RuntimeClass {
        match self.gpus {
            ClassGpus::Cpu => RuntimeClass::Cpu,
            ClassGpus::Gpu(_) => RuntimeClass::Gpu,
        }
    }

    /// The GPUs the Revision expects. `None` only for the CPU runtime class, and then no GPU
    /// backend is to run.
    pub fn gpu_shape(&self) -> Option<&GpuShape> {
        match &self.gpus {
            ClassGpus::Cpu => None,
            ClassGpus::Gpu(shape) => Some(shape),
        }
    }

    /// What every GPU report must be over: [`gpu::gpu_nonce`] of the verified `report_data`.
    pub fn gpu_nonce(&self) -> &[u8; 32] {
        &self.gpu_nonce
    }

    /// The GPU decision over the backends' results, completing the appraisal. On the GPU class
    /// it is [`gpu::check_gpus`] (pure) over the Revision's shape. The CPU class is the only one
    /// whose GPU checks are skipped: there is no GPU to check, and GPU evidence from the pod, or
    /// a GPU a backend verified for it, is refused, never ignored.
    pub fn finish(
        self,
        policy: Option<&GpuPolicy>,
        gpus: &[GpuAppraisal],
    ) -> Result<Appraised, AppraisalError> {
        let checked = match &self.gpus {
            ClassGpus::Cpu => {
                no_gpus(self.gpu_evidence, gpus)?;
                CheckedGpus::default()
            }
            ClassGpus::Gpu(shape) => {
                gpu::check_gpus(policy, shape, self.gpu_evidence, gpus, &self.gpu_nonce)?
            }
        };
        let mut appraised = self.appraised;
        if let Some(coco) = appraised.coco.as_mut() {
            coco.gpus = checked.gpus;
            coco.gpu_verifiers = checked.vouched;
        }
        Ok(appraised)
    }
}

/// The TD half of `kata-tdx/1`, over a quote [`crate::verify_quote`] has already verified. Pure,
/// so the malicious-host cases are tests over synthetic quotes.
pub fn appraise_kata_cpu(
    evidence: &EvidenceV2,
    verified: VerifiedQuote,
    nonce: &[u8; 32],
    runtime_pubkey_spki: &[u8],
    node_xwing_spki: Option<&[u8]>,
    doc: &PlatformDocument,
) -> Result<CpuAppraised, AppraisalError> {
    let binding = Binding::runtime(runtime_pubkey_spki, nonce, node_xwing_spki);
    appraise_kata_cpu_bound(evidence, verified, &binding, doc)
}

/// [`appraise_kata_cpu`] under any [`Binding`].
pub fn appraise_kata_cpu_bound(
    evidence: &EvidenceV2,
    verified: VerifiedQuote,
    binding: &Binding,
    doc: &PlatformDocument,
) -> Result<CpuAppraised, AppraisalError> {
    use AppraisalError::*;

    check_cpu_kind(evidence)?;
    let VerifiedQuote {
        report_data: quoted,
        mut measured,
        mrconfigid,
        tcb_status,
        advisories,
    } = verified;

    if !evidence.cpu.event_log.is_empty() {
        let [r0, r1, r2, _] = event_log::replay(&evidence.cpu.event_log);
        if [r0, r1, r2] != [measured.rtmr0, measured.rtmr1, measured.rtmr2] {
            return Err(Failed(
                "event log does not replay to the quoted RTMR0..2".into(),
            ));
        }
    }

    // The runtime class here is the pod's claim, held to the measured init-data's below. It must
    // be a class a Revision v2 may name: it picks the reference value and decides whether GPUs
    // are checked.
    let class = RuntimeClass::from_name(&evidence.runtime_class).ok_or_else(|| {
        Failed(format!(
            "runtime class {:?} is not supported",
            evidence.runtime_class
        ))
    })?;
    // The guest image must be one captured for that class. A value for the other class, or one
    // that names no class, never stands in, so a TD booted from the NVIDIA guest image cannot pass
    // as the CPU class (whose GPU checks are skipped), nor the CPU guest as the GPU class, provided
    // the two guests' captured registers differ (confirmed at capture).
    let reference = doc
        .reference_values
        .iter()
        .find(|rv| {
            rv.kind == ReferenceKind::KataTdx
                && rv.runtime_class.as_deref() == Some(class.name())
                && rv.values.mrtd == measured.mrtd
                && rv.values.rtmr0 == measured.rtmr0
                && rv.values.rtmr1 == measured.rtmr1
                && rv.values.rtmr2 == measured.rtmr2
        })
        .ok_or_else(|| {
            Unknown(format!(
                "no kata-tdx reference value for mrtd {} and runtime class {}",
                measured.mrtd,
                class.name()
            ))
        })?;

    let initdata =
        InitData::parse(&evidence.initdata).map_err(|e| Failed(format!("init-data: {e}")))?;
    if Measurement(initdata.mrconfigid()) != mrconfigid {
        return Err(Failed(
            "MRCONFIGID is not the digest of the init-data sent".into(),
        ));
    }
    let revision = initdata
        .revision()
        .map_err(|e| Failed(format!("init-data: {e}")))?;

    if evidence.runtime_class != revision.runtime_class {
        return Err(Failed(format!(
            "runtime class {:?} is not the init-data's {:?}",
            evidence.runtime_class, revision.runtime_class
        )));
    }
    // The class decides the GPUs. `InitData::revision` already holds each class to its gpu
    // section; held again here, so nothing can turn the GPU class's checks into the CPU class's.
    let gpus = match (class, &revision.gpu) {
        (RuntimeClass::Cpu, None) => ClassGpus::Cpu,
        (RuntimeClass::Gpu, Some(shape)) => ClassGpus::Gpu(shape.clone()),
        (RuntimeClass::Cpu, Some(_)) => {
            return Err(Failed(format!(
                "init-data: runtime class {CPU_RUNTIME_CLASS} runs no GPU"
            )));
        }
        (RuntimeClass::Gpu, None) => {
            return Err(Failed(format!(
                "init-data: runtime class {} names no GPU",
                class.name()
            )));
        }
    };

    // Last of the TD checks, as the plan orders them (PRD-02 R5e).
    if !binding.binds(&quoted) {
        return Err(Failed(
            "report_data is not bound to this key and nonce".into(),
        ));
    }

    let compose_hash = revision
        .hash()
        .map_err(|e| Failed(format!("revision: {e}")))?;
    if binding.kms_node
        && !doc
            .kms_revisions
            .iter()
            .any(|r| r.compose_hash == compose_hash)
    {
        return Err(Unknown(format!("kms revision {compose_hash}")));
    }

    measured.mrconfigid = Some(mrconfigid);
    let evidence_json = serde_json::to_value(evidence).map_err(|e| Failed(e.to_string()))?;
    let appraised = Appraised {
        measured,
        tcb_status,
        advisories,
        os_image: reference.name.clone(),
        compose_hash,
        runtime_pubkey_sha256: format!("sha256:{}", hex::encode(binding.key_sha256)),
        evidence_sha256: format!(
            "sha256:{}",
            hex::encode(Sha256::digest(
                alpha_core::jcs(&evidence_json).map_err(|e| Failed(e.to_string()))?
            ))
        ),
        policy_version: doc.version,
        coco: Some(CocoAppraised {
            profile: PROFILE_KATA_TDX.into(),
            initdata_sha256: revision.initdata_sha256,
            policy_sha256: revision.policy_sha256,
            runtime_class: revision.runtime_class,
            gpus: Vec::new(),
            gpu_verifiers: Vec::new(),
        }),
    };
    Ok(CpuAppraised {
        appraised,
        gpus,
        gpu_evidence: evidence.gpus.len(),
        gpu_nonce: binding.gpu_nonce,
    })
}

/// The CPU runtime class runs no GPU. GPU evidence from such a pod, or a GPU a backend verified
/// for it, is a device its Revision does not expect: refused, never ignored.
fn no_gpus(evidence_count: usize, appraisals: &[GpuAppraisal]) -> Result<(), AppraisalError> {
    if evidence_count != 0 {
        return Err(AppraisalError::Failed(format!(
            "{evidence_count} GPU evidence entries from a pod of runtime class {CPU_RUNTIME_CLASS}, which runs no GPU"
        )));
    }
    if let Some(appraisal) = appraisals.iter().find(|a| !a.gpus.is_empty()) {
        return Err(AppraisalError::Failed(format!(
            "gpu verifier {:?} verified {} GPUs for a pod of runtime class {CPU_RUNTIME_CLASS}, which runs no GPU",
            appraisal.verifier,
            appraisal.gpus.len()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
