//! `alphacompute-evidence/2` and its two profiles: `kata-tdx/1`, a Kata confidential pod on TDX,
//! either CPU-only (`kata-qemu-tdx`) or with the NVIDIA guest image and passed-through GPUs
//! (`kata-qemu-nvidia-gpu-tdx`); and `kata-snp/1`, the same pods on AMD SEV-SNP (`kata-qemu-snp`,
//! `kata-qemu-nvidia-gpu-snp`).
//!
//! The steps, in the plan's order (PRD-02 R5), after the CPU evidence itself is verified (DCAP and
//! the TCB policy by [`crate::verify_quote`]; the report's chain to the pinned ARK, AMD's CRL, the
//! TCB and guest policy by [`crate::snp::verify_report`]): (TDX: event log replay, when sent) →
//! the pod's runtime class is one a Revision v2 may name, on this CPU's TEE → the guest's
//! measurement (MRTD and RTMR0..2, or the SNP launch measurement) matches a reference value of the
//! profile's kind captured for that runtime class → MRCONFIGID (SNP: HOST_DATA) equals the
//! init-data's digest → the init-data parses, carries a policy and our entry → the evidence's
//! runtime class is the init-data's → report_data binds this key and nonce, last of the CPU checks
//! → the Revision v2 rebuilt from the init-data (for a KMS node, found in `kms_revisions`) → GPUs
//! by runtime class: on a GPU class every expected GPU passed, on a CPU class no GPU was presented
//! or verified. Every step is mandatory; the order only decides which reason a refusal of evidence
//! with several faults names.

use std::sync::Arc;
use std::time::SystemTime;

use alpha_core::ComposeHash;
use alpha_core::coco::{DpuShape, GpuShape, InitData, RuntimeClass, Tee};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::dpu::{self, DpuAppraisal, DpuEvidence, DpuPolicy, DpuVerifier, VerifiedDpu};
use crate::gpu::{
    self, CheckedGpus, GpuAppraisal, GpuEvidence, GpuPolicy, GpuVerifier, GpuVouch, VerifiedGpu,
};
use crate::snp::{self, SnpFindings, VerifiedReport, kds::Kds};
use crate::{
    AppraisalError, Appraised, Collateral, EVIDENCE_FORMAT, EVIDENCE_FORMAT_V2, EventLogEntry,
    Evidence, Measured, Measurement, PlatformDocument, ReferenceKind, VerifiedQuote, base64url,
    event_log, report_data,
};

pub const PROFILE_KATA_TDX: &str = "kata-tdx/1";
pub const PROFILE_KATA_SNP: &str = "kata-snp/1";
/// An SNP report's `tcb_status` in the result: its reported TCB is at or above `snp_policy`'s
/// minimum for its product (there is no TCB-status service as for TDX).
pub const SNP_TCB_STATUS: &str = "AtOrAboveMinimum";

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
    /// The TDX quote, or the SEV-SNP attestation report.
    #[serde(with = "base64url")]
    pub quote: Vec<u8>,
    /// TDX only: the CCEL boot events, when the guest exposes them; RTMR0..2 must then replay
    /// from them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub event_log: Vec<EventLogEntry>,
    /// SNP only: the DER VCEK or VLEK that signed the report, when the host supplied it (the
    /// extended report's certificate table). Without it the KMS fetches the VCEK from KDS.
    #[serde(default, skip_serializing_if = "Vec::is_empty", with = "base64url")]
    pub vek: Vec<u8>,
}

/// `alphacompute-evidence/2`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceV2 {
    pub format: String,
    pub cpu: CpuEvidence,
    #[serde(default)]
    pub gpus: Vec<GpuEvidence>,
    /// One entry per NIC/DPU the Revision expects (`nvidia-dpu/1`); absent when it expects none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nic: Vec<DpuEvidence>,
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

/// What `kata-tdx/1` or `kata-snp/1` found, reported in the attestation result. Like the rest of
/// the result it accepts fields it does not know, so a runtime built before a KMS upgrade that adds
/// one keeps renewing.
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
    /// `nvidia-dpu/1`: every NIC/DPU the Revision expects, as the first listed backend verified it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dpus: Vec<VerifiedDpu>,
    /// `kata-snp/1`: what the verified SNP report says (product, signing key, launch measurement,
    /// HOST_DATA, reported TCB, guest policy, VMPL).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snp: Option<SnpFindings>,
}

/// The CPU evidence of a pod, verified: a TDX quote by DCAP, or an SNP report by its chain to the
/// pinned ARK. What the profile's later checks take.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifiedCpu {
    Tdx(VerifiedQuote),
    Snp(VerifiedReport),
}

impl From<VerifiedQuote> for VerifiedCpu {
    fn from(v: VerifiedQuote) -> Self {
        Self::Tdx(v)
    }
}

impl From<VerifiedReport> for VerifiedCpu {
    fn from(v: VerifiedReport) -> Self {
        Self::Snp(v)
    }
}

/// The appraisal of either evidence format on TDX. For `alphacompute-evidence/2` every TD check
/// runs first; the GPU backends (the one network step, e.g. NRAS) are called only after they all
/// pass and only for a pod on the GPU runtime class, so evidence that fails on the CPU side never
/// costs a verifier call and a CPU-class pod never causes one. v1 evidence has no GPUs and never
/// calls a backend. SEV-SNP evidence is refused here; [`appraise_kata_snp`] appraises it.
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

/// The format, and the CPU kind that picks the profile: refused before any collateral is fetched.
pub fn cpu_kind(evidence: &EvidenceV2) -> Result<CpuKind, AppraisalError> {
    if evidence.format != EVIDENCE_FORMAT_V2 {
        return Err(AppraisalError::Unknown(format!(
            "evidence format {:?}",
            evidence.format
        )));
    }
    Ok(evidence.cpu.kind)
}

/// The format and CPU kind `kata-tdx/1` appraises: refused before any collateral is fetched or
/// quote verified, so SEV-SNP evidence is named for what it is.
pub fn check_cpu_kind(evidence: &EvidenceV2) -> Result<(), AppraisalError> {
    match cpu_kind(evidence)? {
        CpuKind::Tdx => Ok(()),
        CpuKind::Snp => Err(AppraisalError::Unknown(
            "SEV-SNP evidence is appraised by kata-snp/1, not kata-tdx/1".into(),
        )),
    }
}

/// `kata-snp/1`'s CPU evidence check: the format and kind, the platform document's `snp_policy`,
/// the VEK and CRL (from the evidence or KDS, cached), then [`snp::verify_report`].
pub async fn verify_snp(
    evidence: &EvidenceV2,
    doc: &PlatformDocument,
    kds: &Kds,
    now: SystemTime,
) -> Result<VerifiedReport, AppraisalError> {
    if cpu_kind(evidence)? != CpuKind::Snp {
        return Err(AppraisalError::Failed(
            "kata-snp/1 appraises SEV-SNP evidence only".into(),
        ));
    }
    let policy = doc
        .snp_policy
        .as_ref()
        .ok_or_else(|| AppraisalError::Unknown("the platform document has no snp_policy".into()))?;
    let vek = (!evidence.cpu.vek.is_empty()).then_some(evidence.cpu.vek.as_slice());
    let collateral = kds
        .collateral(&evidence.cpu.quote, vek, policy, now)
        .await?;
    snp::verify_report(&evidence.cpu.quote, &collateral, policy, now)
}

/// `kata-snp/1` end to end: [`verify_snp`], then [`appraise_kata`].
#[allow(clippy::too_many_arguments)]
pub async fn appraise_kata_snp(
    evidence: &EvidenceV2,
    nonce: &[u8; 32],
    runtime_pubkey_spki: &[u8],
    node_xwing_spki: Option<&[u8]>,
    doc: &PlatformDocument,
    kds: &Kds,
    gpu_backends: &[Arc<dyn GpuVerifier>],
    dpu_backends: &[Arc<dyn DpuVerifier>],
    now: SystemTime,
) -> Result<Appraised, AppraisalError> {
    let verified = verify_snp(evidence, doc, kds, now).await?;
    appraise_kata(
        evidence,
        verified,
        nonce,
        runtime_pubkey_spki,
        node_xwing_spki,
        doc,
        gpu_backends,
        dpu_backends,
    )
    .await
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

/// `kata-tdx/1` or `kata-snp/1` over CPU evidence already verified ([`crate::verify_quote`],
/// [`verify_snp`]): [`appraise_kata_cpu`], then, only if it passed, the checks that need no
/// backend for the GPUs (GPU runtime classes) and DPUs (a Revision that expects them), then every
/// backend the `gpu_policy` and `dpu_policy` list, then [`CpuAppraised::finish_with_dpus`].
#[allow(clippy::too_many_arguments)]
pub async fn appraise_kata(
    evidence: &EvidenceV2,
    verified: impl Into<VerifiedCpu>,
    nonce: &[u8; 32],
    runtime_pubkey_spki: &[u8],
    node_xwing_spki: Option<&[u8]>,
    doc: &PlatformDocument,
    gpu_backends: &[Arc<dyn GpuVerifier>],
    dpu_backends: &[Arc<dyn DpuVerifier>],
) -> Result<Appraised, AppraisalError> {
    let cpu = appraise_kata_cpu(
        evidence,
        verified,
        nonce,
        runtime_pubkey_spki,
        node_xwing_spki,
        doc,
    )?;
    let gpu_policy = cpu
        .gpu_shape()
        .map(|shape| gpu::precheck(doc.gpu_policy.as_ref(), shape, evidence.gpus.len()))
        .transpose()?;
    let dpu_policy = cpu
        .dpu_shape()
        .map(|shape| dpu::precheck(doc.dpu_policy.as_ref(), shape, evidence.nic.len()))
        .transpose()?;
    let gpus = match gpu_policy {
        None => Vec::new(),
        Some(policy) => {
            gpu::verify_gpus(gpu_backends, &evidence.gpus, cpu.gpu_nonce(), policy).await?
        }
    };
    let dpus = match (cpu.dpu_shape(), dpu_policy) {
        (Some(shape), Some((policy, model))) => {
            dpu::verify_dpus(
                dpu_backends,
                &evidence.nic,
                cpu.dpu_nonce(),
                shape,
                policy,
                model,
            )
            .await?
        }
        _ => Vec::new(),
    };
    cpu.finish_with_dpus(
        doc.gpu_policy.as_ref(),
        &gpus,
        doc.dpu_policy.as_ref(),
        &dpus,
    )
}

/// [`appraise_kata`] over a DCAP-verified TDX quote.
pub async fn appraise_kata_tdx(
    evidence: &EvidenceV2,
    verified: VerifiedQuote,
    nonce: &[u8; 32],
    runtime_pubkey_spki: &[u8],
    node_xwing_spki: Option<&[u8]>,
    doc: &PlatformDocument,
    gpu_backends: &[Arc<dyn GpuVerifier>],
) -> Result<Appraised, AppraisalError> {
    appraise_kata(
        evidence,
        verified,
        nonce,
        runtime_pubkey_spki,
        node_xwing_spki,
        doc,
        gpu_backends,
        &[],
    )
    .await
}

/// What the profile established about the guest before any GPU backend ran: everything but the
/// GPU decision. Only [`CpuAppraised::finish`] turns it into an [`Appraised`].
#[derive(Debug)]
pub struct CpuAppraised {
    appraised: Appraised,
    class: RuntimeClass,
    gpus: ClassGpus,
    gpu_evidence: usize,
    gpu_nonce: [u8; 32],
    dpu: Option<DpuShape>,
    dpu_evidence: usize,
    dpu_nonce: [u8; 32],
}

/// The GPUs the pod's runtime class (from the measured init-data) allows: none on a CPU class,
/// exactly the Revision's on a GPU class. No other combination can be built.
#[derive(Debug)]
enum ClassGpus {
    Cpu,
    Gpu(GpuShape),
}

impl CpuAppraised {
    /// The pod's runtime class, as its measured init-data names it.
    pub fn runtime_class(&self) -> RuntimeClass {
        self.class
    }

    /// The GPUs the Revision expects. `None` only for a CPU runtime class, and then no GPU
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

    /// The NICs/DPUs the Revision expects, on any class; `None` and no DPU backend is to run.
    pub fn dpu_shape(&self) -> Option<&DpuShape> {
        self.dpu.as_ref()
    }

    /// What every DPU transcript must be over: [`dpu::dpu_nonce`] of the verified `report_data`.
    pub fn dpu_nonce(&self) -> &[u8; 32] {
        &self.dpu_nonce
    }

    /// [`Self::finish_with_dpus`] for a pod whose Revision expects no NIC/DPU: one that does is
    /// refused here, since no DPU backend ran.
    pub fn finish(
        self,
        policy: Option<&GpuPolicy>,
        gpus: &[GpuAppraisal],
    ) -> Result<Appraised, AppraisalError> {
        self.finish_with_dpus(policy, gpus, None, &[])
    }

    /// The GPU decision over the backends' results, completing the appraisal. On a GPU class it
    /// is [`gpu::check_gpus`] (pure) over the Revision's shape. The CPU classes are the only ones
    /// whose GPU checks are skipped: there is no GPU to check, and GPU evidence from the pod, or
    /// a GPU a backend verified for it, is refused, never ignored.
    /// The NIC/DPU decision follows: [`dpu::check_dpus`] when the Revision expects DPUs, and
    /// otherwise no DPU evidence and no DPU verified, so DPU evidence is never ignored either.
    pub fn finish_with_dpus(
        self,
        policy: Option<&GpuPolicy>,
        gpus: &[GpuAppraisal],
        dpu_policy: Option<&DpuPolicy>,
        dpus: &[DpuAppraisal],
    ) -> Result<Appraised, AppraisalError> {
        let checked = match &self.gpus {
            ClassGpus::Cpu => {
                no_gpus(self.class, self.gpu_evidence, gpus)?;
                CheckedGpus::default()
            }
            ClassGpus::Gpu(shape) => {
                gpu::check_gpus(policy, shape, self.gpu_evidence, gpus, &self.gpu_nonce)?
            }
        };
        let verified_dpus = match &self.dpu {
            Some(shape) => {
                dpu::check_dpus(dpu_policy, shape, self.dpu_evidence, dpus, &self.dpu_nonce)?
            }
            None => {
                if self.dpu_evidence != 0 || dpus.iter().any(|a| !a.dpus.is_empty()) {
                    return Err(AppraisalError::Failed(
                        "NIC/DPU evidence from a pod whose Revision expects no DPU".into(),
                    ));
                }
                Vec::new()
            }
        };
        let mut appraised = self.appraised;
        if let Some(coco) = appraised.coco.as_mut() {
            coco.gpus = checked.gpus;
            coco.gpu_verifiers = checked.vouched;
            coco.dpus = verified_dpus;
        }
        Ok(appraised)
    }
}

/// The CPU half of `kata-tdx/1` or `kata-snp/1`, over CPU evidence already verified. Pure, so the
/// malicious-host cases are tests over synthetic quotes and reports.
pub fn appraise_kata_cpu(
    evidence: &EvidenceV2,
    verified: impl Into<VerifiedCpu>,
    nonce: &[u8; 32],
    runtime_pubkey_spki: &[u8],
    node_xwing_spki: Option<&[u8]>,
    doc: &PlatformDocument,
) -> Result<CpuAppraised, AppraisalError> {
    use AppraisalError::*;

    let verified = verified.into();
    let tee = match (cpu_kind(evidence)?, &verified) {
        (CpuKind::Tdx, VerifiedCpu::Tdx(_)) => Tee::Tdx,
        (CpuKind::Snp, VerifiedCpu::Snp(_)) => Tee::Snp,
        (kind, _) => {
            return Err(Failed(format!(
                "the evidence is {kind:?}, the verified CPU evidence is not"
            )));
        }
    };
    let (profile, reference_kind) = match tee {
        Tee::Tdx => (PROFILE_KATA_TDX, ReferenceKind::KataTdx),
        Tee::Snp => (PROFILE_KATA_SNP, ReferenceKind::KataSnp),
    };

    match &verified {
        VerifiedCpu::Tdx(quote) if !evidence.cpu.event_log.is_empty() => {
            let [r0, r1, r2, _] = event_log::replay(&evidence.cpu.event_log);
            let m = &quote.measured;
            if [r0, r1, r2] != [m.rtmr0, m.rtmr1, m.rtmr2] {
                return Err(Failed(
                    "event log does not replay to the quoted RTMR0..2".into(),
                ));
            }
        }
        VerifiedCpu::Snp(_) if !evidence.cpu.event_log.is_empty() => {
            return Err(Failed("an SEV-SNP guest has no TDX event log".into()));
        }
        _ => {}
    }
    if tee == Tee::Tdx && !evidence.cpu.vek.is_empty() {
        return Err(Failed("a TDX quote is not signed by an AMD VEK".into()));
    }

    // The runtime class here is the pod's claim, held to the measured init-data's below. It must
    // be a class a Revision v2 may name, on this CPU's TEE: it picks the reference value and
    // decides whether GPUs are checked.
    let class = RuntimeClass::from_name(&evidence.runtime_class).ok_or_else(|| {
        Failed(format!(
            "runtime class {:?} is not supported",
            evidence.runtime_class
        ))
    })?;
    if class.tee() != tee {
        return Err(Failed(format!(
            "runtime class {} does not run on {tee:?}",
            class.name()
        )));
    }
    // The guest image must be one captured for that class. A value for the other class, or one
    // that names no class, never stands in, so a guest booted from the NVIDIA guest image cannot
    // pass as the CPU class (whose GPU checks are skipped), nor the CPU guest as the GPU class,
    // provided the two guests' captured measurements differ (confirmed at capture).
    let for_class = |rv: &&crate::ReferenceValue| {
        rv.kind == reference_kind && rv.runtime_class.as_deref() == Some(class.name())
    };
    let reference = match &verified {
        VerifiedCpu::Tdx(quote) => doc
            .reference_values
            .iter()
            .filter(for_class)
            .find(|rv| rv.values.tdx().is_some_and(|v| v.matches(&quote.measured)))
            .ok_or_else(|| {
                Unknown(format!(
                    "no kata-tdx reference value for mrtd {} and runtime class {}",
                    quote.measured.mrtd,
                    class.name()
                ))
            })?,
        VerifiedCpu::Snp(report) => doc
            .reference_values
            .iter()
            .filter(for_class)
            .find(|rv| {
                rv.values
                    .snp()
                    .is_some_and(|v| v.measurement == report.measurement)
            })
            .ok_or_else(|| {
                Unknown(format!(
                    "no kata-snp reference value for measurement {} and runtime class {}",
                    report.measurement,
                    class.name()
                ))
            })?,
    };

    let initdata =
        InitData::parse(&evidence.initdata).map_err(|e| Failed(format!("init-data: {e}")))?;
    match &verified {
        VerifiedCpu::Tdx(quote) if Measurement(initdata.mrconfigid()) != quote.mrconfigid => {
            return Err(Failed(
                "MRCONFIGID is not the digest of the init-data sent".into(),
            ));
        }
        VerifiedCpu::Snp(report) if initdata.hostdata() != report.host_data => {
            return Err(Failed(
                "HOST_DATA is not the digest of the init-data sent".into(),
            ));
        }
        _ => {}
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
    // section; held again here, so nothing can turn a GPU class's checks into a CPU class's.
    let gpus = match (class.has_gpus(), &revision.gpu) {
        (false, None) => ClassGpus::Cpu,
        (true, Some(shape)) => ClassGpus::Gpu(shape.clone()),
        (false, Some(_)) => {
            return Err(Failed(format!(
                "init-data: runtime class {} runs no GPU",
                class.name()
            )));
        }
        (true, None) => {
            return Err(Failed(format!(
                "init-data: runtime class {} names no GPU",
                class.name()
            )));
        }
    };

    // Last of the CPU checks, as the plan orders them (PRD-02 R5e).
    let quoted = match &verified {
        VerifiedCpu::Tdx(quote) => quote.report_data,
        VerifiedCpu::Snp(report) => report.report_data,
    };
    let expected = report_data(runtime_pubkey_spki, nonce, node_xwing_spki);
    if !report_data_binds(&quoted, &expected) {
        return Err(Failed(
            "report_data is not bound to this key and nonce".into(),
        ));
    }

    let compose_hash = revision
        .hash()
        .map_err(|e| Failed(format!("revision: {e}")))?;
    if node_xwing_spki.is_some()
        && !doc
            .kms_revisions
            .iter()
            .any(|r| r.compose_hash == compose_hash)
    {
        return Err(Unknown(format!("kms revision {compose_hash}")));
    }

    let (measured, tcb_status, advisories, snp_findings): (Option<Measured>, _, _, _) =
        match verified {
            VerifiedCpu::Tdx(quote) => {
                let mut measured = quote.measured;
                measured.mrconfigid = Some(quote.mrconfigid);
                (Some(measured), quote.tcb_status, quote.advisories, None)
            }
            VerifiedCpu::Snp(report) => (
                None,
                SNP_TCB_STATUS.to_owned(),
                Vec::new(),
                Some(report.findings),
            ),
        };
    let evidence_json = serde_json::to_value(evidence).map_err(|e| Failed(e.to_string()))?;
    let appraised = Appraised {
        measured,
        tcb_status,
        advisories,
        os_image: reference.name.clone(),
        compose_hash,
        runtime_pubkey_sha256: format!(
            "sha256:{}",
            hex::encode(Sha256::digest(runtime_pubkey_spki))
        ),
        evidence_sha256: format!(
            "sha256:{}",
            hex::encode(Sha256::digest(
                alpha_core::jcs(&evidence_json).map_err(|e| Failed(e.to_string()))?
            ))
        ),
        policy_version: doc.version,
        coco: Some(CocoAppraised {
            profile: profile.into(),
            initdata_sha256: revision.initdata_sha256,
            policy_sha256: revision.policy_sha256,
            runtime_class: revision.runtime_class,
            gpus: Vec::new(),
            gpu_verifiers: Vec::new(),
            dpus: Vec::new(),
            snp: snp_findings,
        }),
    };
    Ok(CpuAppraised {
        appraised,
        class,
        gpus,
        gpu_evidence: evidence.gpus.len(),
        gpu_nonce: gpu::gpu_nonce(&expected),
        dpu: revision.dpu.clone(),
        dpu_evidence: evidence.nic.len(),
        dpu_nonce: dpu::dpu_nonce(&expected),
    })
}

/// A CPU runtime class runs no GPU. GPU evidence from such a pod, or a GPU a backend verified for
/// it, is a device its Revision does not expect: refused, never ignored.
fn no_gpus(
    class: RuntimeClass,
    evidence_count: usize,
    appraisals: &[GpuAppraisal],
) -> Result<(), AppraisalError> {
    let class = class.name();
    if evidence_count != 0 {
        return Err(AppraisalError::Failed(format!(
            "{evidence_count} GPU evidence entries from a pod of runtime class {class}, which runs no GPU"
        )));
    }
    if let Some(appraisal) = appraisals.iter().find(|a| !a.gpus.is_empty()) {
        return Err(AppraisalError::Failed(format!(
            "gpu verifier {:?} verified {} GPUs for a pod of runtime class {class}, which runs no GPU",
            appraisal.verifier,
            appraisal.gpus.len()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
