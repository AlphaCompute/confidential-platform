//! `alphacompute-evidence/2` and the `kata-tdx/1` profile: a Kata confidential pod on TDX with
//! the NVIDIA guest image and passed-through GPUs.
//!
//! The steps, in the plan's order (PRD-02 R5), after DCAP and the TCB policy that
//! [`crate::verify_quote`] already runs: (event log replay, when sent) → MRTD and RTMR0..2 match a
//! reference value of kind `kata-tdx` for the pod's runtime class → MRCONFIGID equals the
//! init-data's digest → the init-data parses, carries a policy and our entry → the evidence's
//! runtime class is the init-data's → report_data binds this key and nonce, last of the TD checks
//! → the Revision v2 rebuilt from the init-data (for a KMS node, found in `kms_revisions`) → every
//! expected GPU passed. Every step is mandatory; the order only decides which reason a refusal of
//! evidence with several faults names.

use std::time::SystemTime;

use alpha_core::ComposeHash;
use alpha_core::coco::InitData;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::gpu::{self, GpuAppraisal, GpuEvidence, VerifiedGpu};
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

/// What `kata-tdx/1` found, reported in the attestation result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CocoAppraised {
    pub profile: String,
    pub initdata_sha256: ComposeHash,
    pub policy_sha256: ComposeHash,
    pub runtime_class: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gpus: Vec<VerifiedGpu>,
}

/// The appraisal of either evidence format. `gpus` are the GPU backends' results, run by the
/// caller (the one network step) over `evidence.gpus()` with
/// [`gpu::gpu_nonce`]`(report_data(..))`; empty for v1 evidence.
#[allow(clippy::too_many_arguments)]
pub fn appraise_any(
    evidence: &AnyEvidence,
    nonce: &[u8; 32],
    runtime_pubkey_spki: &[u8],
    node_xwing_spki: Option<&[u8]>,
    doc: &PlatformDocument,
    collateral: &Collateral,
    gpus: &[GpuAppraisal],
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
                gpus,
            )
        }
    }
}

fn check_cpu_kind(evidence: &EvidenceV2) -> Result<(), AppraisalError> {
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

/// `kata-tdx/1` over a quote [`crate::verify_quote`] has already verified. Pure, so the
/// malicious-host cases are tests over synthetic quotes.
pub fn appraise_kata_tdx(
    evidence: &EvidenceV2,
    verified: VerifiedQuote,
    nonce: &[u8; 32],
    runtime_pubkey_spki: &[u8],
    node_xwing_spki: Option<&[u8]>,
    doc: &PlatformDocument,
    gpus: &[GpuAppraisal],
) -> Result<Appraised, AppraisalError> {
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

    // The runtime class here is the pod's claim; it is held to the measured init-data's below, so
    // a value listed for another class is never the one chosen.
    let class = evidence.runtime_class.as_str();
    let reference = doc
        .reference_values
        .iter()
        .find(|rv| {
            rv.kind == ReferenceKind::KataTdx
                && rv.runtime_class.as_deref().is_none_or(|c| c == class)
                && rv.values.mrtd == measured.mrtd
                && rv.values.rtmr0 == measured.rtmr0
                && rv.values.rtmr1 == measured.rtmr1
                && rv.values.rtmr2 == measured.rtmr2
        })
        .ok_or_else(|| {
            Unknown(format!(
                "no kata-tdx reference value for mrtd {} and runtime class {class}",
                measured.mrtd
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

    // Last of the TD checks, as the plan orders them (PRD-02 R5e).
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

    let verified_gpus = gpu::check_gpus(
        doc.gpu_policy.as_ref(),
        revision.gpu.as_ref(),
        evidence.gpus.len(),
        gpus,
        &gpu::gpu_nonce(&expected),
    )?;

    measured.mrconfigid = Some(mrconfigid);
    let evidence_json = serde_json::to_value(evidence).map_err(|e| Failed(e.to_string()))?;
    Ok(Appraised {
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
            profile: PROFILE_KATA_TDX.into(),
            initdata_sha256: revision.initdata_sha256,
            policy_sha256: revision.policy_sha256,
            runtime_class: revision.runtime_class,
            gpus: verified_gpus,
        }),
    })
}

#[cfg(test)]
mod tests;
