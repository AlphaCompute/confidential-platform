//! Verifier for the evidence an Instance sends to the KMS: DCAP through `dcap-qvl`, then the
//! checks that are ours — `report_data` binding, RTMR replay, reference values, the measured
//! `compose_hash`, and for a Kata pod its init-data and GPUs. Pure over its arguments except
//! [`fetch_collateral`] and the GPU backends: [`gpu::nras`] calls NRAS over HTTPS, and
//! [`kata::appraise_any`] calls the backends it is given.

#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )
)]

mod event_log;
pub mod export;
pub mod gpu;
pub mod kata;
pub mod verifiers;

use std::fmt;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

pub use alpha_core::KmsRevision;
use alpha_core::{AppId, ComposeHash, OrgId, hex_bytes};
use alpha_core::{CatalogKey, Signer};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
pub use dcap_qvl::QuoteCollateralV3 as Collateral;
use dcap_qvl::verify::QuoteVerifier;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

pub use event_log::{EventLogEntry, compose_hash as event_log_compose_hash};
pub use gpu::{
    GpuAppraisal, GpuEvidence, GpuPolicy, GpuVerdict, GpuVerifier, GpuVerifierKind, GpuVouch,
    VerifiedGpu,
};
pub use kata::{AnyEvidence, CocoAppraised, CpuEvidence, CpuKind, EvidenceV2, appraise_any};
pub use verifiers::{CpuVerifierKind, CpuVouch, Party, Verifiers};

pub const EVIDENCE_FORMAT: &str = "alphacompute-evidence/1";
pub const EVIDENCE_FORMAT_V2: &str = "alphacompute-evidence/2";
pub const RESULT_FORMAT: &str = "alphacompute-attestation-result/1";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub format: String,
    #[serde(with = "base64url")]
    pub quote: Vec<u8>,
    pub event_log: Vec<EventLogEntry>,
}

pub(crate) mod base64url {
    use super::*;

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&BASE64_URL_SAFE_NO_PAD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(deserializer)?;
        BASE64_URL_SAFE_NO_PAD
            .decode(s)
            .map_err(serde::de::Error::custom)
    }
}

/// A 48-byte TDX register value, written `sha384:<hex>` on the wire.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Measurement(pub [u8; 48]);

impl fmt::Display for Measurement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sha384:{}", hex::encode(self.0))
    }
}

impl fmt::Debug for Measurement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("expected sha384:<96 lowercase hex>")]
pub struct ParseMeasurementError;

impl FromStr for Measurement {
    type Err = ParseMeasurementError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.strip_prefix("sha384:")
            .and_then(hex_bytes)
            .map(Self)
            .ok_or(ParseMeasurementError)
    }
}

impl Serialize for Measurement {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Measurement {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Measured {
    pub mrtd: Measurement,
    pub rtmr0: Measurement,
    pub rtmr1: Measurement,
    pub rtmr2: Measurement,
    pub rtmr3: Measurement,
    /// Set by the `kata-tdx/1` profile only: the init-data binding. The prototype profile leaves
    /// it out, so its results are byte-for-byte what they were.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mrconfigid: Option<Measurement>,
}

/// The platform document (release-signed; the signature is checked by whoever fetched it).
///
/// It refuses fields it does not know, as do its policy and reference values: `alpha sign`
/// validates a document through this type, so a misspelled field (a reference value's
/// `runtime_class`, say) is refused at signing instead of being signed and ignored, and a KMS
/// never reads past a rule it does not understand. Pages that only display a document read it
/// through `alpha_channel::platform::PlatformView`, which tolerates new fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformDocument {
    pub version: u64,
    pub issued_at: String,
    pub policy: Policy,
    pub reference_values: Vec<ReferenceValue>,
    pub kms_ca_pem: String,
    pub kms_revisions: Vec<KmsRevision>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<Signer>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catalog_key: Option<CatalogKey>,
    /// What a GPU must prove before a Kata pod that expects GPUs gets a leaf. Absent, no Revision
    /// on the GPU runtime class can attest; pods on the CPU class never need it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu_policy: Option<GpuPolicy>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub tcb_statuses: Vec<String>,
    pub tolerated_advisories: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReferenceValue {
    pub name: String,
    /// Which evidence profile the measurements belong to; a document written before Kata had
    /// none, and every value in it is a prototype guest's.
    #[serde(default, skip_serializing_if = "ReferenceKind::is_prototype")]
    pub kind: ReferenceKind,
    /// For a Kata guest: the runtime class whose guest image these are (`kata-qemu-tdx` or
    /// `kata-qemu-nvidia-gpu-tdx`). Required for `kata-tdx`: a value without one, or naming
    /// another class, never matches a pod, since the class decides whether GPUs are checked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_class: Option<String>,
    pub values: ReferenceMeasurements,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReferenceKind {
    /// The prototype CVM guest: `alphacompute-evidence/1`.
    #[default]
    PrototypeTdx,
    /// A Kata pod VM on TDX, the CPU guest or the NVIDIA guest per `runtime_class`: `kata-tdx/1`.
    KataTdx,
    /// A Kata pod VM on SEV-SNP (PRD-02 P2; no profile appraises it yet).
    KataSnp,
}

impl ReferenceKind {
    pub fn is_prototype(&self) -> bool {
        *self == Self::PrototypeTdx
    }
}

/// rtmr3 is not a reference value: it holds the measured `compose_hash` and per-Instance ids.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReferenceMeasurements {
    pub mrtd: Measurement,
    pub rtmr0: Measurement,
    pub rtmr1: Measurement,
    pub rtmr2: Measurement,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationResult {
    pub format: String,
    pub verdict: Verdict,
    pub measured: Measured,
    pub tcb_status: String,
    pub advisories: Vec<String>,
    pub os_image: String,
    pub revision: Revision,
    pub runtime_pubkey_sha256: String,
    pub evidence_sha256: String,
    pub verified_at: String,
    pub policy_version: u64,
    /// The `kata-tdx/1` profile's findings: init-data, policy, runtime class and every GPU.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coco: Option<CocoAppraised>,
    /// Which verifiers attested the workload (PRD-06 clear claims), from the KMS's own appraisal.
    /// Absent only in a result from a KMS that predates it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifiers: Option<Verifiers>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Verified,
    Failed,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Revision {
    pub compose_hash: ComposeHash,
    pub app_id: AppId,
    pub org_id: OrgId,
}

/// Everything an [`AttestationResult`] needs except `revision` and `verified_at`, which the
/// KMS fills after looking `compose_hash` up in its Revisions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Appraised {
    pub measured: Measured,
    pub tcb_status: String,
    pub advisories: Vec<String>,
    pub os_image: String,
    pub compose_hash: ComposeHash,
    pub runtime_pubkey_sha256: String,
    pub evidence_sha256: String,
    pub policy_version: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coco: Option<CocoAppraised>,
}

#[derive(Debug, thiserror::Error)]
pub enum AppraisalError {
    #[error("evidence does not verify: {0}")]
    Failed(String),
    #[error("no reference for the evidence: {0}")]
    Unknown(String),
    #[error("policy denies the evidence: {0}")]
    PolicyDenied(String),
}

impl AppraisalError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Failed(_) => "attestation_failed",
            Self::Unknown(_) => "attestation_unknown",
            Self::PolicyDenied(_) => "policy_denied",
        }
    }
}

/// The 64 bytes an Instance or a KMS node binds into its quote: `SHA-256(SPKI ‖ nonce)` and,
/// for a node, `SHA-256(xwing_pubkey)`; zeros for an Instance.
pub fn report_data(
    runtime_pubkey_spki: &[u8],
    nonce: &[u8; 32],
    node_xwing_pubkey: Option<&[u8]>,
) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(
        &Sha256::new()
            .chain_update(runtime_pubkey_spki)
            .chain_update(nonce)
            .finalize(),
    );
    if let Some(xwing) = node_xwing_pubkey {
        out[32..].copy_from_slice(&Sha256::digest(xwing));
    }
    out
}

/// What [`verify_quote`] proves about a TDX quote, independent of whose it is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedQuote {
    pub report_data: [u8; 64],
    pub measured: Measured,
    /// TD10 MR_CONFIG_ID, whatever the profile; only `kata-tdx/1` reads it.
    pub mrconfigid: Measurement,
    pub tcb_status: String,
    pub advisories: Vec<String>,
}

/// The DCAP verification, TD10 extraction and policy check, for any TDX quote — a third
/// party's or our own. The crate's one production quote verifier runs here.
pub fn verify_quote(
    quote: &[u8],
    collateral: &Collateral,
    policy: &Policy,
    now: SystemTime,
) -> Result<VerifiedQuote, AppraisalError> {
    use AppraisalError::*;

    let now = now
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Failed("now is before the epoch".into()))?
        .as_secs();
    // The debug bit is a policy decision here, not a verification failure.
    let verified = QuoteVerifier::new_prod()
        .allow_debug(true)
        .verify(quote, collateral, now)
        .map_err(|e| Failed(format!("dcap: {e:#}")))?;
    let report = verified
        .report
        .as_td10()
        .ok_or_else(|| Failed("quote is not a TDX quote".into()))?;

    let tcb_status = verified.status;
    let advisories = verified.advisory_ids;
    check_policy(policy, &tcb_status, &advisories, &report.td_attributes)?;

    let measured = Measured {
        mrtd: Measurement(report.mr_td),
        rtmr0: Measurement(report.rt_mr0),
        rtmr1: Measurement(report.rt_mr1),
        rtmr2: Measurement(report.rt_mr2),
        rtmr3: Measurement(report.rt_mr3),
        mrconfigid: None,
    };
    Ok(VerifiedQuote {
        report_data: report.report_data,
        measured,
        mrconfigid: Measurement(report.mr_config_id),
        tcb_status,
        advisories,
    })
}

/// Steps 1–8a of the appraisal: everything up to and including reading `compose_hash`
/// from the event log. `node_xwing_spki` is `Some` for a KMS node, whose `compose_hash`
/// must then be in `doc.kms_revisions`; for an Instance the KMS looks it up in its own
/// Revisions afterwards.
pub fn appraise(
    evidence: &Evidence,
    nonce: &[u8; 32],
    runtime_pubkey_spki: &[u8],
    node_xwing_spki: Option<&[u8]>,
    doc: &PlatformDocument,
    collateral: &Collateral,
    now: SystemTime,
) -> Result<Appraised, AppraisalError> {
    use AppraisalError::*;

    if evidence.format != EVIDENCE_FORMAT {
        return Err(Unknown(format!("evidence format {:?}", evidence.format)));
    }
    let VerifiedQuote {
        report_data: verified_report_data,
        measured,
        tcb_status,
        advisories,
        ..
    } = verify_quote(&evidence.quote, collateral, &doc.policy, now)?;

    if verified_report_data != report_data(runtime_pubkey_spki, nonce, node_xwing_spki) {
        return Err(Failed(
            "report_data is not bound to this key and nonce".into(),
        ));
    }

    if event_log::replay(&evidence.event_log)
        != [
            measured.rtmr0,
            measured.rtmr1,
            measured.rtmr2,
            measured.rtmr3,
        ]
    {
        return Err(Failed(
            "event log does not replay to the quoted RTMRs".into(),
        ));
    }

    let os_image = doc
        .reference_values
        .iter()
        .find(|rv| {
            rv.kind == ReferenceKind::PrototypeTdx
                && rv.values.mrtd == measured.mrtd
                && rv.values.rtmr0 == measured.rtmr0
                && rv.values.rtmr1 == measured.rtmr1
                && rv.values.rtmr2 == measured.rtmr2
        })
        .map(|rv| rv.name.clone())
        .ok_or_else(|| Unknown(format!("no reference value for mrtd {}", measured.mrtd)))?;

    let compose_hash = event_log::compose_hash(&evidence.event_log)
        .ok_or_else(|| Failed("event log has no compose-hash event".into()))?;
    if node_xwing_spki.is_some()
        && !doc
            .kms_revisions
            .iter()
            .any(|r| r.compose_hash == compose_hash)
    {
        return Err(Unknown(format!("kms revision {compose_hash}")));
    }

    let evidence_json = serde_json::to_value(evidence).map_err(|e| Failed(e.to_string()))?;
    Ok(Appraised {
        measured,
        tcb_status,
        advisories,
        os_image,
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
        coco: None,
    })
}

fn check_policy(
    policy: &Policy,
    tcb_status: &str,
    advisories: &[String],
    td_attributes: &[u8; 8],
) -> Result<(), AppraisalError> {
    use AppraisalError::PolicyDenied;

    if !policy.tcb_statuses.iter().any(|s| s == tcb_status) {
        return Err(PolicyDenied(format!("tcb_status {tcb_status}")));
    }
    if let Some(advisory) = advisories
        .iter()
        .find(|a| !policy.tolerated_advisories.contains(a))
    {
        return Err(PolicyDenied(format!("advisory {advisory}")));
    }
    // TDX Module spec, TD_ATTRIBUTES bit 0: DEBUG.
    if td_attributes[0] & 0x01 != 0 {
        return Err(PolicyDenied("debug TD".into()));
    }
    Ok(())
}

/// The one I/O in the crate: DCAP collateral for `quote` from a PCCS.
pub async fn fetch_collateral(pccs_url: &str, quote: &[u8]) -> Result<Collateral, AppraisalError> {
    dcap_qvl::collateral::CollateralClient::with_default_http(pccs_url)
        .map_err(|e| AppraisalError::Failed(format!("pccs client: {e:#}")))?
        .fetch(quote)
        .await
        .map_err(|e| AppraisalError::Failed(format!("collateral: {e:#}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        Policy {
            tcb_statuses: vec!["UpToDate".into(), "SWHardeningNeeded".into()],
            tolerated_advisories: vec!["INTEL-SA-00837".into()],
        }
    }

    const PROD: [u8; 8] = [0, 0, 0, 0x10, 0, 0, 0, 0];
    const DEBUG: [u8; 8] = [1, 0, 0, 0x10, 0, 0, 0, 0];

    fn denied(status: &str, advisories: &[&str], attrs: [u8; 8]) -> Option<String> {
        let advisories: Vec<String> = advisories.iter().map(|s| s.to_string()).collect();
        check_policy(&policy(), status, &advisories, &attrs)
            .err()
            .map(|e| {
                assert_eq!(e.code(), "policy_denied");
                e.to_string()
            })
    }

    #[test]
    fn policy_check() {
        assert_eq!(denied("UpToDate", &[], PROD), None);
        assert_eq!(denied("SWHardeningNeeded", &["INTEL-SA-00837"], PROD), None);
        assert!(
            denied("OutOfDate", &[], PROD)
                .unwrap()
                .contains("OutOfDate")
        );
        assert!(
            denied(
                "SWHardeningNeeded",
                &["INTEL-SA-00837", "INTEL-SA-00999"],
                PROD
            )
            .unwrap()
            .contains("INTEL-SA-00999")
        );
        assert!(denied("UpToDate", &[], DEBUG).unwrap().contains("debug"));
    }

    #[test]
    fn measurement_round_trips() {
        let m = Measurement([7; 48]);
        assert_eq!(m.to_string().parse::<Measurement>().unwrap(), m);
        assert_eq!(serde_json::to_string(&m).unwrap(), format!("\"{m}\""));
        for bad in ["", "sha384:", "sha256:0707", &m.to_string().to_uppercase()] {
            assert!(bad.parse::<Measurement>().is_err(), "{bad}");
        }
    }

    /// `verify_quote` used standalone, over a third party's quote and our own policy —
    /// the shape `services/alpha-inference` needs, proven here on a real capture rather
    /// than a synthetic one.
    #[test]
    fn verify_quote_reports_the_capture_report_data() {
        use std::path::PathBuf;
        use std::time::Duration;

        let dir =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/attest/phala-dev-0.5.9");
        let read = |name: &str| std::fs::read_to_string(dir.join(name)).unwrap();
        let quote = hex::decode(read("quote.instance.hex").trim()).unwrap();
        let collateral: Collateral = serde_json::from_str(&read("collateral.json")).unwrap();
        let doc: PlatformDocument = serde_json::from_str(&read("platform-document.json")).unwrap();
        let now = UNIX_EPOCH
            + Duration::from_secs(
                chrono::DateTime::parse_from_rfc3339(read("captured_at.txt").trim())
                    .unwrap()
                    .timestamp() as u64,
            );

        let verified = verify_quote(&quote, &collateral, &doc.policy, now).unwrap();

        assert_eq!(
            hex::encode(verified.report_data),
            read("report_data.instance.hex").trim()
        );
        assert_eq!(verified.tcb_status, "UpToDate");
    }
}
