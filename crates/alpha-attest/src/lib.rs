//! Verifier for the evidence an Instance sends to the KMS: DCAP through `dcap-qvl`, then the
//! checks that are ours — `report_data` binding, RTMR replay, reference values, the measured
//! `compose_hash`. Pure over its arguments except [`fetch_collateral`].

mod event_log;

use std::fmt;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use alpha_core::{AppId, ComposeHash, OrgId};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
pub use dcap_qvl::QuoteCollateralV3 as Collateral;
use dcap_qvl::verify::QuoteVerifier;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

pub use event_log::EventLogEntry;

pub const EVIDENCE_FORMAT: &str = "alphacompute-evidence/1";
pub const RESULT_FORMAT: &str = "alphacompute-attestation-result/1";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub format: String,
    #[serde(with = "base64url")]
    pub quote: Vec<u8>,
    pub event_log: Vec<EventLogEntry>,
}

mod base64url {
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
        let hex = s.strip_prefix("sha384:").ok_or(ParseMeasurementError)?;
        if hex.bytes().any(|b| b.is_ascii_uppercase()) {
            return Err(ParseMeasurementError);
        }
        let mut bytes = [0u8; 48];
        hex::decode_to_slice(hex, &mut bytes).map_err(|_| ParseMeasurementError)?;
        Ok(Self(bytes))
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
}

/// The platform document (release-signed; the signature is checked by whoever fetched it).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformDocument {
    pub version: u64,
    pub issued_at: String,
    pub policy: Policy,
    pub reference_values: Vec<ReferenceValue>,
    pub kms_ca_pem: String,
    pub kms_revisions: Vec<KmsRevision>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    pub tcb_statuses: Vec<String>,
    pub tolerated_advisories: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferenceValue {
    pub name: String,
    pub values: ReferenceMeasurements,
}

/// rtmr3 is not a reference value: it holds the measured `compose_hash` and per-Instance ids.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferenceMeasurements {
    pub mrtd: Measurement,
    pub rtmr0: Measurement,
    pub rtmr1: Measurement,
    pub rtmr2: Measurement,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KmsRevision {
    pub compose_hash: ComposeHash,
    pub build: String,
    pub source_url: String,
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Appraised {
    pub measured: Measured,
    pub tcb_status: String,
    pub advisories: Vec<String>,
    pub os_image: String,
    pub compose_hash: ComposeHash,
    pub runtime_pubkey_sha256: String,
    pub evidence_sha256: String,
    pub policy_version: u64,
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
    let now = now
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Failed("now is before the epoch".into()))?
        .as_secs();
    // The debug bit is a policy decision here, not a verification failure.
    let verified = QuoteVerifier::new_prod()
        .allow_debug(true)
        .verify(&evidence.quote, collateral, now)
        .map_err(|e| Failed(format!("dcap: {e:#}")))?;
    let report = verified
        .report
        .as_td10()
        .ok_or_else(|| Failed("quote is not a TDX quote".into()))?;

    let tcb_status = verified.status;
    let advisories = verified.advisory_ids;
    check_policy(&doc.policy, &tcb_status, &advisories, &report.td_attributes)?;

    let mut expected = [0u8; 64];
    expected[..32].copy_from_slice(
        &Sha256::new()
            .chain_update(runtime_pubkey_spki)
            .chain_update(nonce)
            .finalize(),
    );
    if let Some(xwing_spki) = node_xwing_spki {
        expected[32..].copy_from_slice(&Sha256::digest(xwing_spki));
    }
    if report.report_data != expected {
        return Err(Failed(
            "report_data is not bound to this key and nonce".into(),
        ));
    }

    let measured = Measured {
        mrtd: Measurement(report.mr_td),
        rtmr0: Measurement(report.rt_mr0),
        rtmr1: Measurement(report.rt_mr1),
        rtmr2: Measurement(report.rt_mr2),
        rtmr3: Measurement(report.rt_mr3),
    };
    let [rtmr0, rtmr1, rtmr2, rtmr3] = event_log::replay(&evidence.event_log);
    if [rtmr0, rtmr1, rtmr2, rtmr3]
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
            rv.values.mrtd == measured.mrtd
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
            hex::encode(Sha256::digest(alpha_core::jcs(&evidence_json)))
        ),
        policy_version: doc.version,
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
    fn policy_admits_listed_status_and_tolerated_advisories() {
        assert_eq!(denied("UpToDate", &[], PROD), None);
        assert_eq!(denied("SWHardeningNeeded", &["INTEL-SA-00837"], PROD), None);
    }

    #[test]
    fn policy_denies_unlisted_status_even_without_advisories() {
        assert!(
            denied("OutOfDate", &[], PROD)
                .unwrap()
                .contains("OutOfDate")
        );
    }

    #[test]
    fn policy_denies_untolerated_advisory_under_listed_status() {
        assert!(
            denied(
                "SWHardeningNeeded",
                &["INTEL-SA-00837", "INTEL-SA-00999"],
                PROD
            )
            .unwrap()
            .contains("INTEL-SA-00999")
        );
    }

    #[test]
    fn policy_denies_debug_td() {
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
}
