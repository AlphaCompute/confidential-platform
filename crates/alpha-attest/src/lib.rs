//! Verifier for the evidence an Instance sends to the KMS: DCAP through `dcap-qvl`, then the
//! checks that are ours — `report_data` binding, RTMR replay, reference values, the measured
//! `compose_hash`. Pure over its arguments except [`fetch_collateral`].

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

pub const EVIDENCE_FORMAT: &str = "alphacompute-evidence/1";
pub const RESULT_FORMAT: &str = "alphacompute-attestation-result/1";

#[derive(Debug, Serialize, Deserialize)]
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<Signer>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catalog_key: Option<CatalogKey>,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "kata_reference_values"
    )]
    pub kata_reference_values: Vec<KataReference>,
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

/// The measurements of every Kata TD booted under one runtime class. RTMR0 differs per pod
/// shape (vCPUs and memory reach the guest as ACPI, SMBIOS and the TD HOB), so it is a set with
/// one value per offered shape.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KataReference {
    pub runtime_class: String,
    pub mrtd: Measurement,
    pub rtmr0: Vec<Measurement>,
    pub rtmr1: Measurement,
    pub rtmr2: Measurement,
}

impl KataReference {
    fn matches(&self, m: &Measured) -> bool {
        self.mrtd == m.mrtd
            && self.rtmr1 == m.rtmr1
            && self.rtmr2 == m.rtmr2
            && self.rtmr0.contains(&m.rtmr0)
    }

    fn overlaps(&self, other: &KataReference) -> bool {
        self.mrtd == other.mrtd
            && self.rtmr1 == other.rtmr1
            && self.rtmr2 == other.rtmr2
            && self.rtmr0.iter().any(|r| other.rtmr0.contains(r))
    }
}

/// The runtime class is read off the measurements, so no two entries may accept the same TD:
/// otherwise a GPU class could be reported for a CPU pod, or the other way round.
fn kata_reference_values<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<KataReference>, D::Error> {
    use serde::de::Error;

    let entries = Vec::<KataReference>::deserialize(deserializer)?;
    for (i, entry) in entries.iter().enumerate() {
        let class = &entry.runtime_class;
        if class.is_empty() {
            return Err(D::Error::custom(
                "kata_reference_values: runtime_class is empty",
            ));
        }
        for other in entries.iter().skip(i.saturating_add(1)) {
            if entry.overlaps(other) {
                return Err(D::Error::custom(format!(
                    "kata_reference_values: {class} and {} accept the same measurements",
                    other.runtime_class
                )));
            }
        }
    }
    Ok(entries)
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
    pub td_attributes: [u8; 8],
    pub xfam: [u8; 8],
    pub mr_config_id: [u8; 48],
    pub mr_owner: [u8; 48],
    pub mr_owner_config: [u8; 48],
    pub mr_signer_seam: [u8; 48],
    pub measured: Measured,
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
    };
    Ok(VerifiedQuote {
        report_data: report.report_data,
        td_attributes: report.td_attributes,
        xfam: report.xfam,
        mr_config_id: report.mr_config_id,
        mr_owner: report.mr_owner,
        mr_owner_config: report.mr_owner_config,
        mr_signer_seam: report.mr_signer_seam,
        measured,
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
            hex::encode(Sha256::digest(
                alpha_core::jcs(&evidence_json).map_err(|e| Failed(e.to_string()))?
            ))
        ),
        policy_version: doc.version,
    })
}

#[derive(Debug, thiserror::Error)]
pub enum InitDataMismatch {
    // A host can drop the init-data annotation and the pod still boots, under the guest image's
    // default agent policy, which allows exec.
    #[error("MRCONFIGID is zero: the pod was booted without init-data")]
    Absent,
    #[error("MRCONFIGID is not the digest of this init-data")]
    Different,
}

/// Kata's QEMU copies the init-data's SHA-256 into a zeroed 48-byte `MRCONFIGID`. `digest` is
/// [`InitData::digest`](alpha_core::InitData::digest) of the Revision's init-data.
pub fn check_init_data(
    quote: &VerifiedQuote,
    digest: &ComposeHash,
) -> Result<(), InitDataMismatch> {
    if quote.mr_config_id == [0; 48] {
        return Err(InitDataMismatch::Absent);
    }
    if !quote
        .mr_config_id
        .iter()
        .eq(digest.as_bytes().iter().chain(&[0; 16]))
    {
        return Err(InitDataMismatch::Different);
    }
    Ok(())
}

/// SEPT_VE_DISABLE alone. Compared whole, not as a mask, so DEBUG, MIGRATABLE, PKS, KL or
/// PERFMON appearing after a QEMU or Kata config change is refused too.
const KATA_TD_ATTRIBUTES: u64 = 0x1000_0000;
/// x87, SSE, AVX, AVX-512, PKRU, CET and AMX: what `-cpu host` yields on our B300 hosts.
// ponytail: one host CPU class, so one XFAM for every runtime class; a second CPU generation
// moves this into each `kata_reference_values` entry.
const KATA_XFAM: u64 = 0x61ae7;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KataAppraised {
    /// The class whose reference values the measurements matched, never a host's claim.
    pub runtime_class: String,
    pub quote: VerifiedQuote,
}

/// Appraisal of a Kata TD's quote, bound to this request by `expected_report_data` (see
/// [`report_data`]), against `doc.kata_reference_values` and the init-data digest of the
/// Revision it claims to run. No event log is replayed: the events that vary between TDs carry
/// only digests, so the final registers say as much.
pub fn appraise_kata(
    quote: &[u8],
    expected_report_data: &[u8; 64],
    init_data: &ComposeHash,
    doc: &PlatformDocument,
    collateral: &Collateral,
    now: SystemTime,
) -> Result<KataAppraised, AppraisalError> {
    let quote = verify_quote(quote, collateral, &doc.policy, now)?;
    if &quote.report_data != expected_report_data {
        return Err(AppraisalError::Failed(
            "report_data is not bound to this request".into(),
        ));
    }
    let runtime_class = kata_runtime_class(&quote, &doc.kata_reference_values)?.to_owned();
    check_init_data(&quote, init_data).map_err(|e| AppraisalError::Failed(e.to_string()))?;
    Ok(KataAppraised {
        runtime_class,
        quote,
    })
}

fn kata_runtime_class<'a>(
    quote: &VerifiedQuote,
    references: &'a [KataReference],
) -> Result<&'a str, AppraisalError> {
    use AppraisalError::*;

    let td_attributes = u64::from_le_bytes(quote.td_attributes);
    if td_attributes != KATA_TD_ATTRIBUTES {
        return Err(PolicyDenied(format!("td_attributes {td_attributes:#x}")));
    }
    let xfam = u64::from_le_bytes(quote.xfam);
    if xfam != KATA_XFAM {
        return Err(PolicyDenied(format!("xfam {xfam:#x}")));
    }
    // Nothing of ours extends RTMR3, and Kata never sets the owner fields.
    if quote.measured.rtmr3 != Measurement([0; 48]) {
        return Err(Unknown(format!("rtmr3 {}", quote.measured.rtmr3)));
    }
    if quote.mr_owner != [0; 48] || quote.mr_owner_config != [0; 48] {
        return Err(Unknown("mrowner or mrownerconfig is not zero".into()));
    }
    // Zero means Intel signed the TDX module; anything else is a module TCB levels say nothing about.
    if quote.mr_signer_seam != [0; 48] {
        return Err(PolicyDenied("mrsignerseam is not zero".into()));
    }
    // Parsing refuses empty and overlapping entries, but a document built in code skips that.
    let mut matching = references
        .iter()
        .filter(|r| !r.runtime_class.is_empty() && r.matches(&quote.measured));
    match (matching.next(), matching.next()) {
        (Some(r), None) => Ok(r.runtime_class.as_str()),
        (None, _) => Err(Unknown(format!(
            "no kata runtime class for mrtd {} rtmr0 {}",
            quote.measured.mrtd, quote.measured.rtmr0
        ))),
        (Some(_), Some(_)) => Err(Unknown("more than one kata runtime class matches".into())),
    }
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

    fn captured_at(dir: &std::path::Path) -> SystemTime {
        let text = std::fs::read_to_string(dir.join("captured_at.txt")).unwrap();
        let secs = chrono::DateTime::parse_from_rfc3339(text.trim())
            .unwrap()
            .timestamp();
        UNIX_EPOCH + std::time::Duration::from_secs(secs as u64)
    }

    /// `verify_quote` used standalone, over a third party's quote and our own policy —
    /// the shape `services/alpha-inference` needs, proven here on a real capture rather
    /// than a synthetic one.
    #[test]
    fn verify_quote_reports_the_capture_report_data() {
        use std::path::PathBuf;

        let dir =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/attest/phala-dev-0.5.9");
        let read = |name: &str| std::fs::read_to_string(dir.join(name)).unwrap();
        let quote = hex::decode(read("quote.instance.hex").trim()).unwrap();
        let collateral: Collateral = serde_json::from_str(&read("collateral.json")).unwrap();
        let doc: PlatformDocument = serde_json::from_str(&read("platform-document.json")).unwrap();
        let now = captured_at(&dir);

        let verified = verify_quote(&quote, &collateral, &doc.policy, now).unwrap();

        assert_eq!(
            hex::encode(verified.report_data),
            read("report_data.instance.hex").trim()
        );
        assert_eq!(verified.tcb_status, "UpToDate");
    }

    type QuoteChange = fn(&mut VerifiedQuote);

    fn kata_dir() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../testdata/attest/b300-kata-4.0.0")
    }

    fn kata_doc_json() -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(kata_dir().join("platform-document.json")).unwrap())
            .unwrap()
    }

    /// The real CPU-pod quote, so each test below changes exactly one field the hardware
    /// would not produce on request.
    fn kata_cpu_quote() -> (VerifiedQuote, PlatformDocument) {
        let read = |name: &str| std::fs::read(kata_dir().join(name)).unwrap();
        let collateral: Collateral = serde_json::from_slice(&read("collateral.json")).unwrap();
        let doc: PlatformDocument = serde_json::from_value(kata_doc_json()).unwrap();
        let now = captured_at(&kata_dir());
        let quote =
            verify_quote(&read("p1-sha256.quote.bin"), &collateral, &doc.policy, now).unwrap();
        (quote, doc)
    }

    #[test]
    fn kata_td_fields_outside_the_reference_are_refused() {
        let (quote, doc) = kata_cpu_quote();
        let refs = &doc.kata_reference_values;
        assert_eq!(kata_runtime_class(&quote, refs).unwrap(), "kata-qemu-tdx");

        let cases: [(QuoteChange, &str, &str); 8] = [
            (
                |q| q.td_attributes[0] |= 0x01,
                "policy_denied",
                "td_attributes",
            ),
            (|q| q.td_attributes[3] = 0, "policy_denied", "td_attributes"),
            (
                |q| q.td_attributes[3] |= 0x40,
                "policy_denied",
                "td_attributes",
            ),
            (|q| q.xfam[0] ^= 0x01, "policy_denied", "xfam"),
            (
                |q| q.measured.rtmr3.0[47] = 1,
                "attestation_unknown",
                "rtmr3",
            ),
            (|q| q.mr_owner[0] = 1, "attestation_unknown", "mrowner"),
            (
                |q| q.mr_owner_config[47] = 1,
                "attestation_unknown",
                "mrownerconfig",
            ),
            (|q| q.mr_signer_seam[0] = 1, "policy_denied", "mrsignerseam"),
        ];
        for (change, code, fragment) in cases {
            let mut q = quote.clone();
            change(&mut q);
            let err = kata_runtime_class(&q, refs).unwrap_err();
            assert_eq!(err.code(), code, "{err}");
            assert!(err.to_string().contains(fragment), "{err}");
        }
    }

    #[test]
    fn kata_reference_values_that_could_match_anything_or_twice_are_refused() {
        let parse = |change: &dyn Fn(&mut serde_json::Value)| {
            let mut doc = kata_doc_json();
            change(&mut doc);
            serde_json::from_value::<PlatformDocument>(doc)
                .err()
                .map(|e| e.to_string())
        };
        let empty = parse(&|d| d["kata_reference_values"][0]["runtime_class"] = "".into());
        assert!(empty.is_some_and(|e| e.contains("runtime_class is empty")));
        let gpu_rtmr0 = kata_doc_json()["kata_reference_values"][1]["rtmr0"][0].clone();
        let overlap = parse(&|d| {
            let cpu = d["kata_reference_values"][0].clone();
            d["kata_reference_values"][1] = cpu;
            d["kata_reference_values"][1]["runtime_class"] = "kata-qemu-tdx-2".into();
            d["kata_reference_values"][1]["rtmr0"] =
                serde_json::json!([gpu_rtmr0, d["kata_reference_values"][0]["rtmr0"][4]]);
        });
        assert!(overlap.is_some_and(|e| e.contains("accept the same measurements")));
    }
}
