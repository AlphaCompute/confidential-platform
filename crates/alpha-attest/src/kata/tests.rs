//! `kata-tdx/1` over synthetic verified quotes: the DCAP step is exercised by the real captures in
//! `tests/vectors.rs`, and a B300 Kata capture joins them at M1. These are the malicious-host
//! cases the KMS itself must refuse; exec, log reads and container changes are refused inside the
//! guest by the agent policy and are tested on a live pod (PRD-02 §4).

use alpha_core::coco::{InitData, REVISION_FORMAT};
use alpha_core::{AppId, KmsRevision};

use super::*;
use crate::gpu::{GpuPolicy, GpuVerifierKind, gpu_nonce};
use crate::{Measured, Policy, ReferenceMeasurements, ReferenceValue};

const SPKI: &[u8] = b"runtime spki";
const NONCE: [u8; 32] = [3; 32];
const XWING: &[u8] = b"node xwing";
const APP: &str = "01994b3e-5c8a-7d3e-9a1b-2c3d4e5f6a7b";
const CLASS: &str = "kata-qemu-nvidia-gpu-tdx";

fn m(byte: u8) -> Measurement {
    Measurement([byte; 48])
}

fn initdata_text(policy: &str, gpu: Option<u32>) -> String {
    let gpu = gpu
        .map(|n| format!("\"gpu\":{{\"count\":{n},\"model\":\"B300\"}},"))
        .unwrap_or_default();
    format!(
        "algorithm = \"sha384\"\nversion = \"0.1.0\"\n\n[data]\n\"policy.rego\" = '''\n{policy}'''\n\"alpha.json\" = '''{{\"app_id\":\"{APP}\",\"format\":\"alphacompute-initdata/1\",{gpu}\"runtime_class\":\"{CLASS}\"}}'''\n"
    )
}

const POLICY: &str = "package agent_policy\ndefault ExecProcessRequest := false\ndefault ReadStreamRequest := false\n";

struct Pod {
    initdata: String,
    gpus: u32,
    node: bool,
    aa_report_data: bool,
}

impl Pod {
    fn gpu(gpus: u32) -> Self {
        Self {
            initdata: initdata_text(POLICY, Some(gpus)),
            gpus,
            node: false,
            aa_report_data: false,
        }
    }

    fn xwing(&self) -> Option<&'static [u8]> {
        self.node.then_some(XWING)
    }

    fn expected_report_data(&self) -> [u8; 64] {
        report_data(SPKI, &NONCE, self.xwing())
    }

    fn evidence(&self) -> EvidenceV2 {
        EvidenceV2 {
            format: EVIDENCE_FORMAT_V2.into(),
            cpu: CpuEvidence {
                kind: CpuKind::Tdx,
                quote: vec![0; 4],
                event_log: Vec::new(),
            },
            gpus: (0..self.gpus)
                .map(|_| GpuEvidence {
                    arch: "BLACKWELL".into(),
                    evidence: vec![1],
                    certificate: vec![2],
                })
                .collect(),
            initdata: self.initdata.clone().into_bytes(),
            runtime_class: CLASS.into(),
        }
    }

    /// The quote a TD running this pod's init-data produces.
    fn quote(&self) -> VerifiedQuote {
        let expected = self.expected_report_data();
        let report_data = if self.aa_report_data {
            let hex = hex::encode(Sha256::digest(expected));
            <[u8; 64]>::try_from(hex.as_bytes()).unwrap()
        } else {
            expected
        };
        VerifiedQuote {
            report_data,
            measured: Measured {
                mrtd: m(1),
                rtmr0: m(2),
                rtmr1: m(3),
                rtmr2: m(4),
                rtmr3: m(5),
                mrconfigid: None,
            },
            mrconfigid: Measurement(
                InitData::parse(self.initdata.as_bytes())
                    .unwrap()
                    .mrconfigid(),
            ),
            tcb_status: "UpToDate".into(),
            advisories: Vec::new(),
        }
    }

    fn gpu_results(&self) -> Vec<GpuAppraisal> {
        let nonce = gpu_nonce(&self.expected_report_data());
        vec![GpuAppraisal {
            verifier: GpuVerifierKind::Nras,
            gpus: (0..self.gpus)
                .map(|index| VerifiedGpu {
                    index,
                    model: "B300".into(),
                    driver_version: "575.51.03".into(),
                    vbios_version: "97.00.9a.00.01".into(),
                    cc_mode: true,
                    nonce,
                })
                .collect(),
        }]
    }

    fn revision_hash(&self) -> ComposeHash {
        InitData::parse(self.initdata.as_bytes())
            .unwrap()
            .revision()
            .unwrap()
            .hash()
            .unwrap()
    }

    fn appraise_with(
        &self,
        evidence: &EvidenceV2,
        quote: VerifiedQuote,
        doc: &PlatformDocument,
        gpus: &[GpuAppraisal],
    ) -> Result<Appraised, AppraisalError> {
        appraise_kata_tdx(evidence, quote, &NONCE, SPKI, self.xwing(), doc, gpus)
    }

    fn appraise(&self, doc: &PlatformDocument) -> Result<Appraised, AppraisalError> {
        self.appraise_with(&self.evidence(), self.quote(), doc, &self.gpu_results())
    }
}

fn doc() -> PlatformDocument {
    PlatformDocument {
        version: 7,
        issued_at: "2026-10-12T00:00:00Z".into(),
        policy: Policy {
            tcb_statuses: vec!["UpToDate".into()],
            tolerated_advisories: Vec::new(),
        },
        reference_values: vec![ReferenceValue {
            name: "nvidia-uvm-tdx/b300x8".into(),
            kind: ReferenceKind::KataTdx,
            runtime_class: Some(CLASS.into()),
            values: ReferenceMeasurements {
                mrtd: m(1),
                rtmr0: m(2),
                rtmr1: m(3),
                rtmr2: m(4),
            },
        }],
        kms_ca_pem: String::new(),
        kms_revisions: Vec::new(),
        signer: None,
        catalog_key: None,
        gpu_policy: Some(GpuPolicy {
            allowed_models: vec!["B300".into()],
            min_driver_version: Some("570.124.06".into()),
            min_vbios_version: None,
            verifiers: vec![GpuVerifierKind::Nras],
            nras_url: None,
        }),
    }
}

fn refused(result: Result<Appraised, AppraisalError>, code: &str, reason: &str) {
    let error = result
        .err()
        .unwrap_or_else(|| panic!("appraised; expected {reason}"));
    assert_eq!(error.code(), code, "{error}");
    assert!(
        error.to_string().contains(reason),
        "{error} does not mention {reason:?}"
    );
}

#[test]
fn eight_gpu_pod_is_appraised_to_its_revision_v2() {
    let pod = Pod::gpu(8);
    let appraised = pod.appraise(&doc()).unwrap();
    assert_eq!(appraised.compose_hash, pod.revision_hash());
    assert_eq!(appraised.os_image, "nvidia-uvm-tdx/b300x8");
    assert_eq!(appraised.measured.mrconfigid, Some(pod.quote().mrconfigid));
    let coco = appraised.coco.unwrap();
    assert_eq!(coco.profile, "kata-tdx/1");
    assert_eq!(coco.runtime_class, CLASS);
    assert_eq!(coco.gpus.len(), 8);
    assert_eq!(coco.policy_sha256, alpha_core::compose_hash(POLICY));

    // The registered bytes are this init-data's Revision v2, for this App.
    let init = InitData::parse(pod.initdata.as_bytes()).unwrap();
    let revision = init.revision().unwrap();
    assert_eq!(revision.format, REVISION_FORMAT);
    let app: AppId = APP.parse().unwrap();
    assert_eq!(
        alpha_core::check_registration(&revision.canonical().unwrap(), app).unwrap(),
        appraised.compose_hash
    );
}

#[test]
fn attestation_agent_report_data_form_binds_too() {
    let pod = Pod {
        aa_report_data: true,
        ..Pod::gpu(1)
    };
    assert!(pod.appraise(&doc()).is_ok());
}

#[test]
fn cpu_only_pod_needs_no_gpu_policy() {
    let pod = Pod {
        initdata: initdata_text(POLICY, None),
        ..Pod::gpu(0)
    };
    let mut doc = doc();
    doc.gpu_policy = None;
    let appraised = pod.appraise(&doc).unwrap();
    assert!(appraised.coco.unwrap().gpus.is_empty());
}

#[test]
fn kms_node_revision_must_be_in_the_platform_document() {
    let pod = Pod {
        node: true,
        ..Pod::gpu(1)
    };
    refused(pod.appraise(&doc()), "attestation_unknown", "kms revision");
    let mut doc = doc();
    doc.kms_revisions.push(KmsRevision {
        compose_hash: pod.revision_hash(),
        build: "b".into(),
        source_url: "u".into(),
    });
    assert_eq!(
        pod.appraise(&doc).unwrap().compose_hash,
        pod.revision_hash()
    );
}

#[test]
fn init_data_swapped_after_policy_generation_is_refused() {
    // The host boots the TD with one init-data and sends another: changed image digest, extra
    // env or extra mount all change the policy and so the init-data.
    let pod = Pod::gpu(1);
    for changed in [
        POLICY.replace("false\ndefault Read", "true\ndefault Read"),
        format!(
            "{POLICY}allowed_image := \"ghcr.io/x@sha256:{}\"\n",
            "0".repeat(64)
        ),
        format!("{POLICY}env := [\"EXTRA=1\"]\n"),
        format!("{POLICY}mounts := [\"/host\"]\n"),
    ] {
        let mut evidence = pod.evidence();
        evidence.initdata = initdata_text(&changed, Some(1)).into_bytes();
        refused(
            pod.appraise_with(&evidence, pod.quote(), &doc(), &pod.gpu_results()),
            "attestation_failed",
            "MRCONFIGID",
        );
    }
}

#[test]
fn guest_image_not_in_reference_values_is_unknown() {
    let pod = Pod::gpu(1);
    let mut quote = pod.quote();
    quote.measured.rtmr2 = m(9);
    refused(
        pod.appraise_with(&pod.evidence(), quote, &doc(), &pod.gpu_results()),
        "attestation_unknown",
        "kata-tdx reference value",
    );
    // A prototype reference value with the same registers does not stand in for a Kata one.
    let mut doc = doc();
    doc.reference_values[0].kind = ReferenceKind::PrototypeTdx;
    refused(
        pod.appraise(&doc),
        "attestation_unknown",
        "kata-tdx reference value",
    );
}

#[test]
fn stale_nonce_and_replayed_quote_are_refused() {
    let pod = Pod::gpu(1);
    let other = report_data(SPKI, &[4; 32], None);
    let mut quote = pod.quote();
    quote.report_data = other;
    refused(
        pod.appraise_with(&pod.evidence(), quote, &doc(), &pod.gpu_results()),
        "attestation_failed",
        "report_data",
    );
    // A quote for another runtime key (a replay from another pod) fails the same way.
    let replay = appraise_kata_tdx(
        &pod.evidence(),
        pod.quote(),
        &NONCE,
        b"another key",
        None,
        &doc(),
        &pod.gpu_results(),
    );
    refused(replay, "attestation_failed", "report_data");
}

#[test]
fn wrong_gpu_count_and_gpu_not_in_cc_mode_are_refused() {
    let pod = Pod::gpu(8);
    let mut evidence = pod.evidence();
    evidence.gpus.truncate(1);
    refused(
        pod.appraise_with(&evidence, pod.quote(), &doc(), &pod.gpu_results()),
        "attestation_failed",
        "Revision expects 8",
    );
    let mut gpus = pod.gpu_results();
    gpus[0].gpus[5].cc_mode = false;
    refused(
        pod.appraise_with(&pod.evidence(), pod.quote(), &doc(), &gpus),
        "policy_denied",
        "CC mode",
    );
    refused(
        pod.appraise_with(&pod.evidence(), pod.quote(), &doc(), &[]),
        "attestation_failed",
        "did not run",
    );
}

#[test]
fn runtime_class_must_be_the_init_datas_and_the_reference_values() {
    let pod = Pod::gpu(1);
    let mut evidence = pod.evidence();
    evidence.runtime_class = "kata-qemu-nvidia-gpu-snp".into();
    refused(
        pod.appraise_with(&evidence, pod.quote(), &doc(), &pod.gpu_results()),
        "attestation_failed",
        "runtime class",
    );
    let mut doc = doc();
    doc.reference_values[0].runtime_class = Some("kata-qemu-other".into());
    refused(pod.appraise(&doc), "attestation_unknown", "runtime class");
}

#[test]
fn tampered_event_log_is_refused_and_a_matching_one_passes() {
    let pod = Pod::gpu(1);
    // Synthetic RTMRs that a three-event log replays to.
    let events: Vec<EventLogEntry> = (0..3)
        .map(|imr| EventLogEntry {
            imr,
            event_type: 1,
            digest: vec![imr as u8; 48],
            event: String::new(),
            event_payload: Vec::new(),
        })
        .collect();
    let [r0, r1, r2, _] = event_log::replay(&events);
    let mut quote = pod.quote();
    (
        quote.measured.rtmr0,
        quote.measured.rtmr1,
        quote.measured.rtmr2,
    ) = (r0, r1, r2);
    let mut doc = doc();
    let values = &mut doc.reference_values[0].values;
    (values.rtmr0, values.rtmr1, values.rtmr2) = (r0, r1, r2);

    let mut evidence = pod.evidence();
    evidence.cpu.event_log = events.clone();
    assert!(
        pod.appraise_with(&evidence, quote.clone(), &doc, &pod.gpu_results())
            .is_ok()
    );
    evidence.cpu.event_log[1].digest = vec![0xff; 48];
    refused(
        pod.appraise_with(&evidence, quote, &doc, &pod.gpu_results()),
        "attestation_failed",
        "replay",
    );
}

#[test]
fn snp_and_unknown_formats_are_unknown() {
    let pod = Pod::gpu(1);
    let mut evidence = pod.evidence();
    evidence.cpu.kind = CpuKind::Snp;
    refused(
        pod.appraise_with(&evidence, pod.quote(), &doc(), &pod.gpu_results()),
        "attestation_unknown",
        "kata-snp",
    );
    let mut evidence = pod.evidence();
    evidence.format = "alphacompute-evidence/3".into();
    refused(
        pod.appraise_with(&evidence, pod.quote(), &doc(), &pod.gpu_results()),
        "attestation_unknown",
        "format",
    );
}

#[test]
fn any_evidence_dispatches_on_format() {
    let v2 = serde_json::to_value(Pod::gpu(1).evidence()).unwrap();
    assert!(matches!(
        serde_json::from_value::<AnyEvidence>(v2.clone()).unwrap(),
        AnyEvidence::V2(_)
    ));
    let v1 =
        serde_json::json!({"format": "alphacompute-evidence/1", "quote": "AAAA", "event_log": []});
    let any: AnyEvidence = serde_json::from_value(v1.clone()).unwrap();
    assert!(matches!(any, AnyEvidence::V1(_)));
    assert_eq!(serde_json::to_value(&any).unwrap(), v1);
    assert_eq!(any.quote(), [0, 0, 0]);

    let mut extra = v2.clone();
    extra["surprise"] = serde_json::json!(1);
    assert!(serde_json::from_value::<AnyEvidence>(extra).is_err());
    let mut unknown = v2;
    unknown["format"] = serde_json::json!("alphacompute-evidence/9");
    assert!(serde_json::from_value::<AnyEvidence>(unknown).is_err());
}

#[test]
fn report_data_forms() {
    let expected = [0x5a; 64];
    assert!(report_data_binds(&expected, &expected));
    let hex = hex::encode(Sha256::digest(expected));
    assert!(report_data_binds(
        &<[u8; 64]>::try_from(hex.as_bytes()).unwrap(),
        &expected
    ));
    let upper = hex.to_uppercase();
    assert!(!report_data_binds(
        &<[u8; 64]>::try_from(upper.as_bytes()).unwrap(),
        &expected
    ));
    assert!(!report_data_binds(&[0x5b; 64], &expected));
}
