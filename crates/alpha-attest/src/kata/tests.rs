//! `kata-tdx/1` over synthetic verified quotes: the DCAP step is exercised by the real captures in
//! `tests/vectors.rs`, and B300 Kata captures (CPU and GPU class) join them at M1. These are the
//! malicious-host cases the KMS itself must refuse; exec, log reads and container changes are
//! refused inside the guest by the agent policy and are tested on a live pod (PRD-02 §4).

use alpha_core::coco::{
    CPU_RUNTIME_CLASS, GPU_RUNTIME_CLASS, InitData, REVISION_FORMAT, RuntimeClass,
};
use alpha_core::{AppId, KmsRevision, KmsRevisionKind};

use std::sync::Arc;

use super::*;
use crate::gpu::{GpuPolicy, GpuVerifier, GpuVerifierKind, gpu_nonce};
use crate::{Measured, Policy, ReferenceMeasurements, ReferenceValue};

const SPKI: &[u8] = b"runtime spki";
const NONCE: [u8; 32] = [3; 32];
const XWING: &[u8] = b"node xwing";
const APP: &str = "01994b3e-5c8a-7d3e-9a1b-2c3d4e5f6a7b";
const CLASS: &str = GPU_RUNTIME_CLASS;
const CPU_CLASS: &str = CPU_RUNTIME_CLASS;

fn m(byte: u8) -> Measurement {
    Measurement([byte; 48])
}

fn initdata_text(class: &str, policy: &str, gpu: Option<u32>) -> String {
    let gpu = gpu
        .map(|n| format!("\"gpu\":{{\"count\":{n},\"model\":\"B300\"}},"))
        .unwrap_or_default();
    format!(
        "algorithm = \"sha384\"\nversion = \"0.1.0\"\n\n[data]\n\"policy.rego\" = '''\n{policy}'''\n\"alpha.json\" = '''{{\"app_id\":\"{APP}\",\"format\":\"alphacompute-initdata/1\",{gpu}\"runtime_class\":\"{class}\"}}'''\n"
    )
}

const POLICY: &str = "package agent_policy\ndefault ExecProcessRequest := false\ndefault ReadStreamRequest := false\n";

struct Pod {
    initdata: String,
    class: &'static str,
    gpus: u32,
    node: bool,
    aa_report_data: bool,
}

impl Pod {
    fn gpu(gpus: u32) -> Self {
        Self {
            initdata: initdata_text(CLASS, POLICY, Some(gpus)),
            class: CLASS,
            gpus,
            node: false,
            aa_report_data: false,
        }
    }

    /// A CPU-only pod (KMS, broker, signer, guard, front, supervisor): no GPU section, no GPU.
    fn cpu() -> Self {
        Self {
            initdata: initdata_text(CPU_CLASS, POLICY, None),
            class: CPU_CLASS,
            gpus: 0,
            node: false,
            aa_report_data: false,
        }
    }

    /// MRTD and RTMR0..2 of the guest image the pod's runtime class boots: the CPU class's guest
    /// has another kernel and initrd than the NVIDIA guest.
    fn registers(&self) -> [Measurement; 4] {
        if self.class == CPU_CLASS {
            [m(1), m(2), m(13), m(14)]
        } else {
            [m(1), m(2), m(3), m(4)]
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
            runtime_class: self.class.into(),
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
        let [mrtd, rtmr0, rtmr1, rtmr2] = self.registers();
        VerifiedQuote {
            report_data,
            measured: Measured {
                mrtd,
                rtmr0,
                rtmr1,
                rtmr2,
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
            token_sha256: [0xab; 32],
            gpus: (0..self.gpus)
                .map(|index| VerifiedGpu {
                    index,
                    device_id: format!("ueid-{index}"),
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

    /// `kata-tdx/1` over these GPU backend results: the TD checks, then the GPU decision.
    fn appraise_with(
        &self,
        evidence: &EvidenceV2,
        quote: VerifiedQuote,
        doc: &PlatformDocument,
        gpus: &[GpuAppraisal],
    ) -> Result<Appraised, AppraisalError> {
        appraise_kata_cpu(evidence, quote, &NONCE, SPKI, self.xwing(), doc)?
            .finish(doc.gpu_policy.as_ref(), gpus)
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
        reference_values: vec![
            ReferenceValue {
                name: "nvidia-uvm-tdx/b300x8".into(),
                kind: ReferenceKind::KataTdx,
                runtime_class: Some(CLASS.into()),
                values: ReferenceMeasurements {
                    mrtd: m(1),
                    rtmr0: m(2),
                    rtmr1: m(3),
                    rtmr2: m(4),
                },
            },
            ReferenceValue {
                name: "kata-tdx/cpu".into(),
                kind: ReferenceKind::KataTdx,
                runtime_class: Some(CPU_CLASS.into()),
                values: ReferenceMeasurements {
                    mrtd: m(1),
                    rtmr0: m(2),
                    rtmr1: m(13),
                    rtmr2: m(14),
                },
            },
        ],
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
            hwmodels: Default::default(),
            nras_keys: Default::default(),
            nras_cc_mode: None,
        }),
        pccs_url: None,
        expires_at: None,
    }
}

/// `quote` as a TD booted from another guest image would produce it: its MRTD and RTMR0..2.
fn with_registers(
    mut quote: VerifiedQuote,
    [mrtd, rtmr0, rtmr1, rtmr2]: [Measurement; 4],
) -> VerifiedQuote {
    let m = &mut quote.measured;
    (m.mrtd, m.rtmr0, m.rtmr1, m.rtmr2) = (mrtd, rtmr0, rtmr1, rtmr2);
    quote
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
    // The result names who vouched for the GPUs.
    assert_eq!(coco.gpu_verifiers.len(), 1);
    assert_eq!(coco.gpu_verifiers[0].verifier, GpuVerifierKind::Nras);
    assert_eq!(
        coco.gpu_verifiers[0].token_sha256,
        format!("sha256:{}", "ab".repeat(32))
    );

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
fn cpu_class_pod_is_appraised_to_its_revision_v2_without_a_gpu_policy() {
    let pod = Pod::cpu();
    let mut doc = doc();
    doc.gpu_policy = None;
    let appraised = pod.appraise(&doc).unwrap();
    assert_eq!(appraised.compose_hash, pod.revision_hash());
    assert_eq!(appraised.os_image, "kata-tdx/cpu");
    let coco = appraised.coco.unwrap();
    assert_eq!(coco.runtime_class, CPU_CLASS);
    assert!(coco.gpus.is_empty() && coco.gpu_verifiers.is_empty());
    let revision = InitData::parse(pod.initdata.as_bytes())
        .unwrap()
        .revision()
        .unwrap();
    assert_eq!(revision.gpu, None);
    let app: AppId = APP.parse().unwrap();
    assert_eq!(
        alpha_core::check_registration(&revision.canonical().unwrap(), app).unwrap(),
        appraised.compose_hash
    );
}

#[test]
fn kms_node_revision_must_be_in_the_platform_document() {
    // The KMS on Kata runs on the CPU class; a node on the GPU class is checked the same way.
    for pod in [Pod::cpu(), Pod::gpu(1)] {
        let pod = Pod { node: true, ..pod };
        refused(pod.appraise(&doc()), "attestation_unknown", "kms revision");
        let mut doc = doc();
        doc.kms_revisions.push(KmsRevision {
            compose_hash: pod.revision_hash(),
            build: "b".into(),
            source_url: "u".into(),
            kind: KmsRevisionKind::KataTdx,
        });
        assert_eq!(
            pod.appraise(&doc).unwrap().compose_hash,
            pod.revision_hash()
        );
    }
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
        evidence.initdata = initdata_text(CLASS, &changed, Some(1)).into_bytes();
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
    let replay = appraise_kata_cpu(
        &pod.evidence(),
        pod.quote(),
        &NONCE,
        b"another key",
        None,
        &doc(),
    )
    .and_then(|cpu| cpu.finish(doc().gpu_policy.as_ref(), &pod.gpu_results()));
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
fn runtime_class_must_be_supported_the_init_datas_and_the_reference_values() {
    let pod = Pod::gpu(1);
    // A class no Revision v2 may name is refused before any reference value is looked up, even
    // one listed for that class.
    let mut evidence = pod.evidence();
    evidence.runtime_class = "kata-qemu-nvidia-gpu-snp".into();
    let mut listed = doc();
    listed.reference_values[0].runtime_class = Some("kata-qemu-nvidia-gpu-snp".into());
    for doc in [doc(), listed] {
        refused(
            pod.appraise_with(&evidence, pod.quote(), &doc, &pod.gpu_results()),
            "attestation_failed",
            "runtime class \"kata-qemu-nvidia-gpu-snp\" is not supported",
        );
    }
    // A supported claim is held to the measured init-data's class: a GPU pod claims the CPU class
    // in a TD whose registers are the CPU guest's, so a CPU-class value matches first.
    let mut evidence = pod.evidence();
    evidence.runtime_class = CPU_CLASS.into();
    let quote = with_registers(pod.quote(), Pod::cpu().registers());
    refused(
        pod.appraise_with(&evidence, quote, &doc(), &pod.gpu_results()),
        "attestation_failed",
        "is not the init-data's",
    );
    // No value is listed for the pod's own class.
    let mut doc = doc();
    doc.reference_values[0].runtime_class = Some("kata-qemu-other".into());
    refused(
        pod.appraise(&doc),
        "attestation_unknown",
        "runtime class kata-qemu-nvidia-gpu-tdx",
    );
}

#[test]
fn reference_values_match_per_runtime_class() {
    let (cpu, gpu) = (Pod::cpu(), Pod::gpu(1));

    // A CPU-class init-data in a TD booted from the NVIDIA guest image: it would skip the GPU
    // checks, so it is unknown rather than matched to the GPU class's value.
    let quote = with_registers(cpu.quote(), gpu.registers());
    refused(
        cpu.appraise_with(&cpu.evidence(), quote, &doc(), &[]),
        "attestation_unknown",
        "runtime class kata-qemu-tdx",
    );
    // A GPU-class init-data in a TD booted from the CPU guest image.
    let quote = with_registers(gpu.quote(), cpu.registers());
    refused(
        gpu.appraise_with(&gpu.evidence(), quote, &doc(), &gpu.gpu_results()),
        "attestation_unknown",
        "runtime class kata-qemu-nvidia-gpu-tdx",
    );

    // Two classes captured with the same registers: each pod matches its own class's value,
    // whichever comes first in the document.
    let mut same = doc();
    same.reference_values[1].values = same.reference_values[0].values.clone();
    let quote = with_registers(cpu.quote(), gpu.registers());
    let appraised = cpu
        .appraise_with(&cpu.evidence(), quote, &same, &[])
        .unwrap();
    assert_eq!(appraised.os_image, "kata-tdx/cpu");
    assert_eq!(
        gpu.appraise(&same).unwrap().os_image,
        "nvidia-uvm-tdx/b300x8"
    );

    // A kata-tdx value that names no runtime class matches no pod, whatever its registers.
    let mut classless = doc();
    for rv in &mut classless.reference_values {
        rv.runtime_class = None;
    }
    for pod in [cpu, gpu] {
        refused(
            pod.appraise(&classless),
            "attestation_unknown",
            "kata-tdx reference value",
        );
    }
}

#[test]
fn each_class_is_held_to_its_gpu_section_at_appraisal() {
    // What registration refuses, the appraisal refuses too: a GPU-class pod with no GPU or zero
    // GPUs, and a CPU-class pod whose init-data names GPUs.
    for (class, gpu, gpus, why) in [
        (CLASS, None, 0, "needs a gpu section"),
        (CLASS, Some(0), 0, "gpu.count 0"),
        (CPU_CLASS, Some(1), 1, "runs no GPU"),
        (CPU_CLASS, Some(0), 0, "runs no GPU"),
    ] {
        let pod = Pod {
            initdata: initdata_text(class, POLICY, gpu),
            class,
            gpus,
            ..Pod::gpu(1)
        };
        refused(pod.appraise(&doc()), "attestation_failed", why);
    }
}

#[test]
fn only_the_cpu_class_skips_the_gpu_checks() {
    let appraise = |pod: &Pod| {
        appraise_kata_cpu(&pod.evidence(), pod.quote(), &NONCE, SPKI, None, &doc()).unwrap()
    };
    let cpu = appraise(&Pod::cpu());
    assert_eq!(cpu.runtime_class(), RuntimeClass::Cpu);
    assert_eq!(cpu.gpu_shape(), None);
    for count in [1, 8] {
        let gpu = appraise(&Pod::gpu(count));
        assert_eq!(gpu.runtime_class(), RuntimeClass::Gpu);
        assert_eq!(gpu.gpu_shape().map(|shape| shape.count), Some(count));
    }
}

#[test]
fn cpu_pod_presenting_gpu_evidence_is_refused() {
    // A GPU passed through to a CPU-class pod, or a report the pod got elsewhere: its Revision
    // expects no GPU, so it gets no leaf, with or without a backend's passing result for that GPU.
    let liar = Pod {
        gpus: 1,
        ..Pod::cpu()
    };
    let evidence = liar.evidence();
    assert_eq!(evidence.gpus.len(), 1);
    for results in [Vec::new(), liar.gpu_results()] {
        refused(
            liar.appraise_with(&evidence, liar.quote(), &doc(), &results),
            "attestation_failed",
            "1 GPU evidence entries from a pod of runtime class kata-qemu-tdx",
        );
    }
    // A GPU a backend verified for a CPU pod that sent no GPU evidence is refused too, never
    // ignored, whoever ran that backend.
    let pod = Pod::cpu();
    refused(
        pod.appraise_with(&pod.evidence(), pod.quote(), &doc(), &liar.gpu_results()),
        "attestation_failed",
        "verified 1 GPUs for a pod of runtime class kata-qemu-tdx",
    );
}

#[test]
fn the_runtime_class_claim_cannot_skip_or_borrow_gpu_checks() {
    // A GPU pod that claims the CPU class and sends no GPU evidence, in its own NVIDIA guest: no
    // CPU-class value is listed for those registers.
    let pod = Pod::gpu(8);
    let mut evidence = pod.evidence();
    evidence.runtime_class = CPU_CLASS.into();
    evidence.gpus.clear();
    refused(
        pod.appraise_with(&evidence, pod.quote(), &doc(), &[]),
        "attestation_unknown",
        "runtime class kata-qemu-tdx",
    );
    // Even where the two guests' registers are the same, the measured init-data's class (the GPU
    // class) refuses the claim.
    let mut same = doc();
    same.reference_values[1].values = same.reference_values[0].values.clone();
    refused(
        pod.appraise_with(&evidence, pod.quote(), &same, &[]),
        "attestation_failed",
        "is not the init-data's",
    );
    // A CPU pod cannot claim the GPU class either.
    let pod = Pod::cpu();
    let mut evidence = pod.evidence();
    evidence.runtime_class = CLASS.into();
    let quote = with_registers(pod.quote(), Pod::gpu(1).registers());
    refused(
        pod.appraise_with(&evidence, quote, &doc(), &[]),
        "attestation_failed",
        "is not the init-data's",
    );
}

#[test]
fn reference_value_is_chosen_for_the_pods_runtime_class() {
    // The same guest registers listed for two runtime classes: the pod gets the value for its own
    // class, whichever is listed first.
    let pod = Pod::gpu(1);
    let mut doc = doc();
    let mut other = doc.reference_values[0].clone();
    other.name = "kata-tdx/cpu".into();
    other.runtime_class = Some("kata-qemu-tdx".into());
    doc.reference_values.insert(0, other);
    let appraised = pod.appraise(&doc).unwrap();
    assert_eq!(appraised.os_image, "nvidia-uvm-tdx/b300x8");
}

#[test]
fn several_faults_are_refused_for_the_first_in_the_plans_order() {
    // A stale nonce and a guest image that is not listed: the reference values come first and
    // report_data last (PRD-02 R5e).
    let pod = Pod::gpu(1);
    let mut quote = pod.quote();
    quote.report_data = report_data(SPKI, &[4; 32], None);
    quote.measured.rtmr1 = m(9);
    refused(
        pod.appraise_with(&pod.evidence(), quote, &doc(), &pod.gpu_results()),
        "attestation_unknown",
        "kata-tdx reference value",
    );
    // A stale nonce and a swapped init-data: MRCONFIGID first.
    let mut quote = pod.quote();
    quote.report_data = report_data(SPKI, &[4; 32], None);
    let mut evidence = pod.evidence();
    evidence.initdata = initdata_text(CLASS, "package other\n", Some(1)).into_bytes();
    refused(
        pod.appraise_with(&evidence, quote, &doc(), &pod.gpu_results()),
        "attestation_failed",
        "MRCONFIGID",
    );
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
fn results_accept_new_fields_and_platform_documents_refuse_them() {
    // A result from a later KMS that adds fields still parses in a runtime built today.
    let mut result = serde_json::to_value(Pod::gpu(1).appraise(&doc()).unwrap().coco).unwrap();
    result["added_later"] = serde_json::json!(1);
    result["gpus"][0]["added_later"] = serde_json::json!(true);
    result["gpu_verifiers"][0]["added_later"] = serde_json::json!("x");
    assert!(serde_json::from_value::<CocoAppraised>(result).is_ok());

    // A misspelled field in a platform document is refused, not signed and ignored.
    let good = serde_json::to_value(doc()).unwrap();
    assert!(serde_json::from_value::<PlatformDocument>(good.clone()).is_ok());
    let mut typo = good.clone();
    let rv = typo["reference_values"][0].as_object_mut().unwrap();
    let class = rv.remove("runtime_class").unwrap();
    rv.insert("runtime_clas".into(), class);
    let error = serde_json::from_value::<PlatformDocument>(typo)
        .unwrap_err()
        .to_string();
    assert!(error.contains("runtime_clas"), "{error}");
    for (path, field) in [
        ("", "gpu_polcy"),
        ("/policy", "tcb_status"),
        ("/reference_values/0/values", "rtmr3"),
    ] {
        let mut extra = good.clone();
        extra
            .pointer_mut(path)
            .and_then(serde_json::Value::as_object_mut)
            .unwrap()
            .insert(field.into(), serde_json::json!(null));
        assert!(
            serde_json::from_value::<PlatformDocument>(extra).is_err(),
            "{path}/{field}"
        );
    }
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

/// A GPU backend that counts its calls and vouches for every GPU it is given.
struct Counting {
    calls: std::sync::atomic::AtomicUsize,
    gpus: Vec<VerifiedGpu>,
}

impl GpuVerifier for Counting {
    fn kind(&self) -> GpuVerifierKind {
        GpuVerifierKind::Nras
    }

    fn verify<'a>(
        &'a self,
        _: &'a [GpuEvidence],
        _: &'a [u8; 32],
        _: &'a GpuPolicy,
    ) -> gpu::GpuFuture<'a> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let verdict = gpu::GpuVerdict {
            gpus: self.gpus.clone(),
            token_sha256: [0xab; 32],
        };
        Box::pin(async move { Ok(verdict) })
    }
}

#[tokio::test]
async fn gpu_backends_run_only_after_every_td_check_passed() {
    let pod = Pod::gpu(8);
    let counting = Arc::new(Counting {
        calls: Default::default(),
        gpus: pod.gpu_results().remove(0).gpus,
    });
    let backends: Vec<Arc<dyn GpuVerifier>> = vec![counting.clone()];
    let run = |evidence: EvidenceV2, quote: VerifiedQuote, doc: PlatformDocument| {
        let backends = backends.clone();
        async move { appraise_kata_tdx(&evidence, quote, &NONCE, SPKI, None, &doc, &backends).await }
    };
    let calls = || counting.calls.load(std::sync::atomic::Ordering::SeqCst);

    // A stale nonce, an unlisted guest image, a swapped init-data, too few GPU entries and a
    // model the policy does not allow are refused without a verifier call.
    let mut stale = pod.quote();
    stale.report_data = report_data(SPKI, &[4; 32], None);
    refused(
        run(pod.evidence(), stale, doc()).await,
        "attestation_failed",
        "report_data",
    );
    let mut unlisted = pod.quote();
    unlisted.measured.rtmr2 = m(9);
    refused(
        run(pod.evidence(), unlisted, doc()).await,
        "attestation_unknown",
        "reference value",
    );
    let mut swapped = pod.evidence();
    swapped.initdata = initdata_text(
        CLASS,
        "package other
",
        Some(8),
    )
    .into_bytes();
    refused(
        run(swapped, pod.quote(), doc()).await,
        "attestation_failed",
        "MRCONFIGID",
    );
    let mut short = pod.evidence();
    short.gpus.truncate(7);
    refused(
        run(short, pod.quote(), doc()).await,
        "attestation_failed",
        "Revision expects 8",
    );
    let mut no_b300 = doc();
    if let Some(policy) = no_b300.gpu_policy.as_mut() {
        policy.allowed_models = vec!["H200".into()];
    }
    refused(
        run(pod.evidence(), pod.quote(), no_b300).await,
        "policy_denied",
        "not allowed",
    );
    assert_eq!(calls(), 0);

    // A pod that passes every TD check gets one call per listed backend.
    let appraised = run(pod.evidence(), pod.quote(), doc()).await.unwrap();
    assert_eq!(appraised.coco.unwrap().gpus.len(), 8);
    assert_eq!(calls(), 1);

    // A CPU-only pod never calls a backend, with or without a gpu_policy in the document.
    let cpu = Pod::cpu();
    run(cpu.evidence(), cpu.quote(), doc()).await.unwrap();
    let mut no_policy = doc();
    no_policy.gpu_policy = None;
    let appraised = run(cpu.evidence(), cpu.quote(), no_policy).await.unwrap();
    assert!(appraised.coco.unwrap().gpus.is_empty());
    assert_eq!(calls(), 1);

    // Nor does a CPU pod presenting GPU evidence: it is refused without asking a backend, though
    // this backend would vouch for the GPU.
    let liar = Pod {
        gpus: 8,
        ..Pod::cpu()
    };
    refused(
        run(liar.evidence(), liar.quote(), doc()).await,
        "attestation_failed",
        "runs no GPU",
    );
    // Nor a GPU pod that claims the CPU class and hides its GPU evidence.
    let mut hidden = pod.evidence();
    hidden.runtime_class = CPU_CLASS.into();
    hidden.gpus.clear();
    let mut same = doc();
    same.reference_values[1].values = same.reference_values[0].values.clone();
    refused(
        run(hidden, pod.quote(), same).await,
        "attestation_failed",
        "is not the init-data's",
    );
    assert_eq!(calls(), 1);
}
