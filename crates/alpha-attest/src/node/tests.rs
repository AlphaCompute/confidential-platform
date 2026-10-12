//! A KMS node's appraisal: a Kata node over synthetic verified quotes (B300 Kata captures join at
//! M1), a prototype node over the keyed Phala capture.

use std::path::PathBuf;
use std::time::{Duration, UNIX_EPOCH};

use alpha_core::coco::{CPU_RUNTIME_CLASS, GPU_RUNTIME_CLASS, InitData};
use alpha_core::{ComposeHash, KmsRevision, KmsRevisionKind};
use serde_json::json;
use sha2::{Digest, Sha256};

use super::*;
use crate::{
    CpuEvidence, CpuKind, EVIDENCE_FORMAT, EVIDENCE_FORMAT_V2, EventLogEntry, Evidence,
    GpuEvidence, Measured, Measurement, report_data,
};

const SPKI: &[u8] = b"node runtime spki";
const NONCE: [u8; 32] = [6; 32];
const XWING: &[u8] = b"node xwing";
const KMS_APP: &str = "01994b3e-5c8a-7d3e-9a1b-2c3d4e5f6a70";
const POLICY: &str = "package agent_policy\ndefault ExecProcessRequest := false\ndefault ReadStreamRequest := false\n";

fn m(byte: u8) -> Measurement {
    Measurement([byte; 48])
}

/// The init-data of the KMS pod on `class`.
fn initdata(class: &str) -> String {
    let gpu = if class == GPU_RUNTIME_CLASS {
        "\"gpu\":{\"count\":1,\"model\":\"B300\"},"
    } else {
        ""
    };
    format!(
        "algorithm = \"sha384\"\nversion = \"0.1.0\"\n\n[data]\n\"policy.rego\" = '''\n{POLICY}'''\n\"alpha.json\" = '''{{\"app_id\":\"{KMS_APP}\",\"format\":\"alphacompute-initdata/1\",{gpu}\"runtime_class\":\"{class}\"}}'''\n"
    )
}

fn revision_hash(initdata: &str) -> ComposeHash {
    InitData::parse(initdata.as_bytes())
        .unwrap()
        .revision()
        .unwrap()
        .hash()
        .unwrap()
}

fn registers(class: &str) -> [Measurement; 4] {
    if class == CPU_RUNTIME_CLASS {
        [m(1), m(2), m(13), m(14)]
    } else {
        [m(1), m(2), m(3), m(4)]
    }
}

/// A document with a `kata-tdx` reference value for each class and `revisions` listed.
fn doc(revisions: &[(ComposeHash, KmsRevisionKind)]) -> PlatformDocument {
    let value = |name: &str, class: &str| {
        let [mrtd, rtmr0, rtmr1, rtmr2] = registers(class);
        json!({ "name": name, "kind": "kata-tdx", "runtime_class": class,
                "values": { "mrtd": mrtd, "rtmr0": rtmr0, "rtmr1": rtmr1, "rtmr2": rtmr2 } })
    };
    let mut doc: PlatformDocument = serde_json::from_value(json!({
        "version": 3, "issued_at": "2026-11-17T00:00:00Z",
        "policy": { "tcb_statuses": ["UpToDate"], "tolerated_advisories": [] },
        "reference_values": [value("kata-tdx/cpu-4c-8g", CPU_RUNTIME_CLASS),
                             value("nvidia-uvm-tdx/b300x1", GPU_RUNTIME_CLASS)],
        "kms_ca_pem": "", "kms_revisions": [],
        "gpu_policy": { "allowed_models": ["B300"], "verifiers": ["nras"] }
    }))
    .unwrap();
    doc.kms_revisions = revisions
        .iter()
        .map(|&(compose_hash, kind)| KmsRevision {
            compose_hash,
            build: "kms".into(),
            source_url: "u".into(),
            kind,
        })
        .collect();
    doc
}

struct KataNode {
    initdata: String,
    class: &'static str,
    gpus: usize,
}

impl KataNode {
    fn cpu() -> Self {
        Self {
            initdata: initdata(CPU_RUNTIME_CLASS),
            class: CPU_RUNTIME_CLASS,
            gpus: 0,
        }
    }

    fn hash(&self) -> ComposeHash {
        revision_hash(&self.initdata)
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

    /// The quote a TD running this init-data produces over `report_data`.
    fn quote_over(&self, report_data: [u8; 64]) -> VerifiedQuote {
        let [mrtd, rtmr0, rtmr1, rtmr2] = registers(self.class);
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

    fn quote(&self) -> VerifiedQuote {
        self.quote_over(report_data(SPKI, &NONCE, Some(XWING)))
    }

    fn appraise(&self, doc: &PlatformDocument) -> Result<Appraised, AppraisalError> {
        appraise_kata_node(&self.evidence(), self.quote(), &NONCE, SPKI, XWING, doc)
    }
}

fn refused(result: Result<Appraised, AppraisalError>, code: &str, reason: &str) {
    let error = result.unwrap_err();
    assert_eq!(error.code(), code, "{error}");
    assert!(error.to_string().contains(reason), "{error}");
}

#[test]
fn a_kata_node_listed_as_a_kata_build_is_admitted_with_its_revision_v2() {
    let node = KataNode::cpu();
    let appraised = node
        .appraise(&doc(&[(node.hash(), KmsRevisionKind::KataTdx)]))
        .unwrap();
    assert_eq!(appraised.compose_hash, node.hash());
    assert_eq!(appraised.os_image, "kata-tdx/cpu-4c-8g");
    let coco = appraised.coco.unwrap();
    assert_eq!(coco.runtime_class, CPU_RUNTIME_CLASS);
    assert!(coco.gpus.is_empty() && coco.gpu_verifiers.is_empty());

    // The attestation agent's form of report_data binds the same preimage.
    let hex = hex::encode(Sha256::digest(report_data(SPKI, &NONCE, Some(XWING))));
    let quote = node.quote_over(<[u8; 64]>::try_from(hex.as_bytes()).unwrap());
    let doc = doc(&[(node.hash(), KmsRevisionKind::KataTdx)]);
    assert!(appraise_kata_node(&node.evidence(), quote, &NONCE, SPKI, XWING, &doc).is_ok());
}

#[test]
fn a_kata_node_unlisted_or_listed_as_a_prototype_build_is_unknown() {
    let node = KataNode::cpu();
    refused(
        node.appraise(&doc(&[])),
        "attestation_unknown",
        "kms revision",
    );
    refused(
        node.appraise(&doc(&[(node.hash(), KmsRevisionKind::PrototypeTdx)])),
        "attestation_unknown",
        "is not listed as a kata-tdx build",
    );
    // Another KMS build listed, this one not.
    let other = revision_hash(&initdata(CPU_RUNTIME_CLASS).replace("Exec", "Other"));
    refused(
        node.appraise(&doc(&[(other, KmsRevisionKind::KataTdx)])),
        "attestation_unknown",
        "kms revision",
    );
}

#[test]
fn a_kata_node_quote_over_another_xwing_key_or_without_one_is_refused() {
    let node = KataNode::cpu();
    let doc = doc(&[(node.hash(), KmsRevisionKind::KataTdx)]);
    for report_data in [
        report_data(SPKI, &NONCE, Some(b"the host's xwing")),
        report_data(SPKI, &NONCE, None),
        report_data(b"the host's key", &NONCE, Some(XWING)),
    ] {
        refused(
            appraise_kata_node(
                &node.evidence(),
                node.quote_over(report_data),
                &NONCE,
                SPKI,
                XWING,
                &doc,
            ),
            "attestation_failed",
            "report_data is not bound",
        );
    }
}

#[test]
fn a_kata_node_on_the_gpu_class_or_sending_gpu_evidence_is_refused() {
    let gpu = KataNode {
        initdata: initdata(GPU_RUNTIME_CLASS),
        class: GPU_RUNTIME_CLASS,
        gpus: 1,
    };
    refused(
        gpu.appraise(&doc(&[(gpu.hash(), KmsRevisionKind::KataTdx)])),
        "attestation_failed",
        "a KMS node runs on the runtime class kata-qemu-tdx",
    );
    let noisy = KataNode {
        gpus: 1,
        ..KataNode::cpu()
    };
    refused(
        noisy.appraise(&doc(&[(noisy.hash(), KmsRevisionKind::KataTdx)])),
        "attestation_failed",
        "GPU evidence entries from a pod of runtime class kata-qemu-tdx",
    );
}

#[test]
fn snp_node_evidence_is_refused_before_any_quote_is_verified() {
    let node = KataNode::cpu();
    let mut evidence = node.evidence();
    evidence.cpu.kind = CpuKind::Snp;
    let keyed = Keyed::read();
    refused(
        appraise_node(
            &AnyEvidence::V2(evidence),
            &NONCE,
            SPKI,
            XWING,
            &doc(&[(node.hash(), KmsRevisionKind::KataTdx)]),
            &keyed.collateral,
            keyed.now,
        ),
        "attestation_unknown",
        "no kata-snp/1 profile",
    );
}

/// The keyed Phala capture: a prototype node's quote over its runtime and X-Wing keys.
struct Keyed {
    evidence: Evidence,
    nonce: [u8; 32],
    spki: Vec<u8>,
    xwing: Vec<u8>,
    doc: PlatformDocument,
    collateral: Collateral,
    now: SystemTime,
}

impl Keyed {
    fn read() -> Self {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../testdata/attest/phala-0.5.9-1c-2g-keyed");
        let read = |name: &str| std::fs::read(dir.join(name)).unwrap();
        let text = |name: &str| String::from_utf8(read(name)).unwrap();
        let event_log: Vec<EventLogEntry> =
            serde_json::from_slice(&read("event_log.json")).unwrap();
        let captured_at = chrono::DateTime::parse_from_rfc3339(text("captured_at.txt").trim())
            .unwrap()
            .timestamp();
        Self {
            evidence: Evidence {
                format: EVIDENCE_FORMAT.into(),
                quote: hex::decode(text("quote.node.hex").trim()).unwrap(),
                event_log,
            },
            nonce: read("nonce.bin").try_into().unwrap(),
            spki: read("runtime_spki.der"),
            xwing: read("node_xwing_pubkey.bin"),
            doc: serde_json::from_slice(&read("platform-document.json")).unwrap(),
            collateral: serde_json::from_slice(&read("collateral.json")).unwrap(),
            now: UNIX_EPOCH + Duration::from_secs(captured_at as u64),
        }
    }

    fn appraise(&self) -> Result<Appraised, AppraisalError> {
        appraise_node(
            &AnyEvidence::V1(self.evidence.clone()),
            &self.nonce,
            &self.spki,
            &self.xwing,
            &self.doc,
            &self.collateral,
            self.now,
        )
    }
}

#[test]
fn a_prototype_node_is_admitted_only_under_a_prototype_build() {
    let mut keyed = Keyed::read();
    let listed = keyed.doc.kms_revisions[0].compose_hash;
    assert_eq!(keyed.appraise().unwrap().compose_hash, listed);
    keyed.doc.kms_revisions[0].kind = KmsRevisionKind::KataTdx;
    refused(
        keyed.appraise(),
        "attestation_unknown",
        "is not listed as a prototype-tdx build",
    );
    // Both builds listed during the migration: the prototype node is still a node.
    keyed.doc.kms_revisions.push(KmsRevision {
        kind: KmsRevisionKind::PrototypeTdx,
        ..keyed.doc.kms_revisions[0].clone()
    });
    assert!(keyed.appraise().is_ok());
}
