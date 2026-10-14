#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alpha_attest::{
    GpuEvidence, GpuReference, KataGpus, KataReference, PlatformDocument, appraise_gpus,
    appraise_kata_gpus, bind_gpus, verify_quote,
};

fn read(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/attest/b300-gpu-595.58.03")
        .join(name);
    fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn gpu(name: &str) -> GpuEvidence {
    GpuEvidence {
        evidence: read(&format!("{name}.spdm.bin")),
        certificate_chain: read(&format!("{name}.certchain.pem")),
    }
}

fn reference() -> GpuReference {
    serde_json::from_slice(&read("gpu-reference.json")).unwrap()
}

/// The challenges the verifier sent each pod, which the device signed as the SPDM nonce.
fn nonce(name: &str) -> [u8; 32] {
    let hex = match name {
        "g1b" => "6f73634fd052a692871c7ff8b83b4dc05bf1d94f0c9a412afd02de8e7df0e35e",
        "g2b" => "b362090d5341853b9540e363985afd0e6863521eea14687f2aaa00bd8802d025",
        _ => panic!("{name}"),
    };
    hex::decode(hex).unwrap().try_into().unwrap()
}

/// 2026-10-13, the day of the capture.
fn now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_791_849_600)
}

#[test]
fn captured_gpus_are_accepted_with_their_leaf_serials() {
    // g1b reports zero in block 62, g2b the driver RIM's other alternative.
    for (name, serial) in [
        ("g1b", "590fbf5454e4e90d32bf1fb62f713dbbdc42dc07"),
        ("g2b", "415265d5ac81e8ab05191b441d65e8b6e3256466"),
    ] {
        assert_eq!(
            appraise_gpus(&[gpu(name)], &nonce(name), 1, &[reference()], now()).unwrap(),
            [serial],
            "{name}"
        );
    }
}

#[test]
fn altered_gpu_evidence_is_refused() {
    type Change = fn(&mut Vec<GpuEvidence>, &mut [u8; 32], &mut GpuReference, &mut usize);
    let cases: [(&str, Change, &str, &str); 11] = [
        (
            "measurement byte flipped",
            |g, _, _, _| g[0].evidence[120] ^= 1,
            "attestation_failed",
            "signature does not verify",
        ),
        (
            "another nonce",
            |_, n, _, _| n[0] ^= 1,
            "attestation_failed",
            "nonce",
        ),
        (
            "byte appended",
            |g, _, _, _| g[0].evidence.push(0),
            "attestation_failed",
            "trailing bytes",
        ),
        (
            "root not pinned",
            |_, _, r, _| r.root_sha256 = alpha_core::ComposeHash::from([7; 32]),
            "attestation_failed",
            "not pinned",
        ),
        (
            "intermediate dropped",
            |g, _, _, _| {
                let pem = String::from_utf8(g[0].certificate_chain.clone()).unwrap();
                let blocks: Vec<&str> = pem.split_inclusive("-----END CERTIFICATE-----").collect();
                g[0].certificate_chain = [blocks[0], blocks[1], blocks[3], blocks[4]]
                    .concat()
                    .into_bytes();
            },
            "attestation_failed",
            "certificate 2 may not issue",
        ),
        (
            "leaf dropped",
            |g, _, _, _| {
                let pem = String::from_utf8(g[0].certificate_chain.clone()).unwrap();
                let blocks: Vec<&str> = pem.split_inclusive("-----END CERTIFICATE-----").collect();
                g[0].certificate_chain = blocks[1..].concat().into_bytes();
            },
            "attestation_failed",
            "leaf may not sign",
        ),
        (
            "another device's chain",
            |g, _, _, _| g[0].certificate_chain = gpu("g2b").certificate_chain,
            "attestation_failed",
            "signature does not verify",
        ),
        (
            "block value not referenced",
            |_, _, r, _| r.measurements.get_mut(&2).unwrap()[0].0[0] ^= 1,
            "attestation_unknown",
            "block 2",
        ),
        (
            "nonzero block not referenced",
            |_, _, r, _| {
                r.measurements.remove(&2);
            },
            "attestation_unknown",
            "block 2",
        ),
        (
            "same device twice",
            |g, _, _, c| {
                g.push(g[0].clone());
                *c = 2;
            },
            "attestation_failed",
            "appears twice",
        ),
        (
            "fewer evidences than GPUs",
            |_, _, _, c| *c = 2,
            "attestation_failed",
            "1 evidences for 2 GPUs",
        ),
    ];
    for (case, change, code, fragment) in cases {
        let (mut gpus, mut nonce, mut reference, mut count) =
            (vec![gpu("g1b")], nonce("g1b"), reference(), 1);
        change(&mut gpus, &mut nonce, &mut reference, &mut count);
        let err = appraise_gpus(&gpus, &nonce, count, &[reference], now()).unwrap_err();
        assert_eq!(err.code(), code, "{case}: {err}");
        assert!(err.to_string().contains(fragment), "{case}: {err}");
    }
}

fn kata(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/attest/b300-kata-4.0.0")
        .join(name);
    fs::read(path).unwrap()
}

/// The GPU pod's real quote, whose `report_data` is the challenge and the SHA-256 of `g1b`'s
/// evidence, and the GPU class of its platform document.
fn gpu_pod() -> ([u8; 64], KataReference) {
    let doc: PlatformDocument = serde_json::from_slice(&kata("platform-document.json")).unwrap();
    let collateral = serde_json::from_slice(&kata("collateral.json")).unwrap();
    let captured_at = String::from_utf8(kata("captured_at.txt")).unwrap();
    let captured_at = chrono::DateTime::parse_from_rfc3339(captured_at.trim()).unwrap();
    let at = UNIX_EPOCH + Duration::from_secs(captured_at.timestamp() as u64);
    let quote = verify_quote(&kata("g1b-gpu.quote.bin"), &collateral, &doc.policy, at).unwrap();
    let class = doc
        .kata_reference_values
        .into_iter()
        .find(|c| c.gpu)
        .unwrap();
    (quote.report_data, class)
}

#[test]
fn a_gpu_pod_quote_commits_to_its_evidence() {
    let (report_data, _) = gpu_pod();
    assert_eq!(bind_gpus(&report_data, &[gpu("g1b")]), report_data);
    assert_ne!(bind_gpus(&report_data, &[gpu("g2b")]), report_data);
}

#[test]
fn kata_classes_take_gpu_evidence_only_as_pinned() {
    let (report_data, gpu_class) = gpu_pod();
    let pinned = |count: u8| KataReference {
        gpus: Some(KataGpus {
            count: count.try_into().unwrap(),
            reference_values: vec![reference()],
        }),
        ..gpu_class.clone()
    };
    let cpu_class = KataReference {
        gpu: false,
        ..gpu_class.clone()
    };
    let mut other_report_data = report_data;
    other_report_data[63] ^= 1;

    assert_eq!(
        appraise_kata_gpus(&cpu_class, &report_data, &[], now()).unwrap(),
        Vec::<String>::new()
    );
    let cases = [
        (
            "cpu class",
            cpu_class,
            report_data,
            "attestation_failed",
            "passes no GPU",
        ),
        (
            "nothing pinned",
            gpu_class.clone(),
            report_data,
            "policy_denied",
            "pins none",
        ),
        (
            "evidence not quoted",
            pinned(1),
            other_report_data,
            "attestation_failed",
            "does not commit",
        ),
        (
            "class of two GPUs",
            pinned(2),
            report_data,
            "attestation_failed",
            "1 evidences for 2 GPUs",
        ),
        // The capture predates the nonce derivation: the device signed the raw challenge.
        (
            "raw challenge",
            pinned(1),
            report_data,
            "attestation_failed",
            "nonce",
        ),
    ];
    for (case, class, report_data, code, fragment) in cases {
        let err = appraise_kata_gpus(&class, &report_data, &[gpu("g1b")], now()).unwrap_err();
        assert_eq!(err.code(), code, "{case}: {err}");
        assert!(err.to_string().contains(fragment), "{case}: {err}");
    }
}
