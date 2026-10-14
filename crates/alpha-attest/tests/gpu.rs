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

use alpha_attest::{GpuEvidence, GpuReference, appraise_gpus};

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
