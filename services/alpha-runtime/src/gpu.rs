//! NVIDIA GPU evidence in a Kata pod of a GPU runtime class: every GPU the pod sees signs an SPDM
//! measurement report over a nonce derived from the first half of the quote's `report_data`, and
//! the second half commits to those reports, so the TD vouches for exactly the evidence it sends.

use alpha_nvml::{GpuEvidence, Nvml};
use alpha_tsm::Substrate;
use sha2::{Digest, Sha256};

use crate::AttestEvidence;

const NONCE_DOMAIN: &[u8] = b"alphacompute-gpu/1";

/// The nonce every GPU signs: `SHA-256("alphacompute-gpu/1" ‖ report_data[0..32])`, so its report
/// is fresh for the KMS's challenge and this Instance's key.
pub fn nonce(report_data: &[u8; 64]) -> [u8; 32] {
    let mut head = [0u8; 32];
    head.iter_mut().zip(report_data).for_each(|(h, b)| *h = *b);
    Sha256::new()
        .chain_update(NONCE_DOMAIN)
        .chain_update(head)
        .finalize()
        .into()
}

/// `report_data` with its second half set to the SHA-256 of the GPU reports, concatenated in the
/// order they are sent.
pub fn bind(report_data: &[u8; 64], gpus: &[GpuEvidence]) -> [u8; 64] {
    let digest = gpus
        .iter()
        .fold(Sha256::new(), |h, gpu| h.chain_update(&gpu.evidence))
        .finalize();
    let mut out = *report_data;
    out.iter_mut()
        .skip(32)
        .zip(digest)
        .for_each(|(o, b)| *o = b);
    out
}

/// The TD's evidence over `report_data`, or, given NVML, every GPU's evidence over [`nonce`] and
/// the TD's over `report_data` [`bind`]ing it.
pub fn evidence(
    substrate: Substrate,
    nvml: Option<&Nvml>,
    report_data: &[u8; 64],
) -> Result<AttestEvidence, String> {
    let (gpu, report_data) = match nvml {
        Some(nvml) => {
            let gpu = nvml.collect(&nonce(report_data))?;
            let bound = bind(report_data, &gpu);
            (gpu, bound)
        }
        None => (Vec::new(), *report_data),
    };
    let td = alpha_tsm::evidence(substrate, &report_data).map_err(|e| e.to_string())?;
    Ok(AttestEvidence { td, gpu })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kata_evidence_carries_gpu_entries_only_when_there_are_some() {
        use alpha_attest::{InstanceEvidence, KATA_EVIDENCE_FORMAT, KataEvidence};
        let td = || {
            InstanceEvidence::Kata(KataEvidence {
                format: KATA_EVIDENCE_FORMAT.into(),
                quote: vec![1, 2, 3],
            })
        };
        let gpu = AttestEvidence {
            td: td(),
            gpu: vec![GpuEvidence {
                evidence: vec![0xfb, 0xff],
                certificate_chain: b"-----BEGIN".to_vec(),
            }],
        };
        assert_eq!(
            serde_json::to_value(&gpu).unwrap(),
            serde_json::json!({
                "format": "alphacompute-evidence/kata/1",
                "quote": "AQID",
                "gpu": [{"evidence": "-_8", "certificate_chain": "LS0tLS1CRUdJTg"}],
            })
        );
        assert_eq!(
            serde_json::to_value(AttestEvidence::from(td())).unwrap(),
            serde_json::to_value(td()).unwrap()
        );
    }

    #[test]
    fn nonce_and_binding_cover_the_halves_they_claim() {
        let mut report_data = [0u8; 64];
        report_data[..32].copy_from_slice(&[7; 32]);
        report_data[32..].copy_from_slice(&[9; 32]);
        let expected: [u8; 32] = Sha256::new()
            .chain_update(b"alphacompute-gpu/1")
            .chain_update([7u8; 32])
            .finalize()
            .into();
        assert_eq!(nonce(&report_data), expected);
        let mut other = report_data;
        other[63] ^= 1;
        assert_eq!(nonce(&other), expected);

        let gpu = |evidence: &[u8]| GpuEvidence {
            evidence: evidence.to_vec(),
            certificate_chain: b"chain".to_vec(),
        };
        let bound = bind(&report_data, &[gpu(b"first"), gpu(b"second")]);
        assert_eq!(bound[..32], report_data[..32]);
        assert_eq!(bound[32..], Sha256::digest(b"firstsecond")[..]);
        assert_ne!(bind(&report_data, &[gpu(b"second"), gpu(b"first")]), bound);
    }
}
