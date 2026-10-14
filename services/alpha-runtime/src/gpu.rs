//! NVIDIA GPU evidence in a Kata pod of a GPU runtime class: every GPU the pod sees signs an SPDM
//! measurement report over a nonce derived from the first half of the quote's `report_data`, and
//! the second half commits to those reports, so the TD vouches for exactly the evidence it sends.

use alpha_attest::{GpuEvidence, InstanceEvidence, bind_gpus, gpu_nonce};
use alpha_nvml::Nvml;
use alpha_tsm::Substrate;

/// The TD's evidence over `report_data`, or, given NVML, every GPU's evidence over
/// [`gpu_nonce`] and the TD's over `report_data` [binding](bind_gpus) it.
pub fn evidence(
    substrate: Substrate,
    nvml: Option<&Nvml>,
    report_data: &[u8; 64],
) -> Result<InstanceEvidence, String> {
    let quote = |report_data: &[u8; 64]| {
        alpha_tsm::evidence(substrate, report_data).map_err(|e| e.to_string())
    };
    match nvml {
        Some(nvml) => with_gpus(report_data, |nonce| nvml.collect(nonce), quote),
        None => quote(report_data),
    }
}

fn with_gpus(
    report_data: &[u8; 64],
    collect: impl FnOnce(&[u8; 32]) -> Result<Vec<GpuEvidence>, String>,
    quote: impl FnOnce(&[u8; 64]) -> Result<InstanceEvidence, String>,
) -> Result<InstanceEvidence, String> {
    let gpus = collect(&gpu_nonce(report_data))?;
    match quote(&bind_gpus(report_data, &gpus))? {
        InstanceEvidence::Kata(mut kata) => {
            kata.gpu = gpus;
            Ok(InstanceEvidence::Kata(kata))
        }
        InstanceEvidence::Dstack(_) => Err("GPU evidence outside a Kata pod".into()),
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::time::{Duration, UNIX_EPOCH};

    use alpha_attest::{KATA_EVIDENCE_FORMAT, KataEvidence, KataReference, appraise_kata_gpus};
    use alpha_client::AttestRequest;
    use p384::ecdsa::signature::Signer;
    use p384::pkcs8::DecodePrivateKey;
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, CustomExtension, IsCa, KeyPair,
        KeyUsagePurpose, PKCS_ECDSA_P384_SHA384, SerialNumber,
    };
    use sha2::{Digest, Sha256};

    use super::*;

    fn testdata(name: &str) -> Vec<u8> {
        std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../testdata/attest/b300-gpu-595.58.03")
                .join(name),
        )
        .unwrap()
    }

    /// A device chain under a root of our own, whose leaf carries the real GPU's FWID, and that
    /// GPU's real measurements re-signed by the leaf over `nonce`.
    struct Device {
        root_sha256: [u8; 32],
        chain: Vec<u8>,
        leaf: p384::ecdsa::SigningKey,
        evidence: Vec<u8>,
    }

    impl Device {
        fn new() -> Self {
            let mut root = CertificateParams::new(vec![]).unwrap();
            root.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            root.key_usages = vec![KeyUsagePurpose::KeyCertSign];
            let root = CertifiedIssuer::self_signed(
                root,
                KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap(),
            )
            .unwrap();

            let evidence = testdata("g1b.spdm.bin");
            let fwid = evidence
                .windows(52)
                .find(|w| w[..4] == [20, 0, 48, 0])
                .unwrap()[4..]
                .to_vec();
            // TcbInfo { fwids [6] { { sha384, fwid } } }
            let mut tcb_info = vec![0x30, 0x41, 0xa6, 0x3f, 0x30, 0x3d, 0x06, 0x09];
            tcb_info.extend_from_slice(&[
                0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x04, 0x30,
            ]);
            tcb_info.extend_from_slice(&fwid);
            let mut leaf = CertificateParams::new(vec![]).unwrap();
            leaf.serial_number = Some(SerialNumber::from(0x0102_0304u64));
            leaf.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            leaf.custom_extensions = vec![CustomExtension::from_oid_content(
                &[2, 23, 133, 5, 4, 1, 1],
                tcb_info,
            )];
            let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
            let leaf_signer = p384::SecretKey::from_pkcs8_der(&leaf_key.serialize_der())
                .unwrap()
                .into();
            let leaf = leaf.signed_by(&leaf_key, &root).unwrap();

            Self {
                root_sha256: Sha256::digest(root.der()).into(),
                chain: format!("{}{}", leaf.pem(), root.pem()).into_bytes(),
                leaf: leaf_signer,
                evidence,
            }
        }

        fn collect(&self, nonce: &[u8; 32]) -> GpuEvidence {
            let mut evidence = self.evidence.clone();
            evidence[4..36].copy_from_slice(nonce);
            let signed = evidence.len() - 96;
            let signature: p384::ecdsa::Signature = self.leaf.sign(&evidence[..signed]);
            evidence[signed..].copy_from_slice(&signature.to_bytes());
            GpuEvidence {
                evidence,
                certificate_chain: self.chain.clone(),
            }
        }
    }

    fn gpu_class(root_sha256: [u8; 32]) -> KataReference {
        let mut reference: serde_json::Value =
            serde_json::from_slice(&testdata("gpu-reference.json")).unwrap();
        reference["root_sha256"] = alpha_core::ComposeHash::from(root_sha256)
            .to_string()
            .into();
        let zero = format!("sha384:{}", "00".repeat(48));
        serde_json::from_value(serde_json::json!({
            "runtime_class": "kata-qemu-nvidia-gpu-tdx",
            "mrtd": zero, "rtmr0": [zero], "rtmr1": zero, "rtmr2": zero,
            "gpu": true,
            "gpus": { "count": 1, "reference_values": [reference] },
        }))
        .unwrap()
    }

    /// What the runtime sends for a GPU pod is what the KMS parses and appraises: the GPU
    /// evidence over the nonce derived from the request's `report_data`, and the quote over the
    /// `report_data` the KMS expects of that evidence. Only the quote itself is not real.
    #[test]
    fn the_kms_accepts_what_a_gpu_pod_sends() {
        let device = Device::new();
        let (spki, nonce) = (b"runtime spki".as_slice(), [3u8; 32]);
        let quoted = Cell::new([0u8; 64]);
        let sent = with_gpus(
            &alpha_attest::report_data(spki, &nonce, None),
            |nonce| Ok(vec![device.collect(nonce)]),
            |report_data| {
                quoted.set(*report_data);
                Ok(InstanceEvidence::Kata(KataEvidence {
                    format: KATA_EVIDENCE_FORMAT.into(),
                    quote: vec![1],
                    gpu: Vec::new(),
                }))
            },
        )
        .unwrap();
        let wire = serde_json::to_vec(&AttestRequest {
            runtime_pubkey: String::new(),
            nonce: String::new(),
            evidence: sent,
        })
        .unwrap();

        let received: AttestRequest = serde_json::from_slice(&wire).unwrap();
        let InstanceEvidence::Kata(kata) = received.evidence else {
            panic!("not Kata evidence");
        };
        let expected = bind_gpus(&alpha_attest::report_data(spki, &nonce, None), &kata.gpu);
        assert_eq!(quoted.get(), expected);
        let now = UNIX_EPOCH + Duration::from_secs(1_791_849_600);
        assert_eq!(
            appraise_kata_gpus(&gpu_class(device.root_sha256), &expected, &kata.gpu, now).unwrap(),
            ["01020304"]
        );
    }
}
