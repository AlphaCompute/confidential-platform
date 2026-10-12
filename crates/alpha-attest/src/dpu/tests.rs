//! `nvidia-dpu/1` over synthetic SPDM 1.1 transcripts signed by a test DICE chain (a test root of
//! ours, never NVIDIA's): no BlueField capture exists (`ponytail: dpu-capture`).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use p384::ecdsa::SigningKey;
use p384::ecdsa::signature::hazmat::PrehashSigner;
use p384::pkcs8::EncodePrivateKey;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName, DnType, IsCa, KeyPair,
    PKCS_ECDSA_P384_SHA384,
};
use sha2::{Sha384, Sha512};

use super::spdm::{LocalDpu, parse_transcript, verify};
use super::*;

const NONCE: [u8; 32] = [0x42; 32];
const MODEL: &str = "BLUEFIELD-3";

fn params(name: &str) -> CertificateParams {
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.distinguished_name = DistinguishedName::new();
    p.distinguished_name.push(DnType::CommonName, name);
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p
}

/// A test DICE chain, root first: root, DeviceID, alias, leaf; and the leaf's signing key.
struct Chain {
    root_pem: String,
    pem: Vec<String>,
    leaf: SigningKey,
    device_spki: Vec<u8>,
}

fn chain_from(root: &str, leaf_seed: u8) -> Chain {
    let root = CertifiedIssuer::self_signed(
        params(root),
        KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap(),
    )
    .unwrap();
    let device_key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
    let device_spki = rcgen::PublicKeyData::subject_public_key_info(&device_key);
    let device = CertifiedIssuer::signed_by(params("DeviceID"), device_key, &root).unwrap();
    let alias = CertifiedIssuer::signed_by(
        params("Alias"),
        KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap(),
        &device,
    )
    .unwrap();
    let leaf = SigningKey::from_slice(&[leaf_seed; 48]).unwrap();
    let leaf_pair = KeyPair::try_from(leaf.to_pkcs8_der().unwrap().as_bytes()).unwrap();
    let leaf_cert = params("Leaf").signed_by(&leaf_pair, &alias).unwrap();
    Chain {
        root_pem: root.pem(),
        pem: vec![root.pem(), device.pem(), alias.pem(), leaf_cert.pem()],
        leaf,
        device_spki,
    }
}

/// DMTF measurement blocks: index, value type, value.
fn blocks() -> Vec<(u8, u8, Vec<u8>)> {
    vec![
        (1, 0x83, vec![1, 2, 3, 0]),
        (2, 0x01, vec![0x22; 64]),
        (3, 0x01, vec![0x33; 64]),
        (4, 0x01, vec![0x44; 64]),
        (5, 0x02, vec![0x55; 64]),
    ]
}

/// An SPDM 1.1 transcript: one unsigned pair (the measurement count), then the signed pair for
/// all measurements over `nonce` from `slot`, signed by `key` over `hash`.
fn transcript(
    nonce: [u8; 32],
    slot: u8,
    blocks: &[(u8, u8, Vec<u8>)],
    key: &SigningKey,
    sha512: bool,
) -> Vec<u8> {
    let mut t = vec![0x11, 0xE0, 0, 0];
    t.extend([0x11, 0x60, blocks.len() as u8, 0, 0, 0, 0, 0]);
    t.extend([0x77; 32]);
    t.extend([0, 0]);
    t.extend([0x11, 0xE0, 1, 0xFF]);
    t.extend(nonce);
    t.push(slot);
    let mut record = Vec::new();
    for (index, kind, value) in blocks {
        record.push(*index);
        record.push(0x01);
        record.extend(((value.len() + 3) as u16).to_le_bytes());
        record.push(*kind);
        record.extend((value.len() as u16).to_le_bytes());
        record.extend(value);
    }
    t.extend([0x11, 0x60, 0, slot, blocks.len() as u8]);
    t.extend(&(record.len() as u32).to_le_bytes()[..3]);
    t.extend(record);
    t.extend([0x88; 32]);
    t.extend([2, 0, 0xAB, 0xCD]);
    let digest = if sha512 {
        Sha512::digest(&t).to_vec()
    } else {
        Sha384::digest(&t).to_vec()
    };
    let signature: p384::ecdsa::Signature = key.sign_prehash(&digest).unwrap();
    t.extend(signature.to_bytes());
    t
}

fn evidence(chain: &Chain, signed_measurements: Vec<u8>) -> DpuEvidence {
    DpuEvidence {
        spdm_version: "1.1.0".into(),
        hashing_algorithm: "TPM_ALG_SHA_512".into(),
        signing_algorithm: "TPM_ALG_ECDSA_ECC_NIST_P384".into(),
        signed_measurements,
        certificate_chain: chain.pem.concat(),
    }
}

fn good(chain: &Chain) -> DpuEvidence {
    evidence(chain, transcript(NONCE, 0, &blocks(), &chain.leaf, true))
}

fn model(chain: &Chain) -> DpuModel {
    DpuModel {
        roots_pem: vec![chain.root_pem.clone()],
        measurements: BTreeMap::from([
            ("2".into(), vec![format!("01{}", "22".repeat(64))]),
            (
                "3".into(),
                vec!["00".into(), format!("01{}", "33".repeat(64))],
            ),
            ("4".into(), vec![format!("01{}", "44".repeat(64))]),
        ]),
        accept_unchecked_revocation: true,
    }
}

fn now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_791_763_200)
}

fn refused(result: Result<VerifiedDpu, AppraisalError>, code: &str, reason: &str) {
    let error = result
        .err()
        .unwrap_or_else(|| panic!("verified; expected {reason}"));
    assert_eq!(error.code(), code, "{error}");
    assert!(
        error.to_string().contains(reason),
        "{error} does not mention {reason:?}"
    );
}

#[test]
fn a_signed_transcript_under_a_pinned_root_verifies() {
    let chain = chain_from("test root", 7);
    for sha512 in [true, false] {
        let mut e = evidence(&chain, transcript(NONCE, 0, &blocks(), &chain.leaf, sha512));
        if !sha512 {
            e.hashing_algorithm = "TPM_ALG_SHA_384".into();
        }
        let dpu = verify(&e, &NONCE, MODEL, &model(&chain), now()).unwrap();
        assert_eq!(dpu.model, MODEL);
        assert_eq!(dpu.nonce, NONCE);
        assert!(!dpu.revocation_checked);
        assert_eq!(
            dpu.device_id,
            format!("sha256:{}", hex::encode(Sha256::digest(&chain.device_spki)))
        );
        assert_eq!(dpu.measurements.len(), 5);
        assert_eq!(dpu.measurements[&1], "8301020300");
    }
    // A leaf-first chain is the same chain.
    let mut reversed = good(&chain);
    reversed.certificate_chain = chain.pem.iter().rev().cloned().collect::<String>();
    verify(&reversed, &NONCE, MODEL, &model(&chain), now()).unwrap();
}

#[test]
fn transcripts_are_parsed_strictly() {
    let chain = chain_from("test root", 7);
    let t = transcript(NONCE, 0, &blocks(), &chain.leaf, true);
    let parsed = parse_transcript(&t).unwrap();
    assert_eq!(parsed.nonce, NONCE);
    assert_eq!(parsed.signed_len, t.len() - 96);
    for (bytes, why) in [
        (t[..t.len() - 1].to_vec(), "truncated"),
        ([t.clone(), vec![0]].concat(), "continues after"),
        (t[..t.len() - 96 - 4].to_vec(), "truncated"),
        (
            [&[0x12u8][..], &t[1..]].concat(),
            "version 1.1 GET_MEASUREMENTS",
        ),
        (t[..t.len() - 96].to_vec(), "truncated"),
    ] {
        let error = parse_transcript(&bytes).unwrap_err().to_string();
        assert!(error.contains(why), "{why}: {error}");
    }
    // Only unsigned pairs.
    let unsigned = t[..46].to_vec();
    assert!(
        parse_transcript(&unsigned)
            .unwrap_err()
            .to_string()
            .contains("no signed")
    );
    // A block measured twice.
    let mut twice = blocks();
    twice.push((2, 0x01, vec![0x22; 64]));
    let t = transcript(NONCE, 0, &twice, &chain.leaf, true);
    assert!(
        parse_transcript(&t)
            .unwrap_err()
            .to_string()
            .contains("appears twice")
    );
}

#[test]
fn malicious_host_dpu_cases_are_refused() {
    let chain = chain_from("test root", 7);
    let policy = model(&chain);
    let check = |e: &DpuEvidence| verify(e, &NONCE, MODEL, &policy, now());

    // A changed measurement after signing.
    let mut changed = good(&chain);
    let at = changed.signed_measurements.len() - 96 - 40;
    changed.signed_measurements[at] ^= 1;
    refused(
        check(&changed),
        "attestation_failed",
        "signature does not verify",
    );
    // Another nonce (a replayed transcript), another slot.
    refused(
        check(&evidence(
            &chain,
            transcript([1; 32], 0, &blocks(), &chain.leaf, true),
        )),
        "attestation_failed",
        "not over this nonce",
    );
    refused(
        check(&evidence(
            &chain,
            transcript(NONCE, 1, &blocks(), &chain.leaf, true),
        )),
        "attestation_failed",
        "slot 1",
    );
    // Signed by a key the chain does not certify.
    let other = SigningKey::from_slice(&[9; 48]).unwrap();
    refused(
        check(&evidence(
            &chain,
            transcript(NONCE, 0, &blocks(), &other, true),
        )),
        "attestation_failed",
        "does not verify under the leaf",
    );
    // A chain to another root; a chain with a link from another chain.
    let foreign = chain_from("other root", 7);
    refused(check(&good(&foreign)), "attestation_failed", "pinned root");
    let mut spliced = good(&chain);
    spliced.certificate_chain = [
        chain.pem[0].clone(),
        chain.pem[1].clone(),
        foreign.pem[2].clone(),
        foreign.pem[3].clone(),
    ]
    .concat();
    refused(check(&spliced), "attestation_failed", "certificate chain");
    // Firmware not in the reference values; a listed measurement left out.
    let mut old = blocks();
    old[2].2 = vec![0x30; 64];
    refused(
        check(&evidence(
            &chain,
            transcript(NONCE, 0, &old, &chain.leaf, true),
        )),
        "policy_denied",
        "measurement 3 is not a reference value",
    );
    let fewer: Vec<_> = blocks().into_iter().filter(|b| b.0 != 4).collect();
    refused(
        check(&evidence(
            &chain,
            transcript(NONCE, 0, &fewer, &chain.leaf, true),
        )),
        "attestation_failed",
        "measurement 4 is not in the transcript",
    );
    // SPDM 1.2, another signing or hashing algorithm.
    let mut v12 = good(&chain);
    v12.spdm_version = "1.2.0".into();
    refused(check(&v12), "attestation_unknown", "SPDM 1.2.0");
    let mut rsa = good(&chain);
    rsa.signing_algorithm = "TPM_ALG_RSASSA_3072".into();
    refused(check(&rsa), "attestation_failed", "not ECDSA P-384");
    let mut sha256 = good(&chain);
    sha256.hashing_algorithm = "TPM_ALG_SHA_256".into();
    refused(
        check(&sha256),
        "attestation_failed",
        "not SHA-384 or SHA-512",
    );
    // Not yet valid.
    refused(
        verify(&good(&chain), &NONCE, MODEL, &policy, UNIX_EPOCH),
        "attestation_failed",
        "not valid now",
    );
}

#[test]
fn a_policy_without_roots_references_or_revocation_acceptance_refuses_every_dpu() {
    let chain = chain_from("test root", 7);
    let e = good(&chain);
    let mut none = model(&chain);
    none.roots_pem.clear();
    refused(
        verify(&e, &NONCE, MODEL, &none, now()),
        "policy_denied",
        "pins no root",
    );
    let mut none = model(&chain);
    none.measurements.clear();
    refused(
        verify(&e, &NONCE, MODEL, &none, now()),
        "policy_denied",
        "no reference measurements",
    );
    let mut strict = model(&chain);
    strict.accept_unchecked_revocation = false;
    refused(
        verify(&e, &NONCE, MODEL, &strict, now()),
        "policy_denied",
        "revocation",
    );
}

fn verified(index: u32, device: &str) -> VerifiedDpu {
    VerifiedDpu {
        index,
        device_id: device.into(),
        model: MODEL.into(),
        measurements: BTreeMap::new(),
        nonce: NONCE,
        revocation_checked: false,
    }
}

fn policy() -> DpuPolicy {
    DpuPolicy {
        models: BTreeMap::from([(
            MODEL.into(),
            DpuModel {
                roots_pem: Vec::new(),
                measurements: BTreeMap::new(),
                accept_unchecked_revocation: false,
            },
        )]),
        verifiers: vec![DpuVerifierKind::Local],
    }
}

fn shape(count: u32) -> DpuShape {
    DpuShape {
        count,
        model: MODEL.into(),
    }
}

#[test]
fn the_dpu_decision_holds_count_devices_nonce_and_model() {
    let local = |dpus| {
        vec![DpuAppraisal {
            verifier: DpuVerifierKind::Local,
            dpus,
        }]
    };
    let ok = check_dpus(
        Some(&policy()),
        &shape(2),
        2,
        &local(vec![verified(1, "b"), verified(0, "a")]),
        &NONCE,
    )
    .unwrap();
    assert_eq!(ok.iter().map(|d| d.index).collect::<Vec<_>>(), [0, 1]);

    let other_nonce = VerifiedDpu {
        nonce: [0; 32],
        ..verified(0, "a")
    };
    let other_model = VerifiedDpu {
        model: "CX7".into(),
        ..verified(0, "a")
    };
    for (appraisals, count, evidence, reason) in [
        (local(vec![verified(0, "a")]), 2, 2, "verified 1 DPUs"),
        (
            local(vec![verified(0, "a"), verified(1, "a")]),
            2,
            2,
            "another DPU",
        ),
        (
            local(vec![verified(0, "a"), verified(0, "b")]),
            2,
            2,
            "verified twice",
        ),
        (local(vec![verified(3, "a")]), 1, 1, "out of range"),
        (local(vec![other_nonce]), 1, 1, "not over this nonce"),
        (local(vec![other_model]), 1, 1, "model CX7"),
        (Vec::new(), 1, 1, "did not run"),
        (local(vec![verified(0, "a")]), 1, 2, "2 DPUs attested"),
        (local(vec![verified(0, "a")]), 9, 9, "not 1 to 8"),
    ] {
        let error = check_dpus(
            Some(&policy()),
            &shape(count),
            evidence,
            &appraisals,
            &NONCE,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains(reason), "{reason}: {error}");
    }
    let error = precheck(None, &shape(1), 1).unwrap_err();
    assert_eq!(error.code(), "attestation_unknown");
    let error = precheck(
        Some(&policy()),
        &DpuShape {
            count: 1,
            model: "CX8".into(),
        },
        1,
    )
    .unwrap_err();
    assert_eq!(error.code(), "policy_denied");
}

#[tokio::test]
async fn the_local_backend_numbers_dpus_and_names_the_failing_one() {
    let chain = chain_from("test root", 7);
    let backends: Vec<Arc<dyn DpuVerifier>> = vec![Arc::new(LocalDpu::with_clock(now))];
    let policy = DpuPolicy {
        models: BTreeMap::from([(MODEL.into(), model(&chain))]),
        verifiers: vec![DpuVerifierKind::Local],
    };
    let (_, m) = precheck(Some(&policy), &shape(1), 1).unwrap();
    let out = verify_dpus(&backends, &[good(&chain)], &NONCE, &shape(1), &policy, m)
        .await
        .unwrap();
    assert_eq!(out[0].dpus[0].index, 0);
    let mut bad = good(&chain);
    bad.signed_measurements[10] ^= 1;
    let error = verify_dpus(
        &backends,
        &[good(&chain), bad],
        &NONCE,
        &shape(2),
        &policy,
        m,
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("dpu 1:"), "{error}");
    let error = verify_dpus(&[], &[good(&chain)], &NONCE, &shape(1), &policy, m)
        .await
        .unwrap_err();
    assert_eq!(error.code(), "attestation_unknown");
}

#[test]
fn the_dpu_nonce_is_its_own() {
    let rd = [3u8; 64];
    assert_ne!(dpu_nonce(&rd), crate::gpu::gpu_nonce(&rd));
}
