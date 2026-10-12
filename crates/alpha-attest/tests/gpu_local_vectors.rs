//! The local GPU verifier's parsers against NVIDIA's published evidence, RIMs and live OCSP
//! responses (`testdata/gpu`, provenance and SHA-256 in its README). Synthetic cases for every
//! refusal are in the modules' own tests; these prove the parsers read what NVIDIA produces.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::path::PathBuf;
use std::time::Duration;

use alpha_attest::gpu::local::cert::{self, OperationalFlag};
use alpha_attest::gpu::local::ocsp::{self, Freshness};
use alpha_attest::gpu::local::rim::{self, RimKind};
use alpha_attest::gpu::local::{opaque, spdm};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use serde_json::Value;
use x509_cert::Certificate;

/// 2026-10-12T05:00:00Z, half an hour after the OCSP responses were fetched.
const OCSP_NOW: Duration = Duration::from_secs(1_791_781_200);
/// 2024-06-01T00:00:00Z, inside the Hopper RIM signing certificate's validity.
const HOPPER_RIM_NOW: Duration = Duration::from_secs(1_717_200_000);

fn path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/gpu")
        .join(name)
}

fn read(name: &str) -> Vec<u8> {
    std::fs::read(path(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn hex_file(name: &str) -> Vec<u8> {
    hex::decode(String::from_utf8(read(name)).unwrap().trim()).unwrap()
}

fn chain(name: &str) -> Vec<Certificate> {
    cert::parse_pem_chain(&read(name)).unwrap()
}

fn pem_der(name: &str) -> Vec<u8> {
    let certs = cert::parse_pem_chain(&read(name)).unwrap();
    cert::to_der(&certs[0]).unwrap()
}

fn device_root() -> Vec<Vec<u8>> {
    vec![pem_der("nvidia/verifier_device_root.pem")]
}

fn rim_root() -> Vec<Vec<u8>> {
    vec![pem_der("nvidia/verifier_RIM_root.pem")]
}

const BLACKWELL_NONCE: &str = "931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb";
const BLACKWELL_FWID: &str = "d090cab1b6e6ffddca83d1781e25b3f040fa1f3c7608230cb5f41b1c1b99f5f748349e59d0ef8eb830c9bc79ccf77502";

#[test]
fn blackwell_sample_evidence_verifies_end_to_end_under_the_pinned_root() {
    let certs = chain("nvidia/blackwellCertChain.txt");
    assert_eq!(certs.len(), 5);
    cert::verify_chain(&certs, &device_root(), OCSP_NOW).unwrap();
    assert_eq!(cert::common_name(&certs[1]).unwrap(), "GB100 A01 GSP BROM");
    assert_eq!(
        cert::common_name(&certs[4]).unwrap(),
        "NVIDIA Device Identity CA"
    );

    // The certified firmware identity: TcbInfo at 2.23.133.5.4.1.1 (finding 3).
    let tcb = cert::tcb_info(&certs[0]).unwrap();
    assert_eq!(tcb.vendor.as_deref(), Some("NVIDIA"));
    assert_eq!(tcb.model.as_deref(), Some("GB100 A01 GSP"));
    assert_eq!(hex::encode(tcb.fwid), BLACKWELL_FWID);
    assert!(!tcb.flag(OperationalFlag::Debug));
    assert!(!tcb.flag(OperationalFlag::NotSecure));
    assert!(!tcb.flag(OperationalFlag::Recovery));
    // NVIDIA's sample sets notConfigured (bit 0) and fixedWidth (bit 31); what NVIDIA means by
    // notConfigured is confirmed on the B300 at G0 (ponytail: G0-gpu-capture).
    assert!(tcb.flag(OperationalFlag::NotConfigured));

    let raw = hex_file("nvidia/blackwellAttestationReport.txt");
    let report = spdm::parse(&raw).unwrap();
    assert_eq!(hex::encode(report.nonce), BLACKWELL_NONCE);
    assert_eq!(report.blocks.len(), 64);
    assert!(report.blocks.values().all(|b| b.value.len() == 48));
    spdm::verify_signature(&report, &cert::p384_key(&certs[0]).unwrap()).unwrap();

    let o = opaque::parse(report.opaque).unwrap();
    assert_eq!(o.version, 0);
    assert!(!o.nvdaod);
    assert_eq!(o.driver_version().unwrap(), "575.32");
    assert_eq!(o.vbios_version().unwrap(), "97.00.88.00.0F");
    assert_eq!(o.nvdec0_status().unwrap(), 0x55);
    assert_eq!(o.fwid().map(hex::encode).as_deref(), Some(BLACKWELL_FWID));
    assert_eq!(o.feature_flag().unwrap(), None);

    // Any bit of the signed report changed: the signature no longer verifies.
    for at in [40, 100, 2000, raw.len() - 97] {
        let mut tampered = raw.clone();
        tampered[at] ^= 1;
        if let Ok(r) = spdm::parse(&tampered) {
            assert!(spdm::verify_signature(&r, &cert::p384_key(&certs[0]).unwrap()).is_err());
        }
    }
}

#[test]
fn device_chains_end_only_at_a_pinned_root() {
    let certs = chain("nvidia/blackwellCertChain.txt");
    let error = cert::verify_chain(&certs, &rim_root(), OCSP_NOW)
        .unwrap_err()
        .to_string();
    assert!(error.contains("not a root the gpu_policy pins"), "{error}");
    let error = cert::verify_chain(&certs, &[], OCSP_NOW)
        .unwrap_err()
        .to_string();
    assert!(error.contains("not a root"), "{error}");
    // A chain cut short of the root, or with a link removed.
    let error = cert::verify_chain(&certs[..4], &device_root(), OCSP_NOW)
        .unwrap_err()
        .to_string();
    assert!(error.contains("not a root"), "{error}");
    let skipped = [
        certs[0].clone(),
        certs[2].clone(),
        certs[3].clone(),
        certs[4].clone(),
    ];
    let error = cert::verify_chain(&skipped, &device_root(), OCSP_NOW)
        .unwrap_err()
        .to_string();
    assert!(error.contains("does not name"), "{error}");
    // Before the device certificates were issued.
    let error = cert::verify_chain(&certs, &device_root(), Duration::from_secs(1_600_000_000))
        .unwrap_err()
        .to_string();
    assert!(error.contains("not valid yet"), "{error}");
}

#[test]
fn hopper_evidence_parses_but_its_fwid_format_is_refused() {
    let certs = chain("nvidia/hopperCertChain.txt");
    cert::verify_chain(&certs, &device_root(), OCSP_NOW).unwrap();
    let error = cert::tcb_info(&certs[0]).unwrap_err().to_string();
    assert!(error.contains("Hopper-format"), "{error}");
    let raw = hex_file("nvidia/hopperAttestationReport.txt");
    let report = spdm::parse(&raw).unwrap();
    spdm::verify_signature(&report, &cert::p384_key(&certs[0]).unwrap()).unwrap();
}

#[test]
fn the_fsp_responder_report_carries_no_firmware_identity() {
    // Blackwell's FSP answers with typed raw blocks and no NVIDIA opaque data: there is no driver
    // or VBIOS identity to appraise, so the appraisal refuses it (see the backend's tests).
    let certs = chain("nvidia/blackwellFspCertChain.txt");
    cert::verify_chain(&certs, &device_root(), OCSP_NOW).unwrap();
    assert_eq!(cert::common_name(&certs[1]).unwrap(), "GB100 A01 FSP BROM");
    let raw = hex_file("nvidia/blackwellFspAttestationReport.txt");
    let report = spdm::parse(&raw).unwrap();
    spdm::verify_signature(&report, &cert::p384_key(&certs[0]).unwrap()).unwrap();
    assert!(report.opaque.is_empty());
    let o = opaque::parse(report.opaque).unwrap();
    assert!(o.driver_version().is_err());
}

struct Entry {
    signed_info: Vec<u8>,
    document: Vec<u8>,
    signature: Vec<u8>,
    certificates: Vec<Certificate>,
}

fn entry(name: &str) -> Entry {
    let v: Value = serde_json::from_slice(&read(name)).unwrap();
    let b64 = |k: &str| BASE64_STANDARD.decode(v[k].as_str().unwrap()).unwrap();
    Entry {
        signed_info: b64("signed_info"),
        document: b64("document"),
        signature: b64("signature"),
        certificates: v["certificates"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| {
                cert::parse_der(&BASE64_STANDARD.decode(c.as_str().unwrap()).unwrap()).unwrap()
            })
            .collect(),
    }
}

fn verify_rim(e: &Entry, now: Duration) -> Result<rim::Rim, String> {
    cert::verify_chain(&e.certificates, &rim_root(), now).map_err(|e| e.0)?;
    let key = cert::p384_key(&e.certificates[0]).map_err(|e| e.0)?;
    let digest = rim::verify_signed_info(&e.signed_info, &e.signature, &key).map_err(|e| e.0)?;
    rim::parse_document(&e.document, &digest).map_err(|e| e.0)
}

#[test]
fn nvidia_signed_rims_verify_without_canonicalising_and_match_real_measurements() {
    let vbios = verify_rim(
        &entry("rim/NV_GPU_VBIOS_1010_0200_882_96005E0001.json"),
        HOPPER_RIM_NOW,
    )
    .unwrap();
    assert_eq!(vbios.kind, RimKind::Vbios);
    assert_eq!(vbios.version, "96.00.5E.00.01");
    assert_eq!(vbios.platform_model, "GH100");
    let active: Vec<_> = vbios
        .measurements
        .iter()
        .filter(|(_, g)| g.active)
        .collect();
    assert_eq!(active.len(), 12);

    // NVIDIA's Hopper sample report is of that VBIOS: every active golden value is measured.
    let raw = hex_file("nvidia/hopperAttestationReport.txt");
    let report = spdm::parse(&raw).unwrap();
    let o = opaque::parse(report.opaque).unwrap();
    assert_eq!(o.vbios_version().unwrap(), vbios.version);
    for (index, golden) in active {
        let block = &report.blocks[&u8::try_from(index + 1).unwrap()];
        assert!(
            golden.alternatives.contains(&block.value),
            "measurement {index}"
        );
    }

    let driver = verify_rim(
        &entry("rim/NV_GPU_DRIVER_GH100_550.144.03.json"),
        Duration::from_secs(1_760_000_000),
    )
    .unwrap();
    assert_eq!(driver.kind, RimKind::Driver);
    assert_eq!(driver.version, "550.144.03");
    assert!(driver.measurements.values().any(|g| g.active));
}

#[test]
fn rims_are_refused_when_anything_signed_changes_or_the_signer_expired() {
    let good = entry("rim/NV_GPU_VBIOS_1010_0200_882_96005E0001.json");
    // The RIM signing certificate expired 2025-06-22.
    let error = verify_rim(&good, OCSP_NOW).unwrap_err();
    assert!(error.contains("has expired"), "{error}");

    let tamper = |f: &dyn Fn(&mut Entry)| {
        let mut e = entry("rim/NV_GPU_VBIOS_1010_0200_882_96005E0001.json");
        f(&mut e);
        verify_rim(&e, HOPPER_RIM_NOW).unwrap_err()
    };
    let golden_value = |e: &mut Entry| {
        let text = String::from_utf8(e.document.clone()).unwrap();
        let at = text.find("Hash0=\"").unwrap() + 7;
        e.document[at] = if e.document[at] == b'0' { b'1' } else { b'0' };
    };
    for (case, error, reason) in [
        (
            "golden value",
            tamper(&golden_value),
            "not the one its signature covers",
        ),
        (
            "signed info",
            tamper(&|e| {
                let at = e.signed_info.len() - 30;
                e.signed_info[at] ^= 1;
            }),
            "does not verify",
        ),
        (
            "signature",
            tamper(&|e| e.signature[10] ^= 1),
            "does not verify",
        ),
        (
            "another signer",
            tamper(&|e| e.certificates[0] = e.certificates[1].clone()),
            "",
        ),
        (
            "certificates from the device chain",
            tamper(&|e| e.certificates = chain("nvidia/blackwellCertChain.txt")),
            "not a root",
        ),
    ] {
        assert!(error.contains(reason), "{case}: {error}");
    }
    // A document whose DigestValue is right but which is not a RIM still parses strictly.
    let digest: [u8; 48] = sha2::Digest::finalize(sha2::Digest::chain_update(
        <sha2::Sha384 as sha2::Digest>::new(),
        b"<x/>",
    ))
    .into();
    assert!(
        rim::parse_document(b"<x/>", &digest)
            .unwrap_err()
            .0
            .contains("expected SoftwareIdentity")
    );
}

#[test]
fn nvidia_ocsp_responses_vouch_for_the_blackwell_device_chain() {
    let certs = chain("nvidia/blackwellCertChain.txt");
    let fresh = Freshness {
        max_age: Duration::from_secs(24 * 3600),
        accept_certificate_hold: false,
    };
    for (index, file) in [
        (1, "ocsp/blackwell-brom.der"),
        (2, "ocsp/blackwell-provisioner-ica.der"),
        (3, "ocsp/blackwell-identity.der"),
    ] {
        let response = ocsp::parse(&read(file)).unwrap();
        assert!(response.is_about(&certs[index], &certs[index + 1]));
        response
            .check(&certs[index], &certs[index + 1], OCSP_NOW, fresh)
            .unwrap_or_else(|e| panic!("{file}: {e}"));
    }
    let brom = ocsp::parse(&read("ocsp/blackwell-brom.der")).unwrap();
    // A response about another certificate does not count.
    let error = brom
        .check(&certs[2], &certs[3], OCSP_NOW, fresh)
        .unwrap_err()
        .0;
    assert!(error.contains("no status"), "{error}");
    // Older than the policy's maximum age, and past nextUpdate.
    let short = Freshness {
        max_age: Duration::from_secs(60),
        ..fresh
    };
    let error = brom
        .check(&certs[1], &certs[2], OCSP_NOW, short)
        .unwrap_err()
        .0;
    assert!(error.contains("more than the policy's 60s"), "{error}");
    let later = OCSP_NOW + Duration::from_secs(2 * 24 * 3600);
    let error = brom
        .check(
            &certs[1],
            &certs[2],
            later,
            Freshness {
                max_age: Duration::from_secs(30 * 24 * 3600),
                ..fresh
            },
        )
        .unwrap_err()
        .0;
    assert!(error.contains("nextUpdate"), "{error}");
    // Checked against an issuer that did not delegate to its responder.
    let error = brom
        .check(&certs[1], &certs[3], OCSP_NOW, fresh)
        .unwrap_err()
        .0;
    assert!(error.contains("no status"), "{error}");
}

#[test]
fn a_rim_signer_on_hold_is_refused_unless_the_release_accepts_holds() {
    let der = |i: usize| cert::parse_der(&read(&format!("certs/rim-gb100-cc-{i}.der"))).unwrap();
    let rim_chain: Vec<_> = (0..4).map(der).collect();
    cert::verify_chain(&rim_chain, &rim_root(), OCSP_NOW).unwrap();
    let strict = Freshness {
        max_age: Duration::from_secs(24 * 3600),
        accept_certificate_hold: false,
    };
    let signer = ocsp::parse(&read("ocsp/rim-gb100-cc-signer.der")).unwrap();
    let error = signer
        .check(&rim_chain[0], &rim_chain[1], OCSP_NOW, strict)
        .unwrap_err()
        .0;
    assert!(error.contains("revoked (CertificateHold)"), "{error}");
    signer
        .check(
            &rim_chain[0],
            &rim_chain[1],
            OCSP_NOW,
            Freshness {
                accept_certificate_hold: true,
                ..strict
            },
        )
        .unwrap();
    for (index, file) in [
        (1, "ocsp/rim-gb100-cc-l3.der"),
        (2, "ocsp/rim-gb1xx-ca.der"),
    ] {
        ocsp::parse(&read(file))
            .unwrap()
            .check(&rim_chain[index], &rim_chain[index + 1], OCSP_NOW, strict)
            .unwrap_or_else(|e| panic!("{file}: {e}"));
    }
}

/// What the fuzz targets do, deterministically and on stable: every parser over truncations and
/// bit flips of NVIDIA's real inputs must refuse or parse, never panic or loop.
#[test]
fn parsers_survive_truncations_and_bit_flips_of_real_inputs() {
    let mutations = |input: &[u8], stride: usize, f: &dyn Fn(&[u8])| {
        for len in (0..input.len()).step_by(stride) {
            f(&input[..len]);
        }
        for at in (0..input.len()).step_by(stride) {
            let mut m = input.to_vec();
            m[at] ^= 0x5A;
            f(&m);
        }
    };
    let report = hex_file("nvidia/blackwellAttestationReport.txt");
    mutations(&report, 1, &|b| {
        if let Ok(r) = spdm::parse(b)
            && let Ok(o) = opaque::parse(r.opaque)
        {
            let _ = (o.driver_version(), o.vbios_version(), o.nvdec0_status());
            let _ = o.feature_flag();
        }
    });
    mutations(&read("nvidia/blackwellCertChain.txt"), 3, &|b| {
        if let Ok(certs) = cert::parse_pem_chain(b) {
            for c in &certs {
                let _ = (cert::tcb_info(c), cert::extensions(c).is_ok());
            }
        }
    });
    let certs = chain("nvidia/blackwellCertChain.txt");
    mutations(&read("ocsp/blackwell-brom.der"), 1, &|b| {
        // Parsing and CertID matching; the signature check is not a parser and is slow in a
        // debug build.
        if let Ok(r) = ocsp::parse(b) {
            let _ = (r.is_about(&certs[1], &certs[2]), r.nonce());
        }
    });
    let e = entry("rim/NV_GPU_VBIOS_1010_0200_882_96005E0001.json");
    mutations(&e.signed_info, 1, &|b| {
        let _ = rim::signed_digest(b);
    });
    mutations(&e.document, 11, &|b| {
        let digest: [u8; 48] = <sha2::Sha384 as sha2::Digest>::digest(b).into();
        let _ = rim::parse_document(b, &digest);
    });
}

fn real_policy(rim: &str) -> alpha_attest::GpuPolicy {
    use alpha_attest::gpu::local::LocalPolicy;
    let b64 = |v: Vec<Vec<u8>>| v.iter().map(|d| BASE64_STANDARD.encode(d)).collect();
    let doc = entry(rim).document;
    alpha_attest::GpuPolicy {
        allowed_models: vec!["B200".into()],
        min_driver_version: None,
        min_vbios_version: None,
        verifiers: vec![alpha_attest::GpuVerifierKind::Local],
        nras_url: None,
        hwmodels: [("GB100 A01 GSP BROM".to_owned(), "B200".to_owned())].into(),
        nras_keys: Default::default(),
        nras_cc_mode: None,
        local: Some(LocalPolicy {
            device_roots: b64(device_root()),
            rim_roots: b64(rim_root()),
            rims: [(
                format!(
                    "sha384:{}",
                    hex::encode(<sha2::Sha384 as sha2::Digest>::digest(&doc))
                ),
                "hopper vbios".to_owned(),
            )]
            .into(),
            fwids: vec![format!("sha384:{BLACKWELL_FWID}")],
            ocsp_max_age_secs: Some(86_400),
            ocsp_url: None,
            accept_certificate_hold: false,
        }),
    }
}

/// NVIDIA's Blackwell sample through the whole backend with NVIDIA's roots and live OCSP: it
/// passes the chain, revocation, TcbInfo, signature, nonce and FWID steps and stops only at the
/// RIMs, since no NVIDIA driver RIM exists for its pre-release driver (575.32).
#[test]
fn nvidia_blackwell_sample_reaches_rim_selection_through_the_backend() {
    use alpha_attest::gpu::local::{RimCache, appraise};
    let rim = "rim/NV_GPU_VBIOS_1010_0200_882_96005E0001.json";
    let ocsp: Vec<String> = [
        "blackwell-brom",
        "blackwell-provisioner-ica",
        "blackwell-identity",
    ]
    .iter()
    .map(|f| BASE64_STANDARD.encode(read(&format!("ocsp/{f}.der"))))
    .collect();
    let mut cache = RimCache::from_json(
        serde_json::json!({
            "format": "alphacompute-gpu-rim-cache/1",
            "rims": [serde_json::from_slice::<Value>(&read(rim)).unwrap()],
            "ocsp": ocsp,
        })
        .to_string()
        .as_bytes(),
    )
    .unwrap();
    let gpus = [alpha_attest::GpuEvidence {
        arch: "BLACKWELL".into(),
        evidence: hex_file("nvidia/blackwellAttestationReport.txt"),
        certificate: read("nvidia/blackwellCertChain.txt"),
    }];
    let nonce: [u8; 32] = hex::decode(BLACKWELL_NONCE).unwrap().try_into().unwrap();
    let now = std::time::UNIX_EPOCH + OCSP_NOW;
    let policy = real_policy(rim);
    let error = appraise::appraise(&gpus, &nonce, &policy, &cache, &[], now)
        .unwrap_err()
        .to_string();
    assert!(error.contains("no pinned Driver RIM for GB100"), "{error}");
    // Without the device chain's OCSP responses it stops at revocation instead.
    cache.ocsp.clear();
    let error = appraise::appraise(&gpus, &nonce, &policy, &cache, &[], now)
        .unwrap_err()
        .to_string();
    assert!(error.contains("no status"), "{error}");
    // Over another nonce, it stops at the nonce.
    let error = appraise::appraise(&gpus, &[0; 32], &policy, &cache, &[], now);
    assert!(error.is_err());

    // The FSP responder is refused by name.
    let fsp = [alpha_attest::GpuEvidence {
        arch: "BLACKWELL".into(),
        evidence: hex_file("nvidia/blackwellFspAttestationReport.txt"),
        certificate: read("nvidia/blackwellFspCertChain.txt"),
    }];
    let error = appraise::appraise(&fsp, &nonce, &policy, &cache, &[], now)
        .unwrap_err()
        .to_string();
    assert!(error.contains("FSP responder"), "{error}");
}
