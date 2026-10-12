//! The `local` backend end to end over a synthetic B300 world (`testkit`), with the negative
//! cases for each of the review's high findings.
//
// ponytail: G0-gpu-capture — these B300 cases follow the documented Blackwell format (NVIDIA's
// GB100 samples); re-pin them against the first B300 capture.

use std::collections::BTreeMap;

use super::policy::CcSource;
use super::testkit::*;
use crate::gpu::{GpuEvidence, GpuVerifier, VerifiedGpu, check_gpus};
use alpha_core::coco::GpuShape;

fn shape(count: u32) -> GpuShape {
    GpuShape {
        count,
        model: "B300".into(),
    }
}

fn refusal(world: &World, gpus: &[GpuEvidence]) -> String {
    world.appraise(gpus).unwrap_err().to_string()
}

fn expect(world: &World, gpus: &[GpuEvidence], reason: &str) {
    let error = refusal(world, gpus);
    assert!(error.contains(reason), "expected {reason:?} in: {error}");
}

/// The verdict passed through `check_gpus`, as the KMS applies it.
fn decide(world: &World, gpus: &[GpuEvidence]) -> Result<Vec<VerifiedGpu>, (String, String)> {
    let verdict = world
        .appraise(gpus)
        .map_err(|e| (e.code().into(), e.to_string()))?;
    let count = u32::try_from(gpus.len()).unwrap();
    check_gpus(
        Some(&world.policy),
        &shape(count),
        gpus.len(),
        &[crate::gpu::GpuAppraisal {
            verifier: crate::gpu::GpuVerifierKind::Local,
            gpus: verdict.gpus,
            token_sha256: verdict.token_sha256,
        }],
        &NONCE,
    )
    .map(|c| c.gpus)
    .map_err(|e| (e.code().into(), e.to_string()))
}

#[test]
fn eight_production_b300s_pass_with_versions_from_their_rims() {
    let world = World::new(8);
    let gpus = world.evidence();
    let verdict = world.appraise(&gpus).unwrap();
    assert_eq!(verdict.gpus.len(), 8);
    for (i, gpu) in verdict.gpus.iter().enumerate() {
        assert_eq!(gpu.index, u32::try_from(i).unwrap());
        assert_eq!(gpu.model, "B300");
        assert_eq!(gpu.driver_version, DRIVER);
        assert_eq!(gpu.vbios_version, VBIOS);
        assert!(gpu.cc_mode);
        assert_eq!(gpu.nonce, NONCE);
    }
    let ids: std::collections::BTreeSet<_> = verdict.gpus.iter().map(|g| &g.device_id).collect();
    assert_eq!(ids.len(), 8);
    assert_eq!(decide(&world, &gpus).unwrap().len(), 8);
    // The token covers what was appraised: another report gives another digest.
    let other = world.evidence_with(|i| Report {
        nonce: if i == 9 { [0; 32] } else { NONCE },
        ..Report::default()
    });
    assert_ne!(world.appraise(&other).unwrap().token_sha256, [0; 32]);
}

#[test]
fn nothing_passes_until_the_release_pins_every_field() {
    let world = World::new(1);
    let gpus = world.evidence();
    type Clear = fn(&mut World);
    let unset: [(&str, Clear); 7] = [
        ("gpu_policy.local is not set", |w| w.policy.local = None),
        ("device_roots", |w| w.local_policy().device_roots.clear()),
        ("rim_roots", |w| w.local_policy().rim_roots.clear()),
        ("rims", |w| w.local_policy().rims.clear()),
        ("fwids", |w| w.local_policy().fwids.clear()),
        ("cc_mode", |w| w.local_policy().cc_mode = None),
        ("ocsp_max_age_secs", |w| {
            w.local_policy().ocsp_max_age_secs = None
        }),
    ];
    for (field, clear) in unset {
        let mut w = World::new(1);
        clear(&mut w);
        let error = w.appraise(&gpus).unwrap_err();
        assert_eq!(error.code(), "attestation_unknown", "{field}: {error}");
        assert!(error.to_string().contains(field), "{field}: {error}");
        assert!(error.to_string().contains("G0"), "{field}: {error}");
        // Refused before the evidence is looked at.
        let garbage = [GpuEvidence {
            arch: "x".into(),
            evidence: vec![],
            certificate: vec![],
        }];
        assert_eq!(
            w.appraise(&garbage).unwrap_err().code(),
            "attestation_unknown"
        );
    }
    let mut w = World::new(1);
    w.local_policy().ocsp_max_age_secs = Some(30 * 24 * 3600);
    expect(&w, &gpus, "ocsp_max_age_secs: is not 1 s to 7 days");
    let mut w = World::new(1);
    w.local_policy().device_roots = vec!["AAAA".into()];
    expect(&w, &gpus, "device_roots");
}

// Finding 1: the firmware's identity is what it measures as, never what it says it is.

#[test]
fn finding_1_a_gpu_that_misreports_its_driver_is_refused() {
    let world = World::new(1);
    let gpus = world.evidence_with(|_| Report {
        driver: "600.10.01".into(),
        ..Report::default()
    });
    expect(
        &world,
        &gpus,
        "reports driver 600.10.01 but measures as 595.58.03",
    );
    let gpus = world.evidence_with(|_| Report {
        vbios: [0x00, 0x99, 0x00, 0x97, 0x0F, 0, 0, 0],
        ..Report::default()
    });
    expect(
        &world,
        &gpus,
        "reports VBIOS 97.00.99.00.0F but measures as 97.00.88.00.0F",
    );
}

#[test]
fn finding_1_rims_are_selected_by_measurement_not_by_the_reported_version() {
    // A newer driver RIM is pinned too. A GPU still measuring as 595.58.03 but claiming the newer
    // version gets the RIM it measures as, and is refused for the claim; versions in the result
    // are always the matched RIM's.
    let mut world = World::new(1);
    let mut newer: Vec<Measurement> = (5..=9).map(|i| (i, true, vec![vec![0xEE; 48]])).collect();
    newer.push((10, false, vec![vec![0; 48]]));
    let newer = rim_document("600.10.01", CHIP, &newer);
    let chain = [
        &world.rim_signer.cert,
        &world.rim_ca.cert,
        &world.rim_root.cert,
    ];
    world
        .rims
        .push(rim_entry("newer", &newer, &world.rim_signer.key, &chain));
    world
        .local_policy()
        .rims
        .insert(digest_key(&newer), "newer".into());
    let gpus = world.evidence();
    assert_eq!(
        world.appraise(&gpus).unwrap().gpus[0].driver_version,
        DRIVER
    );
    let liar = world.evidence_with(|_| Report {
        driver: "600.10.01".into(),
        ..Report::default()
    });
    expect(
        &world,
        &liar,
        "reports driver 600.10.01 but measures as 595.58.03",
    );
    // Minimum versions apply to the measured version (policy_denied, as for NRAS).
    world.policy.min_driver_version = Some("596.0".into());
    let (code, reason) = decide(&world, &gpus).unwrap_err();
    assert_eq!(code, "policy_denied");
    assert!(
        reason.contains("driver version 595.58.03 is below 596.0"),
        "{reason}"
    );
}

#[test]
fn finding_1_measurements_must_match_a_pinned_rim_exactly_once() {
    let world = World::new(1);
    // One driver measurement differs from every pinned RIM.
    let gpus = world.evidence_with(|_| {
        let mut r = Report::default();
        r.blocks.insert(7, vec![0x77; 48]);
        r
    });
    expect(&world, &gpus, "no pinned Driver RIM for GB110");
    // The RIM it matches is in the cache but not pinned by the release.
    let mut w = World::new(1);
    let driver = digest_key(&driver_document());
    w.local_policy().rims.remove(&driver);
    expect(&w, &w.evidence(), "no pinned Driver RIM for GB110");
    // Two pinned driver RIMs of different versions both match: ambiguous.
    let mut w = World::new(1);
    let twin = driver_document().replace(DRIVER, "595.58.04");
    let chain = [&w.rim_signer.cert, &w.rim_ca.cert, &w.rim_root.cert];
    w.rims
        .push(rim_entry("twin", &twin, &w.rim_signer.key, &chain));
    w.local_policy()
        .rims
        .insert(digest_key(&twin), "twin".into());
    expect(
        &w,
        &w.evidence(),
        "match pinned Driver RIMs of several versions",
    );
    // A block neither RIM lists.
    let gpus = world.evidence_with(|_| {
        let mut r = Report::default();
        r.blocks.insert(40, vec![1; 48]);
        r
    });
    expect(&world, &gpus, "measurement 39 is listed by neither RIM");
    // A RIM for another chip never applies.
    let mut w = World::new(1);
    let other = vbios_document().replace(CHIP, "GB100");
    let chain = [&w.rim_signer.cert, &w.rim_ca.cert, &w.rim_root.cert];
    w.rims = vec![
        w.rims[0].clone(),
        rim_entry("gb100", &other, &w.rim_signer.key, &chain),
    ];
    w.local_policy()
        .rims
        .insert(digest_key(&other), "gb100".into());
    expect(&w, &w.evidence(), "no pinned Vbios RIM for GB110");
}

#[test]
fn finding_1_the_certified_fwid_is_appraised() {
    let mut world = World::new(1);
    world.local_policy().fwids = vec![format!("sha384:{}", hex::encode([0xAB; 48]))];
    expect(
        &world,
        &world.evidence(),
        "is not in gpu_policy.local.fwids",
    );
    let world = World::new(1);
    let gpus = world.evidence_with(|_| Report {
        fwid: Some([0x22; 48]),
        ..Report::default()
    });
    expect(
        &world,
        &gpus,
        "FWID is not the one its certificate certifies",
    );
    let gpus = world.evidence_with(|_| Report {
        fwid: None,
        ..Report::default()
    });
    expect(
        &world,
        &gpus,
        "FWID is not the one its certificate certifies",
    );
}

// Finding 2: a GPU not in production CC mode never passes.

#[test]
fn finding_2_a_devtools_gpu_is_not_in_cc_mode() {
    let world = World::new(8);
    let gpus = world.evidence_with(|i| {
        let mut r = Report::default();
        if i == 5 {
            r.blocks.insert(CC_BLOCK, CC_DEVTOOLS.to_vec());
        }
        r
    });
    let verdict = world.appraise(&gpus).unwrap();
    assert!(!verdict.gpus[5].cc_mode);
    assert!(verdict.gpus[4].cc_mode);
    let (code, reason) = decide(&world, &gpus).unwrap_err();
    assert_eq!(code, "policy_denied");
    assert!(reason.contains("gpu 5: not in CC mode"), "{reason}");
    // CC off: the indicator holds anything else, or is missing.
    let off = world.evidence_with(|_| {
        let mut r = Report::default();
        r.blocks.insert(CC_BLOCK, vec![0; 48]);
        r
    });
    assert_eq!(decide(&world, &off).unwrap_err().0, "policy_denied");
    let missing = world.evidence_with(|_| {
        let mut r = Report::default();
        r.blocks.remove(&CC_BLOCK);
        r
    });
    expect(&world, &missing, "CC-mode measurement 11 is missing");
}

#[test]
fn finding_2_an_opaque_indicator_works_the_same_way() {
    let mut world = World::new(1);
    let rule = world.local_policy().cc_mode.as_mut().unwrap();
    rule.source = CcSource::Opaque;
    rule.index = super::opaque::NVDEC0_STATUS;
    rule.values = vec!["55".into()];
    assert!(world.appraise(&world.evidence()).unwrap().gpus[0].cc_mode);
    let rule = world.local_policy().cc_mode.as_mut().unwrap();
    rule.values = vec!["aa".into()];
    assert!(!world.appraise(&world.evidence()).unwrap().gpus[0].cc_mode);
}

#[test]
fn finding_2_signed_debug_state_and_ppcie_are_not_cc_mode() {
    // DICE OperationalFlags: debug is bit 3, notSecure bit 1, recovery bit 2.
    for (flag, flags) in [
        ("debug", [0x90u8, 0, 0, 1]),
        ("notSecure", [0xC0, 0, 0, 1]),
        ("recovery", [0xA0, 0, 0, 1]),
    ] {
        let mut world = World::new(1);
        world.reissue_leaf(0, FWID, &flags);
        let verdict = world.appraise(&world.evidence()).unwrap();
        assert!(!verdict.gpus[0].cc_mode, "{flag}");
    }
    let world = World::new(1);
    let ppcie = world.evidence_with(|_| Report {
        feature_flag: Some(2),
        ..Report::default()
    });
    assert!(!world.appraise(&ppcie).unwrap().gpus[0].cc_mode);
    let spt = world.evidence_with(|_| Report {
        feature_flag: Some(1),
        ..Report::default()
    });
    assert!(world.appraise(&spt).unwrap().gpus[0].cc_mode);
}

#[test]
fn finding_2_a_debug_rim_in_the_cache_is_never_a_candidate() {
    // A devtools GPU measures one driver block differently, and a RIM for that build sits in the
    // cache, validly signed by NVIDIA. Only pinned RIMs count, so it is refused.
    let mut world = World::new(1);
    let mut debug: Vec<Measurement> = (5..=9).map(|i| (i, true, vec![golden(i)])).collect();
    debug[0] = (5, true, vec![vec![0xDE; 48]]);
    debug.push((10, false, vec![vec![0; 48]]));
    let debug = rim_document(DRIVER, CHIP, &debug);
    let chain = [
        &world.rim_signer.cert,
        &world.rim_ca.cert,
        &world.rim_root.cert,
    ];
    world
        .rims
        .push(rim_entry("debug", &debug, &world.rim_signer.key, &chain));
    let gpus = world.evidence_with(|_| {
        let mut r = Report::default();
        r.blocks.insert(6, vec![0xDE; 48]);
        r
    });
    expect(&world, &gpus, "no pinned Driver RIM for GB110");
}

// Finding 3: Blackwell evidence is what is appraised; other formats are refused by name.

#[test]
fn finding_3_other_architectures_and_formats_are_refused_by_name() {
    let world = World::new(1);
    let mut gpus = world.evidence();
    gpus[0].arch = "HOPPER".into();
    expect(&world, &gpus, "only BLACKWELL is appraised");
    // A leaf with Hopper's FWID extension instead of TcbInfo.
    let mut w = World::new(1);
    let g = &mut w.gpus[0];
    g.leaf.cert = issue(
        "GH100 A01 GSP FMC LF",
        &[0x53, 1],
        &g.leaf.key,
        Some(&g.brom),
        vec![ext("2.23.133.5.4.1", false, vec![0x30, 0x00])],
    );
    expect(&w, &w.evidence(), "Hopper-format FWID");
    // NVDAOD-format opaque data and SPDM 1.2 are covered by the parsers' own tests.
}

// The rest of the chain of trust.

#[test]
fn revocation_and_freshness_fail_closed() {
    let mut world = World::new(1);
    let brom = ocsp_response(
        &world.gpus[0].brom.cert,
        &world.ica,
        revoked(None),
        60,
        None,
    );
    world.ocsp.push(brom);
    expect(&world, &world.evidence(), "is revoked");

    let mut world = World::new(1);
    world.ocsp.retain(|r| {
        !super::ocsp::parse(r)
            .unwrap()
            .is_about(&world.gpus[0].brom.cert, &world.ica.cert)
    });
    expect(
        &world,
        &world.evidence(),
        "no status for certificate \"GB110 A01 GSP BROM\"",
    );
    world.ocsp.push(ocsp_response(
        &world.gpus[0].brom.cert,
        &world.ica,
        super::testkit::good(),
        3 * 86_400,
        None,
    ));
    expect(&world, &world.evidence(), "more than the policy's");

    // The RIM signer revoked: no RIM is usable, and the refusal says why.
    let mut world = World::new(1);
    world.ocsp.push(ocsp_response(
        &world.rim_signer.cert,
        &world.rim_ca,
        revoked(None),
        60,
        None,
    ));
    expect(
        &world,
        &world.evidence(),
        "not usable: NV_GPU_CC_DRIVER_GB110_595.58.03: ocsp:",
    );

    // On hold: refused unless the release accepts holds.
    let mut world = World::new(1);
    let hold = Some(x509_cert::ext::pkix::CrlReason::CertificateHold);
    world.ocsp.push(ocsp_response(
        &world.rim_signer.cert,
        &world.rim_ca,
        revoked(hold),
        60,
        None,
    ));
    expect(&world, &world.evidence(), "CertificateHold");
    world.local_policy().accept_certificate_hold = true;
    assert!(world.appraise(&world.evidence()).is_ok());
}

#[test]
fn the_report_must_be_signed_by_the_certified_device_over_this_nonce() {
    let world = World::new(2);
    let mut gpus = world.evidence();
    gpus[1].certificate = world.chain(0);
    expect(
        &world,
        &gpus,
        "GPU-1: spdm: the report's signature does not verify",
    );
    let stale = world.evidence_with(|_| Report {
        nonce: [1; 32],
        ..Report::default()
    });
    expect(&world, &stale, "report is not over this nonce");
    let mut wrong_root = World::new(1);
    let other = ca("Other Root", 99, None);
    wrong_root.local_policy().device_roots = vec![{
        use base64::Engine;
        use der::Encode;
        base64::prelude::BASE64_STANDARD.encode(other.cert.to_der().unwrap())
    }];
    expect(
        &wrong_root,
        &wrong_root.evidence(),
        "not a root the gpu_policy pins",
    );
    let mut no_model = World::new(1);
    no_model.policy.hwmodels = BTreeMap::new();
    expect(
        &no_model,
        &no_model.evidence(),
        "hwmodel \"GB110 A01 GSP BROM\" is not in gpu_policy.hwmodels",
    );
    let nvdec = world.evidence_with(|_| Report {
        nvdec: 0,
        ..Report::default()
    });
    expect(&world, &nvdec, "NVDEC0 status 0x00");
}

#[test]
fn eight_copies_of_one_gpu_do_not_pass_for_eight() {
    let world = World::new(8);
    let one = world.evidence();
    let copies: Vec<_> = (0..8).map(|_| one[0].clone()).collect();
    let (code, reason) = decide(&world, &copies).unwrap_err();
    assert_eq!(code, "attestation_failed");
    assert!(
        reason.contains("is reported for another GPU of this pod too"),
        "{reason}"
    );
}

#[test]
fn rim_cache_files_round_trip_and_refuse_garbage() {
    use base64::Engine;
    use base64::prelude::BASE64_STANDARD as B;
    use der::Encode;
    let world = World::new(1);
    let file = serde_json::json!({
        "format": super::cache::FORMAT,
        "rims": world.rims.iter().map(|r| serde_json::json!({
            "id": r.id,
            "signed_info": B.encode(&r.signed_info),
            "document": B.encode(&r.document),
            "signature": B.encode(&r.signature),
            "certificates": r.certificates.iter().map(|c| B.encode(c.to_der().unwrap())).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "ocsp": world.ocsp.iter().map(|o| B.encode(o)).collect::<Vec<_>>(),
    });
    let cache = super::cache::RimCache::from_json(file.to_string().as_bytes()).unwrap();
    assert_eq!(cache.rims.len(), 2);
    let verdict =
        super::appraise::appraise(&world.evidence(), &NONCE, &world.policy, &cache, &[], now());
    assert!(verdict.is_ok());
    for bad in [
        serde_json::json!({"format": "other"}),
        serde_json::json!({"format": super::cache::FORMAT, "extra": 1}),
        serde_json::json!({"format": super::cache::FORMAT, "ocsp": ["!!"]}),
    ] {
        assert!(super::cache::RimCache::from_json(bad.to_string().as_bytes()).is_err());
    }
}

#[tokio::test]
async fn the_backend_refuses_before_any_work_and_queries_only_the_pinned_ocsp_endpoint() {
    let mut world = World::new(1);
    // Nothing pinned: refused without touching the cache or the network.
    let backend = super::Local::new(Default::default())
        .unwrap()
        .with_clock(now);
    let mut none = world.policy.clone();
    none.local = None;
    let error = backend
        .verify(&world.evidence(), &NONCE, &none)
        .await
        .unwrap_err();
    assert_eq!(error.code(), "attestation_unknown");

    // http:// ocsp_url is rejected at policy-parse time (HTTPS closes an observation channel).
    {
        let mut w = World::new(1);
        w.local_policy().ocsp_url = Some("http://ocsp.example.com/".into());
        let backend = super::Local::new(w.cache()).unwrap().with_clock(now);
        let err = backend
            .verify(&w.evidence(), &NONCE, &w.policy)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("is not an https"),
            "http:// should be rejected: {err}"
        );
    }

    // With all OCSP responses in the cache and an https:// URL, the backend passes without
    // making any network calls.
    {
        world.local_policy().ocsp_url = Some("https://ocsp.example.com/".into());
        let backend = super::Local::new(world.cache()).unwrap().with_clock(now);
        let verdict = backend
            .verify(&world.evidence(), &NONCE, &world.policy)
            .await
            .unwrap();
        assert!(verdict.gpus[0].cc_mode);
    }
}

#[test]
fn test_certificates_parse_like_nvidias() {
    let world = World::new(1);
    let leaf = roundtrip(&world.gpus[0].leaf.cert);
    let tcb = super::cert::tcb_info(&leaf).unwrap();
    assert_eq!(tcb.fwid, FWID);
    assert_eq!(tcb.model.as_deref(), Some("GB110 A01 GSP"));
}
