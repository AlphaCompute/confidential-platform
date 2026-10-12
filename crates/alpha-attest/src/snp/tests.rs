//! The SNP report checks over the one real report we have (`testdata/attest/snp-virtee-milan`,
//! virtee's Milan report with AMD's chain and CRL), and the policy checks the real report cannot
//! show over synthetic parsed reports.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};

use sev::firmware::guest::{GuestPolicy, PlatformInfo};

use super::kds::{CRL_REFRESH, Kds, KdsClient, KdsFuture, crl_url, vcek_url};
use super::*;

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/attest/snp-virtee-milan")
}

pub(crate) fn report() -> Vec<u8> {
    hex::decode(
        std::fs::read_to_string(dir().join("report.hex"))
            .unwrap()
            .trim(),
    )
    .unwrap()
}

pub(crate) fn vcek() -> Vec<u8> {
    std::fs::read(dir().join("vcek.der")).unwrap()
}

pub(crate) fn crl() -> Vec<u8> {
    std::fs::read(dir().join("crl.der")).unwrap()
}

/// AMD's Milan ASK and ARK, PEM, in KDS's order.
fn ask_ark() -> (String, String) {
    let chain = std::fs::read_to_string(dir().join("cert_chain.pem")).unwrap();
    let end = "-----END CERTIFICATE-----";
    let at = chain.find(end).unwrap() + end.len();
    (
        chain[..at].trim().to_owned() + "\n",
        chain[at..].trim().to_owned() + "\n",
    )
}

/// 2026-10-12T00:00:00Z: inside the CRL's window and every certificate's validity.
pub(crate) fn now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_791_763_200)
}

const MILAN_TCB: SnpTcb = SnpTcb {
    bootloader: 3,
    tee: 0,
    snp: 8,
    microcode: 115,
    fmc: None,
};

/// A `snp_policy` pinning AMD's Milan certificates, at the report's own TCB, allowing the SMT the
/// virtee host ran with.
pub(crate) fn policy() -> SnpPolicy {
    let (ask, ark) = ask_ark();
    SnpPolicy {
        products: BTreeMap::from([(
            "Milan".to_owned(),
            SnpProduct {
                ark_pem: ark,
                ask_pem: ask,
                asvk_pem: None,
                min_tcb: MILAN_TCB,
            },
        )]),
        allow_smt: true,
        allow_migration_agent: false,
        vmpl: 0,
        kds_url: Some("https://kds.example".into()),
    }
}

fn collateral() -> SnpCollateral {
    SnpCollateral {
        vek: vcek(),
        crl: crl(),
    }
}

fn refused(result: Result<VerifiedReport, AppraisalError>, code: &str, reason: &str) {
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
fn the_virtee_milan_report_verifies_through_the_pinned_amd_chain() {
    let report = report();
    let verified = verify_report(&report, &collateral(), &policy(), now()).unwrap();
    assert_eq!(verified.report_data.as_slice(), &report[0x50..0x90]);
    assert_eq!(verified.measurement.0.as_slice(), &report[0x90..0xC0]);
    assert_eq!(verified.host_data, [0; 32]);
    assert_eq!(
        verified.findings,
        SnpFindings {
            product: "Milan".into(),
            signing_key: VekKind::Vcek,
            measurement: verified.measurement,
            host_data: [0; 32],
            reported_tcb: MILAN_TCB,
            guest_policy: "0x30000".into(),
            vmpl: 0,
        }
    );
    // The result records the measurement as the reference values write it.
    let json = serde_json::to_value(&verified.findings).unwrap();
    assert_eq!(
        json["measurement"],
        "sha384:7a1e5c266c0108dbc9bb94fa926951320940915d0aafb42464bd88b579ea158d3e1a0dc39b2c60bd95b9c480cd81841f"
    );
    assert_eq!(json["signing_key"], "vcek");
}

#[test]
fn a_changed_report_byte_is_refused() {
    let mut report = report();
    // report_data: still parses, no longer verifies.
    report[0x50] ^= 1;
    refused(
        verify_report(&report, &collateral(), &policy(), now()),
        "attestation_failed",
        "signature does not verify under the vcek",
    );
    // A reserved byte: refused by the parser, before the signature.
    let mut report = self::report();
    report[0x1F8] = 1;
    refused(
        verify_report(&report, &collateral(), &policy(), now()),
        "attestation_failed",
        "does not parse",
    );
    // The signature's unused high bytes.
    let mut report = self::report();
    report[0x2A0 + 60] = 1;
    refused(
        verify_report(&report, &collateral(), &policy(), now()),
        "attestation_failed",
        "not a P-384 signature",
    );
    refused(
        verify_report(&self::report()[..1000], &collateral(), &policy(), now()),
        "attestation_failed",
        "not 1184",
    );
}

#[test]
fn only_the_pinned_amd_chain_verifies() {
    let (ask, ark) = ask_ark();
    // An ARK that is not AMD's Milan root: here the ASK, which is not self-signed.
    let mut other_root = policy();
    other_root.products.get_mut("Milan").unwrap().ark_pem = ask;
    refused(
        verify_report(&report(), &collateral(), &other_root, now()),
        "attestation_failed",
        "pinned AMD chain does not verify",
    );
    // An intermediate that did not sign the VCEK: the ARK pinned in its place.
    let mut other_ask = policy();
    other_ask.products.get_mut("Milan").unwrap().ask_pem = ark;
    refused(
        verify_report(&report(), &collateral(), &other_ask, now()),
        "attestation_failed",
        "the vcek is not signed by the pinned ASK",
    );
    // Another product's certificates only.
    let mut genoa = policy();
    let milan = genoa.products.remove("Milan").unwrap();
    genoa.products.insert("Genoa".into(), milan);
    refused(
        verify_report(&report(), &collateral(), &genoa, now()),
        "attestation_unknown",
        "pins no AMD certificates for product Milan",
    );
    // The VCEK is not a certificate.
    let bad = SnpCollateral {
        vek: b"not der".to_vec(),
        crl: crl(),
    };
    refused(
        verify_report(&report(), &bad, &policy(), now()),
        "attestation_failed",
        "vcek: not a certificate",
    );
}

#[test]
fn amd_crl_must_verify_under_the_pinned_ark_and_be_current() {
    let mut tampered = crl();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    let collateral = SnpCollateral {
        vek: vcek(),
        crl: tampered,
    };
    refused(
        verify_report(&report(), &collateral, &policy(), now()),
        "attestation_failed",
        "not signed by the pinned ARK",
    );
    // thisUpdate is 2026-09-22T07:35:42Z, nextUpdate 2026-11-09T01:00:00Z.
    let before = UNIX_EPOCH + Duration::from_secs(1_790_000_000);
    let after = UNIX_EPOCH + Duration::from_secs(1_794_200_000);
    for at in [before, after] {
        refused(
            verify_report(&report(), &self::collateral(), &policy(), at),
            "attestation_failed",
            "AMD CRL is not current",
        );
    }
    refused(
        verify_report(
            &report(),
            &SnpCollateral {
                vek: vcek(),
                crl: b"no crl".to_vec(),
            },
            &policy(),
            now(),
        ),
        "attestation_failed",
        "AMD CRL does not parse",
    );
}

#[test]
fn an_expired_vcek_is_refused() {
    // The VCEK runs to 2030-04-03T19:23:43Z.
    let later = UNIX_EPOCH + Duration::from_secs(1_920_000_000);
    refused(
        verify_report(&report(), &collateral(), &policy(), later),
        "attestation_failed",
        "vcek certificate is not valid now",
    );
}

#[test]
fn policy_refuses_smt_and_a_tcb_below_the_minimum_on_the_real_report() {
    let mut no_smt = policy();
    no_smt.allow_smt = false;
    refused(
        verify_report(&report(), &collateral(), &no_smt, now()),
        "policy_denied",
        "SMT enabled",
    );
    for min in [
        SnpTcb {
            microcode: 116,
            ..MILAN_TCB
        },
        SnpTcb {
            snp: 9,
            ..MILAN_TCB
        },
        SnpTcb {
            bootloader: 4,
            ..MILAN_TCB
        },
        SnpTcb {
            tee: 1,
            ..MILAN_TCB
        },
    ] {
        let mut higher = policy();
        higher.products.get_mut("Milan").unwrap().min_tcb = min;
        refused(
            verify_report(&report(), &collateral(), &higher, now()),
            "policy_denied",
            "below the minimum",
        );
    }
    let mut vmpl = policy();
    vmpl.vmpl = 1;
    refused(
        verify_report(&report(), &collateral(), &vmpl, now()),
        "policy_denied",
        "VMPL 0, not 1",
    );
}

#[test]
fn guest_policy_debug_and_migration_agent_are_refused() {
    let policy = policy();
    let base = AttestationReport {
        policy: GuestPolicy::from(0x30000),
        ..Default::default()
    };
    assert!(check_policy(&policy, &base, &MILAN_TCB, &MILAN_TCB).is_ok());
    for (bits, reason) in [
        (1u64 << 19, "allows debugging"),
        (1u64 << 18, "migration agent"),
    ] {
        let report = AttestationReport {
            policy: GuestPolicy::from(0x30000 | bits),
            ..base
        };
        let error = check_policy(&policy, &report, &MILAN_TCB, &MILAN_TCB).unwrap_err();
        assert_eq!(error.code(), "policy_denied");
        assert!(error.to_string().contains(reason), "{error}");
    }
    let mut ma = policy.clone();
    ma.allow_migration_agent = true;
    let report = AttestationReport {
        policy: GuestPolicy::from(0x30000 | 1 << 18),
        plat_info: PlatformInfo::from(1),
        ..base
    };
    assert!(check_policy(&ma, &report, &MILAN_TCB, &MILAN_TCB).is_ok());
}

#[test]
fn tcb_comparison_is_per_component_and_fmc_needs_one() {
    assert!(MILAN_TCB.at_least(&MILAN_TCB));
    let lower = SnpTcb {
        microcode: 100,
        ..MILAN_TCB
    };
    assert!(MILAN_TCB.at_least(&lower));
    assert!(!lower.at_least(&MILAN_TCB));
    let fmc = SnpTcb {
        fmc: Some(1),
        ..MILAN_TCB
    };
    assert!(!MILAN_TCB.at_least(&fmc));
    assert!(fmc.at_least(&MILAN_TCB));
}

#[test]
fn the_vcek_certifies_its_chip_and_tcb() {
    let vek = Certificate::from_der(&vcek()).unwrap();
    assert_eq!(vek_tcb(&vek).unwrap(), MILAN_TCB);
    assert_eq!(product_name(&vek).unwrap().as_deref(), Some("Milan"));
    let report = AttestationReport::from_bytes(&report()).unwrap();
    assert!(check_hwid(&vek, &report.chip_id, "Milan").is_ok());
    let mut other = report.chip_id;
    other[63] ^= 1;
    let error = check_hwid(&vek, &other, "Milan").unwrap_err();
    assert!(error.to_string().contains("another chip"), "{error}");
}

#[test]
fn the_header_names_the_key_and_tcb_before_any_check() {
    let header = header(&report()).unwrap();
    assert_eq!(header.signing_key, VekKind::Vcek);
    // A version 2 report has no CPUID fields.
    assert_eq!(header.product, None);
    assert_eq!(header.reported_tcb, MILAN_TCB);
}

#[test]
fn policy_round_trips_and_refuses_unknown_fields() {
    let policy = policy();
    let json = serde_json::to_value(&policy).unwrap();
    assert_eq!(
        serde_json::from_value::<SnpPolicy>(json.clone()).unwrap(),
        policy
    );
    let mut extra = json.clone();
    extra["allow_debug"] = serde_json::json!(true);
    assert!(serde_json::from_value::<SnpPolicy>(extra).is_err());
    let mut tcb = json;
    tcb["products"]["Milan"]["min_tcb"]["svn"] = serde_json::json!(1);
    assert!(serde_json::from_value::<SnpPolicy>(tcb).is_err());
}

/// KDS standing in: fixed bodies by URL, counting calls, failing on demand.
#[derive(Default)]
pub(crate) struct FakeKds {
    pub bodies: Mutex<BTreeMap<String, Vec<u8>>>,
    pub calls: AtomicUsize,
}

impl KdsClient for FakeKds {
    fn get<'a>(&'a self, url: &'a str) -> KdsFuture<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let body = self.bodies.lock().unwrap().get(url).cloned();
        Box::pin(async move {
            body.ok_or_else(|| AppraisalError::Failed(format!("kds {url}: status 404")))
        })
    }
}

#[test]
fn kds_urls_follow_amds_specification() {
    let chip = [0xab; 64];
    assert_eq!(
        vcek_url("https://kds.example/", "Milan", &chip, &MILAN_TCB),
        format!(
            "https://kds.example/vcek/v1/Milan/{}?blSPL=03&teeSPL=00&snpSPL=08&ucodeSPL=115",
            "ab".repeat(64)
        )
    );
    let turin = SnpTcb {
        fmc: Some(1),
        ..MILAN_TCB
    };
    assert_eq!(
        vcek_url("https://kds.example", "Turin", &chip, &turin),
        format!(
            "https://kds.example/vcek/v1/Turin/{}?blSPL=03&teeSPL=00&snpSPL=08&ucodeSPL=115&fmcSPL=01",
            "ab".repeat(8)
        )
    );
    assert_eq!(
        crl_url("https://kds.example", "Genoa", VekKind::Vlek),
        "https://kds.example/vlek/v1/Genoa/crl"
    );
}

#[tokio::test]
async fn kds_serves_the_crl_cached_and_the_evidences_vcek_is_used() {
    let fake = Arc::new(FakeKds::default());
    let url = crl_url("https://kds.example", "Milan", VekKind::Vcek);
    fake.bodies.lock().unwrap().insert(url.clone(), crl());
    let kds = Kds::new(fake.clone());
    let vcek = vcek();

    let got = kds
        .collateral(&report(), Some(&vcek), &policy(), now())
        .await
        .unwrap();
    assert_eq!(got, collateral());
    assert!(verify_report(&report(), &got, &policy(), now()).is_ok());
    assert_eq!(fake.calls.load(Ordering::SeqCst), 1);

    // Cached within CRL_REFRESH; fetched again after it.
    kds.collateral(&report(), Some(&vcek), &policy(), now())
        .await
        .unwrap();
    assert_eq!(fake.calls.load(Ordering::SeqCst), 1);
    let later = now() + CRL_REFRESH;
    kds.collateral(&report(), Some(&vcek), &policy(), later)
        .await
        .unwrap();
    assert_eq!(fake.calls.load(Ordering::SeqCst), 2);

    // KDS down: the cached CRL still serves, and verify_report decides whether it is current.
    fake.bodies.lock().unwrap().clear();
    let much_later = later + CRL_REFRESH * 24 * 40;
    let stale = kds
        .collateral(&report(), Some(&vcek), &policy(), much_later)
        .await
        .unwrap();
    assert_eq!(stale.crl, crl());
    refused(
        verify_report(&report(), &stale, &policy(), much_later),
        "attestation_failed",
        "AMD CRL is not current",
    );

    // Nothing cached and KDS down: refused.
    let empty = Kds::new(fake.clone());
    let error = empty
        .collateral(&report(), Some(&vcek), &policy(), now())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("404"), "{error}");
}

#[tokio::test]
async fn without_kds_or_a_vcek_snp_collateral_is_refused() {
    let kds = Kds::new(Arc::new(FakeKds::default()));
    let mut no_kds = policy();
    no_kds.kds_url = None;
    let vcek = vcek();
    let error = kds
        .collateral(&report(), Some(&vcek), &no_kds, now())
        .await
        .unwrap_err();
    assert_eq!(error.code(), "attestation_unknown");
    assert!(error.to_string().contains("no kds_url"), "{error}");
    // A version 2 report does not say which product's KDS to ask.
    let error = kds
        .collateral(&report(), None, &policy(), now())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("must carry its VCEK"), "{error}");
}
