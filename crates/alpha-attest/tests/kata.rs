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
    AppraisalError, Collateral, InitDataMismatch, KataAppraised, PlatformDocument, VerifiedQuote,
    appraise_kata, check_init_data, verify_quote,
};
use alpha_core::{ComposeHash, InitData};
use serde_json::Value;

fn read(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/attest/b300-kata-4.0.0")
        .join(name);
    fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn collateral() -> Collateral {
    serde_json::from_slice(&read("collateral.json")).unwrap()
}

fn now() -> SystemTime {
    let captured_at = String::from_utf8(read("captured_at.txt")).unwrap();
    UNIX_EPOCH
        + Duration::from_secs(
            chrono::DateTime::parse_from_rfc3339(captured_at.trim())
                .unwrap()
                .timestamp() as u64,
        )
}

fn doc_json() -> Value {
    serde_json::from_slice(&read("platform-document.json")).unwrap()
}

fn doc() -> PlatformDocument {
    serde_json::from_value(doc_json()).unwrap()
}

fn verify(quote: &str) -> VerifiedQuote {
    verify_quote(&read(quote), &collateral(), &doc().policy, now()).unwrap()
}

fn t1() -> String {
    String::from_utf8(read("t1-sha256.toml")).unwrap()
}

fn t1_digest() -> ComposeHash {
    InitData::parse(t1()).unwrap().digest()
}

fn appraise(
    quote: &str,
    init_data: &ComposeHash,
    doc: &PlatformDocument,
) -> Result<KataAppraised, AppraisalError> {
    let report_data = verify(quote).report_data;
    appraise_kata(
        &read(quote),
        &report_data,
        init_data,
        doc,
        &collateral(),
        now(),
    )
}

fn refused(result: Result<KataAppraised, AppraisalError>, code: &str, fragment: &str) {
    let err = result.unwrap_err();
    assert_eq!(err.code(), code, "{err}");
    assert!(err.to_string().contains(fragment), "{err}");
}

#[test]
fn quote_binds_the_init_data_it_booted_with() {
    check_init_data(&verify("p1-sha256.quote.bin"), &t1_digest()).unwrap();
}

#[test]
fn quote_refuses_init_data_one_byte_off() {
    let toml = t1().replace("probe A", "probe B");
    assert_eq!(toml.len(), t1().len());
    let digest = InitData::parse(toml).unwrap().digest();
    assert!(matches!(
        check_init_data(&verify("p1-sha256.quote.bin"), &digest),
        Err(InitDataMismatch::Different)
    ));
}

#[test]
fn quote_of_a_pod_without_init_data_is_refused() {
    let quote = verify("p0-none.quote.bin");
    assert_eq!(quote.mr_config_id, [0; 48]);
    assert!(matches!(
        check_init_data(&quote, &t1_digest()),
        Err(InitDataMismatch::Absent)
    ));
}

#[test]
fn zero_tail_of_mr_config_id_is_enforced() {
    let mut quote = verify("p1-sha256.quote.bin");
    quote.mr_config_id[47] ^= 1;
    assert!(matches!(
        check_init_data(&quote, &t1_digest()),
        Err(InitDataMismatch::Different)
    ));
}

#[test]
fn cpu_pod_is_appraised_as_the_cpu_class() {
    let appraised = appraise("p1-sha256.quote.bin", &t1_digest(), &doc()).unwrap();
    assert_eq!(appraised.runtime_class, "kata-qemu-tdx");
    assert_eq!(appraised.quote.tcb_status, "UpToDate");
}

#[test]
fn debug_console_on_the_kernel_cmdline_is_refused() {
    refused(
        appraise("r10-debug-console.quote.bin", &t1_digest(), &doc()),
        "attestation_unknown",
        "no kata runtime class",
    );
}

#[test]
fn pod_shape_not_offered_is_refused() {
    refused(
        appraise("r14-2c-4096.quote.bin", &t1_digest(), &doc()),
        "attestation_unknown",
        "no kata runtime class",
    );
}

#[test]
fn class_with_another_mrtd_is_refused() {
    let mut json = doc_json();
    for class in json["kata_reference_values"].as_array_mut().unwrap() {
        class["mrtd"] = format!("sha384:{}", "ab".repeat(48)).into();
    }
    let doc: PlatformDocument = serde_json::from_value(json).unwrap();
    refused(
        appraise("p1-sha256.quote.bin", &t1_digest(), &doc),
        "attestation_unknown",
        "no kata runtime class",
    );
}

#[test]
fn zero_mr_config_id_is_refused_even_when_its_shape_is_listed() {
    let rtmr0 = verify("p0-none.quote.bin").measured.rtmr0;
    let mut json = doc_json();
    json["kata_reference_values"][0]["rtmr0"]
        .as_array_mut()
        .unwrap()
        .push(rtmr0.to_string().into());
    let doc: PlatformDocument = serde_json::from_value(json).unwrap();
    refused(
        appraise("p0-none.quote.bin", &t1_digest(), &doc),
        "attestation_failed",
        "MRCONFIGID is zero",
    );
}

#[test]
fn gpu_pod_against_cpu_only_reference_values_is_refused() {
    let mut json = doc_json();
    json["kata_reference_values"]
        .as_array_mut()
        .unwrap()
        .retain(|class| class["runtime_class"] == "kata-qemu-tdx");
    let cpu_only: PlatformDocument = serde_json::from_value(json).unwrap();
    refused(
        appraise("g1b-gpu.quote.bin", &t1_digest(), &cpu_only),
        "attestation_unknown",
        "no kata runtime class",
    );
    // With the GPU class listed the quote gets past class matching and stops only at its own
    // init-data, which is not this Revision's.
    refused(
        appraise("g1b-gpu.quote.bin", &t1_digest(), &doc()),
        "attestation_failed",
        "not the digest of this init-data",
    );
}

#[test]
fn a_quote_over_other_report_data_is_refused() {
    let doc = doc();
    let mut other = verify("p1-sha256.quote.bin").report_data;
    other[0] ^= 1;
    refused(
        appraise_kata(
            &read("p1-sha256.quote.bin"),
            &other,
            &t1_digest(),
            &doc,
            &collateral(),
            now(),
        ),
        "attestation_failed",
        "report_data",
    );
}
