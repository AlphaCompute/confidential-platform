#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::fs;
use std::path::PathBuf;
use std::time::{Duration, UNIX_EPOCH};

use alpha_attest::{
    Collateral, InitDataMismatch, Policy, VerifiedQuote, check_init_data, verify_quote,
};
use alpha_core::InitData;

fn read(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/attest/b300-kata-4.0.0")
        .join(name);
    fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn verify(quote: &str) -> VerifiedQuote {
    let collateral: Collateral = serde_json::from_slice(&read("collateral.json")).unwrap();
    let captured_at = String::from_utf8(read("captured_at.txt")).unwrap();
    let now = UNIX_EPOCH
        + Duration::from_secs(
            chrono::DateTime::parse_from_rfc3339(captured_at.trim())
                .unwrap()
                .timestamp() as u64,
        );
    let policy = Policy {
        tcb_statuses: vec!["UpToDate".into()],
        tolerated_advisories: vec![],
    };
    verify_quote(&read(quote), &collateral, &policy, now).unwrap()
}

fn t1() -> String {
    String::from_utf8(read("t1-sha256.toml")).unwrap()
}

#[test]
fn quote_binds_the_init_data_it_booted_with() {
    let init_data = InitData::parse(t1()).unwrap();
    check_init_data(&verify("p1-sha256.quote.bin"), &init_data).unwrap();
}

#[test]
fn quote_refuses_init_data_one_byte_off() {
    let toml = t1().replace("probe A", "probe B");
    assert_eq!(toml.len(), t1().len());
    let init_data = InitData::parse(toml).unwrap();
    assert!(matches!(
        check_init_data(&verify("p1-sha256.quote.bin"), &init_data),
        Err(InitDataMismatch::Different)
    ));
}

#[test]
fn quote_of_a_pod_without_init_data_is_refused() {
    let quote = verify("p0-none.quote.bin");
    assert_eq!(quote.mr_config_id, [0; 48]);
    let init_data = InitData::parse(t1()).unwrap();
    assert!(matches!(
        check_init_data(&quote, &init_data),
        Err(InitDataMismatch::Absent)
    ));
}

#[test]
fn zero_tail_of_mr_config_id_is_enforced() {
    let mut quote = verify("p1-sha256.quote.bin");
    quote.mr_config_id[47] ^= 1;
    let init_data = InitData::parse(t1()).unwrap();
    assert!(matches!(
        check_init_data(&quote, &init_data),
        Err(InitDataMismatch::Different)
    ));
}
