#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::collections::BTreeMap;

const VECTORS: &[(&str, &[u8])] = &[
    (
        "01-compose-body.json",
        include_bytes!("../../../testdata/jcs/01-compose-body.json"),
    ),
    (
        "02-nested.json",
        include_bytes!("../../../testdata/jcs/02-nested.json"),
    ),
    (
        "03-numbers.json",
        include_bytes!("../../../testdata/jcs/03-numbers.json"),
    ),
    (
        "04-duplicate-key.json",
        include_bytes!("../../../testdata/jcs/04-duplicate-key.json"),
    ),
    (
        "05-escaped-duplicate.json",
        include_bytes!("../../../testdata/jcs/05-escaped-duplicate.json"),
    ),
    (
        "06-nested-duplicate.json",
        include_bytes!("../../../testdata/jcs/06-nested-duplicate.json"),
    ),
    (
        "07-lone-surrogate.json",
        include_bytes!("../../../testdata/jcs/07-lone-surrogate.json"),
    ),
    (
        "08-empty-object.json",
        include_bytes!("../../../testdata/jcs/08-empty-object.json"),
    ),
    (
        "09-empty.json",
        include_bytes!("../../../testdata/jcs/09-empty.json"),
    ),
];

const EXPECTED: &str = include_str!("../../../testdata/jcs/expected.json");

fn digest(bytes: &[u8]) -> String {
    alpha_core::parse(bytes)
        .and_then(|value| alpha_core::jcs(&value))
        .map_or_else(
            |_| "refused".to_owned(),
            |c| alpha_channel::sha256_label(&c),
        )
}

#[wasm_bindgen_test::wasm_bindgen_test(unsupported = test)]
fn every_canonical_json_vector_gives_its_recorded_digest() {
    let expected: BTreeMap<String, String> = serde_json::from_str(EXPECTED).unwrap();
    let computed: BTreeMap<String, String> = VECTORS
        .iter()
        .map(|(name, bytes)| ((*name).to_owned(), digest(bytes)))
        .collect();
    assert_eq!(computed, expected);
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn every_file_in_the_vector_directory_is_listed() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/jcs");
    let mut on_disk: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name != "expected.json")
        .collect();
    on_disk.sort();
    let listed: Vec<String> = VECTORS.iter().map(|(name, _)| (*name).to_owned()).collect();
    assert_eq!(on_disk, listed);
}
