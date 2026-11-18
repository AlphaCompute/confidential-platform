#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::collections::BTreeMap;

use alpha_core::catalog::{CatalogFile, render};
use alpha_core::{AppId, CatalogKey};
use serde_json::Value;

macro_rules! v {
    ($n:literal) => {
        (
            $n,
            include_bytes!(concat!("../../../testdata/catalog/", $n)),
        )
    };
}

const FILES: &[(&str, &[u8])] = &[
    v!("signed-by-other-key.json"),
    v!("substitutions-miscounted.json"),
    v!("template-tampered.json"),
    v!("valid.json"),
];

const EXPECTED: &str = include_str!("../../../testdata/catalog/expected.json");
const INIT_DATA: &str = include_str!("../../../testdata/catalog/init-data.toml");

#[wasm_bindgen_test::wasm_bindgen_test(unsupported = test)]
fn every_catalog_vector_gives_its_recorded_verdict() {
    let expected: Value = serde_json::from_str(EXPECTED).unwrap();
    let key: CatalogKey = serde_json::from_value(expected["catalog_key"].clone()).unwrap();
    let app_id: AppId = serde_json::from_value(expected["app_id"].clone()).unwrap();
    let slug = expected["slug"].as_str().unwrap();
    let computed: BTreeMap<&str, Value> = FILES
        .iter()
        .map(|(name, bytes)| {
            let file: CatalogFile = serde_json::from_slice(bytes).unwrap();
            let verdict = match render(&file, &key, app_id, slug) {
                Ok(rendered) => {
                    assert_eq!(rendered.init_data, INIT_DATA, "{name}");
                    assert_eq!(rendered.revision.to_string(), expected["compose_hash"]);
                    "ok"
                }
                Err(e) => e.code(),
            };
            (*name, verdict.into())
        })
        .collect();
    assert_eq!(serde_json::to_value(computed).unwrap(), expected["vectors"]);
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn every_file_in_the_catalog_vector_directory_is_listed() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/catalog");
    let mut on_disk: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| !["expected.json", "init-data.toml"].contains(&name.as_str()))
        .collect();
    on_disk.sort();
    let listed: Vec<&str> = FILES.iter().map(|(name, _)| *name).collect();
    assert_eq!(on_disk, listed);
}
