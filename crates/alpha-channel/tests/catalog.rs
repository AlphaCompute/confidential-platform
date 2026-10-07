#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::collections::BTreeMap;

use alpha_core::catalog::{CatalogFile, render, verify};
use alpha_core::{AppId, CatalogKey};
use serde_json::{Value, json};

macro_rules! v {
    ($n:literal) => {
        (
            $n,
            include_bytes!(concat!("../../../testdata/catalog/", $n)),
        )
    };
}

const FILES: &[(&str, &[u8])] = &[v!("valid.json")];

const EXPECTED: &str = include_str!("../../../testdata/catalog/expected.json");
const COMPOSE: &[u8] = include_bytes!("../../../testdata/catalog/app-compose.json");

#[wasm_bindgen_test::wasm_bindgen_test(unsupported = test)]
fn every_catalog_vector_gives_its_recorded_verdicts() {
    let expected: Value = serde_json::from_str(EXPECTED).unwrap();
    let key: CatalogKey = serde_json::from_value(expected["catalog_key"].clone()).unwrap();
    let app_id: AppId = serde_json::from_value(expected["app_id"].clone()).unwrap();
    let computed: BTreeMap<&str, Value> = FILES
        .iter()
        .map(|(name, bytes)| {
            let file: CatalogFile = serde_json::from_slice(bytes).unwrap();
            let signature = verify(&file, &key).map_or_else(|e| e.code(), |()| "ok");
            let render = match render(&file.template, &file.entry.template_sha256, app_id) {
                Ok(compose) => {
                    assert_eq!(compose.as_bytes(), COMPOSE, "{name}");
                    "ok"
                }
                Err(e) => e.code(),
            };
            (*name, json!({"signature": signature, "render": render}))
        })
        .collect();
    assert_eq!(serde_json::to_value(computed).unwrap(), expected["vectors"]);
}
