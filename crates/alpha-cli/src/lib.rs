//! The `alpha` binary's commands as library functions: `main` parses flags, prompts for the
//! passphrase and prints; everything that decides lives here so it can run against an
//! in-process KMS in tests.

#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )
)]
pub mod call;
pub mod catalog;
pub mod coco;
pub mod deploy;
pub mod instances;
pub mod keyfile;
pub mod node;
pub mod request;
pub mod sign;
pub mod verify;

use std::time::SystemTime;

use alpha_client::platform::ReleaseKeys;

pub fn release_keys() -> Result<ReleaseKeys, String> {
    alpha_channel::platform::release_keys().map_err(|e| e.to_string())
}

pub fn rfc3339(t: SystemTime) -> String {
    chrono::DateTime::<chrono::Utc>::from(t).to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

pub fn random<const N: usize>() -> Result<[u8; N], String> {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).map_err(|e| format!("rng: {e}"))?;
    Ok(out)
}
