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
pub mod deploy;
pub mod instances;
pub mod keyfile;
pub mod node;
pub mod request;
pub mod sign;

use std::time::SystemTime;

use ed25519_dalek::VerifyingKey;

pub fn release_key() -> Result<VerifyingKey, String> {
    alpha_channel::platform::release_key().map_err(|e| e.to_string())
}

pub fn rfc3339(t: SystemTime) -> String {
    chrono::DateTime::<chrono::Utc>::from(t).to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

pub fn random<const N: usize>() -> Result<[u8; N], String> {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).map_err(|e| format!("rng: {e}"))?;
    Ok(out)
}

pub fn sha256_prefixed(bytes: &[u8]) -> String {
    use sha2::Digest;
    format!("sha256:{}", hex::encode(sha2::Sha256::digest(bytes)))
}

#[cfg(test)]
mod tests {
    #[test]
    fn compiled_in_release_key_parses() {
        super::release_key().unwrap();
    }
}
