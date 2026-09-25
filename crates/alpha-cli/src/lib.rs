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
pub mod sign;

use std::time::SystemTime;

use ed25519_dalek::VerifyingKey;

/// The release key's public half, the same file `alpha-kms` compiles in; replaced at the
/// ceremony, never in CI.
pub fn release_key() -> Result<VerifyingKey, String> {
    alpha_core::hex_bytes::<32>(include_str!("../../../services/alpha-kms/release-key.pub").trim())
        .and_then(|b| VerifyingKey::from_bytes(&b).ok())
        .ok_or_else(|| "release-key.pub is not an Ed25519 public key".to_owned())
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
