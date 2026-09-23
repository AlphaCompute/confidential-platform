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

pub mod compose;
pub mod id;
pub mod phala;
pub mod signing;

pub use compose::{
    ComposeHash, ParseComposeHashError, RegistrationError, check_registration, compose_hash,
    hex_bytes,
};
pub use id::{AppId, KeyId, OrgId, PrincipalId, RequestId, SecretId};
pub use signing::{context, jcs, signing_digest};

/// The name of a key an App derives: 1 to 64 lowercase ASCII letters, digits, `.`, `_` or `-`,
/// starting with a letter or digit, so it is safe as a path segment.
pub fn is_key_purpose(purpose: &str) -> bool {
    let bytes = purpose.as_bytes();
    matches!(bytes.first(), Some(b) if b.is_ascii_lowercase() || b.is_ascii_digit())
        && bytes.len() <= 64
        && bytes.iter().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_purpose_is_a_bounded_lowercase_path_segment() {
        let longest = "a".repeat(64);
        for ok in ["connectors", "a", "0", "a.b-c_d", longest.as_str()] {
            assert!(is_key_purpose(ok), "{ok:?}");
        }
        let too_long = "a".repeat(65);
        for bad in [
            "",
            too_long.as_str(),
            ".x",
            "-x",
            "_x",
            "..",
            "A",
            "aB",
            "a/b",
            "a b",
            "é",
            "a\u{0}",
        ] {
            assert!(!is_key_purpose(bad), "{bad:?}");
        }
    }
}
