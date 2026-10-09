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

use serde::{Deserialize, Serialize};

pub mod catalog;
pub mod compose;
pub mod id;
pub mod phala;
pub mod platform;
pub mod signing;

pub use compose::{
    ComposeHash, ParseComposeHashError, RegistrationError, check_registration, compose_hash,
    hex_bytes,
};
pub use id::{AppId, KeyId, OrgId, PrincipalId, RequestId, SecretId};
pub use platform::{CatalogKey, KmsRevision, Signer};
pub use signing::{context, jcs, parse, signing_digest};

/// `{algorithm, signature}`, the signature in base64url.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedSignature {
    pub algorithm: String,
    pub signature: String,
}

/// The name of a key an App derives: 1 to 64 lowercase ASCII letters, digits, `.`, `_` or `-`,
/// starting with a letter or digit, so it is safe as a path segment.
pub fn is_key_purpose(purpose: &str) -> bool {
    is_segment(purpose, 64)
}

/// The name of a Secret at the KMS: the key-purpose alphabet with up to 101 bytes, room for an
/// App id and a dot before a 64-byte declared name.
pub fn is_secret_name(name: &str) -> bool {
    is_segment(name, 101)
}

fn is_segment(name: &str, max: usize) -> bool {
    let bytes = name.as_bytes();
    matches!(bytes.first(), Some(b) if b.is_ascii_lowercase() || b.is_ascii_digit())
        && bytes.len() <= max
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

    #[test]
    fn secret_name_admits_an_app_prefix_before_a_purpose_name() {
        let app = "01994b3e-5c8a-7d3e-9a1b-2c3d4e5f6a7b";
        let longest = format!("{app}.{}", "a".repeat(64));
        assert_eq!(longest.len(), 101);
        assert!(is_secret_name(&longest));
        for purpose in ["connectors", "a", "0", "a.b-c_d", "db_password"] {
            assert!(is_key_purpose(purpose));
            assert!(is_secret_name(purpose), "{purpose:?}");
            assert!(is_secret_name(&format!("{app}.{purpose}")), "{purpose:?}");
        }
        let too_long = format!("{longest}a");
        for bad in [
            "",
            too_long.as_str(),
            ".x",
            "A",
            "01994B3E-5c8a-7d3e-9a1b-2c3d4e5f6a7b.x",
            "a/b",
        ] {
            assert!(!is_secret_name(bad), "{bad:?}");
        }
    }
}
