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
pub mod initdata;
mod network;
pub mod phala;
pub mod platform;
pub mod signing;

pub use compose::{
    ComposeHash, ParseComposeHashError, RegistrationError, check_registration, compose_hash,
    has_sha256_digest, hex_bytes,
};
pub use id::{AppId, KeyId, OrgId, PrincipalId, RequestId, SecretId};
pub use initdata::{InitData, InitDataError, MAX_INIT_DATA, guest_pull};
pub use network::{Opening, Openings, Protocol};
pub use platform::{CatalogKey, KataPolicy, KmsRevision, Signer};
pub use signing::{context, jcs, parse, signing_digest};

/// The zone every App Endpoint `<slug>.app.alphacompute.cc` lives under.
pub const APP_ZONE: &str = "app.alphacompute.cc";

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

/// A put carries a Secret's value after this many random bytes and commits to both in
/// `content_sha256`, so the signed document stored beside the ciphertext does not let a reader
/// of the database test guesses of a weak value against it.
pub const SECRET_SALT_LEN: usize = 32;

/// An App's slug, the first label of its Endpoint `<slug>.app.alphacompute.cc`: 3 to 48 lowercase
/// letters, digits or `-`, starting with a letter, not ending with `-`. `--` is refused because it
/// separates an Instance id from the slug in an Instance Endpoint; the reserved words name
/// platform hosts.
pub fn is_slug(slug: &str) -> bool {
    const RESERVED: [&str; 13] = [
        "api",
        "sign",
        "verify",
        "kms",
        "registry",
        "inference",
        "app",
        "apps",
        "www",
        "mail",
        "docs",
        "status",
        "admin",
    ];
    let bytes = slug.as_bytes();
    (3..=48).contains(&bytes.len())
        && bytes.first().is_some_and(u8::is_ascii_lowercase)
        && bytes.last().is_some_and(|b| *b != b'-')
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
        && !slug.contains("--")
        && !RESERVED.contains(&slug)
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
    fn slug_is_one_dns_label_that_names_no_platform_host() {
        let longest = format!("a{}", "0".repeat(47));
        for ok in ["abc", "rafay-0123abcd", "a-b", "a10", longest.as_str()] {
            assert!(is_slug(ok), "{ok:?}");
        }
        let too_long = format!("{longest}0");
        for bad in [
            "",
            "ab",
            too_long.as_str(),
            "1abc",
            "-abc",
            "abc-",
            "a--b",
            "Abc",
            "a_b",
            "a.b",
            "sign",
            "api",
            "app",
        ] {
            assert!(!is_slug(bad), "{bad:?}");
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
