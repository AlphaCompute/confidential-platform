//! The attested inner channel: a client that cannot hold a TLS session to an Instance (a browser
//! behind a relay it does not trust) checks the Instance's KMS certificate, its Revision and the
//! compose it runs, then exchanges frames sealed to that Instance alone. Both ends live here so the
//! page, the worker and the broker run one implementation, natively and as wasm.
//!
//! Nothing here reads a clock: every check that needs time takes `now`, because in
//! `wasm32-unknown-unknown` the system clock traps.

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

use std::time::{Duration, SystemTime};

use alpha_core::ComposeHash;

pub mod cert;
pub mod compose;
pub mod frame;
pub mod handshake;
pub mod platform;
#[cfg(target_arch = "wasm32")]
pub mod wasm;

/// Every variant is one reason a client stops; `code()` is its stable name on the wire.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    PlatformSignature(String),
    #[error("{0}")]
    ForeignCertificate(String),
    #[error("the certificate is outside its validity")]
    CertificateExpired,
    #[error("revision {0} is not in the allowlist")]
    UnknownRevision(ComposeHash),
    #[error("the compose does not hash to the certificate's revision")]
    ComposeMismatch,
    #[error("{0}")]
    HandshakeSignature(String),
    #[error("{0}")]
    Malformed(String),
    #[error("the system RNG failed")]
    Rng,
    #[error("sealing failed")]
    Seal,
    #[error("the frame does not open under this channel, sequence number and route")]
    Open,
    #[error("sequence number {0} was already used")]
    Replayed(u64),
    #[error("the channel has carried its last request")]
    Exhausted,
    #[error("the response ended without its end frame")]
    Truncated,
}

impl Error {
    pub fn code(&self) -> &'static str {
        match self {
            Self::PlatformSignature(_) => "platform_signature",
            Self::ForeignCertificate(_) => "foreign_certificate",
            Self::CertificateExpired => "certificate_expired",
            Self::UnknownRevision(_) => "unknown_revision",
            Self::ComposeMismatch => "compose_mismatch",
            Self::HandshakeSignature(_) => "handshake_signature",
            Self::Malformed(_) => "malformed",
            Self::Rng => "rng",
            Self::Seal => "seal",
            Self::Open => "open",
            Self::Replayed(_) => "replayed",
            Self::Exhausted => "exhausted",
            Self::Truncated => "truncated",
        }
    }
}

fn random<const N: usize>() -> Result<[u8; N], Error> {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).map_err(|_| Error::Rng)?;
    Ok(out)
}

fn unix_seconds(t: SystemTime) -> Result<i64, Error> {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .ok_or_else(|| Error::Malformed("now is before 1970 or too far ahead".into()))
}

fn rfc3339(t: SystemTime) -> Result<String, Error> {
    chrono::DateTime::from_timestamp(unix_seconds(t)?, 0)
        .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .ok_or_else(|| Error::Malformed("now is out of range".into()))
}

fn from_unix_seconds(seconds: i64) -> Option<SystemTime> {
    SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(u64::try_from(seconds).ok()?))
}

fn sha256_label(bytes: &[u8]) -> String {
    use sha2::Digest;
    format!("sha256:{}", hex::encode(sha2::Sha256::digest(bytes)))
}
