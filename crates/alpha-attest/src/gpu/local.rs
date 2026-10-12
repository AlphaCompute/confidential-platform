//! The local GPU verifier (`local`, option 3): appraises NVIDIA GPU evidence in the KMS itself,
//! with no call to NRAS. Its design, and how it closes the three high findings of its review, is
//! `docs/local-gpu-verifier.md`.
//!
//! Every parser here reads attacker-supplied bytes (the GPU report and certificate chain come
//! from the pod; the RIM and OCSP data come from an operator-supplied cache), so each one is
//! bounded before it allocates, never indexes or does unchecked arithmetic (the workspace lints
//! deny both), and refuses what it does not recognise instead of skipping it. Each has a fuzz
//! target under `fuzz/`. They are listed in the PR for the external parser review.
//!
//! - [`spdm`]: the SPDM 1.1 `GET_MEASUREMENTS` request and signed response NVIDIA GPUs emit.
//! - [`opaque`]: NVIDIA's opaque data inside that response (legacy TLV and `NVDAOD` formats).
//! - [`cert`]: the device certificate chain, its pinned root, and the TCG DICE `TcbInfo` of the
//!   Blackwell leaf certificate (the certified firmware identity).
//! - [`ocsp`]: OCSP responses for every certificate a chain's revocation depends on.
//! - [`rim`]: NVIDIA's signed reference integrity manifests (SWID), verified without
//!   canonicalising XML in the KMS.

pub mod appraise;
pub mod backend;
pub mod cache;
pub mod cert;
pub mod ocsp;
pub mod opaque;
pub mod policy;
pub mod rim;
pub mod spdm;
#[cfg(test)]
mod testkit;
#[cfg(test)]
mod tests_appraise;

pub use backend::Local;
pub use cache::RimCache;
pub use policy::{CcModeRule, CcSource, LocalPolicy};

use std::fmt;

/// Why a parser or check refused its input. Reported to the caller inside
/// [`crate::AppraisalError::Failed`], prefixed with the GPU it concerns.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refused(pub String);

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Refused {}

pub type Result<T> = std::result::Result<T, Refused>;

pub(crate) fn refuse<T>(message: impl Into<String>) -> Result<T> {
    Err(Refused(message.into()))
}

/// A cursor over untrusted bytes: every read is bounds-checked and fails rather than panics.
pub(crate) struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    what: &'static str,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(data: &'a [u8], what: &'static str) -> Self {
        Self { data, pos: 0, what }
    }

    pub(crate) fn take(&mut self, n: usize, field: &str) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n);
        match end.and_then(|end| self.data.get(self.pos..end).map(|s| (end, s))) {
            Some((end, slice)) => {
                self.pos = end;
                Ok(slice)
            }
            None => refuse(format!(
                "{}: {field} needs {n} bytes at offset {}, {} remain",
                self.what,
                self.pos,
                self.remaining()
            )),
        }
    }

    pub(crate) fn array<const N: usize>(&mut self, field: &str) -> Result<[u8; N]> {
        let slice = self.take(N, field)?;
        <[u8; N]>::try_from(slice).or_else(|_| refuse(format!("{}: {field}", self.what)))
    }

    pub(crate) fn u8(&mut self, field: &str) -> Result<u8> {
        let [b] = self.array::<1>(field)?;
        Ok(b)
    }

    pub(crate) fn u16_le(&mut self, field: &str) -> Result<u16> {
        Ok(u16::from_le_bytes(self.array::<2>(field)?))
    }

    pub(crate) fn u24_le(&mut self, field: &str) -> Result<u32> {
        let [a, b, c] = self.array::<3>(field)?;
        Ok(u32::from_le_bytes([a, b, c, 0]))
    }

    pub(crate) fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.remaining() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_refuses_reads_past_the_end_without_panicking() {
        let mut r = Reader::new(&[1, 2, 3], "test");
        assert_eq!(r.u16_le("a").unwrap(), 0x0201);
        assert!(r.u16_le("b").is_err());
        // A failed read consumes nothing.
        assert_eq!(r.u8("c").unwrap(), 3);
        assert!(r.is_empty());
        assert!(r.take(usize::MAX, "huge").is_err());
        let mut r = Reader::new(&[1, 2, 3], "test");
        assert_eq!(r.u24_le("len").unwrap(), 0x030201);
    }
}
