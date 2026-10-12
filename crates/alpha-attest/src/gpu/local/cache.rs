//! The RIM cache: NVIDIA-signed RIMs (as canonical entries, see [`super::rim`]) and NVIDIA-signed
//! OCSP responses, refreshed offline by the operator and read by the KMS at start. Nothing in it
//! is trusted for being there: every RIM is verified against the policy at each appraisal
//! ([`super::appraise`]), and every OCSP response is checked for the certificate it is used for.
//!
//! ```json
//! {"format": "alphacompute-gpu-rim-cache/1",
//!  "rims": [{"id": "...", "signed_info": "<b64>", "document": "<b64>", "signature": "<b64>",
//!            "certificates": ["<b64 DER>", ...]}],
//!  "ocsp": ["<b64 DER OCSPResponse>", ...]}
//! ```

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use serde::Deserialize;
use x509_cert::Certificate;

use super::{Result, cert, ocsp, refuse};

pub const FORMAT: &str = "alphacompute-gpu-rim-cache/1";
pub const MAX_CACHE_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_RIMS: usize = 512;
pub const MAX_OCSP: usize = 4096;

/// One RIM as the cache holds it, decoded but not verified.
#[derive(Clone, Debug)]
pub struct CachedRim {
    /// The RIM service ID; unsigned, for messages only.
    pub id: String,
    pub signed_info: Vec<u8>,
    pub document: Vec<u8>,
    pub signature: Vec<u8>,
    /// Signer first, root last.
    pub certificates: Vec<Certificate>,
}

/// The decoded cache.
#[derive(Clone, Debug, Default)]
pub struct RimCache {
    pub rims: Vec<CachedRim>,
    pub ocsp: Vec<ocsp::Response>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    format: String,
    #[serde(default)]
    rims: Vec<Entry>,
    #[serde(default)]
    ocsp: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    id: String,
    signed_info: String,
    document: String,
    signature: String,
    certificates: Vec<String>,
}

fn b64(what: &str, text: &str) -> Result<Vec<u8>> {
    BASE64_STANDARD
        .decode(text)
        .or_else(|_| refuse(format!("rim cache: {what} is not base64")))
}

impl RimCache {
    /// Decodes a cache file. Refuses the whole file if any entry is malformed, so a broken
    /// refresh is noticed at start rather than appearing as missing RIMs.
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_CACHE_BYTES {
            return refuse(format!("rim cache is larger than {MAX_CACHE_BYTES} bytes"));
        }
        let file: File = serde_json::from_slice(bytes)
            .or_else(|e| refuse(format!("rim cache does not parse: {e}")))?;
        if file.format != FORMAT {
            return refuse(format!(
                "rim cache format {:?} is not {FORMAT}",
                file.format
            ));
        }
        if file.rims.len() > MAX_RIMS || file.ocsp.len() > MAX_OCSP {
            return refuse("rim cache has too many entries");
        }
        let rims = file
            .rims
            .into_iter()
            .map(|e| {
                let certificates = e
                    .certificates
                    .iter()
                    .take(cert::MAX_CERTS.saturating_add(1))
                    .map(|c| cert::parse_der(&b64("certificate", c)?))
                    .collect::<Result<Vec<_>>>()
                    .map_err(|err| super::Refused(format!("rim cache: {}: {err}", e.id)))?;
                Ok(CachedRim {
                    signed_info: b64("signed_info", &e.signed_info)?,
                    document: b64("document", &e.document)?,
                    signature: b64("signature", &e.signature)?,
                    certificates,
                    id: e.id,
                })
            })
            .collect::<Result<_>>()?;
        let ocsp = file
            .ocsp
            .iter()
            .map(|r| ocsp::parse(&b64("ocsp response", r)?))
            .collect::<Result<_>>()?;
        Ok(Self { rims, ocsp })
    }
}
