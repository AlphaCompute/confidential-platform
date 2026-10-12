//! `gpu_policy.local`: everything the `local` backend trusts, release-signed in the platform
//! document. There is no CC-mode field to pin: as in NVIDIA's verifier, production CC mode is
//! every measurement matching a pinned driver and VBIOS RIM, with no DICE debug state. Every field the decision rests on must be set before any GPU is looked at; until a
//! document pins them (after the B300 capture at G0), the backend refuses every GPU.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use serde::{Deserialize, Serialize};

use crate::AppraisalError;

/// The longest OCSP maximum age a policy may set: a week.
pub const MAX_OCSP_MAX_AGE: Duration = Duration::from_secs(7 * 24 * 3600);

/// `gpu_policy.local` as the document has it. Fields default to empty so that a partial policy
/// still parses and the refusal names what is missing.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalPolicy {
    /// Device identity roots, base64 DER (NVIDIA Device Identity CA).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub device_roots: Vec<String>,
    /// RIM signing roots, base64 DER (NVIDIA CoRIM signing Root CA).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rim_roots: Vec<String>,
    /// Every RIM the verifier may use: `sha384:<hex DigestValue>` to the RIM's ID (for people).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub rims: BTreeMap<String, String>,
    /// Certified FMC firmware IDs (`sha384:<hex>`) the release accepts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fwids: Vec<String>,
    /// Maximum age of an OCSP response, in seconds (1 to a week).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ocsp_max_age_secs: Option<u64>,
    /// An OCSP endpoint the KMS may query at appraisal time; absent, cached responses only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ocsp_url: Option<String>,
    /// Whether `certificateHold` counts as good. Default no.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub accept_certificate_hold: bool,
}

/// A policy whose every required field is set and well-formed, decoded.
#[derive(Clone, Debug)]
pub struct Pinned {
    pub device_roots: Vec<Vec<u8>>,
    pub rim_roots: Vec<Vec<u8>>,
    pub rims: BTreeSet<[u8; 48]>,
    pub fwids: BTreeSet<[u8; 48]>,
    pub ocsp: super::ocsp::Freshness,
    pub ocsp_url: Option<String>,
}

fn missing(field: &str) -> AppraisalError {
    AppraisalError::Unknown(format!(
        "gpu_policy.local.{field} is not set (G0 check); the local verifier refuses every GPU"
    ))
}

fn malformed(field: &str, why: &str) -> AppraisalError {
    AppraisalError::Failed(format!("gpu_policy.local.{field}: {why}"))
}

fn sha384(field: &str, text: &str) -> Result<[u8; 48], AppraisalError> {
    text.strip_prefix("sha384:")
        .and_then(|h| hex::decode(h).ok())
        .and_then(|b| <[u8; 48]>::try_from(b).ok())
        .ok_or_else(|| malformed(field, &format!("{text:?} is not sha384:<96 hex>")))
}

fn ders(field: &str, list: &[String]) -> Result<Vec<Vec<u8>>, AppraisalError> {
    if list.is_empty() {
        return Err(missing(field));
    }
    list.iter()
        .map(|b64| {
            let der = BASE64_STANDARD
                .decode(b64)
                .map_err(|_| malformed(field, "an entry is not base64"))?;
            // Each must be a certificate, so a typo cannot pin nothing.
            super::cert::parse_der(&der).map_err(|e| malformed(field, &e.0))?;
            Ok(der)
        })
        .collect()
}

/// Every required field of `gpu_policy.local` set and well-formed, or the refusal naming the
/// first that is not: `attestation_unknown` for a missing field (nothing is pinned yet, G0),
/// `attestation_failed` for a malformed one.
pub fn pinned(policy: Option<&LocalPolicy>) -> Result<Pinned, AppraisalError> {
    let p = policy.ok_or_else(|| {
        AppraisalError::Unknown(
            "gpu_policy.local is not set (G0 check); the local verifier refuses every GPU".into(),
        )
    })?;
    let device_roots = ders("device_roots", &p.device_roots)?;
    let rim_roots = ders("rim_roots", &p.rim_roots)?;
    if p.rims.is_empty() {
        return Err(missing("rims"));
    }
    let rims = p
        .rims
        .keys()
        .map(|k| sha384("rims", k))
        .collect::<Result<_, _>>()?;
    if p.fwids.is_empty() {
        return Err(missing("fwids"));
    }
    let fwids = p
        .fwids
        .iter()
        .map(|k| sha384("fwids", k))
        .collect::<Result<_, _>>()?;
    let max_age = p
        .ocsp_max_age_secs
        .map(Duration::from_secs)
        .ok_or_else(|| missing("ocsp_max_age_secs"))?;
    if max_age.is_zero() || max_age > MAX_OCSP_MAX_AGE {
        return Err(malformed("ocsp_max_age_secs", "is not 1 s to 7 days"));
    }
    if let Some(url) = &p.ocsp_url
        && !url.starts_with("https://")
    {
        return Err(malformed("ocsp_url", "is not an https:// URL"));
    }
    Ok(Pinned {
        device_roots,
        rim_roots,
        rims,
        fwids,
        ocsp: super::ocsp::Freshness {
            max_age,
            accept_certificate_hold: p.accept_certificate_hold,
        },
        ocsp_url: p.ocsp_url.clone(),
    })
}
