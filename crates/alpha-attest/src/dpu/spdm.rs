//! The KMS's own verifier of BlueField DPU evidence: an SPDM 1.1 measurement transcript, as DMTF's
//! Redfish `ComponentIntegrity` schema defines `SignedMeasurements` for SPDM 1.0 and 1.1 (the
//! `GET_MEASUREMENTS` requests and `MEASUREMENTS` responses exchanged, the last response signed
//! over all of it), and the device's certificate chain.
//!
//! It verifies: the transcript's structure (DSP0274 1.1), that the signed request carried our
//! nonce from slot 0, the ECDSA P-384 signature under the chain's leaf over the hash of everything
//! before it, the chain (ECDSA P-384 SHA-384, every link, validity now) up to a root the
//! release-signed `dpu_policy` pins, and every measurement the policy lists. It does not verify
//! revocation, CoRIMs, or that the device is the one attached to the pod's host
//! (`docs/dpu-attestation.md`).

use std::collections::BTreeMap;
use std::time::SystemTime;

use p384::ecdsa::signature::Verifier as _;
use p384::ecdsa::signature::hazmat::PrehashVerifier;
use sha2::{Digest, Sha256, Sha384, Sha512};
use x509_cert::Certificate;
use x509_cert::der::{DecodePem, Encode};

use super::{DpuEvidence, DpuFuture, DpuModel, DpuVerifier, DpuVerifierKind, VerifiedDpu};
use crate::AppraisalError;

/// SPDM 1.1, the version DMTF's `SignedMeasurements` definition and BlueField's BMC use.
const SPDM_11: u8 = 0x11;
const GET_MEASUREMENTS: u8 = 0xE0;
const MEASUREMENTS: u8 = 0x60;
const P384_SIGNATURE: usize = 96;
const ECDSA_WITH_SHA384: &str = "1.2.840.10045.4.3.3";
/// DSP0274 `MeasurementSpecification` bit 0: DMTF.
const DMTF: u8 = 0x01;

fn failed(message: impl Into<String>) -> AppraisalError {
    AppraisalError::Failed(message.into())
}

/// The KMS's local DPU backend.
pub struct LocalDpu {
    clock: fn() -> SystemTime,
}

impl LocalDpu {
    pub fn new() -> Self {
        Self {
            clock: SystemTime::now,
        }
    }

    /// For tests: certificate validity judged at `clock()`.
    pub fn with_clock(clock: fn() -> SystemTime) -> Self {
        Self { clock }
    }
}

impl Default for LocalDpu {
    fn default() -> Self {
        Self::new()
    }
}

impl DpuVerifier for LocalDpu {
    fn kind(&self) -> DpuVerifierKind {
        DpuVerifierKind::Local
    }

    fn verify<'a>(
        &'a self,
        dpus: &'a [DpuEvidence],
        nonce: &'a [u8; 32],
        model: &'a str,
        policy: &'a DpuModel,
    ) -> DpuFuture<'a> {
        let now = (self.clock)();
        let out = dpus
            .iter()
            .zip(0u32..)
            .map(|(evidence, index)| {
                verify(evidence, nonce, model, policy, now)
                    .map(|dpu| VerifiedDpu { index, ..dpu })
                    .map_err(|e| match e {
                        AppraisalError::Failed(m) => failed(format!("dpu {index}: {m}")),
                        other => other,
                    })
            })
            .collect::<Result<Vec<_>, _>>();
        Box::pin(async move { out })
    }
}

/// What a transcript says once parsed.
#[derive(Debug, PartialEq, Eq)]
pub struct Transcript {
    /// The nonce of the last request, the one the signature is over.
    pub nonce: [u8; 32],
    pub slot: u8,
    /// By index: DMTF value type, then value.
    pub measurements: BTreeMap<u8, Vec<u8>>,
    /// Where the signature starts: everything before it is signed.
    pub signed_len: usize,
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], AppraisalError> {
        let end = self
            .at
            .checked_add(n)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| failed("SPDM transcript is truncated"))?;
        let out = self.bytes.get(self.at..end).unwrap_or_default();
        self.at = end;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, AppraisalError> {
        self.take(1)?
            .first()
            .copied()
            .ok_or_else(|| failed("SPDM transcript is truncated"))
    }

    fn le(&mut self, n: usize) -> Result<usize, AppraisalError> {
        Ok(self
            .take(n)?
            .iter()
            .rev()
            .fold(0usize, |acc, b| (acc << 8) | usize::from(*b)))
    }
}

/// DSP0274 1.1 `GET_MEASUREMENTS`/`MEASUREMENTS` pairs, the last pair signed and no other.
pub fn parse_transcript(bytes: &[u8]) -> Result<Transcript, AppraisalError> {
    let mut r = Reader { bytes, at: 0 };
    let mut measurements = BTreeMap::new();
    loop {
        // GET_MEASUREMENTS: version, code, Param1 (bit 0: signature requested), Param2 (the
        // operation), and when signed the nonce and SlotIDParam.
        let (version, code, param1, _) = (r.u8()?, r.u8()?, r.u8()?, r.u8()?);
        if version != SPDM_11 || code != GET_MEASUREMENTS {
            return Err(failed(format!(
                "SPDM transcript: expected a version 1.1 GET_MEASUREMENTS, found {version:#04x} {code:#04x}"
            )));
        }
        let signed = param1 & 1 == 1;
        let request = if signed {
            let nonce: [u8; 32] = r.take(32)?.try_into().map_err(|_| failed("nonce"))?;
            Some((nonce, r.u8()? & 0x0F))
        } else {
            None
        };

        // MEASUREMENTS: version, code, Param1, Param2, NumberOfBlocks, MeasurementRecordLength
        // (3 bytes), the record, the responder's nonce, OpaqueLength, OpaqueData, the signature.
        let (version, code) = (r.u8()?, r.u8()?);
        if version != SPDM_11 || code != MEASUREMENTS {
            return Err(failed(format!(
                "SPDM transcript: expected a version 1.1 MEASUREMENTS, found {version:#04x} {code:#04x}"
            )));
        }
        r.take(2)?;
        let blocks = r.u8()?;
        let length = r.le(3)?;
        let record = r.take(length)?;
        parse_record(record, blocks, &mut measurements)?;
        r.take(32)?;
        let opaque = r.le(2)?;
        r.take(opaque)?;

        match request {
            None => {
                if r.at == bytes.len() {
                    return Err(failed("SPDM transcript has no signed MEASUREMENTS"));
                }
            }
            Some((nonce, slot)) => {
                let signed_len = r.at;
                r.take(P384_SIGNATURE)?;
                if r.at != bytes.len() {
                    return Err(failed(
                        "SPDM transcript continues after its signed MEASUREMENTS",
                    ));
                }
                return Ok(Transcript {
                    nonce,
                    slot,
                    measurements,
                    signed_len,
                });
            }
        }
    }
}

/// Measurement blocks: Index, MeasurementSpecification, MeasurementSize (2), then for DMTF the
/// value type, value size (2) and value.
fn parse_record(
    record: &[u8],
    blocks: u8,
    out: &mut BTreeMap<u8, Vec<u8>>,
) -> Result<(), AppraisalError> {
    let mut r = Reader {
        bytes: record,
        at: 0,
    };
    for _ in 0..blocks {
        let index = r.u8()?;
        let spec = r.u8()?;
        let size = r.le(2)?;
        let block = r.take(size)?;
        if spec != DMTF {
            return Err(failed(format!(
                "measurement {index} is not a DMTF measurement"
            )));
        }
        let (kind, rest) = block
            .split_first()
            .ok_or_else(|| failed(format!("measurement {index} is empty")))?;
        let (len, value) = rest
            .split_at_checked(2)
            .ok_or_else(|| failed(format!("measurement {index} is truncated")))?;
        let len = usize::from(u16::from_le_bytes([
            len.first().copied().unwrap_or_default(),
            len.get(1).copied().unwrap_or_default(),
        ]));
        if value.len() != len {
            return Err(failed(format!(
                "measurement {index}: value is {} bytes, its header says {len}",
                value.len()
            )));
        }
        let mut entry = vec![*kind];
        entry.extend_from_slice(value);
        if out.insert(index, entry).is_some() {
            return Err(failed(format!("measurement {index} appears twice")));
        }
    }
    if r.at != record.len() {
        return Err(failed("measurement record is longer than its blocks"));
    }
    Ok(())
}

/// The chain in SPDM order (root first); a leaf-first chain is turned around.
fn chain(pem: &str) -> Result<Vec<Certificate>, AppraisalError> {
    let mut chain = Certificate::load_pem_chain(pem.as_bytes())
        .map_err(|e| failed(format!("certificate chain: {e}")))?;
    let self_issued = |c: &Certificate| c.tbs_certificate.issuer == c.tbs_certificate.subject;
    if chain.last().is_some_and(self_issued) && !chain.first().is_some_and(self_issued) {
        chain.reverse();
    }
    Ok(chain)
}

fn p384_key(cert: &Certificate) -> Result<p384::ecdsa::VerifyingKey, AppraisalError> {
    p384::ecdsa::VerifyingKey::from_sec1_bytes(
        cert.tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes(),
    )
    .map_err(|_| failed("a certificate key is not P-384"))
}

/// `issuer` signed `cert` with ECDSA P-384 SHA-384, and names it as its issuer.
fn signed_by(cert: &Certificate, issuer: &Certificate) -> Result<(), AppraisalError> {
    if cert.tbs_certificate.issuer != issuer.tbs_certificate.subject {
        return Err(failed("certificate chain: an issuer name does not match"));
    }
    if cert.signature_algorithm.oid.to_string() != ECDSA_WITH_SHA384 {
        return Err(failed(
            "certificate chain: a signature is not ECDSA with SHA-384",
        ));
    }
    let tbs = cert
        .tbs_certificate
        .to_der()
        .map_err(|e| failed(format!("certificate: {e}")))?;
    let signature = p384::ecdsa::Signature::from_der(cert.signature.raw_bytes())
        .map_err(|_| failed("certificate chain: a signature does not parse"))?;
    p384_key(issuer)?
        .verify(&tbs, &signature)
        .map_err(|_| failed("certificate chain: a signature does not verify"))
}

fn valid_at(cert: &Certificate, now: SystemTime) -> Result<(), AppraisalError> {
    let v = &cert.tbs_certificate.validity;
    if now < v.not_before.to_system_time() || now > v.not_after.to_system_time() {
        return Err(failed(format!(
            "certificate chain: a certificate is not valid now ({} to {})",
            v.not_before, v.not_after
        )));
    }
    Ok(())
}

/// One DPU's evidence, verified. `index` is left 0 for the caller.
pub fn verify(
    evidence: &DpuEvidence,
    nonce: &[u8; 32],
    model: &str,
    policy: &DpuModel,
    now: SystemTime,
) -> Result<VerifiedDpu, AppraisalError> {
    use AppraisalError::*;

    if policy.roots_pem.is_empty() {
        return Err(PolicyDenied(format!("dpu_policy pins no root for {model}")));
    }
    if policy.measurements.is_empty() {
        return Err(PolicyDenied(format!(
            "dpu_policy has no reference measurements for {model}"
        )));
    }
    // ponytail: dpu-spdm-1.2 — a 1.2 transcript starts with VCA and signs a context-prefixed
    // hash; BlueField's BMC reports 1.1, so only 1.1 is verified.
    if !matches!(evidence.spdm_version.as_str(), "1.1" | "1.1.0") {
        return Err(Unknown(format!(
            "SPDM {} transcripts are not verified; 1.1 is",
            evidence.spdm_version
        )));
    }
    if evidence.signing_algorithm != "TPM_ALG_ECDSA_ECC_NIST_P384" {
        return Err(Failed(format!(
            "signing algorithm {} is not ECDSA P-384",
            evidence.signing_algorithm
        )));
    }
    let transcript = parse_transcript(&evidence.signed_measurements)?;
    if transcript.nonce != *nonce {
        return Err(Failed("the signed request is not over this nonce".into()));
    }
    if transcript.slot != 0 {
        return Err(Failed(format!(
            "signed from certificate slot {}, not NVIDIA's slot 0",
            transcript.slot
        )));
    }

    let chain = chain(&evidence.certificate_chain)?;
    let (first, leaf) = chain
        .first()
        .zip(chain.last())
        .ok_or_else(|| Failed("certificate chain is empty".into()))?;
    let roots = policy
        .roots_pem
        .iter()
        .map(|pem| {
            Certificate::from_pem(pem.as_bytes())
                .map_err(|e| Failed(format!("dpu_policy root is not a PEM certificate: {e}")))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let root = roots
        .iter()
        .find(|root| *root == first || signed_by(first, root).is_ok())
        .ok_or_else(|| Failed("certificate chain does not end at a pinned root".into()))?;
    valid_at(root, now)?;
    for pair in chain.windows(2) {
        if let [issuer, cert] = pair {
            signed_by(cert, issuer)?;
        }
    }
    for cert in &chain {
        valid_at(cert, now)?;
    }

    let signed = evidence
        .signed_measurements
        .get(..transcript.signed_len)
        .ok_or_else(|| Failed("SPDM transcript".into()))?;
    let signature = evidence
        .signed_measurements
        .get(transcript.signed_len..)
        .and_then(|s| p384::ecdsa::Signature::from_slice(s).ok())
        .ok_or_else(|| Failed("SPDM signature is not a P-384 signature".into()))?;
    let digest = match evidence.hashing_algorithm.as_str() {
        "TPM_ALG_SHA_384" => Sha384::digest(signed).to_vec(),
        "TPM_ALG_SHA_512" => Sha512::digest(signed).to_vec(),
        other => {
            return Err(Failed(format!(
                "hashing algorithm {other} is not SHA-384 or SHA-512"
            )));
        }
    };
    p384_key(leaf)?
        .verify_prehash(&digest, &signature)
        .map_err(|_| Failed("SPDM measurements signature does not verify under the leaf".into()))?;

    for (index, allowed) in &policy.measurements {
        let at: u8 = index
            .parse()
            .map_err(|_| Failed(format!("dpu_policy measurement index {index:?}")))?;
        let value = transcript
            .measurements
            .get(&at)
            .ok_or_else(|| Failed(format!("measurement {at} is not in the transcript")))?;
        if !allowed
            .iter()
            .any(|v| v.eq_ignore_ascii_case(&hex::encode(value)))
        {
            return Err(PolicyDenied(format!(
                "measurement {at} is not a reference value for {model}"
            )));
        }
    }

    // The DICE DeviceID certificate (L4, provisioned per device) sits below the two
    // boot-generated alias certificates (L5, L6).
    // ponytail: dpu-capture — confirm the DeviceID position on a BlueField-3's chain.
    let device = chain
        .len()
        .checked_sub(3)
        .and_then(|i| chain.get(i))
        .ok_or_else(|| Failed("certificate chain is too short to name a device".into()))?;
    let device_key = device
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| Failed(format!("device key: {e}")))?;

    // ponytail: dpu-ocsp — no revocation source for BlueField certificates is built; a document
    // must accept that explicitly, and the result records it.
    if !policy.accept_unchecked_revocation {
        return Err(PolicyDenied(format!(
            "revocation of {model} certificates is not checked, and dpu_policy does not accept that"
        )));
    }

    Ok(VerifiedDpu {
        index: 0,
        device_id: format!("sha256:{}", hex::encode(Sha256::digest(device_key))),
        model: model.to_owned(),
        measurements: transcript
            .measurements
            .iter()
            .map(|(i, v)| (*i, hex::encode(v)))
            .collect(),
        nonce: transcript.nonce,
        revocation_checked: false,
    })
}
