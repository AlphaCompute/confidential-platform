//! Appraisal of NVIDIA GPU evidence: the SPDM 1.1 GET_MEASUREMENTS exchange a confidential
//! GPU signs with its device identity key, the certificate chain of that key, and our own
//! reference values for its firmware.

use std::collections::{BTreeMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use alpha_core::ComposeHash;
use p384::ecdsa::signature::Verifier;
use p384::ecdsa::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x509_parser::asn1_rs::{Any, Class, FromDer, Oid, Tag};
use x509_parser::certificate::X509Certificate;
use x509_parser::oid_registry::{OID_NIST_HASH_SHA384, OID_SIG_ECDSA_WITH_SHA384};
use x509_parser::pem::Pem;
use x509_parser::time::ASN1Time;

use crate::{AppraisalError, Measurement, base64url};

/// One GPU's evidence as NVML hands it out: the request and signed response of SPDM
/// GET_MEASUREMENTS, and the device certificate chain in PEM, leaf first.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GpuEvidence {
    #[serde(with = "base64url")]
    pub evidence: Vec<u8>,
    #[serde(with = "base64url")]
    pub certificate_chain: Vec<u8>,
}

/// What one GPU model on one VBIOS and driver must report. The identity fields are read off
/// the signed opaque data; a measurement block absent from `measurements` must be zero.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GpuReference {
    /// SHA-256 of the DER of the device identity root the chain must end in.
    pub root_sha256: ComposeHash,
    pub chip: String,
    pub project: String,
    pub project_sku: String,
    pub chip_sku: String,
    pub vbios_version: String,
    pub driver_version: String,
    pub measurements: BTreeMap<u8, Vec<Measurement>>,
}

/// SPDM 1.1 GET_MEASUREMENTS, signature requested, all blocks.
const REQUEST: [u8; 4] = [0x11, 0xe0, 0x01, 0xff];
/// SPDM 1.1 MEASUREMENTS.
const RESPONSE: [u8; 2] = [0x11, 0x60];
const BLOCKS: u8 = 64;
const DMTF_SPEC: u8 = 0x01;
const SIGNATURE_LEN: usize = 96;
const TCB_INFO_OID: &str = "2.23.133.5.4.1.1";

/// The NVIDIA opaque data types read by name.
mod tlv {
    pub const DRIVER_VERSION: u16 = 3;
    pub const VBIOS_VERSION: u16 = 6;
    pub const CHIP_SKU: u16 = 15;
    pub const PROJECT: u16 = 17;
    pub const PROJECT_SKU: u16 = 18;
    pub const FWID: u16 = 20;
    pub const OPAQUE_DATA_VERSION: u16 = 34;
    pub const CHIP_INFO: u16 = 35;
}

fn failed(what: impl Into<String>) -> AppraisalError {
    AppraisalError::Failed(format!("gpu evidence: {}", what.into()))
}

/// Appraises `count` GPU evidences, each fresh for `nonce` and from a distinct device, and
/// returns their leaf certificate serials in lowercase hex, in evidence order.
// ponytail: no revocation check. Device certificates never expire, so NVIDIA's OCSP responders
// (ocsp.ndis.nvidia.com, one per chain level) are the only way a leaked device key stops
// verifying; the upgrade is an OCSP fetch with nonce at appraisal, or a revocation list pinned
// in the platform document.
pub fn appraise_gpus(
    gpus: &[GpuEvidence],
    nonce: &[u8; 32],
    count: usize,
    references: &[GpuReference],
    now: SystemTime,
) -> Result<Vec<String>, AppraisalError> {
    if gpus.len() != count {
        return Err(failed(format!("{} evidences for {count} GPUs", gpus.len())));
    }
    let mut serials = HashSet::new();
    gpus.iter()
        .map(|gpu| {
            let serial = appraise_gpu(gpu, nonce, references, now)?;
            if !serials.insert(serial.clone()) {
                return Err(failed(format!("device {serial} appears twice")));
            }
            Ok(serial)
        })
        .collect()
}

fn appraise_gpu(
    gpu: &GpuEvidence,
    nonce: &[u8; 32],
    references: &[GpuReference],
    now: SystemTime,
) -> Result<String, AppraisalError> {
    let leaf = verify_chain(&gpu.certificate_chain, references, now)?;
    let spdm = parse_spdm(&gpu.evidence)?;
    let signature = Signature::from_slice(&spdm.signature).map_err(|_| failed("signature"))?;
    leaf.key
        .verify(spdm.signed, &signature)
        .map_err(|_| failed("signature does not verify with the leaf key"))?;
    if &spdm.nonce != nonce {
        return Err(failed("nonce is not this request's"));
    }

    let opaque = Opaque::parse(spdm.opaque)?;
    if opaque.fwid != leaf.fwid {
        return Err(failed("FWID differs from the leaf certificate's"));
    }
    let reference = references
        .iter()
        .find(|r| r.root_sha256 == leaf.root && opaque.is(r))
        .ok_or_else(|| {
            AppraisalError::Unknown(format!(
                "no gpu reference for {} {} {} {} vbios {} driver {}",
                opaque.chip,
                opaque.project,
                opaque.project_sku,
                opaque.chip_sku,
                opaque.vbios_version,
                opaque.driver_version
            ))
        })?;
    for (index, value) in (1..=BLOCKS).zip(&spdm.blocks) {
        let allowed = reference.measurements.get(&index);
        let ok = match allowed {
            Some(values) => values.contains(value),
            None => value.0 == [0; 48],
        };
        if !ok {
            return Err(AppraisalError::Unknown(format!(
                "gpu measurement block {index} is {value}"
            )));
        }
    }
    Ok(leaf.serial)
}

struct Spdm<'a> {
    nonce: [u8; 32],
    blocks: Vec<Measurement>,
    opaque: &'a [u8],
    signed: &'a [u8],
    signature: [u8; SIGNATURE_LEN],
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], AppraisalError> {
        let (head, rest) = self
            .0
            .split_at_checked(n)
            .ok_or_else(|| failed("truncated"))?;
        self.0 = rest;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], AppraisalError> {
        let (head, rest) = self
            .0
            .split_first_chunk()
            .ok_or_else(|| failed("truncated"))?;
        self.0 = rest;
        Ok(*head)
    }

    fn u16(&mut self) -> Result<u16, AppraisalError> {
        self.array().map(u16::from_le_bytes)
    }
}

fn parse_spdm(evidence: &[u8]) -> Result<Spdm<'_>, AppraisalError> {
    let (signed, signature) = evidence
        .split_last_chunk::<SIGNATURE_LEN>()
        .ok_or_else(|| failed("truncated"))?;
    let mut r = Reader(signed);
    if r.array()? != REQUEST {
        return Err(failed("not a signed GET_MEASUREMENTS of all blocks"));
    }
    let nonce = r.array()?;
    if r.array()? != [0] {
        return Err(failed("slot is not 0"));
    }
    let [version, code, _, _] = r.array()?;
    if [version, code] != RESPONSE {
        return Err(failed("not an SPDM 1.1 MEASUREMENTS response"));
    }
    if r.array()? != [BLOCKS] {
        return Err(failed("block count"));
    }
    let [l0, l1, l2] = r.array()?;
    let record_len = usize::try_from(u32::from_le_bytes([l0, l1, l2, 0]))
        .map_err(|_| failed("record length"))?;
    let mut record = Reader(r.take(record_len)?);
    let mut blocks = Vec::with_capacity(BLOCKS.into());
    for index in 1..=BLOCKS {
        let [block_index, spec] = record.array()?;
        let size = record.u16()?;
        let [_value_type] = record.array()?;
        let value_len = record.u16()?;
        if block_index != index || spec != DMTF_SPEC || size != 51 || value_len != 48 {
            return Err(failed(format!(
                "measurement block {index} is not a SHA-384"
            )));
        }
        blocks.push(Measurement(record.array()?));
    }
    if !record.0.is_empty() {
        return Err(failed("measurement record is longer than its blocks"));
    }
    let _responder_nonce = r.take(32)?;
    let opaque_len = r.u16()?;
    let opaque = r.take(opaque_len.into())?;
    if !r.0.is_empty() {
        return Err(failed("trailing bytes"));
    }
    Ok(Spdm {
        nonce,
        blocks,
        opaque,
        signed,
        signature: *signature,
    })
}

struct Opaque {
    chip: String,
    project: String,
    project_sku: String,
    chip_sku: String,
    vbios_version: String,
    driver_version: String,
    fwid: [u8; 48],
}

impl Opaque {
    fn parse(data: &[u8]) -> Result<Self, AppraisalError> {
        let mut fields = BTreeMap::new();
        let mut r = Reader(data);
        while !r.0.is_empty() {
            let kind = r.u16()?;
            let len = r.u16()?;
            let value = r.take(len.into())?;
            // Every type the B300 firmware reports. Any other is refused, so a firmware that
            // starts reporting something new is looked at before it is accepted.
            if !matches!(kind, 3 | 4 | 6 | 11..=20 | 33..=36) {
                return Err(failed(format!("unknown opaque type {kind}")));
            }
            if fields.insert(kind, value).is_some() {
                return Err(failed(format!("opaque type {kind} repeated")));
            }
        }
        let field = |kind: u16| {
            fields
                .get(&kind)
                .copied()
                .ok_or_else(|| failed(format!("opaque type {kind} missing")))
        };
        let text = |kind: u16| {
            let value = field(kind)?;
            let end = value.iter().position(|b| *b == 0).unwrap_or(value.len());
            value
                .get(..end)
                .and_then(|v| std::str::from_utf8(v).ok())
                .map(str::to_owned)
                .ok_or_else(|| failed(format!("opaque type {kind} is not text")))
        };
        if field(tlv::OPAQUE_DATA_VERSION)? != [1, 0] {
            return Err(failed("opaque data version"));
        }
        // Little-endian bytes b0..b7 of 97.10.52.00.17 are 00 52 10 97 17 00 00 00.
        let vbios_version = match field(tlv::VBIOS_VERSION)? {
            [b0, b1, b2, b3, b4, 0, 0, 0] => {
                format!("{b3:02x}.{b2:02x}.{b1:02x}.{b0:02x}.{b4:02x}")
            }
            _ => return Err(failed("vbios version")),
        };
        Ok(Self {
            chip: text(tlv::CHIP_INFO)?,
            project: text(tlv::PROJECT)?,
            project_sku: text(tlv::PROJECT_SKU)?,
            chip_sku: text(tlv::CHIP_SKU)?,
            vbios_version,
            driver_version: text(tlv::DRIVER_VERSION)?,
            fwid: field(tlv::FWID)?
                .try_into()
                .map_err(|_| failed("FWID is not a SHA-384"))?,
        })
    }

    fn is(&self, r: &GpuReference) -> bool {
        self.chip == r.chip
            && self.project == r.project
            && self.project_sku == r.project_sku
            && self.chip_sku == r.chip_sku
            && self.vbios_version == r.vbios_version
            && self.driver_version == r.driver_version
    }
}

struct Leaf {
    key: VerifyingKey,
    serial: String,
    fwid: [u8; 48],
    root: ComposeHash,
}

/// The chain must end in a root some reference pins; the root shipped in the evidence is
/// trusted only because its bytes hash to that pin.
fn verify_chain(
    pem: &[u8],
    references: &[GpuReference],
    now: SystemTime,
) -> Result<Leaf, AppraisalError> {
    let ders = Pem::iter_from_buffer(pem)
        .map(|block| match block {
            Ok(block) if block.label == "CERTIFICATE" => Ok(block.contents),
            _ => Err(failed("certificate chain is not PEM certificates")),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let certs = ders
        .iter()
        .map(|der| match X509Certificate::from_der(der) {
            Ok(([], cert)) => Ok(cert),
            _ => Err(failed("certificate does not parse")),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (Some(leaf), Some(root)) = (certs.first(), certs.last()) else {
        return Err(failed("certificate chain is empty"));
    };
    let root_sha256 = ComposeHash::from(<[u8; 32]>::from(Sha256::digest(root.as_raw())));
    if !references.iter().any(|r| r.root_sha256 == root_sha256) {
        return Err(failed(format!(
            "chain ends in {root_sha256}, which is not pinned"
        )));
    }

    let now = now
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .and_then(|secs| ASN1Time::from_timestamp(secs).ok())
        .ok_or_else(|| failed("now"))?;
    for (depth, (cert, issuer)) in certs.iter().zip(certs.iter().skip(1)).enumerate() {
        let n = depth.saturating_add(1);
        let ca = issuer
            .basic_constraints()
            .ok()
            .flatten()
            .filter(|bc| bc.value.ca)
            .ok_or_else(|| failed(format!("certificate {n} is not a CA")))?;
        let within_path_len = ca
            .value
            .path_len_constraint
            .is_none_or(|max| u32::try_from(depth).is_ok_and(|d| d <= max));
        let may_sign = issuer
            .key_usage()
            .ok()
            .flatten()
            .is_some_and(|ku| ku.value.key_cert_sign());
        if !within_path_len || !may_sign || cert.issuer().as_raw() != issuer.subject().as_raw() {
            return Err(failed(format!("certificate {n} may not issue")));
        }
        if cert.signature_algorithm.algorithm != OID_SIG_ECDSA_WITH_SHA384 {
            return Err(failed(format!(
                "certificate {depth} is not ecdsa-with-SHA384"
            )));
        }
        let signature = Signature::from_der(&cert.signature_value.data)
            .map_err(|_| failed(format!("certificate {depth} signature")))?;
        p384_key(issuer)?
            .verify(cert.tbs_certificate.as_ref(), &signature)
            .map_err(|_| failed(format!("certificate {depth} is not signed by its issuer")))?;
    }
    if !certs.iter().all(|c| c.validity().is_valid_at(now)) {
        return Err(failed("certificate outside its validity"));
    }
    let leaf_is_ca = leaf
        .basic_constraints()
        .map_or(true, |bc| bc.is_some_and(|bc| bc.value.ca));
    let leaf_may_sign = leaf
        .key_usage()
        .ok()
        .flatten()
        .is_some_and(|ku| ku.value.digital_signature());
    if leaf_is_ca || !leaf_may_sign {
        return Err(failed("leaf may not sign evidence"));
    }

    Ok(Leaf {
        key: p384_key(leaf)?,
        serial: hex::encode(leaf.raw_serial()),
        fwid: leaf
            .extensions()
            .iter()
            .find(|e| e.oid.to_id_string() == TCB_INFO_OID)
            .and_then(|e| tcb_info_fwid(e.value))
            .ok_or_else(|| failed("leaf has no SHA-384 TcbInfo FWID"))?,
        root: root_sha256,
    })
}

fn p384_key(cert: &X509Certificate<'_>) -> Result<VerifyingKey, AppraisalError> {
    VerifyingKey::from_sec1_bytes(&cert.public_key().subject_public_key.data)
        .map_err(|_| failed("certificate key is not P-384"))
}

/// The first FWID of a TCG DICE TcbInfo: `SEQUENCE { …, fwids [6] IMPLICIT SEQUENCE OF
/// SEQUENCE { hashAlg OID, digest OCTET STRING }, … }`.
fn tcb_info_fwid(value: &[u8]) -> Option<[u8; 48]> {
    let ([], tcb_info) = Any::from_der(value).ok()? else {
        return None;
    };
    let mut fields = tcb_info.data;
    while !fields.is_empty() {
        let (rest, field) = Any::from_der(fields).ok()?;
        fields = rest;
        if field.class() == Class::ContextSpecific && field.tag() == Tag(6) {
            let (_, fwid) = Any::from_der(field.data).ok()?;
            let (digest, hash_alg) = Oid::from_der(fwid.data).ok()?;
            let ([], digest) = Any::from_der(digest).ok()? else {
                return None;
            };
            return (hash_alg == OID_NIST_HASH_SHA384 && digest.tag() == Tag::OctetString)
                .then(|| digest.data.try_into().ok())
                .flatten();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opaque_types_unknown_or_repeated_are_refused() {
        let evidence = std::fs::read(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../testdata/attest/b300-gpu-595.58.03/g1b.spdm.bin"),
        )
        .unwrap();
        let opaque = parse_spdm(&evidence).unwrap().opaque.to_vec();
        assert!(Opaque::parse(&opaque).is_ok());

        let mut unknown = opaque.clone();
        unknown[0] = 99;
        let mut repeated = opaque[..12].to_vec();
        repeated.extend_from_slice(&opaque);
        for (data, fragment) in [
            (unknown, "unknown opaque type 99"),
            (repeated, "type 6 repeated"),
        ] {
            let err = Opaque::parse(&data).err().unwrap();
            assert!(err.to_string().contains(fragment), "{err}");
        }
    }
}
