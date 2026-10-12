//! The GPU attestation report: an SPDM 1.1 `GET_MEASUREMENTS` request followed by the GPU's
//! signed `MEASUREMENTS` response, exactly as NVML returns it and the attestation agent's NVIDIA
//! attester forwards it (DMTF DSP0274 1.1.x §10.11; NVIDIA nv-attestation-sdk-cpp
//! `src/spdm/spdm_req.cpp`, `spdm_resp.cpp`, `spdm_measurement_records.cpp` at release
//! 2026.10.02, commit 11b2bfeb42a1158aa08744603ecb239ccb3d2265).
//!
//! ```text
//! request  (37 bytes): 0x11 0xE0 param1 param2 nonce[32] slot_id
//! response:            0x11 0x60 param1 param2 n_blocks u8 record_len u24le record[record_len]
//!                      responder_nonce[32] opaque_len u16le opaque[opaque_len] signature[96]
//! record:              n_blocks × (index u8 ≥ 1, spec u8 = 1 (DMTF), size u16le,
//!                                  dmtf_type u8, dmtf_size u16le, value[dmtf_size])
//! ```
//!
//! The signature is ECDSA P-384 over SHA-384 of the request and the response up to the signature
//! (SPDM 1.1's L1/L2 transcript for a single exchange), `r ‖ s`, 48 bytes each, under the device
//! certificate chain's leaf key. Our nonce is the *request* nonce, which the signature covers.
//!
//! Only SPDM 1.1 is accepted: both the Hopper and the Blackwell reports NVIDIA publishes are 1.1.
//! SPDM 1.2 and later sign a prefixed transcript hash (DSP0274 1.2.x §15), and 1.3 adds a
//! requester context to the response; a report in either is refused rather than parsed with 1.1
//! rules. A 1.2 path is added only once a B300 capture shows one (G0).

use std::collections::BTreeMap;

use super::{Reader, Result, refuse};

/// SPDM 1.1.
pub const SPDM_VERSION_1_1: u8 = 0x11;
pub const GET_MEASUREMENTS: u8 = 0xE0;
pub const MEASUREMENTS: u8 = 0x60;
pub const REQUEST_LEN: usize = 37;
/// ECDSA P-384 `r ‖ s`.
pub const SIGNATURE_LEN: usize = 96;
/// A real report is about 4 KiB (64 blocks of 48-byte digests plus opaque data).
pub const MAX_REPORT_LEN: usize = 64 * 1024;
/// The largest measurement value accepted; NVIDIA's digests are 48 bytes, the FSP's raw
/// bit-stream blocks are at most a few hundred.
pub const MAX_MEASUREMENT_VALUE: usize = 1024;
/// DMTF measurement specification.
const SPEC_DMTF: u8 = 0x01;

/// One measurement block, by its SPDM index (1-based).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeasurementBlock {
    /// DMTFSpecMeasurementValueType: bit 7 set for a raw bit stream, else a digest; the low bits
    /// name what was measured (DSP0274 1.1 Table 45).
    pub value_type: u8,
    pub value: Vec<u8>,
}

/// A parsed report. Nothing in it is trusted until [`MeasurementReport::signed`] is verified
/// against the leaf of a verified certificate chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeasurementReport<'a> {
    /// The requester's nonce: ours, for a report collected over the GPU nonce.
    pub nonce: [u8; 32],
    pub slot_id: u8,
    /// Measurement blocks by SPDM index (1..=254); the RIMs number them from 0.
    pub blocks: BTreeMap<u8, MeasurementBlock>,
    pub responder_nonce: [u8; 32],
    /// NVIDIA's opaque data, parsed by [`super::opaque::parse`].
    pub opaque: &'a [u8],
    /// The bytes the signature covers: the request and the response up to the signature.
    pub signed: &'a [u8],
    pub signature: [u8; SIGNATURE_LEN],
}

/// Parses a report; refuses anything but one complete SPDM 1.1 exchange that asks for every
/// measurement with a signature.
pub fn parse(report: &[u8]) -> Result<MeasurementReport<'_>> {
    if report.len() > MAX_REPORT_LEN {
        return refuse(format!(
            "spdm: report is {} bytes, more than {MAX_REPORT_LEN}",
            report.len()
        ));
    }
    let signed_len = report
        .len()
        .checked_sub(SIGNATURE_LEN)
        .filter(|n| *n > REQUEST_LEN)
        .ok_or_else(|| super::Refused("spdm: report is too short".into()))?;
    let (signed, signature) = report.split_at(signed_len);
    let signature = <[u8; SIGNATURE_LEN]>::try_from(signature)
        .or_else(|_| refuse("spdm: signature is not 96 bytes"))?;

    let mut r = Reader::new(signed, "spdm request");
    let version = r.u8("SPDMVersion")?;
    check_version(version)?;
    if r.u8("RequestResponseCode")? != GET_MEASUREMENTS {
        return refuse("spdm: the request is not GET_MEASUREMENTS");
    }
    // Param1 bit 0: a signature was requested; SPDM 1.1 defines no other bit.
    if r.u8("Param1")? != 0x01 {
        return refuse("spdm: the request did not ask for a signed response");
    }
    // Param2 0xFF: every measurement block, so a missing block means the GPU has none.
    if r.u8("Param2")? != 0xFF {
        return refuse("spdm: the request did not ask for every measurement");
    }
    let nonce = r.array::<32>("Nonce")?;
    let slot_id = r.u8("SlotIDParam")?;
    if slot_id > 7 {
        return refuse(format!("spdm: slot {slot_id} is not 0 to 7"));
    }

    let mut r = Reader::new(
        signed.get(REQUEST_LEN..).unwrap_or_default(),
        "spdm response",
    );
    if r.u8("SPDMVersion")? != version {
        return refuse("spdm: the response's version is not the request's");
    }
    if r.u8("RequestResponseCode")? != MEASUREMENTS {
        return refuse("spdm: the response is not MEASUREMENTS");
    }
    let _param1 = r.u8("Param1")?;
    // Param2 bits 0..3: the slot whose certificate chain signed.
    if r.u8("Param2")? & 0x0F != slot_id {
        return refuse("spdm: the response names another slot than the request");
    }
    let count = r.u8("NumberOfBlocks")?;
    if count == 0 {
        return refuse("spdm: the response has no measurement block");
    }
    let record_len = usize::try_from(r.u24_le("MeasurementRecordLength")?)
        .or_else(|_| refuse("spdm: record length"))?;
    let record = r.take(record_len, "MeasurementRecord")?;
    let blocks = parse_record(record, count)?;
    let responder_nonce = r.array::<32>("Nonce")?;
    let opaque_len = usize::from(r.u16_le("OpaqueLength")?);
    let opaque = r.take(opaque_len, "OpaqueData")?;
    if !r.is_empty() {
        return refuse(format!(
            "spdm: {} bytes between the opaque data and the signature",
            r.remaining()
        ));
    }
    Ok(MeasurementReport {
        nonce,
        slot_id,
        blocks,
        responder_nonce,
        opaque,
        signed,
        signature,
    })
}

fn check_version(version: u8) -> Result<()> {
    match version {
        SPDM_VERSION_1_1 => Ok(()),
        0x12 | 0x13 => refuse(format!(
            "spdm: version {}.{} is not supported (its signature covers a prefixed transcript \
             hash; only SPDM 1.1 reports are appraised)",
            version >> 4,
            version & 0x0F
        )),
        other => refuse(format!("spdm: version byte {other:#04x} is not SPDM 1.1")),
    }
}

fn parse_record(record: &[u8], count: u8) -> Result<BTreeMap<u8, MeasurementBlock>> {
    let mut r = Reader::new(record, "spdm measurement record");
    let mut blocks = BTreeMap::new();
    for _ in 0..count {
        let index = r.u8("Index")?;
        if index == 0 || index == 0xFF {
            return refuse(format!("spdm: measurement index {index} is reserved"));
        }
        if r.u8("MeasurementSpecification")? != SPEC_DMTF {
            return refuse(format!(
                "spdm: measurement {index} is not in the DMTF specification format"
            ));
        }
        let size = usize::from(r.u16_le("MeasurementSize")?);
        let mut m = Reader::new(r.take(size, "Measurement")?, "spdm measurement");
        let value_type = m.u8("DMTFSpecMeasurementValueType")?;
        let value_size = usize::from(m.u16_le("DMTFSpecMeasurementValueSize")?);
        if value_size > MAX_MEASUREMENT_VALUE {
            return refuse(format!(
                "spdm: measurement {index} is {value_size} bytes, more than \
                 {MAX_MEASUREMENT_VALUE}"
            ));
        }
        let value = m.take(value_size, "DMTFSpecMeasurementValue")?.to_vec();
        if !m.is_empty() {
            return refuse(format!(
                "spdm: measurement {index} has {} bytes after its value",
                m.remaining()
            ));
        }
        if blocks
            .insert(index, MeasurementBlock { value_type, value })
            .is_some()
        {
            return refuse(format!("spdm: measurement index {index} appears twice"));
        }
    }
    if !r.is_empty() {
        return refuse(format!(
            "spdm: {} bytes after the last measurement block",
            r.remaining()
        ));
    }
    Ok(blocks)
}

/// Verifies the report's signature with the device's leaf key.
pub fn verify_signature(
    report: &MeasurementReport<'_>,
    key: &p384::ecdsa::VerifyingKey,
) -> Result<()> {
    use p384::ecdsa::Signature;
    use p384::ecdsa::signature::Verifier;
    let signature = Signature::from_slice(&report.signature)
        .or_else(|_| refuse("spdm: the signature is not a P-384 signature"))?;
    key.verify(report.signed, &signature)
        .or_else(|_| refuse("spdm: the report's signature does not verify under the device key"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A well-formed report with the given blocks and opaque data, signed by nobody.
    pub(crate) fn report(blocks: &[(u8, &[u8])], opaque: &[u8]) -> Vec<u8> {
        let mut out = vec![0x11, 0xE0, 0x01, 0xFF];
        out.extend([7u8; 32]);
        out.push(0);
        let mut record = Vec::new();
        for (index, value) in blocks {
            record.push(*index);
            record.push(1);
            record.extend(u16::try_from(value.len() + 3).unwrap().to_le_bytes());
            record.push(1);
            record.extend(u16::try_from(value.len()).unwrap().to_le_bytes());
            record.extend(*value);
        }
        out.extend([0x11, 0x60, 0, 0, u8::try_from(blocks.len()).unwrap()]);
        out.extend(&u32::try_from(record.len()).unwrap().to_le_bytes()[..3]);
        out.extend(record);
        out.extend([9u8; 32]);
        out.extend(u16::try_from(opaque.len()).unwrap().to_le_bytes());
        out.extend(opaque);
        out.extend([0u8; 96]);
        out
    }

    #[test]
    fn parses_blocks_nonce_and_opaque_data() {
        let r = report(&[(1, &[0xAA; 48]), (3, &[0xBB; 48])], b"opaque");
        let parsed = parse(&r).unwrap();
        assert_eq!(parsed.nonce, [7; 32]);
        assert_eq!(parsed.responder_nonce, [9; 32]);
        assert_eq!(parsed.blocks.len(), 2);
        assert_eq!(parsed.blocks[&3].value, vec![0xBB; 48]);
        assert_eq!(parsed.opaque, b"opaque");
        assert_eq!(parsed.signed.len(), r.len() - 96);
    }

    #[test]
    fn refuses_malformed_reports() {
        let good = report(&[(1, &[0xAA; 48])], b"");
        let edit = |at: usize, value: u8| {
            let mut r = good.clone();
            r[at] = value;
            r
        };
        let resp = REQUEST_LEN;
        for (case, bytes, reason) in [
            ("empty", Vec::new(), "too short"),
            ("SPDM 1.2", edit(0, 0x12), "1.2 is not supported"),
            ("SPDM 1.0", edit(0, 0x10), "not SPDM 1.1"),
            (
                "not GET_MEASUREMENTS",
                edit(1, 0x81),
                "not GET_MEASUREMENTS",
            ),
            ("unsigned request", edit(2, 0x00), "signed response"),
            ("one block only", edit(3, 0x01), "every measurement"),
            ("response version", edit(resp, 0x12), "version is not"),
            ("not MEASUREMENTS", edit(resp + 1, 0x61), "not MEASUREMENTS"),
            ("other slot", edit(resp + 3, 0x01), "slot"),
            ("no blocks", edit(resp + 4, 0), "no measurement block"),
            ("more blocks than recorded", edit(resp + 4, 2), "needs"),
            ("index 0", edit(resp + 8, 0), "reserved"),
            ("not DMTF", edit(resp + 9, 2), "DMTF"),
            ("value overruns its block", edit(resp + 13, 49), "needs"),
            (
                "value shorter than its block",
                edit(resp + 13, 47),
                "after its value",
            ),
            ("too long", vec![0x11; MAX_REPORT_LEN + 1], "more than"),
        ] {
            let error = parse(&bytes).unwrap_err().to_string();
            assert!(error.contains(reason), "{case}: {error}");
        }
        // Trailing bytes before the signature, and a duplicated index.
        let mut extra = good.clone();
        extra.insert(good.len() - 96, 0);
        assert!(parse(&extra).is_err());
        let twice = report(&[(1, &[0xAA; 48]), (1, &[0xAA; 48])], b"");
        assert!(
            parse(&twice)
                .unwrap_err()
                .to_string()
                .contains("appears twice")
        );
    }

    #[test]
    fn every_truncation_is_refused_without_panicking() {
        let good = report(&[(1, &[0xAA; 48]), (2, &[0xBB; 3])], b"opaque data");
        for len in 0..good.len() {
            let _ = parse(&good[..len]);
        }
        for i in 0..good.len() {
            let mut r = good.clone();
            r[i] ^= 0xFF;
            let _ = parse(&r);
        }
    }
}
