//! NVIDIA's opaque data in the GPU's signed `MEASUREMENTS` response: what the GPU firmware
//! reports about itself (driver and VBIOS versions, SKU, FWID, NVDEC state, mode flags). It is
//! signed by the device, but it is written by the firmware being appraised, so nothing here is
//! taken as the firmware's identity on its own word (finding 1): the versions must agree with the
//! RIMs the measurements matched, and the FWID with the device certificate.
//!
//! Two encodings (nv-attestation-sdk-cpp release 2026.10.02, `src/spdm/spdm_opaque_data_parser.cpp`
//! and `src/gpu/spdm/gpu_opaque_data_parser.cpp`):
//!
//! ```text
//! legacy:  repeated { type u16le, size u16le, data[size] }; version = field 34 (0 when absent)
//! NVDAOD:  "NVDAOD" profile u16le (= 0) major u8 minor u8 reserved[2]
//!          repeated { type u16le, value_type u16le, size u16le, data[size] }; version = major
//! ```
//!
//! A version above 2 is refused (the SDK's bound), as is a field that appears twice: the SDK
//! keeps the last copy, which would let a report carry two different driver versions.

use std::collections::BTreeMap;

use super::{Reader, Result, refuse};

pub const DRIVER_VERSION: u16 = 3;
pub const VBIOS_VERSION: u16 = 6;
pub const NVDEC0_STATUS: u16 = 11;
pub const CHIP_SKU: u16 = 15;
pub const PROJECT: u16 = 17;
pub const PROJECT_SKU: u16 = 18;
pub const FWID: u16 = 20;
pub const PROTECTED_PCIE_STATUS: u16 = 21;
pub const OPAQUE_DATA_VERSION: u16 = 34;
pub const CHIP_INFO: u16 = 35;
pub const FEATURE_FLAG: u16 = 36;

/// `rmDataValueType` of an `NVDAOD` minimum-SVN entry (NVIDIA opaque-data spec, `ns3:minSvn`).
pub const MIN_SVN_VALUE_TYPE: u16 = 0x87;
/// The newest opaque data version this parser knows.
pub const MAX_VERSION: u64 = 2;
/// `FEATURE_FLAG` exists from opaque data version 1.
pub const MIN_VERSION_FOR_FEATURE_FLAG: u64 = 1;
const MAGIC: &[u8; 6] = b"NVDAOD";
const MAX_FIELDS: usize = 128;

/// One opaque field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Field {
    /// 0 in the legacy encoding.
    pub value_type: u16,
    pub data: Vec<u8>,
}

/// The GPU's mode as `FEATURE_FLAG` reports it (`GpuEvidence::AttestationReport::
/// OpaqueDataFeatureFlag`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeatureFlag {
    /// Multi-GPU passthrough.
    Mpt,
    /// Single-GPU passthrough.
    Spt,
    /// Protected PCIe: the GPUs' CC mode is off and only the PCIe links are protected.
    Ppcie,
    Other(u64),
}

/// Parsed opaque data.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OpaqueData {
    pub version: u64,
    /// Whether the `NVDAOD` header was present.
    pub nvdaod: bool,
    pub fields: BTreeMap<u16, Field>,
}

/// Parses opaque data; refuses an unknown profile or version, a duplicated field and a field that
/// overruns the data.
pub fn parse(raw: &[u8]) -> Result<OpaqueData> {
    let (nvdaod, header_version, body) = match raw.strip_prefix(MAGIC) {
        Some(rest) => {
            let mut h = Reader::new(rest, "opaque header");
            if h.u16_le("profile")? != 0 {
                return refuse("opaque: NVDAOD profile is not 0");
            }
            let major = h.u8("major")?;
            let _minor = h.u8("minor")?;
            let _reserved = h.take(2, "reserved")?;
            (
                true,
                Some(u64::from(major)),
                rest.get(6..).unwrap_or_default(),
            )
        }
        None => (false, None, raw),
    };
    let mut r = Reader::new(body, "opaque data");
    let mut fields = BTreeMap::new();
    while !r.is_empty() {
        if fields.len() >= MAX_FIELDS {
            return refuse(format!("opaque: more than {MAX_FIELDS} fields"));
        }
        let kind = r.u16_le("type")?;
        let value_type = if nvdaod { r.u16_le("value type")? } else { 0 };
        let size = usize::from(r.u16_le("size")?);
        let data = r.take(size, "data")?.to_vec();
        if fields.insert(kind, Field { value_type, data }).is_some() {
            return refuse(format!("opaque: field {kind} appears twice"));
        }
    }
    let version = match header_version {
        Some(major) => major,
        None => match fields.get(&OPAQUE_DATA_VERSION) {
            Some(field) => le_uint(&field.data)
                .ok_or_else(|| super::Refused("opaque: version field is malformed".into()))?,
            None => 0,
        },
    };
    if version > MAX_VERSION {
        return refuse(format!(
            "opaque: data version {version} is newer than this verifier knows ({MAX_VERSION})"
        ));
    }
    Ok(OpaqueData {
        version,
        nvdaod,
        fields,
    })
}

/// A little-endian unsigned integer of 1 to 8 bytes.
fn le_uint(data: &[u8]) -> Option<u64> {
    if data.is_empty() || data.len() > 8 {
        return None;
    }
    let mut bytes = [0u8; 8];
    bytes.get_mut(..data.len())?.copy_from_slice(data);
    Some(u64::from_le_bytes(bytes))
}

/// The text of a NUL-padded ASCII field: printable, at most 64 characters, not empty.
fn text(data: &[u8], what: &str) -> Result<String> {
    let trimmed = match data.iter().rposition(|b| *b != 0) {
        Some(last) => data.get(..=last).unwrap_or_default(),
        None => &[],
    };
    if trimmed.is_empty()
        || trimmed.len() > 64
        || !trimmed.iter().all(|b| b.is_ascii_graphic() || *b == b' ')
    {
        return refuse(format!("opaque: {what} is not printable text"));
    }
    Ok(String::from_utf8_lossy(trimmed).into_owned())
}

impl OpaqueData {
    pub fn field(&self, kind: u16) -> Option<&Field> {
        self.fields.get(&kind)
    }

    fn required(&self, kind: u16, what: &str) -> Result<&Field> {
        self.field(kind)
            .ok_or_else(|| super::Refused(format!("opaque: no {what} field")))
    }

    /// The driver version the firmware reports, e.g. `580.159.03`.
    pub fn driver_version(&self) -> Result<String> {
        text(
            &self.required(DRIVER_VERSION, "driver version")?.data,
            "driver version",
        )
    }

    /// The VBIOS version the firmware reports, formatted as NVIDIA's RIMs write it: the eight
    /// little-endian bytes `b0..b7` read as `b3.b2.b1.b0.b4`, upper-case hex (the SDK's
    /// `get_vbios_version`; e.g. `00 88 00 97 0f 00 00 00` is `97.00.88.00.0F`).
    pub fn vbios_version(&self) -> Result<String> {
        let data = &self.required(VBIOS_VERSION, "VBIOS version")?.data;
        let [b0, b1, b2, b3, b4, _, _, _] = <[u8; 8]>::try_from(data.as_slice())
            .or_else(|_| refuse("opaque: VBIOS version is not 8 bytes"))?;
        Ok(format!("{b3:02X}.{b2:02X}.{b1:02X}.{b0:02X}.{b4:02X}"))
    }

    /// NVDEC0's state: `0xAA` enabled, `0x55` disabled (measurement 35 is then not compared).
    pub fn nvdec0_status(&self) -> Result<u8> {
        match self
            .required(NVDEC0_STATUS, "NVDEC0 status")?
            .data
            .as_slice()
        {
            [status] => Ok(*status),
            _ => refuse("opaque: NVDEC0 status is not one byte"),
        }
    }

    /// The firmware ID the GPU reports (SHA-384 of its FMC), to be matched against the device
    /// certificate's `TcbInfo`.
    pub fn fwid(&self) -> Option<&[u8]> {
        self.field(FWID).map(|f| f.data.as_slice())
    }

    /// The mode flag, from opaque data version 1.
    pub fn feature_flag(&self) -> Result<Option<FeatureFlag>> {
        if self.version < MIN_VERSION_FOR_FEATURE_FLAG {
            return Ok(None);
        }
        let Some(field) = self.field(FEATURE_FLAG) else {
            return Ok(None);
        };
        let value = le_uint(&field.data)
            .ok_or_else(|| super::Refused("opaque: feature flag is malformed".into()))?;
        Ok(Some(match value {
            0 => FeatureFlag::Mpt,
            1 => FeatureFlag::Spt,
            2 => FeatureFlag::Ppcie,
            other => FeatureFlag::Other(other),
        }))
    }

    /// A minimum-SVN field as a RIM's opaque record compares it: two little-endian bytes of
    /// value type [`MIN_SVN_VALUE_TYPE`]; `None` when absent or of another shape.
    pub fn min_svn(&self, kind: u16) -> Option<u16> {
        let field = self.field(kind)?;
        if field.value_type != MIN_SVN_VALUE_TYPE {
            return None;
        }
        let bytes = <[u8; 2]>::try_from(field.data.as_slice()).ok()?;
        Some(u16::from_le_bytes(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn legacy(fields: &[(u16, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (kind, data) in fields {
            out.extend(kind.to_le_bytes());
            out.extend(u16::try_from(data.len()).unwrap().to_le_bytes());
            out.extend(*data);
        }
        out
    }

    #[test]
    fn reads_versions_as_nvidia_formats_them() {
        let raw = legacy(&[
            (DRIVER_VERSION, b"575.32\0"),
            (VBIOS_VERSION, &[0x00, 0x88, 0x00, 0x97, 0x0f, 0, 0, 0]),
            (NVDEC0_STATUS, b"U"),
        ]);
        let o = parse(&raw).unwrap();
        assert_eq!(o.version, 0);
        assert_eq!(o.driver_version().unwrap(), "575.32");
        assert_eq!(o.vbios_version().unwrap(), "97.00.88.00.0F");
        assert_eq!(o.nvdec0_status().unwrap(), 0x55);
        assert_eq!(o.feature_flag().unwrap(), None);
    }

    #[test]
    fn reads_the_nvdaod_format_with_value_types() {
        let mut raw = b"NVDAOD".to_vec();
        raw.extend([0, 0, 2, 0, 0, 0]);
        for (kind, vt, data) in [
            (FEATURE_FLAG, 0u16, &[1u8, 0][..]),
            (0x30, MIN_SVN_VALUE_TYPE, &[5, 0][..]),
        ] {
            raw.extend(kind.to_le_bytes());
            raw.extend(vt.to_le_bytes());
            raw.extend(u16::try_from(data.len()).unwrap().to_le_bytes());
            raw.extend(data);
        }
        let o = parse(&raw).unwrap();
        assert!(o.nvdaod);
        assert_eq!(o.version, 2);
        assert_eq!(o.feature_flag().unwrap(), Some(FeatureFlag::Spt));
        assert_eq!(o.min_svn(0x30), Some(5));
        assert_eq!(o.min_svn(FEATURE_FLAG), None);
    }

    #[test]
    fn refuses_ambiguous_or_unknown_opaque_data() {
        let twice = legacy(&[(DRIVER_VERSION, b"1.0"), (DRIVER_VERSION, b"2.0")]);
        assert!(
            parse(&twice)
                .unwrap_err()
                .to_string()
                .contains("appears twice")
        );
        let newer = legacy(&[(OPAQUE_DATA_VERSION, &[3, 0])]);
        assert!(parse(&newer).unwrap_err().to_string().contains("newer"));
        let mut profile = b"NVDAOD".to_vec();
        profile.extend([1, 0, 1, 0, 0, 0]);
        assert!(parse(&profile).unwrap_err().to_string().contains("profile"));
        let overrun = [3u8, 0, 10, 0, b'1'];
        assert!(parse(&overrun).is_err());
        let o = parse(&legacy(&[(VBIOS_VERSION, &[1, 2, 3])])).unwrap();
        assert!(o.vbios_version().is_err());
        let o = parse(&legacy(&[(DRIVER_VERSION, b"\0\0")])).unwrap();
        assert!(o.driver_version().is_err());
        let o = parse(&legacy(&[(DRIVER_VERSION, b"5\n7")])).unwrap();
        assert!(o.driver_version().is_err());
        assert!(o.nvdec0_status().is_err());
    }
}
