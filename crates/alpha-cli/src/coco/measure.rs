//! MRTD, RTMR1 and RTMR2 of a Kata TDX guest from its firmware, kernel and command line, as
//! QEMU ≥ 9 builds the TD and TDVF measures the boot. RTMR0 is not here: it covers ACPI and
//! SMBIOS tables that only Kata's QEMU generates for each VM shape, so it stays captured.

use alpha_attest::Measurement;
use sha2::{Digest, Sha384};

const PAGE: u64 = 0x1000;
const CHUNK: usize = 256;
/// GUIDs in their on-disk byte order.
const TABLE_FOOTER: [u8; 16] = [
    0xde, 0x82, 0xb5, 0x96, 0xb2, 0x1f, 0xf7, 0x45, 0xba, 0xea, 0xa3, 0x66, 0xc5, 0x5a, 0x08, 0x2d,
];
const TDX_METADATA: [u8; 16] = [
    0x35, 0x65, 0x7a, 0xe4, 0x4a, 0x98, 0x98, 0x47, 0x86, 0x5e, 0x46, 0x85, 0xa7, 0xbf, 0x8e, 0xc2,
];
const MR_EXTEND: u32 = 1;
const ZERO_PAGE: [u8; PAGE as usize] = [0; PAGE as usize];

struct Section<'a> {
    address: u64,
    size: u64,
    extend: bool,
    /// `None` for the zeroed TD HOB and temporary memory.
    source: Option<&'a [u8]>,
}

/// Each TDVF section in metadata order: every page `MEM.PAGE.ADD`ed, then, for an `MR.EXTEND`
/// section, its 256-byte chunks. Refuses whatever QEMU's `tdvf_parse_metadata` refuses, so no
/// value comes out for firmware Kata could not boot.
pub fn mrtd(firmware: &[u8]) -> Result<Measurement, String> {
    let descriptor = metadata_offset(firmware)?;
    if bytes::<4>(firmware, descriptor, 0)? != *b"TDVF" || u32_at(firmware, descriptor, 8)? != 1 {
        return Err("firmware: no TDVF metadata version 1".into());
    }
    let length = u32_at(firmware, descriptor, 4)? as usize;
    let count = u32_at(firmware, descriptor, 12)? as usize;
    if count < 2 || Some(length) != count.checked_mul(32).and_then(|n| n.checked_add(16)) {
        return Err(format!(
            "firmware: TDVF metadata length {length:#x} does not hold exactly its {count} sections"
        ));
    }
    let sections = range(firmware, add(descriptor, 16)?, add(descriptor, length)?)?
        .chunks_exact(32)
        .enumerate()
        .map(|(i, entry)| section(firmware, i, entry))
        .collect::<Result<Vec<_>, String>>()?;
    let mut h = Sha384::new();
    for s in sections {
        // A source holds exactly size / PAGE pages, so only a sourceless section reaches the zeros.
        let contents = s
            .source
            .unwrap_or_default()
            .chunks_exact(PAGE as usize)
            .chain(std::iter::repeat(ZERO_PAGE.as_slice()));
        // address + size fits in u64, so neither range below steps past it.
        let pages = (s.address..)
            .step_by(PAGE as usize)
            .take((s.size / PAGE) as usize);
        for (page, content) in pages.zip(contents) {
            tdx_op(&mut h, b"MEM.PAGE.ADD", page);
            if !s.extend {
                continue;
            }
            for (gpa, chunk) in (page..).step_by(CHUNK).zip(content.chunks_exact(CHUNK)) {
                tdx_op(&mut h, b"MR.EXTEND", gpa);
                h.update(chunk);
            }
        }
    }
    Ok(Measurement(h.finalize().into()))
}

/// QEMU copies a firmware volume's whole `MemoryDataSize` from the image at `DataOffset`, and
/// maps zeroed memory for the TD HOB and temporary memory; it ignores the PAGE.AUG attribute.
fn section<'a>(firmware: &'a [u8], i: usize, entry: &[u8]) -> Result<Section<'a>, String> {
    let data_offset = u32_at(entry, 0, 0)? as usize;
    let raw_size = u32_at(entry, 0, 4)?;
    let address = u64::from_le_bytes(bytes(entry, 0, 8)?);
    let size = u64::from_le_bytes(bytes(entry, 0, 16)?);
    let kind = u32_at(entry, 0, 24)?;
    if u64::from(raw_size) > size
        || address % PAGE != 0
        || size % PAGE != 0
        || address.checked_add(size).is_none()
    {
        return Err(format!(
            "firmware: section {i} is not a page range holding its data"
        ));
    }
    let source = match (kind, raw_size) {
        // Boot and configuration firmware volumes, with data.
        (0 | 1, 1..) => {
            let size = usize::try_from(size).map_err(|_| "firmware: section too large")?;
            Some(range(firmware, data_offset, add(data_offset, size)?)?)
        }
        // TD HOB and temporary memory, without.
        (2 | 3, 0) => None,
        _ => {
            return Err(format!(
                "firmware: section {i} of type {kind} with {raw_size:#x} data bytes is not one QEMU loads"
            ));
        }
    };
    Ok(Section {
        address,
        size,
        extend: u32_at(entry, 0, 28)? & MR_EXTEND != 0,
        source,
    })
}

/// RTMR1 when TDVF boots the kernel straight from QEMU's `-kernel`: the kernel's Authenticode
/// digest, then the four events every such boot logs after it.
pub fn rtmr1(kernel: &[u8]) -> Result<Measurement, String> {
    Ok(boot_chain(authenticode(kernel)?))
}

/// RTMR2 when the Linux EFI stub measures its load options: the `-append` string in UTF-16LE
/// with a terminating NUL, and no initrd.
pub fn rtmr2(cmdline: &str) -> Measurement {
    let mut h = Sha384::new();
    for unit in cmdline.encode_utf16().chain([0]) {
        h.update(unit.to_le_bytes());
    }
    extend([h.finalize().into()])
}

fn boot_chain(kernel: [u8; 48]) -> Measurement {
    extend([
        kernel,
        Sha384::digest(b"Calling EFI Application from Boot Option").into(),
        Sha384::digest([0u8; 4]).into(),
        Sha384::digest(b"Exit Boot Services Invocation").into(),
        Sha384::digest(b"Exit Boot Services Returned with Success").into(),
    ])
}

fn extend<const N: usize>(digests: [[u8; 48]; N]) -> Measurement {
    Measurement(digests.into_iter().fold([0; 48], |register, digest| {
        Sha384::new()
            .chain_update(register)
            .chain_update(digest)
            .finalize()
            .into()
    }))
}

/// The 128-byte buffer the TDX module hashes for a page operation: name, GPA, zeros.
fn tdx_op(h: &mut Sha384, name: &[u8], gpa: u64) {
    let mut label = [0u8; 16];
    for (dst, src) in label.iter_mut().zip(name) {
        *dst = *src;
    }
    h.update(label);
    h.update(gpa.to_le_bytes());
    h.update([0u8; 104]);
}

/// The OVMF GUIDed table ends 32 bytes before the end of the image and is read backwards.
fn metadata_offset(firmware: &[u8]) -> Result<usize, String> {
    let short = || "firmware: too short".to_string();
    let end = firmware.len().checked_sub(32).ok_or_else(short)?;
    let footer = end.checked_sub(18).ok_or_else(short)?;
    if bytes::<16>(firmware, footer, 2)? != TABLE_FOOTER {
        return Err("firmware: no GUIDed table footer".into());
    }
    let start = end
        .checked_sub(u16_at(firmware, footer, 0)?.into())
        .ok_or("firmware: GUIDed table longer than the image")?;
    let mut cursor = footer;
    while cursor > start {
        let entry = cursor.checked_sub(18).ok_or_else(short)?;
        let length = usize::from(u16_at(firmware, entry, 0)?);
        let entry_start = cursor
            .checked_sub(length)
            .filter(|s| length >= 18 && *s >= start)
            .ok_or("firmware: bad GUIDed entry length")?;
        if bytes::<16>(firmware, entry, 2)? == TDX_METADATA {
            let from_end = u32_at(firmware, entry.checked_sub(4).ok_or_else(short)?, 0)?;
            return firmware
                .len()
                .checked_sub(from_end as usize)
                .ok_or_else(|| "firmware: TDVF metadata offset out of range".into());
        }
        cursor = entry_start;
    }
    Err("firmware: no TDX metadata in the GUIDed table".into())
}

/// The PE image digest as EDK2's `Tcg2MeasurePeImage` computes it: headers without the checksum
/// and the certificate directory, sections in file order, then whatever trails them except the
/// certificate table.
fn authenticode(pe: &[u8]) -> Result<[u8; 48], String> {
    let lfanew = u32_at(pe, 0x3c, 0)? as usize;
    if bytes::<4>(pe, lfanew, 0)? != *b"PE\0\0" {
        return Err("kernel: not a PE image".into());
    }
    let coff = add(lfanew, 4)?;
    let optional = add(coff, 20)?;
    let (directory_count, directories) = match u16_at(pe, optional, 0)? {
        0x10b => (u32_at(pe, optional, 92)?, add(optional, 96)?),
        0x20b => (u32_at(pe, optional, 108)?, add(optional, 112)?),
        magic => {
            return Err(format!(
                "kernel: unknown PE optional header magic {magic:#x}"
            ));
        }
    };
    let checksum = add(optional, 64)?;
    let headers_end = u32_at(pe, optional, 60)? as usize;
    let mut h = Sha384::new();
    h.update(range(pe, 0, checksum)?);
    let cert_size = if directory_count <= 4 {
        h.update(range(pe, add(checksum, 4)?, headers_end)?);
        0
    } else {
        let security = add(directories, 32)?;
        h.update(range(pe, add(checksum, 4)?, security)?);
        h.update(range(pe, add(security, 8)?, headers_end)?);
        u32_at(pe, security, 4)? as usize
    };
    let table = add(optional, u16_at(pe, coff, 16)?.into())?;
    let mut sections = (0..usize::from(u16_at(pe, coff, 2)?))
        .map(|i| {
            let header = add(table, i.checked_mul(40).ok_or("image offset overflows")?)?;
            Ok((
                u32_at(pe, header, 20)? as usize,
                u32_at(pe, header, 16)? as usize,
            ))
        })
        .collect::<Result<Vec<_>, String>>()?;
    sections.sort_by_key(|(offset, _)| *offset);
    let mut hashed = headers_end;
    for (offset, size) in sections.into_iter().filter(|(_, size)| *size != 0) {
        h.update(range(pe, offset, add(offset, size)?)?);
        hashed = add(hashed, size)?;
    }
    if pe.len() > hashed {
        let end = pe
            .len()
            .checked_sub(cert_size)
            .filter(|end| *end >= hashed)
            .ok_or("kernel: certificate table overlaps the sections")?;
        h.update(range(pe, hashed, end)?);
    }
    Ok(h.finalize().into())
}

fn add(a: usize, b: usize) -> Result<usize, String> {
    a.checked_add(b)
        .ok_or_else(|| "image offset overflows".into())
}

fn range(b: &[u8], start: usize, end: usize) -> Result<&[u8], String> {
    b.get(start..end).ok_or_else(|| {
        format!(
            "{start:#x}..{end:#x} is outside the {:#x}-byte image",
            b.len()
        )
    })
}

fn bytes<const N: usize>(b: &[u8], base: usize, offset: usize) -> Result<[u8; N], String> {
    let at = add(base, offset)?;
    range(b, at, add(at, N)?)?
        .try_into()
        .map_err(|_| format!("{at:#x}: short read"))
}

fn u16_at(b: &[u8], base: usize, offset: usize) -> Result<u16, String> {
    bytes(b, base, offset).map(u16::from_le_bytes)
}

fn u32_at(b: &[u8], base: usize, offset: usize) -> Result<u32, String> {
    bytes(b, base, offset).map(u32::from_le_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha384(hex: &str) -> Measurement {
        format!("sha384:{hex}").parse().unwrap()
    }

    /// Expected values are the registers of B300 quotes of the two runtime classes.
    #[test]
    fn rtmr2_of_the_captured_command_lines() {
        let cpu = include_str!("../../../../testdata/coco/measure/kata-qemu-tdx.cmdline");
        let gpu =
            include_str!("../../../../testdata/coco/measure/kata-qemu-nvidia-gpu-tdx.cmdline");
        assert_eq!(
            rtmr2(cpu),
            sha384(
                "3661c5ad2aa8c26d3389061ad0f752e71ecf9047c11c14a9c4c99f3eb0bb5a6f91628bf81334ae4794a3f0b5e28f57ab"
            )
        );
        assert_eq!(
            rtmr2(gpu),
            sha384(
                "7cd6f2627a5004a31c75dded2a4ad05f6eae2f24a2e0ff3e6e4fe9a2ad82a868e6fd6a5ad904137d1852c1f7b2a8e4f6"
            )
        );
    }

    #[test]
    fn rtmr1_of_the_captured_kernel_digest() {
        let kernel = hex::decode(
            "aea2e6468dbdcca9e91bda36d1b093f6c5c3e4f50179757e4e7321f3c415ed40f0a6c05de176b4dcf0c4f5d0fe7f7846",
        )
        .unwrap();
        assert_eq!(
            boot_chain(kernel.try_into().unwrap()),
            sha384(
                "2bc5f4530adf0b51f5f89047ffbece35cbd1ccf80acdd458b809d3fe402b68305352c20b6089774d52457c4f552d6874"
            )
        );
    }

    const TDVF: &[u8] = include_bytes!("../../../../testdata/coco/measure/tdvf.bin");
    /// The TDVF descriptor's offset in `tdvf.bin`.
    const DESCRIPTOR: usize = 0x1000;

    /// A TDVF image with an extended boot volume, an added-only configuration volume and
    /// temporary memory, and a PE32+ image with sections out of file order, trailing data and a
    /// certificate table; expected values from an independent implementation.
    #[test]
    fn small_images_match_an_independent_implementation() {
        let pe = include_bytes!("../../../../testdata/coco/measure/pe.bin");
        assert_eq!(
            rtmr1(pe).unwrap(),
            sha384(
                "7282392c33ebf58d5d77cbabad48d99b0c53d12a3c60386b2b7c3cba41d417cc279c3e85ef7f8842a42961dc51169815"
            )
        );
        assert_eq!(
            mrtd(TDVF).unwrap(),
            sha384(
                "d2cecc79e35187c698ef051f1c45e872a195742154da73cf2b950b395a2022adfcf376fd30491d589f5ba88d7657701c"
            )
        );
        assert!(mrtd(&TDVF[..TDVF.len() - 1]).is_err());
        assert!(rtmr1(&pe[..0x300]).is_err());
    }

    fn patched(at: usize, value: u32) -> Vec<u8> {
        let mut image = TDVF.to_vec();
        image[at..at + 4].copy_from_slice(&value.to_le_bytes());
        image
    }

    #[test]
    fn firmware_qemu_would_not_load_is_refused() {
        let section = |i: usize, field: usize| DESCRIPTOR + 16 + 32 * i + field;
        for (what, image) in [
            (
                "length beyond the sections",
                patched(DESCRIPTOR + 4, 16 + 32 * 4),
            ),
            ("one section", patched(DESCRIPTOR + 12, 1)),
            ("unsupported type", patched(section(1, 24), 4)),
            ("temporary memory with data", patched(section(1, 4), 0x1000)),
            ("firmware volume without data", patched(section(2, 4), 0)),
            ("unaligned address", patched(section(0, 8), 0xFFFF_F800)),
        ] {
            assert!(mrtd(&image).is_err(), "{what}");
        }
    }
}
