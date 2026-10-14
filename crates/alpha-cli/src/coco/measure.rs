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
const PAGE_AUG: u32 = 2;

/// Each TDVF section in metadata order: every page `MEM.PAGE.ADD`ed, then, for an `MR.EXTEND`
/// section, its 256-byte chunks.
pub fn mrtd(firmware: &[u8]) -> Result<Measurement, String> {
    let descriptor = metadata_offset(firmware)?;
    if bytes::<4>(firmware, descriptor, 0)? != *b"TDVF" || u32_at(firmware, descriptor, 8)? != 1 {
        return Err("firmware: no TDVF metadata version 1".into());
    }
    let mut h = Sha384::new();
    for i in 0..u32_at(firmware, descriptor, 12)? {
        let at = add(descriptor, add(16, mul(i as usize, 32)?)?)?;
        let data_offset = u32_at(firmware, at, 0)? as usize;
        let raw_size = u32_at(firmware, at, 4)? as usize;
        let address = u64::from_le_bytes(bytes(firmware, at, 8)?);
        let size = u64::from_le_bytes(bytes(firmware, at, 16)?);
        let attributes = u32_at(firmware, at, 28)?;
        if attributes & PAGE_AUG != 0 {
            continue;
        }
        if size % PAGE != 0 || address % PAGE != 0 || address.checked_add(size).is_none() {
            return Err(format!("firmware: section {i} is not a page range"));
        }
        let mut chunks = if attributes & MR_EXTEND == 0 {
            None
        } else if u64::try_from(raw_size).ok() == Some(size) {
            Some(range(firmware, data_offset, add(data_offset, raw_size)?)?.chunks_exact(CHUNK))
        } else {
            return Err(format!(
                "firmware: section {i} measures fewer bytes than it maps"
            ));
        };
        // address + size fits in u64, so neither range below steps past it.
        for page in (address..)
            .step_by(PAGE as usize)
            .take((size / PAGE) as usize)
        {
            tdx_op(&mut h, b"MEM.PAGE.ADD", page);
            let Some(chunks) = chunks.as_mut() else {
                continue;
            };
            let per_page = chunks.by_ref().take(PAGE as usize / CHUNK);
            for (gpa, chunk) in (page..).step_by(CHUNK).zip(per_page) {
                tdx_op(&mut h, b"MR.EXTEND", gpa);
                h.update(chunk);
            }
        }
    }
    Ok(Measurement(h.finalize().into()))
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
            let header = add(table, mul(i, 40)?)?;
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

fn mul(a: usize, b: usize) -> Result<usize, String> {
    a.checked_mul(b)
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

    /// A TDVF image with an extended, an added and an accepted-later section, and a PE32+ image
    /// with sections out of file order, trailing data and a certificate table; expected values
    /// from an independent implementation.
    #[test]
    fn small_images_match_an_independent_implementation() {
        let pe = include_bytes!("../../../../testdata/coco/measure/pe.bin");
        let tdvf = include_bytes!("../../../../testdata/coco/measure/tdvf.bin");
        assert_eq!(
            rtmr1(pe).unwrap(),
            sha384(
                "7282392c33ebf58d5d77cbabad48d99b0c53d12a3c60386b2b7c3cba41d417cc279c3e85ef7f8842a42961dc51169815"
            )
        );
        assert_eq!(
            mrtd(tdvf).unwrap(),
            sha384(
                "dc6a713c35f8b7fa7843edfb7f2ac61e9f562402dd8b9d6419cb938673db11c15a8cba117ed701c7e7bd5e756eb8d7ad"
            )
        );
        assert!(mrtd(&tdvf[..tdvf.len() - 1]).is_err());
        assert!(rtmr1(&pe[..0x300]).is_err());
    }
}
