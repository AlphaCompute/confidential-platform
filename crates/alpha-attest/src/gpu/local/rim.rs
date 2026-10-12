//! NVIDIA's reference integrity manifests: TCG/SWID (ISO/IEC 19770-2:2015) documents with an
//! enveloped XML-DSig signature (ECDSA P-384, SHA-384, Canonical XML 1.1), signed by
//! `RIM L4 Signer` certificates that chain to `NVIDIA CoRIM signing Root CA`. The driver RIM
//! (`NV_GPU_CC_DRIVER_<chip>_<version>`) and the VBIOS RIM
//! (`NV_GPU_VBIOS_<project>_<sku>_<chip sku>_<version>`) hold the golden values of the GPU's
//! measurement blocks; NVIDIA's RIM service returns them as `{"id", "rim": base64, ...}`.
//!
//! **The KMS never canonicalises XML.** The offline cache refresh (`docs/local-gpu-verifier.md`,
//! "RIM cache") runs the canonicalisation XML-DSig prescribes, with a vetted library, and stores
//! its two outputs next to the signature: the canonical `SignedInfo` (the signed bytes) and the
//! canonical document without its `Signature` (the bytes `DigestValue` is over). Here the
//! signature is verified over the first, `SHA-384` of the second must equal the signed
//! `DigestValue`, and only then is the second parsed. A refresh that canonicalised wrongly
//! produces bytes that do not verify, so it can only fail closed; nothing it does is trusted.
//!
//! What the signed content does not say is whether a driver RIM is the confidential-computing
//! one: `NV_GPU_CC_DRIVER_GB100_580.159.03` and `NV_GPU_BMSAI_DRIVER_GB100_620.06` have the same
//! `Meta` fields. The release-signed `gpu_policy` therefore pins every RIM the verifier may use
//! by its signed digest (finding 2).
//!
//! Format reference: nv-attestation-sdk-cpp release 2026.10.02 (`src/rim.cpp`), nvtrust
//! `guest_tools/gpu_verifiers/local_gpu_verifier/src/verifier/rim/` (schemas), and the RIMs in
//! `testdata/gpu/nvidia`.

use std::collections::BTreeMap;

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use p384::ecdsa::signature::Verifier;
use p384::ecdsa::{Signature, VerifyingKey};
use roxmltree::{Document, Node, ParsingOptions};
use sha2::{Digest, Sha384};

use super::{Result, refuse};

pub const MAX_SIGNED_INFO: usize = 8 * 1024;
pub const MAX_DOCUMENT: usize = 512 * 1024;
/// XML nodes a document may have (a 64-measurement RIM has about 200).
pub const MAX_NODES: u32 = 20_000;
pub const MAX_RESOURCES: usize = 1024;
pub const MAX_ALTERNATIVES: usize = 16;
pub const MAX_GOLDEN_SIZE: usize = 1024;
/// RIM resources at or above this index are opaque-data records (minimum SVNs), not
/// measurements; the record's opaque field type is `index - 0x1000`.
pub const OPAQUE_RECORD_BASE: u32 = 0x1000;

pub const NS_DSIG: &str = "http://www.w3.org/2000/09/xmldsig#";
pub const NS_SWID: &str = "http://standards.iso.org/iso/19770/-2/2015/schema.xsd";
pub const NS_TCG_RIM: &str = "https://trustedcomputinggroup.org/resource/tcg-reference-integrity-manifest-rim-information-model/";
pub const NS_SHA384: &str = "http://www.w3.org/2001/04/xmlenc#sha384";
pub const NS_OPAQUE: &str = "https://docs.nvidia.com/attestation/specs/latest/opaque-data.html";
const C14N11: &str = "http://www.w3.org/2006/12/xml-c14n11";
const ECDSA_SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384";
const ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const DIGEST_SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#sha384";

/// Which firmware a RIM describes, decided by the format of its signed version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RimKind {
    /// Dotted decimal, e.g. `580.159.03`.
    Driver,
    /// Five dotted hex pairs, e.g. `97.00.88.00.0F`.
    Vbios,
}

/// One golden measurement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Golden {
    pub name: String,
    pub active: bool,
    pub size: usize,
    /// Any one of these values matches.
    pub alternatives: Vec<Vec<u8>>,
}

/// A minimum-SVN opaque record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MinSvn {
    pub name: String,
    pub opaque_type: u16,
    pub min_svn: u64,
}

/// A verified, parsed RIM.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rim {
    /// SHA-384 of the canonical document: the signed `DigestValue`, which `gpu_policy` pins.
    pub digest: [u8; 48],
    pub kind: RimKind,
    pub version: String,
    /// `ns1:PlatformModel`, the chip (e.g. `GB100`).
    pub platform_model: String,
    /// Golden values by RIM index (0-based; the SPDM block index minus one).
    pub measurements: BTreeMap<u32, Golden>,
    /// Active minimum-SVN records.
    pub min_svns: Vec<MinSvn>,
}

/// Verifies a RIM's signature over its canonical `SignedInfo` with the signer's key and returns
/// the `DigestValue` it signs. The `SignedInfo` must be NVIDIA's profile exactly: Canonical XML
/// 1.1, ECDSA SHA-384, one reference to the whole document (`URI=""`) with the enveloped-signature
/// transform then Canonical XML 1.1, SHA-384.
pub fn verify_signed_info(
    signed_info: &[u8],
    signature: &[u8],
    signer: &VerifyingKey,
) -> Result<[u8; 48]> {
    if signed_info.len() > MAX_SIGNED_INFO {
        return refuse("rim: SignedInfo is too large");
    }
    let signature = Signature::from_slice(signature)
        .or_else(|_| refuse("rim: SignatureValue is not a P-384 r ‖ s"))?;
    signer
        .verify(signed_info, &signature)
        .or_else(|_| refuse("rim: signature does not verify under the RIM signing certificate"))?;
    signed_digest(signed_info)
}

/// The `DigestValue` of a canonical `SignedInfo` in NVIDIA's profile. Meaningful only for bytes
/// whose signature [`verify_signed_info`] checked; public for the fuzz target.
pub fn signed_digest(signed_info: &[u8]) -> Result<[u8; 48]> {
    if signed_info.len() > MAX_SIGNED_INFO {
        return refuse("rim: SignedInfo is too large");
    }
    let text =
        std::str::from_utf8(signed_info).or_else(|_| refuse("rim: SignedInfo is not UTF-8"))?;
    let doc = parse_xml(text, "SignedInfo")?;
    let root = doc.root_element();
    expect_element(root, NS_DSIG, "SignedInfo")?;
    let mut children = elements(root)?;
    let c14n = next(&mut children, "CanonicalizationMethod")?;
    expect_algorithm(c14n, C14N11)?;
    let method = next(&mut children, "SignatureMethod")?;
    expect_algorithm(method, ECDSA_SHA384)?;
    let reference = next(&mut children, "Reference")?;
    if children.next().is_some() {
        return refuse("rim: SignedInfo has more than one Reference");
    }
    if reference.attribute("URI") != Some("") || reference.attributes().len() != 1 {
        return refuse("rim: the Reference is not to the whole document");
    }
    let mut parts = elements(reference)?;
    let transforms = next(&mut parts, "Transforms")?;
    let mut list = elements(transforms)?;
    expect_algorithm(next(&mut list, "Transform")?, ENVELOPED)?;
    expect_algorithm(next(&mut list, "Transform")?, C14N11)?;
    if list.next().is_some() {
        return refuse("rim: the Reference has more transforms than NVIDIA's profile");
    }
    expect_algorithm(next(&mut parts, "DigestMethod")?, DIGEST_SHA384)?;
    let value = next(&mut parts, "DigestValue")?;
    if parts.next().is_some() {
        return refuse("rim: the Reference has unexpected content");
    }
    let encoded: String = value
        .text()
        .unwrap_or_default()
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    let digest = BASE64_STANDARD
        .decode(encoded)
        .or_else(|_| refuse("rim: DigestValue is not base64"))?;
    <[u8; 48]>::try_from(digest).or_else(|_| refuse("rim: DigestValue is not 48 bytes"))
}

/// Parses the canonical document after checking it is the one `digest` (from
/// [`verify_signed_info`]) signs.
pub fn parse_document(document: &[u8], digest: &[u8; 48]) -> Result<Rim> {
    if document.len() > MAX_DOCUMENT {
        return refuse("rim: document is too large");
    }
    let actual: [u8; 48] = Sha384::digest(document).into();
    if actual != *digest {
        return refuse("rim: document is not the one its signature covers");
    }
    let text = std::str::from_utf8(document).or_else(|_| refuse("rim: document is not UTF-8"))?;
    let doc = parse_xml(text, "document")?;
    let root = doc.root_element();
    expect_element(root, NS_SWID, "SoftwareIdentity")?;
    let mut meta = None;
    let mut payload = None;
    for child in elements(root)? {
        if child.tag_name().namespace() != Some(NS_SWID) {
            continue;
        }
        let slot = match child.tag_name().name() {
            "Meta" => &mut meta,
            "Payload" => &mut payload,
            _ => continue,
        };
        if slot.replace(child).is_some() {
            return refuse(format!("rim: more than one {}", child.tag_name().name()));
        }
    }
    let meta = meta.ok_or_else(|| super::Refused("rim: no Meta".into()))?;
    let payload = payload.ok_or_else(|| super::Refused("rim: no Payload".into()))?;
    let version = meta
        .attribute("colloquialVersion")
        .ok_or_else(|| super::Refused("rim: Meta has no colloquialVersion".into()))?
        .to_owned();
    let kind = kind_of(&version)?;
    let platform_model = meta
        .attribute((NS_TCG_RIM, "PlatformModel"))
        .ok_or_else(|| super::Refused("rim: Meta has no PlatformModel".into()))?
        .to_owned();

    let mut measurements = BTreeMap::new();
    let mut min_svns = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for resource in elements(payload)? {
        if seen.len() >= MAX_RESOURCES {
            return refuse("rim: too many resources");
        }
        expect_element(resource, NS_SWID, "Resource")?;
        if resource.attribute("type") != Some("Measurement") {
            return refuse("rim: a resource is not a Measurement");
        }
        let index: u32 = number(resource, "index")?;
        if !seen.insert(index) {
            return refuse(format!("rim: index {index} appears twice"));
        }
        let active = match resource.attribute("active") {
            Some("True") => true,
            Some("False") => false,
            _ => return refuse(format!("rim: index {index}: active is not True or False")),
        };
        let name = resource.attribute("name").unwrap_or_default().to_owned();
        if index >= OPAQUE_RECORD_BASE {
            let opaque_type = index
                .checked_sub(OPAQUE_RECORD_BASE)
                .and_then(|t| u16::try_from(t).ok())
                .ok_or_else(|| {
                    super::Refused(format!("rim: opaque index {index} is out of range"))
                })?;
            if active {
                let min_svn = resource
                    .attribute((NS_OPAQUE, "minSvn"))
                    .and_then(decimal)
                    .ok_or_else(|| {
                        super::Refused(format!("rim: opaque record {index} has no minSvn"))
                    })?;
                min_svns.push(MinSvn {
                    name,
                    opaque_type,
                    min_svn,
                });
            }
            continue;
        }
        if index > 253 {
            return refuse(format!("rim: measurement index {index} has no SPDM block"));
        }
        let size: usize = number(resource, "size")?;
        let count: usize = number(resource, "alternatives")?;
        if size == 0 || size > MAX_GOLDEN_SIZE || count == 0 || count > MAX_ALTERNATIVES {
            return refuse(format!(
                "rim: index {index}: size or alternatives out of range"
            ));
        }
        let mut alternatives = Vec::with_capacity(count);
        for alt in 0..count {
            let hex_value = resource
                .attribute((NS_SHA384, format!("Hash{alt}").as_str()))
                .ok_or_else(|| super::Refused(format!("rim: index {index} lacks Hash{alt}")))?;
            let value = hex::decode(hex_value)
                .ok()
                .filter(|v| v.len() == size)
                .ok_or_else(|| {
                    super::Refused(format!("rim: index {index}: Hash{alt} is not {size} bytes"))
                })?;
            alternatives.push(value);
        }
        measurements.insert(
            index,
            Golden {
                name,
                active,
                size,
                alternatives,
            },
        );
    }
    Ok(Rim {
        digest: *digest,
        kind,
        version,
        platform_model,
        measurements,
        min_svns,
    })
}

/// A driver version is two or three dotted decimals, the first of three digits (`575.32`,
/// `580.159.03`); a VBIOS version is five dotted hex pairs (`97.00.88.00.0F`).
pub fn kind_of(version: &str) -> Result<RimKind> {
    let parts: Vec<&str> = version.split('.').collect();
    let hex_pair = |p: &&str| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit());
    let digits = |p: &str, len: std::ops::RangeInclusive<usize>| {
        len.contains(&p.len()) && p.chars().all(|c| c.is_ascii_digit())
    };
    if parts.len() == 5 && parts.iter().all(hex_pair) {
        Ok(RimKind::Vbios)
    } else if (2..=3).contains(&parts.len())
        && parts
            .iter()
            .enumerate()
            .all(|(i, p)| digits(p, if i == 0 { 3..=3 } else { 1..=3 }))
    {
        Ok(RimKind::Driver)
    } else {
        refuse(format!(
            "rim: version {version:?} is neither a driver nor a VBIOS version"
        ))
    }
}

fn parse_xml<'a>(text: &'a str, what: &str) -> Result<Document<'a>> {
    Document::parse_with_options(
        text,
        ParsingOptions {
            allow_dtd: false,
            nodes_limit: MAX_NODES,
            ..ParsingOptions::default()
        },
    )
    .or_else(|e| refuse(format!("rim: {what} is not well-formed XML: {e}")))
}

fn expect_element(node: Node<'_, '_>, ns: &str, name: &str) -> Result<()> {
    if node.is_element()
        && node.tag_name().namespace() == Some(ns)
        && node.tag_name().name() == name
    {
        Ok(())
    } else {
        refuse(format!(
            "rim: expected {name}, found {}",
            node.tag_name().name()
        ))
    }
}

/// The element children of `node`; text between them must be whitespace, and nothing else
/// (comments, processing instructions) may appear.
fn elements<'a, 'i>(node: Node<'a, 'i>) -> Result<std::vec::IntoIter<Node<'a, 'i>>> {
    let mut out = Vec::new();
    for child in node.children() {
        if child.is_element() {
            out.push(child);
        } else if child.is_text() {
            if !child.text().unwrap_or_default().trim().is_empty() {
                return refuse(format!("rim: text inside {}", node.tag_name().name()));
            }
        } else {
            return refuse(format!(
                "rim: unexpected node inside {}",
                node.tag_name().name()
            ));
        }
    }
    Ok(out.into_iter())
}

fn next<'a, 'i>(it: &mut std::vec::IntoIter<Node<'a, 'i>>, name: &str) -> Result<Node<'a, 'i>> {
    let node = it
        .next()
        .ok_or_else(|| super::Refused(format!("rim: SignedInfo lacks {name}")))?;
    expect_element(node, NS_DSIG, name)?;
    Ok(node)
}

fn expect_algorithm(node: Node<'_, '_>, algorithm: &str) -> Result<()> {
    if node.attribute("Algorithm") != Some(algorithm) || node.attributes().len() != 1 {
        return refuse(format!(
            "rim: {} is not {algorithm}",
            node.tag_name().name()
        ));
    }
    if node
        .children()
        .any(|c| !c.is_text() || !c.text().unwrap_or_default().trim().is_empty())
    {
        return refuse(format!("rim: {} has content", node.tag_name().name()));
    }
    Ok(())
}

fn decimal(v: &str) -> Option<u64> {
    (!v.is_empty() && v.len() <= 19 && v.chars().all(|c| c.is_ascii_digit()))
        .then(|| v.parse().ok())
        .flatten()
}

fn number<T: TryFrom<u64>>(node: Node<'_, '_>, attribute: &str) -> Result<T> {
    node.attribute(attribute)
        .and_then(decimal)
        .and_then(|v| T::try_from(v).ok())
        .ok_or_else(|| super::Refused(format!("rim: {attribute} is not a number")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_decide_the_kind() {
        assert_eq!(kind_of("580.159.03").unwrap(), RimKind::Driver);
        assert_eq!(kind_of("575.32").unwrap(), RimKind::Driver);
        assert_eq!(kind_of("97.00.88.00.0F").unwrap(), RimKind::Vbios);
        for bad in [
            "",
            "580",
            "97.00.88.00",
            "97.00.88.00.0G",
            "5x.1",
            "1.2.3.4.5.6",
            "580.1.2.3",
            "58.10",
        ] {
            assert!(kind_of(bad).is_err(), "{bad}");
        }
    }
}
