//! Reference values for one GPU from NVIDIA's signed Reference Integrity Manifests: a SWID tag
//! per driver and per VBIOS, each signed with an enveloped XML signature. Only the one profile
//! NVIDIA signs with is verified: inclusive C14N 1.1, ECDSA P-384 with SHA-384, one reference to
//! the whole document. The canonical form is computed over the same tree the values are read
//! from, so a canonicalization that strays from the standard refuses a RIM rather than accepting
//! another one.

use std::collections::BTreeMap;
use std::time::SystemTime;

use alpha_core::ComposeHash;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use p384::ecdsa::Signature;
use p384::ecdsa::signature::Verifier;
use roxmltree::{Document, Node, NodeType};
use sha2::{Digest, Sha384};

use super::{BLOCKS, GpuEvidence, GpuReference, OcspQuery, read_gpu, verify_chain};
use crate::{AppraisalError, Measurement};

/// SHA-256 of the DER of "NVIDIA CoRIM signing Root CA", the root NVIDIA's local GPU verifier
/// pins as `verifier_RIM_root.pem`.
const RIM_ROOT: &str = "sha256:12977b5115acb0381179279fffeb5a8c4d264971ebb32298023a465fa41df5d1";
/// SHA-256 of the DER of "NVIDIA Device Identity CA", the root NVIDIA publishes for GPU device
/// certificates.
const DEVICE_ROOT: &str = "sha256:102bf659d5419614c9d8e6aecebc80454eb26b1df6a769ac720b9a690b167b48";

const SWID: &str = "http://standards.iso.org/iso/19770/-2/2015/schema.xsd";
const DSIG: &str = "http://www.w3.org/2000/09/xmldsig#";
const SHA384_NS: &str = "http://www.w3.org/2001/04/xmlenc#sha384";
const C14N11: &str = "http://www.w3.org/2006/12/xml-c14n11";
const ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const ECDSA_SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384";
const SHA384_DIGEST: &str = "http://www.w3.org/2001/04/xmldsig-more#sha384";

fn failed(what: impl Into<String>) -> AppraisalError {
    AppraisalError::Failed(what.into())
}

struct Rim {
    version: String,
    product: String,
    /// The active measurements by SPDM block index, which is the RIM's index plus one.
    measurements: BTreeMap<u8, Vec<Measurement>>,
    signers: Vec<OcspQuery>,
}

/// The reference for the GPU that produced `evidence`, whose chain must end in NVIDIA's device
/// root: its identity and FWID as it reports them, and for each measurement block the
/// alternatives the driver or the VBIOS RIM lists. Refuses when the GPU reports a block neither
/// RIM lists it with, or a nonzero block neither covers.
/// Also returns an OCSP query for each certificate below the RIM root that signs either RIM;
/// the reference stands only once each answers `good`.
pub fn gpu_reference(
    evidence: &GpuEvidence,
    driver_rim: &[u8],
    vbios_rim: &[u8],
    now: SystemTime,
) -> Result<(GpuReference, Vec<OcspQuery>), AppraisalError> {
    let device_root = pin(DEVICE_ROOT)?;
    let (leaf, spdm, opaque) = read_gpu(evidence, &[device_root], now)?;
    let mut covered = BTreeMap::new();
    let mut signers = Vec::new();
    for (name, xml, version) in [
        ("driver", driver_rim, &opaque.driver_version),
        ("vbios", vbios_rim, &opaque.vbios_version),
    ] {
        let rim = verify_rim(xml, now).map_err(|e| match e {
            AppraisalError::Failed(what) => AppraisalError::Failed(format!("{name} RIM: {what}")),
            e => e,
        })?;
        if !rim.version.eq_ignore_ascii_case(version) || rim.product != opaque.chip {
            return Err(failed(format!(
                "{name} RIM is for {} {}, the GPU is {} {version}",
                rim.product, rim.version, opaque.chip
            )));
        }
        for query in rim.signers {
            if !signers.contains(&query) {
                signers.push(query);
            }
        }
        for (block, values) in rim.measurements {
            if covered.insert(block, values).is_some() {
                return Err(failed(format!("block {block} is active in both RIMs")));
            }
        }
    }
    for (block, value) in (1..=BLOCKS).zip(&spdm.blocks) {
        let listed = match covered.get(&block) {
            Some(values) => values.contains(value),
            None => value.0 == [0; 48],
        };
        if !listed {
            return Err(AppraisalError::Unknown(format!(
                "gpu measurement block {block} is {value}, which no RIM lists"
            )));
        }
    }
    let reference = GpuReference {
        root_sha256: leaf.root,
        chip: opaque.chip,
        project: opaque.project,
        project_sku: opaque.project_sku,
        chip_sku: opaque.chip_sku,
        vbios_version: opaque.vbios_version,
        driver_version: opaque.driver_version,
        fwid: Measurement(opaque.fwid),
        feature_flag: opaque.feature_flag,
        measurements: covered,
    };
    Ok((reference, signers))
}

fn pin(hash: &str) -> Result<ComposeHash, AppraisalError> {
    hash.parse().map_err(|_| failed("pinned root"))
}

fn verify_rim(xml: &[u8], now: SystemTime) -> Result<Rim, AppraisalError> {
    let text = std::str::from_utf8(xml).map_err(|_| failed("not UTF-8"))?;
    let doc = Document::parse(text).map_err(|e| failed(format!("not XML: {e}")))?;
    let root = doc.root_element();
    if !root.has_tag_name((SWID, "SoftwareIdentity")) {
        return Err(failed("not a SWID tag"));
    }
    let signature = child(root, DSIG, "Signature")?;
    let signed_info = child(signature, DSIG, "SignedInfo")?;
    let algorithms = [
        ("CanonicalizationMethod", C14N11),
        ("SignatureMethod", ECDSA_SHA384),
    ];
    for (name, algorithm) in algorithms {
        if child(signed_info, DSIG, name)?.attribute("Algorithm") != Some(algorithm) {
            return Err(failed(format!("{name} is not {algorithm}")));
        }
    }
    let reference = child(signed_info, DSIG, "Reference")?;
    let transforms: Vec<_> = elements(child(reference, DSIG, "Transforms")?)
        .map(|t| t.attribute("Algorithm"))
        .collect();
    if reference.attribute("URI") != Some("")
        || transforms != [Some(ENVELOPED), Some(C14N11)]
        || child(reference, DSIG, "DigestMethod")?.attribute("Algorithm") != Some(SHA384_DIGEST)
    {
        return Err(failed("signature is not over the whole document"));
    }
    if elements(signed_info).count() != 3 || elements(reference).count() != 3 {
        return Err(failed(
            "SignedInfo carries more than one reference and its algorithms",
        ));
    }
    let digest = base64(child(reference, DSIG, "DigestValue")?)?;
    if digest != Sha384::digest(canonical(root, Some(signature))?.as_bytes()).as_slice() {
        return Err(failed("digest does not match the document"));
    }

    let ders = elements(child(child(signature, DSIG, "KeyInfo")?, DSIG, "X509Data")?)
        .map(|cert| {
            if cert.has_tag_name((DSIG, "X509Certificate")) {
                base64(cert)
            } else {
                Err(failed("X509Data holds more than certificates"))
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    let leaf = verify_chain(&ders, &[pin(RIM_ROOT)?], now)?;
    let value = Signature::from_slice(&base64(child(signature, DSIG, "SignatureValue")?)?)
        .map_err(|_| failed("SignatureValue is not a P-384 signature"))?;
    leaf.key
        .verify(canonical(signed_info, None)?.as_bytes(), &value)
        .map_err(|_| failed("signature does not verify with the signer's key"))?;

    let meta = child(root, SWID, "Meta")?;
    let mut all = BTreeMap::new();
    for resource in elements(child(root, SWID, "Payload")?) {
        if !resource.has_tag_name((SWID, "Resource"))
            || attribute(resource, "type")? != "Measurement"
        {
            return Err(failed("payload holds more than measurements"));
        }
        let index = attribute(resource, "index")?;
        let block = index
            .parse::<u8>()
            .ok()
            .and_then(|i| i.checked_add(1))
            .filter(|b| *b <= BLOCKS)
            .ok_or_else(|| failed(format!("measurement index {index}")))?;
        let alternatives: u8 = attribute(resource, "alternatives")?
            .parse()
            .map_err(|_| failed(format!("measurement {index} alternatives")))?;
        let values = (0..alternatives)
            .map(|k| {
                resource
                    .attribute((SHA384_NS, format!("Hash{k}").as_str()))
                    .and_then(|h| hex::decode(h).ok())
                    .and_then(|h| h.try_into().ok())
                    .map(Measurement)
                    .ok_or_else(|| failed(format!("measurement {index} Hash{k}")))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let active = match attribute(resource, "active")? {
            "True" => true,
            "False" => false,
            other => return Err(failed(format!("measurement {index} active {other}"))),
        };
        if all.insert(block, (active, values)).is_some() {
            return Err(failed(format!("measurement {index} repeated")));
        }
    }
    let measurements = all
        .into_iter()
        .filter_map(|(block, (active, values))| active.then_some((block, values)))
        .collect();
    Ok(Rim {
        version: attribute(meta, "colloquialVersion")?.to_owned(),
        product: attribute(meta, "product")?.to_owned(),
        measurements,
        signers: ders
            .windows(2)
            .filter_map(|pair| match pair {
                [cert, issuer] => Some(OcspQuery::new(cert.clone(), issuer.clone())),
                _ => None,
            })
            .collect(),
    })
}

fn attribute<'a>(node: Node<'a, '_>, name: &str) -> Result<&'a str, AppraisalError> {
    node.attribute(name)
        .ok_or_else(|| failed(format!("{} has no {name}", node.tag_name().name())))
}

fn elements<'a, 'i>(node: Node<'a, 'i>) -> impl Iterator<Item = Node<'a, 'i>> {
    node.children().filter(Node::is_element)
}

/// The only child element of `node` with this name.
fn child<'a, 'i>(node: Node<'a, 'i>, ns: &str, name: &str) -> Result<Node<'a, 'i>, AppraisalError> {
    let mut found = elements(node).filter(|n| n.has_tag_name((ns, name)));
    match (found.next(), found.next()) {
        (Some(child), None) => Ok(child),
        _ => Err(failed(format!("not exactly one {name}"))),
    }
}

fn base64(node: Node) -> Result<Vec<u8>, AppraisalError> {
    let text: String = node
        .text()
        .unwrap_or_default()
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    BASE64_STANDARD
        .decode(text)
        .map_err(|_| failed(format!("{} is not base64", node.tag_name().name())))
}

/// Inclusive canonical XML without comments of `apex`'s subtree, leaving out `skip`'s. The apex
/// declares every namespace in scope, as canonicalizing a document subset requires. Refuses
/// processing instructions and `xml:` attributes, which RIMs do not carry and C14N 1.1 treats
/// specially.
fn canonical(apex: Node, skip: Option<Node>) -> Result<String, AppraisalError> {
    let mut out = String::new();
    let mut node = apex;
    'walk: loop {
        if Some(node) != skip {
            open(&mut out, node, apex)?;
            if let Some(first) = node.first_child() {
                node = first;
                continue;
            }
            close(&mut out, node)?;
        }
        while node != apex {
            if let Some(next) = node.next_sibling() {
                node = next;
                continue 'walk;
            }
            node = node
                .parent()
                .ok_or_else(|| failed("node outside the document"))?;
            close(&mut out, node)?;
        }
        return Ok(out);
    }
}

fn source<'i>(
    node: Node<'_, 'i>,
    range: std::ops::Range<usize>,
) -> Result<&'i str, AppraisalError> {
    node.document()
        .input_text()
        .get(range)
        .ok_or_else(|| failed("node outside the document"))
}

fn open(out: &mut String, node: Node, apex: Node) -> Result<(), AppraisalError> {
    match node.node_type() {
        NodeType::Element => {}
        NodeType::Text => {
            escape(out, node.text().unwrap_or_default(), false);
            return Ok(());
        }
        NodeType::PI => return Err(failed("processing instruction")),
        NodeType::Comment | NodeType::Root => return Ok(()),
    }
    out.push('<');
    out.push_str(qname(source(node, node.range())?));
    let parent = node.parent_element().filter(|_| node != apex);
    let mut namespaces: Vec<_> = node
        .namespaces()
        .filter(|ns| ns.name() != Some("xml"))
        .map(|ns| (ns.name(), ns.uri()))
        .filter(|(prefix, uri)| {
            parent.is_none_or(|p| p.lookup_namespace_uri(*prefix) != Some(*uri))
        })
        .collect();
    if node.lookup_namespace_uri(None).is_none()
        && parent.is_some_and(|p| p.lookup_namespace_uri(None).is_some())
    {
        namespaces.push((None, ""));
    }
    namespaces.sort_unstable();
    for (prefix, uri) in namespaces {
        out.push_str(" xmlns");
        if let Some(prefix) = prefix {
            out.push(':');
            out.push_str(prefix);
        }
        attribute_value(out, uri);
    }
    let mut attributes: Vec<_> = node.attributes().collect();
    if attributes
        .iter()
        .any(|a| a.namespace() == Some("http://www.w3.org/XML/1998/namespace"))
    {
        return Err(failed("xml: attributes"));
    }
    attributes.sort_unstable_by_key(|a| (a.namespace().unwrap_or_default(), a.name()));
    for a in attributes {
        out.push(' ');
        out.push_str(source(node, a.range_qname())?);
        attribute_value(out, a.value());
    }
    out.push('>');
    Ok(())
}

fn close(out: &mut String, node: Node) -> Result<(), AppraisalError> {
    if node.is_element() {
        out.push_str("</");
        out.push_str(qname(source(node, node.range())?));
        out.push('>');
    }
    Ok(())
}

/// The element name a start tag `<qname …` opens with.
fn qname(tag: &str) -> &str {
    let name = tag.strip_prefix('<').unwrap_or(tag);
    name.split(|c: char| c.is_ascii_whitespace() || c == '/' || c == '>')
        .next()
        .unwrap_or(name)
}

fn attribute_value(out: &mut String, value: &str) {
    out.push_str("=\"");
    escape(out, value, true);
    out.push('"');
}

/// C14N escapes `"`, tab and newline in attribute values only, `>` in text only.
fn escape(out: &mut String, value: &str, attribute: bool) {
    for c in value.chars() {
        match (c, attribute) {
            ('&', _) => out.push_str("&amp;"),
            ('<', _) => out.push_str("&lt;"),
            ('\r', _) => out.push_str("&#xD;"),
            ('>', false) => out.push_str("&gt;"),
            ('"', true) => out.push_str("&quot;"),
            ('\t', true) => out.push_str("&#x9;"),
            ('\n', true) => out.push_str("&#xA;"),
            (c, _) => out.push(c),
        }
    }
}
