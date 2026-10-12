//! Certificate chains: the GPU's device identity chain (in the evidence) and a RIM's signing
//! chain (in the RIM cache). Both end at a root the release-signed `gpu_policy` pins by its exact
//! DER; no root is compiled in, so NVIDIA rotating one is a new platform document.
//!
//! A Blackwell device chain, as NVIDIA's sample evidence has it (nv-attestation-sdk-cpp
//! `unit-tests/testdata/sample_attestation_data/gpu/blackwellCertChain.txt`):
//!
//! ```text
//! 0  CN=GB100 A01 GSP FMC LF            leaf: signs the SPDM report; TcbInfo (2.23.133.5.4.1.1)
//! 1  CN=GB100 A01 GSP BROM              the device: per-GPU, its CN is the hardware model
//! 2  CN=NVIDIA GB100 Provisioner ICA 00000
//! 3  CN=NVIDIA GB100 Identity
//! 4  CN=NVIDIA Device Identity CA       root (self-signed)
//! ```
//!
//! Hopper's leaf carries its FWID in a TCG `CompositeDeviceID` at 2.23.133.5.4.1 instead, which is
//! why a Hopper-only parser refuses Blackwell evidence (finding 3). This verifier reads the DICE
//! `TcbInfo` at 2.23.133.5.4.1.1 and appraises Blackwell only.
//!
//! Every certificate is checked: DER (strict), ECDSA by its issuer's P-384 key (SHA-384, or SHA-256
//! as some NVIDIA responder certificates use), issuer and
//! subject names chained, validity at `now`, CA constraints and key usage on issuers, and no
//! critical extension this module does not process. Path building is not done: the chain must be
//! in order, leaf first, ending at the pinned root.

use std::time::Duration;

use der::asn1::{
    BitStringRef, ObjectIdentifier, OctetStringRef, PrintableStringRef, Utf8StringRef,
};
use der::{Decode, Encode, Sequence};
use p384::ecdsa::signature::Verifier;
use p384::ecdsa::{Signature, VerifyingKey};
use x509_cert::Certificate;
use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages};

use super::{Result, refuse};

pub const MAX_CHAIN_PEM: usize = 64 * 1024;
pub const MAX_CERTS: usize = 8;
pub const MAX_CERT_DER: usize = 8 * 1024;

pub const ECDSA_WITH_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
/// NVIDIA's RIM-side OCSP responder certificates are signed with SHA-256 by P-384 keys.
pub const ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
pub const ID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
pub const SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
pub const SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
pub const ID_KP_OCSP_SIGNING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.9");
/// TCG DICE `TcbInfo` as NVIDIA's Blackwell leaf certificates carry it (the SDK's
/// `OID_TCG_DICE_TCB_INFO_ALIAS`).
pub const TCG_DICE_TCB_INFO_BLACKWELL: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.23.133.5.4.1.1");
/// TCG DICE `TcbInfo`; Hopper puts a `CompositeDeviceID` under it.
pub const TCG_DICE_TCB_INFO: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.23.133.5.4.1");
const ID_CE_BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
const ID_CE_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");
const ID_CE_EXT_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");
const ID_CE_SUBJECT_KEY_IDENTIFIER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");
const ID_AT_COMMON_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");
/// Extensions a certificate may mark critical: the ones checked here.
const UNDERSTOOD_CRITICAL: [ObjectIdentifier; 5] = [
    ID_CE_BASIC_CONSTRAINTS,
    ID_CE_KEY_USAGE,
    ID_CE_EXT_KEY_USAGE,
    TCG_DICE_TCB_INFO,
    TCG_DICE_TCB_INFO_BLACKWELL,
];

/// Splits a PEM chain into certificates. Only `CERTIFICATE` blocks separated by whitespace are
/// accepted. (`x509_cert`'s own `load_pem_chain` is not used: it underflows on input that is
/// empty after trimming.)
pub fn parse_pem_chain(pem: &[u8]) -> Result<Vec<Certificate>> {
    const BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----";
    const END: &[u8] = b"-----END CERTIFICATE-----";
    if pem.len() > MAX_CHAIN_PEM {
        return refuse(format!(
            "certificate chain is {} bytes, more than {MAX_CHAIN_PEM}",
            pem.len()
        ));
    }
    let mut rest = pem;
    let mut certs = Vec::new();
    loop {
        rest = trim_start(rest);
        if rest.is_empty() {
            break;
        }
        let Some(body) = rest.strip_prefix(BEGIN) else {
            return refuse("certificate chain has text outside a CERTIFICATE block");
        };
        let end = find(body, END)
            .ok_or_else(|| super::Refused("certificate chain has an unterminated block".into()))?;
        let (encoded, after) = body.split_at(end);
        rest = after.get(END.len()..).unwrap_or_default();
        if certs.len() >= MAX_CERTS {
            return refuse(format!(
                "certificate chain has more than {MAX_CERTS} certificates"
            ));
        }
        let compact: Vec<u8> = encoded
            .iter()
            .copied()
            .filter(|b| !b.is_ascii_whitespace())
            .collect();
        use base64::Engine;
        let der = base64::prelude::BASE64_STANDARD
            .decode(&compact)
            .or_else(|_| refuse("certificate chain has a block that is not base64"))?;
        certs.push(parse_der(&der)?);
    }
    if certs.is_empty() {
        return refuse("certificate chain is empty");
    }
    Ok(certs)
}

fn trim_start(mut s: &[u8]) -> &[u8] {
    while let Some((first, rest)) = s.split_first() {
        if !first.is_ascii_whitespace() {
            break;
        }
        s = rest;
    }
    s
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// One certificate from DER; strict, bounded, and nothing may follow it.
pub fn parse_der(der: &[u8]) -> Result<Certificate> {
    if der.len() > MAX_CERT_DER {
        return refuse(format!(
            "certificate is {} bytes, more than {MAX_CERT_DER}",
            der.len()
        ));
    }
    Certificate::from_der(der).or_else(|e| refuse(format!("certificate does not parse: {e}")))
}

/// The certificate's DER, re-encoded from the strictly parsed structure.
pub fn to_der(cert: &Certificate) -> Result<Vec<u8>> {
    cert.to_der()
        .or_else(|e| refuse(format!("certificate does not encode: {e}")))
}

/// The P-384 public key of a certificate; any other key is refused.
pub fn p384_key(cert: &Certificate) -> Result<VerifyingKey> {
    let spki = &cert.tbs_certificate.subject_public_key_info;
    let curve = spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|p| p.decode_as::<ObjectIdentifier>().ok());
    if spki.algorithm.oid != ID_EC_PUBLIC_KEY || curve != Some(SECP384R1) {
        return refuse(format!("{}: key is not EC P-384", describe(cert)));
    }
    let point = spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| super::Refused(format!("{}: key is not whole bytes", describe(cert))))?;
    VerifyingKey::from_sec1_bytes(point)
        .or_else(|_| refuse(format!("{}: key is not a P-384 point", describe(cert))))
}

/// Whether `issuer`'s key signed `cert` (ECDSA P-384, SHA-384), and the names chain.
pub fn verify_issued_by(cert: &Certificate, issuer: &Certificate) -> Result<()> {
    if cert.tbs_certificate.issuer != issuer.tbs_certificate.subject {
        return refuse(format!(
            "{} does not name {} as its issuer",
            describe(cert),
            describe(issuer)
        ));
    }
    if cert.signature_algorithm != cert.tbs_certificate.signature {
        return refuse(format!(
            "{}: the signature algorithm is not the one the certificate names",
            describe(cert)
        ));
    }
    let tbs = cert
        .tbs_certificate
        .to_der()
        .or_else(|e| refuse(format!("{}: {e}", describe(cert))))?;
    let signature = cert.signature.as_bytes().unwrap_or_default();
    verify_ecdsa(
        &p384_key(issuer)?,
        &cert.signature_algorithm,
        &tbs,
        signature,
    )
    .or_else(|e| {
        refuse(format!(
            "{}: signature by {}: {e}",
            describe(cert),
            describe(issuer)
        ))
    })
}

/// An X.509-style ECDSA signature (DER `Ecdsa-Sig-Value`) by a P-384 key, with SHA-384 or
/// SHA-256 as `algorithm` names; no parameters, nothing else.
pub fn verify_ecdsa(
    key: &VerifyingKey,
    algorithm: &x509_cert::spki::AlgorithmIdentifierOwned,
    message: &[u8],
    signature_der: &[u8],
) -> Result<()> {
    use p384::ecdsa::signature::hazmat::PrehashVerifier;
    use sha2::Digest;
    if algorithm.parameters.is_some() {
        return refuse("signature algorithm has parameters");
    }
    let signature =
        Signature::from_der(signature_der).or_else(|_| refuse("signature is malformed"))?;
    let verified = match algorithm.oid {
        ECDSA_WITH_SHA384 => key.verify(message, &signature),
        ECDSA_WITH_SHA256 => key.verify_prehash(&sha2::Sha256::digest(message), &signature),
        other => {
            return refuse(format!(
                "signature algorithm {other} is not ECDSA SHA-384/256"
            ));
        }
    };
    verified.or_else(|_| refuse("signature does not verify"))
}

fn unix(time: x509_cert::time::Time) -> Duration {
    time.to_unix_duration()
}

/// The certificate is valid at `now` (seconds since the Unix epoch).
pub fn check_validity(cert: &Certificate, now: Duration) -> Result<()> {
    let validity = &cert.tbs_certificate.validity;
    if now < unix(validity.not_before) {
        return refuse(format!("{} is not valid yet", describe(cert)));
    }
    if now > unix(validity.not_after) {
        return refuse(format!("{} has expired", describe(cert)));
    }
    Ok(())
}

/// The extensions a certificate's role depends on; refuses an extension that is critical but not
/// understood here, or one that appears twice.
pub struct Extensions {
    pub basic_constraints: Option<BasicConstraints>,
    pub key_usage: Option<KeyUsage>,
    pub extended_key_usage: Option<ExtendedKeyUsage>,
    pub subject_key_identifier: Option<Vec<u8>>,
}

pub fn extensions(cert: &Certificate) -> Result<Extensions> {
    let mut out = Extensions {
        basic_constraints: None,
        key_usage: None,
        extended_key_usage: None,
        subject_key_identifier: None,
    };
    let mut seen = std::collections::BTreeSet::new();
    let bad = |what: &str| super::Refused(format!("{}: {what}", describe(cert)));
    for ext in cert.tbs_certificate.extensions.iter().flatten() {
        if !seen.insert(ext.extn_id) {
            return Err(bad(&format!("extension {} appears twice", ext.extn_id)));
        }
        if ext.critical && !UNDERSTOOD_CRITICAL.contains(&ext.extn_id) {
            return Err(bad(&format!(
                "critical extension {} is not understood",
                ext.extn_id
            )));
        }
        let value = ext.extn_value.as_bytes();
        match ext.extn_id {
            ID_CE_BASIC_CONSTRAINTS => {
                out.basic_constraints = Some(
                    BasicConstraints::from_der(value)
                        .map_err(|_| bad("basic constraints are malformed"))?,
                )
            }
            ID_CE_KEY_USAGE => {
                out.key_usage =
                    Some(KeyUsage::from_der(value).map_err(|_| bad("key usage is malformed"))?)
            }
            ID_CE_EXT_KEY_USAGE => {
                out.extended_key_usage = Some(
                    ExtendedKeyUsage::from_der(value)
                        .map_err(|_| bad("extended key usage is malformed"))?,
                )
            }
            ID_CE_SUBJECT_KEY_IDENTIFIER => {
                out.subject_key_identifier = Some(
                    OctetStringRef::from_der(value)
                        .map_err(|_| bad("subject key identifier is malformed"))?
                        .as_bytes()
                        .to_vec(),
                )
            }
            _ => {}
        }
    }
    Ok(out)
}

/// May `cert` issue the certificate `below` positions under it (0 for its direct subordinate)?
fn check_issuer(cert: &Certificate, below: usize) -> Result<()> {
    let ext = extensions(cert)?;
    let bc = ext
        .basic_constraints
        .ok_or_else(|| super::Refused(format!("{} is not a CA", describe(cert))))?;
    if !bc.ca {
        return refuse(format!("{} is not a CA", describe(cert)));
    }
    if let Some(limit) = bc.path_len_constraint
        && below > usize::from(limit)
    {
        return refuse(format!("{}: path length exceeded", describe(cert)));
    }
    if let Some(ku) = ext.key_usage
        && !ku.0.contains(KeyUsages::KeyCertSign)
    {
        return refuse(format!("{} may not sign certificates", describe(cert)));
    }
    Ok(())
}

/// Verifies `chain` (leaf first) up to a root pinned by its exact DER in `roots`, every
/// certificate valid at `now`. Returns the index of nothing: success means every link held.
pub fn verify_chain(chain: &[Certificate], roots: &[Vec<u8>], now: Duration) -> Result<()> {
    if chain.len() < 2 || chain.len() > MAX_CERTS {
        return refuse(format!(
            "certificate chain has {} certificates, not 2 to {MAX_CERTS}",
            chain.len()
        ));
    }
    let root = chain
        .last()
        .ok_or_else(|| super::Refused("certificate chain is empty".into()))?;
    let root_der = to_der(root)?;
    if !roots.contains(&root_der) {
        return refuse(format!(
            "{} is not a root the gpu_policy pins",
            describe(root)
        ));
    }
    // The root signs itself; the pin is what makes it trusted, the check keeps the chain whole.
    verify_issued_by(root, root)?;
    for cert in chain {
        check_validity(cert, now)?;
    }
    // Every certificate is issued by the next; issuers are CAs within their path length.
    for (position, pair) in chain.windows(2).enumerate() {
        let [cert, issuer] = pair else {
            return refuse("certificate chain");
        };
        verify_issued_by(cert, issuer)?;
        check_issuer(issuer, position)?;
    }
    let leaf = chain
        .first()
        .ok_or_else(|| super::Refused("certificate chain is empty".into()))?;
    let leaf_ext = extensions(leaf)?;
    if let Some(ku) = leaf_ext.key_usage
        && !ku.0.contains(KeyUsages::DigitalSignature)
    {
        return refuse(format!("{} may not sign", describe(leaf)));
    }
    Ok(())
}

/// The subject's common name, UTF8String or PrintableString.
pub fn common_name(cert: &Certificate) -> Result<String> {
    for rdn in &cert.tbs_certificate.subject.0 {
        for atv in rdn.0.iter() {
            if atv.oid != ID_AT_COMMON_NAME {
                continue;
            }
            if let Ok(s) = atv.value.decode_as::<Utf8StringRef<'_>>() {
                return Ok(s.as_str().to_owned());
            }
            if let Ok(s) = atv.value.decode_as::<PrintableStringRef<'_>>() {
                return Ok(s.as_str().to_owned());
            }
            return refuse("common name is not a UTF8String or PrintableString");
        }
    }
    refuse("certificate has no common name")
}

/// A short name for messages.
pub fn describe(cert: &Certificate) -> String {
    common_name(cert)
        .map(|cn| format!("certificate {cn:?}"))
        .unwrap_or_else(|_| "certificate".into())
}

/// The certificate's serial number as a decimal string: NVIDIA's `ueid` for a device leaf
/// (`X509CertChain::get_end_entity_serial`).
pub fn serial_decimal(cert: &Certificate) -> String {
    let mut digits: Vec<u8> = Vec::new();
    for byte in cert.tbs_certificate.serial_number.as_bytes() {
        // digits (little-endian base 10) = digits * 256 + byte
        let mut carry = u32::from(*byte);
        for d in digits.iter_mut() {
            let v = u32::from(*d).saturating_mul(256).saturating_add(carry);
            *d = u8::try_from(v % 10).unwrap_or(0);
            carry = v / 10;
        }
        while carry > 0 {
            digits.push(u8::try_from(carry % 10).unwrap_or(0));
            carry /= 10;
        }
    }
    if digits.is_empty() {
        return "0".into();
    }
    digits
        .iter()
        .rev()
        .map(|d| char::from(b'0'.saturating_add(*d)))
        .collect()
}

/// One TCG DICE FWID: a hash algorithm and a digest.
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
pub struct Fwid {
    pub hash_alg: ObjectIdentifier,
    pub digest: der::asn1::OctetString,
}

/// TCG DICE `DiceTcbInfo` (TCG DICE Attestation Architecture 1.1 §6.1.1, with `flagsMask` at
/// [10] and `integrityRegisters` at [11] as its ASN.1 module has them).
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
pub struct TcbInfoAsn<'a> {
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub vendor: Option<Utf8StringRef<'a>>,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub model: Option<Utf8StringRef<'a>>,
    #[asn1(context_specific = "2", tag_mode = "IMPLICIT", optional = "true")]
    pub version: Option<Utf8StringRef<'a>>,
    #[asn1(context_specific = "3", tag_mode = "IMPLICIT", optional = "true")]
    pub svn: Option<u64>,
    #[asn1(context_specific = "4", tag_mode = "IMPLICIT", optional = "true")]
    pub layer: Option<u64>,
    #[asn1(context_specific = "5", tag_mode = "IMPLICIT", optional = "true")]
    pub index: Option<u64>,
    #[asn1(context_specific = "6", tag_mode = "IMPLICIT", optional = "true")]
    pub fwids: Option<Vec<Fwid>>,
    #[asn1(context_specific = "7", tag_mode = "IMPLICIT", optional = "true")]
    pub flags: Option<BitStringRef<'a>>,
    #[asn1(context_specific = "8", tag_mode = "IMPLICIT", optional = "true")]
    pub vendor_info: Option<OctetStringRef<'a>>,
    #[asn1(context_specific = "9", tag_mode = "IMPLICIT", optional = "true")]
    pub tcb_type: Option<OctetStringRef<'a>>,
    #[asn1(context_specific = "10", tag_mode = "IMPLICIT", optional = "true")]
    pub flags_mask: Option<BitStringRef<'a>>,
    #[asn1(context_specific = "11", tag_mode = "IMPLICIT", optional = "true")]
    pub integrity_registers: Option<Vec<der::asn1::Any>>,
}

/// TCG DICE `OperationalFlags` bits a production device must not have set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperationalFlag {
    NotConfigured = 0,
    NotSecure = 1,
    Recovery = 2,
    Debug = 3,
}

/// What the certified firmware identity says, from the leaf's `TcbInfo`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TcbInfo {
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub version: Option<String>,
    pub svn: Option<u64>,
    /// The first FWID, which NVIDIA requires to be SHA-384 (the SDK's `get_first_fwid_digest`).
    pub fwid: [u8; 48],
    flags: Option<Vec<u8>>,
    flags_bits: usize,
    flags_mask: Option<(Vec<u8>, usize)>,
}

impl TcbInfo {
    /// Whether an operational flag is set (and, when a mask is present, in the mask).
    pub fn flag(&self, flag: OperationalFlag) -> bool {
        let bit = flag as usize;
        let set = |bytes: &[u8], len: usize| {
            bit < len
                && bytes
                    .get(bit / 8)
                    .is_some_and(|b| b & (0x80u8 >> (bit % 8)) != 0)
        };
        let in_value = self
            .flags
            .as_deref()
            .is_some_and(|bytes| set(bytes, self.flags_bits));
        let in_mask = self
            .flags_mask
            .as_ref()
            .is_none_or(|(bytes, len)| set(bytes, *len));
        in_value && in_mask
    }
}

fn bits(b: BitStringRef<'_>) -> Result<(Vec<u8>, usize)> {
    let bytes = b
        .as_bytes()
        .ok_or_else(|| super::Refused("TcbInfo flags are not whole bytes".into()))?;
    Ok((bytes.to_vec(), bytes.len().saturating_mul(8)))
}

/// The Blackwell leaf's `TcbInfo`, which must be present and name a SHA-384 FWID.
pub fn tcb_info(cert: &Certificate) -> Result<TcbInfo> {
    let mut found = None;
    for ext in cert.tbs_certificate.extensions.iter().flatten() {
        if ext.extn_id == TCG_DICE_TCB_INFO_BLACKWELL {
            if found.is_some() {
                return refuse("TcbInfo appears twice");
            }
            found = Some(ext.extn_value.as_bytes());
        }
    }
    let Some(value) = found else {
        let hopper = cert
            .tbs_certificate
            .extensions
            .iter()
            .flatten()
            .any(|e| e.extn_id == TCG_DICE_TCB_INFO);
        return refuse(if hopper {
            "the leaf carries a Hopper-format FWID (2.23.133.5.4.1); only Blackwell evidence is \
             appraised"
        } else {
            "the leaf has no TcbInfo (2.23.133.5.4.1.1)"
        });
    };
    let asn =
        TcbInfoAsn::from_der(value).or_else(|e| refuse(format!("TcbInfo does not parse: {e}")))?;
    let first = asn
        .fwids
        .as_ref()
        .and_then(|f| f.first())
        .ok_or_else(|| super::Refused("TcbInfo names no FWID".into()))?;
    if first.hash_alg != SHA384 {
        return refuse("TcbInfo's FWID is not SHA-384");
    }
    let fwid = <[u8; 48]>::try_from(first.digest.as_bytes())
        .or_else(|_| refuse("TcbInfo's FWID is not 48 bytes"))?;
    let flags = asn.flags.map(bits).transpose()?;
    let flags_mask = asn.flags_mask.map(bits).transpose()?;
    let text = |s: Option<Utf8StringRef<'_>>| s.map(|s| s.as_str().to_owned());
    Ok(TcbInfo {
        vendor: text(asn.vendor),
        model: text(asn.model),
        version: text(asn.version),
        svn: asn.svn,
        fwid,
        flags_bits: flags.as_ref().map_or(0, |(_, n)| *n),
        flags: flags.map(|(b, _)| b),
        flags_mask,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimal_serials_match_bignum_conversion() {
        let cert = |serial: &[u8]| {
            // Only the serial matters to serial_decimal; build one through the public parser.
            let mut c = crate::gpu::local::cert::tests::any_cert();
            c.tbs_certificate.serial_number =
                x509_cert::serial_number::SerialNumber::new(serial).unwrap();
            c
        };
        assert_eq!(serial_decimal(&cert(&[0x01])), "1");
        assert_eq!(serial_decimal(&cert(&[0x01, 0x00])), "256");
        assert_eq!(
            serial_decimal(&cert(&[
                0x41, 0xE6, 0xDE, 0x55, 0xC3, 0xBD, 0xC1, 0x42, 0x77
            ])),
            u128::from_str_radix("41E6DE55C3BDC14277", 16)
                .unwrap()
                .to_string()
        );
    }

    pub(crate) fn any_cert() -> Certificate {
        let pem = include_bytes!("../../../../../testdata/gpu/nvidia/blackwellCertChain.txt");
        parse_pem_chain(pem).unwrap().remove(0)
    }

    #[test]
    fn pem_chains_are_strict_and_bounded() {
        for (case, input, reason) in [
            ("empty", &b""[..], "empty"),
            ("whitespace", &b" \n\r\n"[..], "empty"),
            ("noise", &b"hello"[..], "outside"),
            (
                "unterminated",
                &b"-----BEGIN CERTIFICATE-----\nAAAA"[..],
                "unterminated",
            ),
            (
                "not base64",
                &b"-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----"[..],
                "base64",
            ),
            (
                "not a certificate",
                &b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"[..],
                "does not parse",
            ),
        ] {
            let error = parse_pem_chain(input).unwrap_err().to_string();
            assert!(error.contains(reason), "{case}: {error}");
        }
        let big = vec![b' '; MAX_CHAIN_PEM + 1];
        assert!(
            parse_pem_chain(&big)
                .unwrap_err()
                .to_string()
                .contains("more than")
        );
    }
}
