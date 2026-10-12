//! AMD SEV-SNP attestation reports: the CPU half of the `kata-snp/1` profile.
//!
//! [`verify_report`] is pure over its arguments, like [`crate::verify_quote`] for TDX. It proves
//! that a report was signed by a VCEK (or VLEK) that chains through the ASK (or ASVK) to AMD's root
//! key ARK, all three as the release-signed `snp_policy` pins them for the report's product, that
//! AMD's CRL (signed by that ARK and current) does not revoke the intermediate, that the VCEK
//! certifies the report's chip and TCB, and that the guest policy, platform and TCB are what
//! `snp_policy` allows. Nothing is trusted on first use: the root and intermediates are never read
//! from the evidence or from AMD's KDS, only the per-chip VCEK and the CRL, both of which verify
//! under them. [`kds`] fetches and caches that collateral.
//!
//! Parsing is the `sev` crate's (virtee, the parser Trustee's SNP verifier uses), and so are the
//! RSA-PSS checks of the certificate chain; the report signature is checked here over the raw
//! bytes, and the parsed report must re-encode to exactly those bytes, so no field is read from
//! anything but what AMD's firmware signed.

pub mod kds;

use std::collections::BTreeMap;
use std::time::SystemTime;

use p384::ecdsa::signature::Verifier as _;
use serde::{Deserialize, Serialize};
use sev::Generation;
use sev::certs::snp::{Certificate as SevCertificate, Verifiable, ca};
use sev::firmware::guest::AttestationReport;
use sev::firmware::host::TcbVersion;
use sev::parser::ByteParser;
use x509_cert::der::{Decode, DecodePem, Encode};
use x509_cert::{Certificate, crl::CertificateList};

use crate::{AppraisalError, Measurement};

/// An attestation report as the firmware returns it (`MSG_REPORT_RSP`'s report, configfs-tsm's
/// `outblob`).
pub const REPORT_LEN: usize = 0x4A0;
/// The report bytes its signature covers.
const SIGNED_LEN: usize = 0x2A0;
/// `SIGNATURE_ALGO` 1: ECDSA P-384 with SHA-384, the only one SNP defines.
const ECDSA_P384_SHA384: u32 = 1;

const RSA_PSS: &str = "1.2.840.113549.1.1.10";
// AMD's VCEK/VLEK certificate extensions (VCEK spec 57230, table 8).
const EXT_PRODUCT_NAME: &str = "1.3.6.1.4.1.3704.1.2";
const EXT_BL_SPL: &str = "1.3.6.1.4.1.3704.1.3.1";
const EXT_TEE_SPL: &str = "1.3.6.1.4.1.3704.1.3.2";
const EXT_SNP_SPL: &str = "1.3.6.1.4.1.3704.1.3.3";
const EXT_UCODE_SPL: &str = "1.3.6.1.4.1.3704.1.3.8";
const EXT_FMC_SPL: &str = "1.3.6.1.4.1.3704.1.3.9";
const EXT_HWID: &str = "1.3.6.1.4.1.3704.1.4";

/// The platform document's `snp_policy`: what an SEV-SNP guest must prove before a pod on an SNP
/// runtime class gets a leaf. Absent, no SNP pod can attest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnpPolicy {
    /// By AMD product name (`Milan`, `Genoa`, `Turin`): its pinned certificates and minimum TCB.
    /// A report from a product not listed is refused.
    pub products: BTreeMap<String, SnpProduct>,
    /// Whether the host may run with SMT enabled. Off, a report whose platform has SMT enabled is
    /// refused, whatever the guest policy allows.
    #[serde(default)]
    pub allow_smt: bool,
    /// Whether the guest policy may allow a migration agent.
    #[serde(default)]
    pub allow_migration_agent: bool,
    /// The VMPL the report must be requested at: 0 for a Kata guest without an SVSM.
    #[serde(default)]
    pub vmpl: u32,
    /// AMD's Key Distribution Service, for VCEKs the evidence does not carry and for the CRL.
    /// Absent, the VCEK must come with the evidence and no CRL can be had, so every SNP pod is
    /// refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kds_url: Option<String>,
}

/// One AMD product's certificates, copied from AMD's KDS (`/vcek/v1/{product}/cert_chain`, and
/// `/vlek/v1/{product}/cert_chain` for the ASVK) when the document is prepared, and its minimum TCB.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnpProduct {
    /// AMD Root Key, PEM. The only root: no certificate the evidence or KDS supplies replaces it.
    pub ark_pem: String,
    /// AMD SEV Key, PEM, signed by the ARK; it signs every VCEK of the product.
    pub ask_pem: String,
    /// AMD SEV VLEK Key, PEM, signed by the ARK; it signs VLEKs. Absent, VLEK-signed reports are
    /// refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asvk_pem: Option<String>,
    /// The lowest reported TCB accepted, component by component.
    pub min_tcb: SnpTcb,
}

/// A TCB version's security patch levels. `fmc` exists from Turin on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnpTcb {
    pub bootloader: u8,
    pub tee: u8,
    pub snp: u8,
    pub microcode: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fmc: Option<u8>,
}

impl From<TcbVersion> for SnpTcb {
    fn from(t: TcbVersion) -> Self {
        Self {
            bootloader: t.bootloader,
            tee: t.tee,
            snp: t.snp,
            microcode: t.microcode,
            fmc: t.fmc,
        }
    }
}

impl SnpTcb {
    /// Every component at or above `min`'s; a minimum `fmc` needs one in `self`.
    pub fn at_least(&self, min: &Self) -> bool {
        self.bootloader >= min.bootloader
            && self.tee >= min.tee
            && self.snp >= min.snp
            && self.microcode >= min.microcode
            && match min.fmc {
                None => true,
                Some(m) => self.fmc.is_some_and(|f| f >= m),
            }
    }
}

/// Which key signed the report (`KEY_INFO.SIGNING_KEY`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VekKind {
    /// Versioned Chip Endorsement Key: per chip and TCB, from AMD's KDS.
    Vcek,
    /// Versioned Loaded Endorsement Key: per cloud provider, loaded by the host.
    Vlek,
}

impl VekKind {
    fn path(self) -> &'static str {
        match self {
            Self::Vcek => "vcek",
            Self::Vlek => "vlek",
        }
    }
}

/// What `kata-snp/1` records about the report in the attestation result. Like the rest of the
/// result it accepts fields it does not know.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnpFindings {
    pub product: String,
    pub signing_key: VekKind,
    pub measurement: Measurement,
    #[serde(with = "hex::serde")]
    pub host_data: [u8; 32],
    pub reported_tcb: SnpTcb,
    /// The guest policy, `0x`-prefixed hex.
    pub guest_policy: String,
    pub vmpl: u32,
}

/// What [`verify_report`] proves about an SNP report, independent of whose it is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedReport {
    pub report_data: [u8; 64],
    /// The launch measurement; `kata-snp/1` matches it against reference values.
    pub measurement: Measurement,
    /// HOST_DATA, which the pinned Kata sets to the init-data digest.
    pub host_data: [u8; 32],
    pub findings: SnpFindings,
}

/// What a report says before its signature is checked: enough to find its VCEK and CRL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReportHeader {
    pub signing_key: VekKind,
    /// From the report's CPUID fields (version 3 and later); a version 2 report names none.
    pub product: Option<&'static str>,
    pub chip_id: [u8; 64],
    pub reported_tcb: SnpTcb,
}

fn failed(message: impl Into<String>) -> AppraisalError {
    AppraisalError::Failed(message.into())
}

/// Parses `bytes` as an SNP report and requires the parse to re-encode to exactly `bytes`, so every
/// field read afterwards is a field of the signed report (and any reserved byte that is not zero,
/// or a layout this parser does not know, refuses the report).
fn parse(bytes: &[u8]) -> Result<AttestationReport, AppraisalError> {
    if bytes.len() != REPORT_LEN {
        return Err(failed(format!(
            "SNP report is {} bytes, not {REPORT_LEN}",
            bytes.len()
        )));
    }
    let report = AttestationReport::from_bytes(bytes)
        .map_err(|e| failed(format!("SNP report does not parse: {e}")))?;
    let again = report
        .to_bytes()
        .map_err(|e| failed(format!("SNP report does not re-encode: {e}")))?;
    if again.as_slice() != bytes {
        return Err(failed(
            "SNP report has bytes its parser does not account for",
        ));
    }
    Ok(report)
}

fn generation_name(generation: Generation) -> Option<&'static str> {
    match generation {
        Generation::Milan => Some("Milan"),
        Generation::Genoa => Some("Genoa"),
        Generation::Turin => Some("Turin"),
        Generation::Venice => Some("Venice"),
        #[allow(unreachable_patterns)]
        _ => None,
    }
}

fn signing_key(report: &AttestationReport) -> Result<VekKind, AppraisalError> {
    if report.key_info.mask_chip_key() {
        return Err(failed("SNP report is not signed (MASK_CHIP_KEY)"));
    }
    match report.key_info.signing_key() {
        0 => Ok(VekKind::Vcek),
        1 => Ok(VekKind::Vlek),
        other => Err(failed(format!(
            "SNP report signing key {other} is not a VCEK or VLEK"
        ))),
    }
}

/// The unverified header of `bytes`.
pub fn header(bytes: &[u8]) -> Result<ReportHeader, AppraisalError> {
    let report = parse(bytes)?;
    let product = match (report.cpuid_fam_id, report.cpuid_mod_id) {
        (Some(family), Some(model)) => Some(
            Generation::identify_cpu(family, model)
                .ok()
                .and_then(generation_name)
                .ok_or_else(|| {
                    failed(format!(
                        "SNP report CPUID family {family:#x} model {model:#x} is no known product"
                    ))
                })?,
        ),
        _ => None,
    };
    Ok(ReportHeader {
        signing_key: signing_key(&report)?,
        product,
        chip_id: report.chip_id,
        reported_tcb: report.reported_tcb.into(),
    })
}

/// The collateral [`verify_report`] needs besides the pinned certificates: the VCEK or VLEK, and
/// AMD's CRL for that key kind and product.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnpCollateral {
    /// DER.
    pub vek: Vec<u8>,
    /// DER.
    pub crl: Vec<u8>,
}

/// The appraisal of one SNP report: signature, chain, revocation, TCB and policy. Pure.
pub fn verify_report(
    bytes: &[u8],
    collateral: &SnpCollateral,
    policy: &SnpPolicy,
    now: SystemTime,
) -> Result<VerifiedReport, AppraisalError> {
    use AppraisalError::*;

    let report = parse(bytes)?;
    if report.sig_algo != ECDSA_P384_SHA384 {
        return Err(Failed(format!(
            "SNP report signature algorithm {} is not ECDSA P-384",
            report.sig_algo
        )));
    }
    let kind = signing_key(&report)?;
    let vek = Certificate::from_der(&collateral.vek)
        .map_err(|e| Failed(format!("{}: not a certificate: {e}", kind.path())))?;

    // The product names the pinned certificates. The VEK's productName (`Milan-B0`) and the
    // report's CPUID (version 3 and later) must agree where both are present.
    let from_vek = product_name(&vek)?;
    let from_report = match (report.cpuid_fam_id, report.cpuid_mod_id) {
        (Some(family), Some(model)) => Generation::identify_cpu(family, model)
            .ok()
            .and_then(generation_name),
        _ => None,
    };
    let product = match (from_vek.as_deref(), from_report) {
        (Some(a), Some(b)) if a != b => {
            return Err(Failed(format!(
                "the {} is for {a}, the report's CPU is {b}",
                kind.path()
            )));
        }
        (Some(a), _) => a.to_owned(),
        (None, Some(b)) => b.to_owned(),
        (None, None) => return Err(Failed("SNP report names no product".into())),
    };
    let pinned = policy.products.get(&product).ok_or_else(|| {
        Unknown(format!(
            "snp_policy pins no AMD certificates for product {product}"
        ))
    })?;

    let ark = pem_certificate("ark_pem", &pinned.ark_pem)?;
    let intermediate = match kind {
        VekKind::Vcek => pem_certificate("ask_pem", &pinned.ask_pem)?,
        VekKind::Vlek => pem_certificate(
            "asvk_pem",
            pinned.asvk_pem.as_deref().ok_or_else(|| {
                PolicyDenied(format!(
                    "snp_policy pins no ASVK for {product}, so VLEK-signed reports are refused"
                ))
            })?,
        )?,
    };
    check_chain(&ark, &intermediate, &vek, kind)?;
    for (what, cert) in [
        ("ARK", &ark),
        ("intermediate", &intermediate),
        (kind.path(), &vek),
    ] {
        check_validity(what, cert, now)?;
    }
    check_crl(&collateral.crl, &ark, &intermediate, now)?;

    verify_signature(bytes, &vek, kind)?;

    let reported: SnpTcb = report.reported_tcb.into();
    let certified = vek_tcb(&vek)?;
    if certified != reported {
        return Err(Failed(format!(
            "the {} certifies TCB {certified:?}, the report's is {reported:?}",
            kind.path()
        )));
    }
    if kind == VekKind::Vcek {
        check_hwid(&vek, &report.chip_id, &product)?;
    }

    check_policy(policy, &report, &reported, &pinned.min_tcb)?;

    let measurement = Measurement(report.measurement);
    Ok(VerifiedReport {
        report_data: report.report_data,
        measurement,
        host_data: report.host_data,
        findings: SnpFindings {
            product,
            signing_key: kind,
            measurement,
            host_data: report.host_data,
            reported_tcb: reported,
            guest_policy: format!("{:#x}", u64::from(report.policy)),
            vmpl: report.vmpl,
        },
    })
}

fn pem_certificate(field: &str, pem: &str) -> Result<Certificate, AppraisalError> {
    Certificate::from_pem(pem.as_bytes())
        .map_err(|e| failed(format!("snp_policy {field} is not a PEM certificate: {e}")))
}

/// ARK self-signed, ARK signs the intermediate, the intermediate signs the VEK: RSA-PSS SHA-384
/// throughout (the `sev` crate's checks). The VEK's key must be P-384.
fn check_chain(
    ark: &Certificate,
    intermediate: &Certificate,
    vek: &Certificate,
    kind: VekKind,
) -> Result<(), AppraisalError> {
    let [ark_s, int_s, vek_s] = [ark, intermediate, vek].map(|c| SevCertificate::from(c.clone()));
    let chain = ca::Chain {
        ark: ark_s,
        ask: int_s.clone(),
    };
    (&chain)
        .verify()
        .map_err(|e| failed(format!("pinned AMD chain does not verify: {e}")))?;
    (&int_s, &vek_s).verify().map_err(|e| {
        failed(format!(
            "the {} is not signed by the pinned {}: {e}",
            kind.path(),
            match kind {
                VekKind::Vcek => "ASK",
                VekKind::Vlek => "ASVK",
            }
        ))
    })?;
    if vek.tbs_certificate.issuer != intermediate.tbs_certificate.subject {
        return Err(failed(format!(
            "the {} names another issuer than the pinned intermediate",
            kind.path()
        )));
    }
    Ok(())
}

fn check_validity(what: &str, cert: &Certificate, now: SystemTime) -> Result<(), AppraisalError> {
    let validity = &cert.tbs_certificate.validity;
    if now < validity.not_before.to_system_time() || now > validity.not_after.to_system_time() {
        return Err(failed(format!(
            "{what} certificate is not valid now (valid {} to {})",
            validity.not_before, validity.not_after
        )));
    }
    Ok(())
}

/// AMD's CRL for the product and key kind: signed by the pinned ARK (RSA-PSS, SHA-384, salt 48),
/// current, and not listing the intermediate.
fn check_crl(
    der: &[u8],
    ark: &Certificate,
    intermediate: &Certificate,
    now: SystemTime,
) -> Result<(), AppraisalError> {
    use rsa::pkcs8::DecodePublicKey;
    use rsa::signature::Verifier;

    let crl = CertificateList::from_der(der)
        .map_err(|e| failed(format!("AMD CRL does not parse: {e}")))?;
    if crl.signature_algorithm.oid.to_string() != RSA_PSS {
        return Err(failed("AMD CRL is not signed with RSA-PSS"));
    }
    if crl.tbs_cert_list.issuer != ark.tbs_certificate.subject {
        return Err(failed("AMD CRL is not issued by the pinned ARK"));
    }
    let spki = ark
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| failed(format!("ARK key: {e}")))?;
    let key = rsa::RsaPublicKey::from_public_key_der(&spki)
        .map_err(|e| failed(format!("ARK key is not RSA: {e}")))?;
    let tbs = crl
        .tbs_cert_list
        .to_der()
        .map_err(|e| failed(format!("AMD CRL: {e}")))?;
    let signature = rsa::pss::Signature::try_from(crl.signature.raw_bytes())
        .map_err(|e| failed(format!("AMD CRL signature: {e}")))?;
    rsa::pss::VerifyingKey::<sha2_10::Sha384>::new(key)
        .verify(&tbs, &signature)
        .map_err(|_| failed("AMD CRL is not signed by the pinned ARK"))?;

    let this_update = crl.tbs_cert_list.this_update.to_system_time();
    let next_update = crl
        .tbs_cert_list
        .next_update
        .ok_or_else(|| failed("AMD CRL has no nextUpdate"))?
        .to_system_time();
    if now < this_update || now >= next_update {
        return Err(failed("AMD CRL is not current"));
    }
    let serial = &intermediate.tbs_certificate.serial_number;
    if crl
        .tbs_cert_list
        .revoked_certificates
        .iter()
        .flatten()
        .any(|r| &r.serial_number == serial)
    {
        return Err(failed("AMD's CRL revokes the pinned intermediate"));
    }
    Ok(())
}

fn verify_signature(bytes: &[u8], vek: &Certificate, kind: VekKind) -> Result<(), AppraisalError> {
    let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(
        vek.tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes(),
    )
    .map_err(|_| failed(format!("the {} key is not P-384", kind.path())))?;
    // R and S are 72-byte little-endian fields at 0x2A0 and 0x2E8, of which P-384 uses 48.
    let scalar = |at: usize| -> Result<[u8; 48], AppraisalError> {
        let field = bytes
            .get(at..at.saturating_add(72))
            .ok_or_else(|| failed("SNP report is too short for its signature"))?;
        let (value, rest) = field.split_at(48);
        if rest.iter().any(|b| *b != 0) {
            return Err(failed("SNP report signature is not a P-384 signature"));
        }
        let mut out = [0u8; 48];
        for (dst, src) in out.iter_mut().zip(value.iter().rev()) {
            *dst = *src;
        }
        Ok(out)
    };
    let mut rs = [0u8; 96];
    for (dst, src) in rs
        .iter_mut()
        .zip(scalar(SIGNED_LEN)?.iter().chain(&scalar(0x2E8)?))
    {
        *dst = *src;
    }
    let signature = p384::ecdsa::Signature::from_slice(&rs)
        .map_err(|_| failed("SNP report signature is not a P-384 signature"))?;
    let signed = bytes
        .get(..SIGNED_LEN)
        .ok_or_else(|| failed("SNP report is too short"))?;
    key.verify(signed, &signature).map_err(|_| {
        failed(format!(
            "SNP report signature does not verify under the {}",
            kind.path()
        ))
    })
}

fn extension<'a>(cert: &'a Certificate, oid: &str) -> Option<&'a [u8]> {
    cert.tbs_certificate
        .extensions
        .iter()
        .flatten()
        .find(|e| e.extn_id.to_string() == oid)
        .map(|e| e.extn_value.as_bytes())
}

/// The product from `productName` (an IA5String such as `Milan-B0`): the part before the stepping.
fn product_name(cert: &Certificate) -> Result<Option<String>, AppraisalError> {
    let Some(value) = extension(cert, EXT_PRODUCT_NAME) else {
        return Ok(None);
    };
    let name = x509_cert::der::asn1::Ia5StringRef::from_der(value)
        .map_err(|e| failed(format!("certificate productName: {e}")))?;
    let name = name.as_str();
    Ok(Some(name.split('-').next().unwrap_or(name).to_owned()))
}

fn vek_tcb(cert: &Certificate) -> Result<SnpTcb, AppraisalError> {
    let spl = |oid: &str, what: &str| -> Result<Option<u8>, AppraisalError> {
        extension(cert, oid)
            .map(|v| u8::from_der(v).map_err(|e| failed(format!("certificate {what}: {e}"))))
            .transpose()
    };
    let required = |oid: &str, what: &str| {
        spl(oid, what)?.ok_or_else(|| failed(format!("certificate has no {what}")))
    };
    Ok(SnpTcb {
        bootloader: required(EXT_BL_SPL, "blSPL")?,
        tee: required(EXT_TEE_SPL, "teeSPL")?,
        snp: required(EXT_SNP_SPL, "snpSPL")?,
        microcode: required(EXT_UCODE_SPL, "ucodeSPL")?,
        fmc: spl(EXT_FMC_SPL, "fmcSPL")?,
    })
}

/// The chip identifier a VCEK is for, as KDS names it: all 64 bytes, or from Turin on the first 8.
fn hwid_len(product: &str) -> usize {
    match product {
        "Milan" | "Genoa" => 64,
        _ => 8,
    }
}

fn check_hwid(vek: &Certificate, chip_id: &[u8; 64], product: &str) -> Result<(), AppraisalError> {
    let hwid = extension(vek, EXT_HWID).ok_or_else(|| failed("VCEK has no hwID"))?;
    let expected = chip_id.get(..hwid_len(product)).unwrap_or(chip_id);
    if hwid != expected {
        return Err(failed("the VCEK is for another chip than the report's"));
    }
    Ok(())
}

fn check_policy(
    policy: &SnpPolicy,
    report: &AttestationReport,
    reported: &SnpTcb,
    min: &SnpTcb,
) -> Result<(), AppraisalError> {
    use AppraisalError::PolicyDenied;

    if report.policy.debug_allowed() {
        return Err(PolicyDenied("SNP guest policy allows debugging".into()));
    }
    if report.policy.migrate_ma_allowed() && !policy.allow_migration_agent {
        return Err(PolicyDenied(
            "SNP guest policy allows a migration agent".into(),
        ));
    }
    if report.plat_info.smt_enabled() && !policy.allow_smt {
        return Err(PolicyDenied("the SNP host runs with SMT enabled".into()));
    }
    if report.vmpl != policy.vmpl {
        return Err(PolicyDenied(format!(
            "SNP report is from VMPL {}, not {}",
            report.vmpl, policy.vmpl
        )));
    }
    if !reported.at_least(min) {
        return Err(PolicyDenied(format!(
            "SNP reported TCB {reported:?} is below the minimum {min:?}"
        )));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests;
