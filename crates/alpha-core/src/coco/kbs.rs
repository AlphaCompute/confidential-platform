//! Option B (PRD-02 deliverable 26): the guest components' configuration in a pod's init-data,
//! which points the attestation agent (AA) and the Confidential Data Hub (CDH) at Trustee's Key
//! Broker Service, and the names of the resources a pod asks that KBS for.
//!
//! The Kata 4.1.0 agent writes the init-data's `aa.toml` and `cdh.toml` entries to
//! `/run/confidential-containers/initdata/` and starts AA and CDH with them. Both entries are
//! measured with the rest of the init-data, so the KBS's address and the certificate the guest
//! trusts for it are part of what the tenant approves; a host that substitutes its own KBS changes
//! MRCONFIGID. The generator writes exactly one form of each entry ([`KbsConfig::aa_toml`],
//! [`KbsConfig::cdh_toml`]), and [`KbsConfig::from_entries`] accepts nothing else, so a Revision
//! names one URL and one certificate and no other setting of AA or CDH.
//!
//! The settings are those of guest-components [`GUEST_COMPONENTS`], the `coco-guest-components`
//! of kata-containers 4.1.0, whose KBS protocol Trustee v0.21.0 speaks:
//! - AA (`attestation-agent/src/config/{mod,kbs}.rs`): `[token_configs.kbs]` with `url`, `cert`
//!   (PEM, added as a root of the KBS client's TLS) and `tee_key_algorithm`; the event-log and log
//!   settings keep their defaults.
//! - CDH (`confidential-data-hub/hub/src/config/mod.rs`): `[kbc]` with `name = "cc_kbc"`, `url`
//!   and `kbs_cert`. No `[image]` section, so guest pull keeps the configuration it has without
//!   one (from the measured kernel command line); no `credentials`, and sealed-secret signatures
//!   stay verified (`skip_sealed_secret_verification` unset).

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{AppId, ComposeHash};

/// The guest-components commit whose configuration format this module writes.
pub const GUEST_COMPONENTS: &str = "d4dce5ce62294cfa741225f7e5b4527ea276f326";
/// The init-data entry the Kata agent hands the attestation agent.
pub const AA_ENTRY: &str = "aa.toml";
/// The init-data entry the Kata agent hands the Confidential Data Hub.
pub const CDH_ENTRY: &str = "cdh.toml";
/// CDH's KBS client for the RCAR protocol, which gets its token from the AA.
pub const KBC: &str = "cc_kbc";
/// The TEE key the AA generates in the TD and the KBS seals resources to: guest-components'
/// default (`kbs_protocol::TeeKeyAlgorithm`), written out so the measured entry says it.
pub const TEE_KEY_ALGORITHM: &str = "ECDH-ES+A256KW-P256";
/// The prefix of a KBS resource URI; the empty authority means "the configured KBS".
pub const URI_PREFIX: &str = "kbs:///";

const PEM_BEGIN: &str = "-----BEGIN CERTIFICATE-----";
const PEM_END: &str = "-----END CERTIFICATE-----";

/// The KBS a pod's AA and CDH use: its `https://` URL and the one certificate the guest trusts
/// for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KbsConfig {
    url: String,
    cert_der: Vec<u8>,
    cert_spki_sha256: ComposeHash,
}

/// What a Revision v2 says of its pod's KBS: the URL, and the SHA-256 of the certificate's
/// `SubjectPublicKeyInfo`, the same form as the platform document's `kms_ca_spki_sha256`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevisionKbs {
    pub cert_spki_sha256: ComposeHash,
    pub url: String,
}

impl RevisionKbs {
    pub fn check(&self) -> Result<(), String> {
        check_url(&self.url)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AaToml {
    token_configs: AaTokenConfigs,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AaTokenConfigs {
    kbs: AaKbs,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AaKbs {
    url: String,
    cert: String,
    tee_key_algorithm: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CdhToml {
    kbc: CdhKbc,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CdhKbc {
    name: String,
    url: String,
    kbs_cert: String,
}

impl KbsConfig {
    /// `url` is `https://<host>[:<port>]`; `cert_pem` holds exactly one certificate.
    pub fn new(url: &str, cert_pem: &str) -> Result<Self, String> {
        check_url(url)?;
        let cert_der = pem_certificate(cert_pem)?;
        let spki = spki(&cert_der).ok_or("kbs cert: not an X.509 certificate")?;
        Ok(Self {
            url: url.to_owned(),
            cert_spki_sha256: ComposeHash::from(<[u8; 32]>::from(Sha256::digest(spki))),
            cert_der,
        })
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    /// The certificate as the entries carry it: PEM with 64-column lines.
    pub fn cert_pem(&self) -> String {
        let body = BASE64_STANDARD.encode(&self.cert_der);
        let mut out = format!("{PEM_BEGIN}\n");
        for line in body.as_bytes().chunks(64) {
            out.push_str(&String::from_utf8_lossy(line));
            out.push('\n');
        }
        out.push_str(PEM_END);
        out.push('\n');
        out
    }

    pub fn revision(&self) -> RevisionKbs {
        RevisionKbs {
            cert_spki_sha256: self.cert_spki_sha256,
            url: self.url.clone(),
        }
    }

    /// The `aa.toml` entry. The certificate is a TOML multi-line basic string, which (unlike the
    /// literal strings the init-data wraps entries in) PEM cannot end early.
    pub fn aa_toml(&self) -> String {
        format!(
            "[token_configs.kbs]\nurl = \"{}\"\ncert = \"\"\"\n{}\"\"\"\ntee_key_algorithm = \"{TEE_KEY_ALGORITHM}\"\n",
            self.url,
            self.cert_pem()
        )
    }

    /// The `cdh.toml` entry.
    pub fn cdh_toml(&self) -> String {
        format!(
            "[kbc]\nname = \"{KBC}\"\nurl = \"{}\"\nkbs_cert = \"\"\"\n{}\"\"\"\n",
            self.url,
            self.cert_pem()
        )
    }

    /// The configuration two init-data entries hold, if they are exactly what [`Self::aa_toml`]
    /// and [`Self::cdh_toml`] write for one URL and certificate.
    pub fn from_entries(aa: &str, cdh: &str) -> Result<Self, String> {
        let aa_doc: AaToml =
            toml::from_str(aa).map_err(|e| format!("{AA_ENTRY}: {}", e.message()))?;
        let cdh_doc: CdhToml =
            toml::from_str(cdh).map_err(|e| format!("{CDH_ENTRY}: {}", e.message()))?;
        let kbs = aa_doc.token_configs.kbs;
        let config = Self::new(&kbs.url, &kbs.cert).map_err(|e| format!("{AA_ENTRY}: {e}"))?;
        if kbs.tee_key_algorithm != TEE_KEY_ALGORITHM {
            return Err(format!(
                "{AA_ENTRY}: tee_key_algorithm {:?} is not {TEE_KEY_ALGORITHM:?}",
                kbs.tee_key_algorithm
            ));
        }
        if cdh_doc.kbc.name != KBC {
            return Err(format!(
                "{CDH_ENTRY}: kbc.name {:?} is not {KBC:?}",
                cdh_doc.kbc.name
            ));
        }
        if cdh_doc.kbc.url != kbs.url || pem_certificate(&cdh_doc.kbc.kbs_cert)? != config.cert_der
        {
            return Err(format!(
                "{AA_ENTRY} and {CDH_ENTRY} name different KBSes or certificates"
            ));
        }
        if aa != config.aa_toml() || cdh != config.cdh_toml() {
            return Err(format!(
                "{AA_ENTRY} or {CDH_ENTRY} is not in the form the generator writes"
            ));
        }
        Ok(config)
    }
}

/// `https://<host>[:<port>]`: a lowercase DNS name or IPv4 address, no path, query or user.
pub fn check_url(url: &str) -> Result<(), String> {
    let bad = || format!("kbs url {url:?} is not https://<host>[:<port>]");
    let rest = url.strip_prefix("https://").ok_or_else(bad)?;
    let (host, port) = match rest.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (rest, None),
    };
    let label_ok = |l: &str| {
        (1..=63).contains(&l.len())
            && l.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && !l.starts_with('-')
            && !l.ends_with('-')
    };
    if host.is_empty() || host.len() > 253 || !host.split('.').all(label_ok) {
        return Err(bad());
    }
    if let Some(port) = port {
        let ok = !port.starts_with('0')
            && port.bytes().all(|b| b.is_ascii_digit())
            && port.parse::<u16>().is_ok_and(|p| p > 0);
        if !ok {
            return Err(bad());
        }
    }
    Ok(())
}

/// The DER of the one `CERTIFICATE` block in `pem`, which holds nothing else.
fn pem_certificate(pem: &str) -> Result<Vec<u8>, String> {
    let bad = |m: &str| format!("kbs cert: {m}");
    let body = pem
        .trim()
        .strip_prefix(PEM_BEGIN)
        .and_then(|rest| rest.strip_suffix(PEM_END))
        .ok_or_else(|| bad("not one PEM CERTIFICATE block"))?;
    if body.contains("-----") {
        return Err(bad("holds more than one PEM block"));
    }
    let b64: String = body.split_ascii_whitespace().collect();
    let der = BASE64_STANDARD
        .decode(b64)
        .map_err(|_| bad("PEM body is not base64"))?;
    if der.is_empty() {
        return Err(bad("empty"));
    }
    Ok(der)
}

/// The DER `SubjectPublicKeyInfo` of a certificate that is exactly one DER `Certificate`.
fn spki(cert: &[u8]) -> Option<&[u8]> {
    let (_, certificate, trailing) = tlv(cert, 0x30)?;
    if !trailing.is_empty() {
        return None;
    }
    let (_, mut rest, _) = tlv(certificate, 0x30)?;
    if rest.first() == Some(&0xa0) {
        rest = tlv(rest, 0xa0)?.2;
    }
    // serialNumber, signature, issuer, validity, subject.
    for tag in [0x02, 0x30, 0x30, 0x30, 0x30] {
        rest = tlv(rest, tag)?.2;
    }
    Some(tlv(rest, 0x30)?.0)
}

/// One DER element of tag `tag` at the start of `input`: the whole element, its content, and
/// what follows it. Only definite, minimally encoded lengths.
fn tlv(input: &[u8], tag: u8) -> Option<(&[u8], &[u8], &[u8])> {
    let (&found, rest) = input.split_first()?;
    if found != tag {
        return None;
    }
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 {
            return None;
        }
        let (bytes, rest) = rest.split_at_checked(n)?;
        if bytes.first() == Some(&0) {
            return None;
        }
        let len = bytes.iter().try_fold(0usize, |acc, b| {
            acc.checked_mul(256)?.checked_add(usize::from(*b))
        })?;
        if len < 0x80 {
            return None;
        }
        (len, rest)
    };
    let (content, after) = rest.split_at_checked(len)?;
    let header = input.len().checked_sub(rest.len())?;
    let whole = input.get(..header.checked_add(len)?)?;
    Some((whole, content, after))
}

/// The resource types of the contract between the init-data generator and Trustee's KBS
/// (`docs/encrypted-storage.md`): `kbs:///<App id>/<type>/<tag>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceType {
    /// A tenant Secret, by name: sealed secrets' values.
    Secret,
    /// The App's derived key for a purpose (`.` for `:`): storage keys, `volume.<name>`.
    Key,
    /// The 32-byte key-encryption key an encrypted image's layer keys are wrapped under.
    ImageKey,
    /// The P-256 public JWK that verifies a sealed secret's signature.
    SealedSecretKey,
}

impl ResourceType {
    pub const ALL: [Self; 4] = [
        Self::Secret,
        Self::Key,
        Self::ImageKey,
        Self::SealedSecretKey,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::Secret => "secret",
            Self::Key => "key",
            Self::ImageKey => "image-key",
            Self::SealedSecretKey => "sealed-secret-key",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|t| t.name() == name)
    }

    /// Key purposes in the KMS's purpose alphabet; every other tag in the Secret-name alphabet.
    /// Neither has `:` or `/`.
    fn tag_ok(self, tag: &str) -> bool {
        match self {
            Self::Key => crate::is_key_purpose(tag),
            _ => crate::is_secret_name(tag),
        }
    }
}

/// A resource of the contract, as `kbs:///<app>/<type>/<tag>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resource {
    pub app: AppId,
    pub kind: ResourceType,
    pub tag: String,
}

impl Resource {
    pub fn new(app: AppId, kind: ResourceType, tag: &str) -> Result<Self, String> {
        if !kind.tag_ok(tag) {
            return Err(format!("{} {tag:?} is not a valid name", kind.name()));
        }
        Ok(Self {
            app,
            kind,
            tag: tag.to_owned(),
        })
    }

    /// Exactly `kbs:///<canonical App id>/<type>/<tag>` of the contract.
    pub fn parse(uri: &str) -> Result<Self, String> {
        let bad = || format!("{uri:?} is not kbs:///<App id>/<type>/<name>");
        let rest = uri.strip_prefix(URI_PREFIX).ok_or_else(bad)?;
        let mut parts = rest.splitn(3, '/');
        let (Some(app), Some(kind), Some(tag)) = (parts.next(), parts.next(), parts.next()) else {
            return Err(bad());
        };
        let app = app
            .parse::<AppId>()
            .ok()
            .filter(|a| a.to_string() == app)
            .ok_or_else(bad)?;
        let kind = ResourceType::from_name(kind).ok_or_else(|| {
            format!("{uri:?}: type {kind:?} is not secret, key, image-key or sealed-secret-key")
        })?;
        Self::new(app, kind, tag)
    }

    pub fn uri(&self) -> String {
        format!("{URI_PREFIX}{}/{}/{}", self.app, self.kind.name(), self.tag)
    }
}

#[cfg(test)]
pub(crate) mod tests;
