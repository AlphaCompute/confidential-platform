use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use crate::ComposeHash;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KmsRevision {
    pub compose_hash: ComposeHash,
    pub build: String,
    pub source_url: String,
    /// The evidence profile this build's nodes attest under. A document written before Kata has
    /// none, and every build in it is a prototype CVM's. During the migration (PRD-05) one
    /// document lists the prototype build and the Kata build side by side.
    #[serde(default, skip_serializing_if = "KmsRevisionKind::is_prototype")]
    pub kind: KmsRevisionKind,
}

/// What a KMS build's `compose_hash` is the hash of: a prototype CVM's measured compose
/// (`alphacompute-evidence/1`) or a Kata pod's Revision v2 rebuilt from its init-data
/// (`kata-tdx/1`). A node is admitted only under the profile its build is listed for.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KmsRevisionKind {
    #[default]
    PrototypeTdx,
    KataTdx,
}

impl KmsRevisionKind {
    pub fn is_prototype(&self) -> bool {
        *self == Self::PrototypeTdx
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "SignerFields")]
pub struct Signer {
    pub origins: Vec<String>,
    pub rp_id: String,
    pub bundle_sha256: String,
    pub api_origin: String,
}

#[derive(Deserialize)]
struct SignerFields {
    origins: Vec<String>,
    rp_id: String,
    bundle_sha256: String,
    api_origin: String,
}

impl TryFrom<SignerFields> for Signer {
    type Error = String;

    fn try_from(f: SignerFields) -> Result<Self, Self::Error> {
        if !is_host(&f.rp_id) {
            return Err(format!(
                "signer.rp_id {:?} is not a lowercase host",
                f.rp_id
            ));
        }
        if f.origins.is_empty() {
            return Err("signer.origins is empty".into());
        }
        for origin in &f.origins {
            let on_rp_id = origin_host(origin)
                .and_then(|host| host.strip_suffix(f.rp_id.as_str()))
                .is_some_and(|rest| rest.is_empty() || rest.ends_with('.'));
            if !on_rp_id {
                return Err(format!(
                    "signer.origins {origin:?} is not an https origin on {:?}",
                    f.rp_id
                ));
            }
        }
        if origin_host(&f.api_origin).is_none() {
            return Err(format!(
                "signer.api_origin {:?} is not an https origin",
                f.api_origin
            ));
        }
        if f.bundle_sha256
            .strip_prefix("sha256:")
            .and_then(crate::hex_bytes::<32>)
            .is_none()
        {
            return Err(format!(
                "signer.bundle_sha256 {:?} is not sha256:<64 lowercase hex>",
                f.bundle_sha256
            ));
        }
        Ok(Self {
            origins: f.origins,
            rp_id: f.rp_id,
            bundle_sha256: f.bundle_sha256,
            api_origin: f.api_origin,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "CatalogKeyFields")]
pub struct CatalogKey {
    pub algorithm: String,
    pub public_key: String,
}

impl CatalogKey {
    pub fn verifying_key(&self) -> Option<ed25519_dalek::VerifyingKey> {
        if self.algorithm != "ed25519" {
            return None;
        }
        BASE64_URL_SAFE_NO_PAD
            .decode(&self.public_key)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .and_then(|b| ed25519_dalek::VerifyingKey::from_bytes(&b).ok())
            .filter(|k| !k.is_weak())
    }
}

impl From<&ed25519_dalek::VerifyingKey> for CatalogKey {
    fn from(key: &ed25519_dalek::VerifyingKey) -> Self {
        Self {
            algorithm: "ed25519".into(),
            public_key: BASE64_URL_SAFE_NO_PAD.encode(key.to_bytes()),
        }
    }
}

#[derive(Deserialize)]
struct CatalogKeyFields {
    algorithm: String,
    public_key: String,
}

impl TryFrom<CatalogKeyFields> for CatalogKey {
    type Error = String;

    fn try_from(f: CatalogKeyFields) -> Result<Self, Self::Error> {
        if f.algorithm != "ed25519" {
            return Err(format!("catalog_key.algorithm {:?}", f.algorithm));
        }
        let key = Self {
            algorithm: f.algorithm,
            public_key: f.public_key,
        };
        if key.verifying_key().is_none() {
            return Err(format!(
                "catalog_key.public_key {:?} is not an Ed25519 public key in base64url",
                key.public_key
            ));
        }
        Ok(key)
    }
}

/// The PCCS a platform document names (PRD-05: our own): `https://<lowercase host>[:port][/path]`,
/// the base URL a DCAP collateral client is given. No query, fragment, user info or whitespace.
pub fn check_pccs_url(url: &str) -> Result<(), String> {
    let refused = || format!("pccs_url {url:?} is not an https URL on a lowercase host");
    let rest = url.strip_prefix("https://").ok_or_else(refused)?;
    let authority = rest.split('/').next().unwrap_or_default();
    let host = match authority.split_once(':') {
        None => authority,
        Some((host, port)) => {
            if port.starts_with('0') || !matches!(port.parse::<u16>(), Ok(p) if p != 0) {
                return Err(refused());
            }
            host
        }
    };
    if !is_host(host) || url.contains(['?', '#', '@', '\\']) || url.contains(char::is_whitespace) {
        return Err(refused());
    }
    Ok(())
}

/// `pccs_url` of a platform document, checked as it is read.
pub fn deserialize_pccs_url<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<String>, D::Error> {
    let url = Option::<String>::deserialize(d)?;
    if let Some(url) = &url {
        check_pccs_url(url).map_err(serde::de::Error::custom)?;
    }
    Ok(url)
}

/// The host of a serialized `https` origin. A non-canonical origin is refused rather than
/// normalized, because the passkey check later compares origins byte for byte.
fn origin_host(origin: &str) -> Option<&str> {
    let rest = origin.strip_prefix("https://")?;
    let host = match rest.split_once(':') {
        None => rest,
        Some((host, port)) => {
            // `u16` parsing takes `+443` and `0443`, and a browser serializes neither of them,
            // nor the default port.
            if port.starts_with('0')
                || !port.bytes().all(|b| b.is_ascii_digit())
                || !matches!(port.parse::<u16>(), Ok(p) if p != 443)
            {
                return None;
            }
            host
        }
    };
    is_host(host).then_some(host)
}

fn is_host(host: &str) -> bool {
    host.len() <= 253
        && host.split('.').all(|label| {
            let bytes = label.as_bytes();
            !bytes.is_empty()
                && bytes.len() <= 63
                && bytes.first() != Some(&b'-')
                && bytes.last() != Some(&b'-')
                && bytes
                    .iter()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
        })
        && host
            .rsplit('.')
            .next()
            .is_some_and(|tld| tld.bytes().any(|b| b.is_ascii_lowercase()))
}

#[cfg(test)]
mod tests {
    use base64::prelude::{BASE64_STANDARD_NO_PAD, BASE64_URL_SAFE};
    use ed25519_dalek::SigningKey;
    use serde_json::{Value, json};

    use super::*;

    #[test]
    fn a_pccs_url_is_https_on_a_lowercase_host() {
        for good in [
            "https://pccs.site1.alphacompute.internal:8081/sgx/certification/v4/",
            "https://pccs.example",
            "https://pccs.example/",
        ] {
            assert_eq!(check_pccs_url(good), Ok(()), "{good}");
        }
        for bad in [
            "http://pccs.example/",
            "https://PCCS.example/",
            "https://pccs.example:0/",
            "https://pccs.example:08081/",
            "https://pccs.example:99999/",
            "https://user@pccs.example/",
            "https://pccs.example/?x=1",
            "https://pccs.example/#f",
            "https://pccs.example/ v4",
            "https:///v4",
            "pccs.example",
        ] {
            assert!(check_pccs_url(bad).is_err(), "{bad}");
        }
    }

    fn signer_on(rp_id: &str, field: &str, value: Value) -> Result<Signer, serde_json::Error> {
        let mut s = json!({
            "origins": [format!("https://{rp_id}")],
            "rp_id": rp_id,
            "bundle_sha256": format!("sha256:{}", "0".repeat(64)),
            "api_origin": "https://api.example"
        });
        s[field] = value;
        serde_json::from_value(s)
    }

    fn signer(field: &str, value: Value) -> Result<Signer, serde_json::Error> {
        signer_on("sign.example", field, value)
    }

    fn public_key() -> [u8; 32] {
        SigningKey::from_bytes(&[7u8; 32])
            .verifying_key()
            .to_bytes()
    }

    fn catalog_key(algorithm: &str, public_key: &str) -> Result<CatalogKey, serde_json::Error> {
        serde_json::from_value(json!({ "algorithm": algorithm, "public_key": public_key }))
    }

    #[test]
    fn origin_is_a_serialized_https_origin() {
        for ok in [
            "https://api.example",
            "https://api.example:1",
            "https://api.example:65535",
            "https://api.example:8443",
            "https://localhost",
        ] {
            assert!(signer("api_origin", json!(ok)).is_ok(), "{ok:?}");
        }
        for bad in [
            "http://api.example",
            "https://API.example",
            "https://api.example/",
            "https://api.example/v1",
            "https://api.example?x",
            "https://api.example#x",
            "https://u@api.example",
            "https://api.example:",
            "https://api.example:0",
            "https://api.example:443",
            "https://api.example:+443",
            "https://api.example:0443",
            "https://api.example:65536",
            "https://api.example:99999999999999999999",
            "https://127.0.0.1",
            "https://[::1]",
            "https://api.example.",
            "https://-a.example",
            "https://a..example",
            "https://",
            "",
        ] {
            assert!(signer("api_origin", json!(bad)).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn signer_origins_sit_on_rp_id_at_a_label_boundary() {
        for ok in [
            "https://sign.example",
            "https://a.sign.example",
            "https://a.b.sign.example:8443",
        ] {
            assert!(signer("origins", json!([ok])).is_ok(), "{ok:?}");
        }
        for bad in [
            "https://evilsign.example",
            "https://sign.example.evil",
            "https://example",
            "https://other.example",
        ] {
            assert!(signer("origins", json!([bad])).is_err(), "{bad:?}");
        }
        for ok in ["https://localhost:8443", "https://localhost"] {
            assert!(
                signer_on("localhost", "origins", json!([ok])).is_ok(),
                "{ok:?}"
            );
        }
        assert!(signer_on("localhost", "origins", json!(["http://localhost:8443"])).is_err());
        for bad in [
            "",
            "Sign.example",
            "sign.example.",
            "127.0.0.1",
            "https://sign.example",
        ] {
            assert!(signer("rp_id", json!(bad)).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn signer_refuses_empty_origins_and_bad_bundle_hashes() {
        assert!(signer("origins", json!([])).is_err());
        assert!(signer("origins", json!(["https://sign.example"])).is_ok());
        for bad in [
            format!("sha256:{}", "0".repeat(63)),
            format!("sha256:{}", "0".repeat(65)),
            format!("sha256:{}", "A".repeat(64)),
            format!("sha256:{}", "g".repeat(64)),
            "0".repeat(64),
        ] {
            assert!(signer("bundle_sha256", json!(bad)).is_err(), "{bad:?}");
        }
        let good = format!("sha256:{}", "0".repeat(64));
        assert!(signer("bundle_sha256", json!(good)).is_ok());
    }

    #[test]
    fn signer_keeps_origin_order_and_duplicates_and_tolerates_unknown_fields() {
        let b = "https://b.sign.example";
        let a = "https://a.sign.example";
        assert_eq!(
            signer("origins", json!([b, a, b])).unwrap().origins,
            [b, a, b]
        );
        assert!(signer("later", json!(1)).is_ok());
        let key = json!({
            "algorithm": "ed25519",
            "public_key": BASE64_URL_SAFE_NO_PAD.encode(public_key()),
            "later": 1
        });
        assert!(serde_json::from_value::<CatalogKey>(key).is_ok());
    }

    #[test]
    fn catalog_key_is_an_ed25519_public_key_in_base64url() {
        let good = BASE64_URL_SAFE_NO_PAD.encode(public_key());
        assert_eq!(catalog_key("ed25519", &good).unwrap().public_key, good);
        let standard = BASE64_STANDARD_NO_PAD.encode(public_key());
        assert!(standard.contains('+') || standard.contains('/'));
        for (algorithm, public_key) in [
            ("ml-dsa", good.clone()),
            ("Ed25519", good.clone()),
            (
                "ed25519",
                BASE64_URL_SAFE_NO_PAD.encode(&public_key()[..31]),
            ),
            (
                "ed25519",
                BASE64_URL_SAFE_NO_PAD.encode([&public_key()[..], &[0]].concat()),
            ),
            ("ed25519", BASE64_URL_SAFE.encode(public_key())),
            ("ed25519", standard),
            ("ed25519", BASE64_URL_SAFE_NO_PAD.encode([0u8; 32])),
            ("ed25519", BASE64_URL_SAFE_NO_PAD.encode([7u8; 32])),
        ] {
            assert!(
                catalog_key(algorithm, &public_key).is_err(),
                "{algorithm:?} {public_key:?}"
            );
        }
    }

    #[test]
    fn a_kms_revision_without_kind_is_a_prototype_build_and_a_kata_build_says_so() {
        let hash = crate::compose_hash("{}");
        let old = json!({ "compose_hash": hash, "build": "kms v1", "source_url": "u" });
        let revision: KmsRevision = serde_json::from_value(old.clone()).unwrap();
        assert_eq!(revision.kind, KmsRevisionKind::PrototypeTdx);
        assert_eq!(serde_json::to_value(&revision).unwrap(), old);

        let mut kata = old;
        kata["kind"] = json!("kata-tdx");
        let revision: KmsRevision = serde_json::from_value(kata.clone()).unwrap();
        assert_eq!(revision.kind, KmsRevisionKind::KataTdx);
        assert_eq!(serde_json::to_value(&revision).unwrap(), kata);

        kata["kind"] = json!("kata-snp");
        assert!(serde_json::from_value::<KmsRevision>(kata).is_err());
    }
}
