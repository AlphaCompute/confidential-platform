use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use crate::ComposeHash;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KmsRevision {
    pub compose_hash: ComposeHash,
    pub build: String,
    pub source_url: String,
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
        match BASE64_URL_SAFE_NO_PAD.decode(&f.public_key) {
            Ok(bytes) if bytes.len() == 32 => Ok(Self {
                algorithm: f.algorithm,
                public_key: f.public_key,
            }),
            _ => Err(format!(
                "catalog_key.public_key {:?} is not 32 bytes of base64url",
                f.public_key
            )),
        }
    }
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
