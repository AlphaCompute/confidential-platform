//! A catalog file is `{entry, signature, template}`. The signature covers the entry only; the
//! template is bound to it through `template_sha256`, which `render` checks before anything else,
//! so a template is never used except through `render`.

use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::{
    AppId, CatalogKey, ComposeHash, NamedSignature, compose_hash, context, signing_digest,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resources {
    pub cpu: u32,
    pub memory_mib: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub catalog_id: String,
    pub version: String,
    pub title: String,
    pub template_sha256: ComposeHash,
    pub resources: Resources,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogFile {
    pub entry: Entry,
    pub signature: NamedSignature,
    pub template: String,
}

/// `code()` is the verdict the shared vectors record and other implementations map to their own
/// errors.
#[derive(Debug, thiserror::Error)]
pub enum CatalogError {
    #[error("{0}")]
    SignatureInvalid(String),
    #[error("the template does not hash to template_sha256")]
    TemplateMismatch,
    #[error("the template names the nil App id {0} times, not once")]
    NameNotOnce(usize),
    #[error("{0}")]
    Malformed(String),
}

impl CatalogError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::SignatureInvalid(_) => "signature_invalid",
            Self::TemplateMismatch => "template_mismatch",
            Self::NameNotOnce(_) => "name_not_once",
            Self::Malformed(_) => "malformed",
        }
    }
}

const NIL_NAME: &str = "\"name\":\"00000000-0000-0000-0000-000000000000\"";

fn digest(entry: &Entry) -> Result<[u8; 32], CatalogError> {
    serde_json::to_value(entry)
        .and_then(|value| signing_digest(context::CATALOG, &value))
        .map_err(|e| CatalogError::Malformed(format!("entry does not canonicalize: {e}")))
}

pub fn sign(entry: Entry, template: String, key: &SigningKey) -> Result<CatalogFile, CatalogError> {
    if compose_hash(&template) != entry.template_sha256 {
        return Err(CatalogError::TemplateMismatch);
    }
    let signature = key
        .try_sign(&digest(&entry)?)
        .map_err(|e| CatalogError::Malformed(format!("signing failed: {e}")))?;
    Ok(CatalogFile {
        entry,
        signature: NamedSignature {
            algorithm: "ed25519".into(),
            signature: BASE64_URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        },
        template,
    })
}

/// Only `key` is tried: the caller passes the `catalog_key` of a verified platform document.
pub fn verify(file: &CatalogFile, key: &CatalogKey) -> Result<(), CatalogError> {
    let usable_key = (key.algorithm == "ed25519")
        .then(|| BASE64_URL_SAFE_NO_PAD.decode(&key.public_key).ok())
        .flatten()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .and_then(|b| VerifyingKey::from_bytes(&b).ok())
        .filter(|k| !k.is_weak())
        .ok_or_else(|| {
            CatalogError::Malformed(format!(
                "catalog key {:?} {:?} is not an Ed25519 public key in base64url",
                key.algorithm, key.public_key
            ))
        })?;
    if file.signature.algorithm != "ed25519" {
        return Err(CatalogError::SignatureInvalid(format!(
            "signature algorithm {:?}",
            file.signature.algorithm
        )));
    }
    let signature = BASE64_URL_SAFE_NO_PAD
        .decode(&file.signature.signature)
        .ok()
        .and_then(|b| Signature::from_slice(&b).ok())
        .ok_or_else(|| {
            CatalogError::SignatureInvalid("signature is not base64url Ed25519".into())
        })?;
    usable_key
        .verify_strict(&digest(&file.entry)?, &signature)
        .map_err(|_| {
            CatalogError::SignatureInvalid("the entry is not signed by the catalog key".into())
        })
}

/// The template with its one nil App id replaced by `app_id`; every other byte is kept, so the
/// result is exactly what is measured.
pub fn render(
    template: &str,
    template_sha256: &ComposeHash,
    app_id: AppId,
) -> Result<String, CatalogError> {
    if compose_hash(template) != *template_sha256 {
        return Err(CatalogError::TemplateMismatch);
    }
    match template.matches(NIL_NAME).count() {
        1 => Ok(template.replacen(NIL_NAME, &format!("\"name\":\"{app_id}\""), 1)),
        count => Err(CatalogError::NameNotOnce(count)),
    }
}
