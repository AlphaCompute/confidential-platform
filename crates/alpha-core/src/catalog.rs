//! A catalog file is `{entry, signature, template}`. The signature covers the entry only; the
//! template is bound to it through `template_sha256`, which `render` checks before anything else,
//! so a template is never used except through `render`.

use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Signer as _, SigningKey};
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
    let usable_key = key.verifying_key().ok_or_else(|| {
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

#[cfg(test)]
mod tests {
    use base64::prelude::BASE64_URL_SAFE;

    use super::*;

    const TEMPLATE: &str = r#"{"a":1,"name":"00000000-0000-0000-0000-000000000000","z":"é"}"#;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn catalog_key_of(key: &SigningKey) -> CatalogKey {
        CatalogKey::from(&key.verifying_key())
    }

    fn entry(template: &str) -> Entry {
        Entry {
            catalog_id: "cpu-app".into(),
            version: "1".into(),
            title: "CPU App".into(),
            template_sha256: compose_hash(template),
            resources: Resources {
                cpu: 1,
                memory_mib: 2048,
            },
        }
    }

    fn signed_by(seed: u8) -> CatalogFile {
        sign(entry(TEMPLATE), TEMPLATE.into(), &key(seed)).unwrap()
    }

    fn app_id() -> AppId {
        "01994b3e-5c8a-7d3e-9a1b-2c3d4e5f6a7b".parse().unwrap()
    }

    #[test]
    fn an_entry_signed_by_the_catalog_key_verifies() {
        verify(&signed_by(11), &catalog_key_of(&key(11))).unwrap();
    }

    #[test]
    fn an_entry_signed_by_another_key_is_refused() {
        let catalog_key = catalog_key_of(&key(11));
        for seed in [12, 13] {
            let err = verify(&signed_by(seed), &catalog_key).unwrap_err();
            assert_eq!(err.code(), "signature_invalid", "{seed}");
            let err = verify(&signed_by(11), &catalog_key_of(&key(seed))).unwrap_err();
            assert_eq!(err.code(), "signature_invalid", "{seed}");
        }
    }

    #[test]
    fn an_entry_changed_after_signing_is_refused() {
        let changes: [fn(&mut Entry); 6] = [
            |e| e.catalog_id.push('x'),
            |e| e.version = "2".into(),
            |e| e.title = "CPU app".into(),
            |e| e.resources.cpu = 2,
            |e| e.resources.memory_mib = 4096,
            |e| e.template_sha256 = compose_hash("{}"),
        ];
        for (i, change) in changes.into_iter().enumerate() {
            let mut file = signed_by(11);
            change(&mut file.entry);
            let err = verify(&file, &catalog_key_of(&key(11))).unwrap_err();
            assert_eq!(err.code(), "signature_invalid", "change {i}");
        }
    }

    #[test]
    fn a_signature_in_another_form_is_refused() {
        let good = signed_by(11);
        let bytes = BASE64_URL_SAFE_NO_PAD
            .decode(&good.signature.signature)
            .unwrap();
        for (algorithm, signature) in [
            ("ecdsa-p256", good.signature.signature.clone()),
            ("ed25519", String::new()),
            ("ed25519", "not base64url!".into()),
            ("ed25519", BASE64_URL_SAFE.encode(&bytes)),
            ("ed25519", BASE64_URL_SAFE_NO_PAD.encode(&bytes[..63])),
        ] {
            let mut file = good.clone();
            file.signature = NamedSignature {
                algorithm: algorithm.into(),
                signature: signature.clone(),
            };
            let err = verify(&file, &catalog_key_of(&key(11))).unwrap_err();
            assert_eq!(
                err.code(),
                "signature_invalid",
                "{algorithm:?} {signature:?}"
            );
        }
    }

    #[test]
    fn an_unusable_catalog_key_is_malformed() {
        let public = key(11).verifying_key().to_bytes();
        for (algorithm, public_key) in [
            ("x25519", BASE64_URL_SAFE_NO_PAD.encode(public)),
            ("ed25519", String::new()),
            ("ed25519", BASE64_URL_SAFE_NO_PAD.encode(&public[..31])),
            ("ed25519", BASE64_URL_SAFE.encode(public)),
            ("ed25519", BASE64_URL_SAFE_NO_PAD.encode([0u8; 32])),
        ] {
            let catalog_key = CatalogKey {
                algorithm: algorithm.into(),
                public_key: public_key.clone(),
            };
            let err = verify(&signed_by(11), &catalog_key).unwrap_err();
            assert_eq!(err.code(), "malformed", "{algorithm:?} {public_key:?}");
        }
    }

    #[test]
    fn a_catalog_file_must_have_exactly_its_fields() {
        let file = signed_by(11);
        let signature = serde_json::to_string(&file.signature).unwrap();
        let template = serde_json::to_string(&file.template).unwrap();
        let hash = format!("\"{}\"", file.entry.template_sha256);
        let entry_with = |sha: &str, version: &str, resources: &str, extra: &str| {
            format!(
                r#"{{"catalog_id":"cpu-app","version":{version},"title":"CPU App"{extra},"template_sha256":{sha},"resources":{resources}}}"#
            )
        };
        let good_resources = r#"{"cpu":1,"memory_mib":2048}"#;
        let good_entry = entry_with(&hash, "\"1\"", good_resources, "");
        let file_with = |entry: &str, extra: &str| {
            format!(r#"{{"entry":{entry},"signature":{signature},"template":{template}{extra}}}"#)
        };
        let parsed: CatalogFile = serde_json::from_str(&file_with(&good_entry, "")).unwrap();
        assert_eq!(parsed, file);

        let hex = hash
            .trim_matches('"')
            .strip_prefix("sha256:")
            .unwrap()
            .to_owned();
        let bad_hashes = [
            format!("\"sha256:{}\"", hex.to_uppercase()),
            format!("\"{hex}\""),
            format!("\"sha256:{}\"", &hex[..63]),
        ];
        let mut bad = vec![
            file_with(&good_entry, r#","later":1"#),
            file_with(
                &entry_with(&hash, "\"1\"", good_resources, r#","later":1"#),
                "",
            ),
            file_with(
                &entry_with(&hash, "\"1\"", r#"{"cpu":1,"memory_mib":2048,"gpu":1}"#, ""),
                "",
            ),
            format!(
                r#"{{"entry":{good_entry},"signature":{},"template":{template}}}"#,
                signature.replacen('{', r#"{"later":1,"#, 1)
            ),
            format!(
                r#"{{"entry":{good_entry},"entry":{good_entry},"signature":{signature},"template":{template}}}"#
            ),
            file_with(
                &entry_with(&hash, "\"1\"", good_resources, r#","title":"CPU App""#),
                "",
            ),
            file_with(
                &entry_with(&hash, "\"1\"", r#"{"cpu":1.0,"memory_mib":2048}"#, ""),
                "",
            ),
            file_with(
                &entry_with(&hash, "\"1\"", r#"{"cpu":-1,"memory_mib":2048}"#, ""),
                "",
            ),
            file_with(
                &entry_with(
                    &hash,
                    "\"1\"",
                    r#"{"cpu":4294967296,"memory_mib":2048}"#,
                    "",
                ),
                "",
            ),
            file_with(&entry_with(&hash, "1", good_resources, ""), ""),
            format!(r#"{{"entry":{good_entry},"signature":{signature}}}"#),
        ];
        bad.extend(
            bad_hashes
                .iter()
                .map(|sha| file_with(&entry_with(sha, "\"1\"", good_resources, ""), "")),
        );
        for text in bad {
            assert!(
                serde_json::from_str::<CatalogFile>(&text).is_err(),
                "{text}"
            );
        }
    }

    #[test]
    fn render_replaces_the_one_nil_name_with_the_app_id() {
        let rendered = render(TEMPLATE, &compose_hash(TEMPLATE), app_id()).unwrap();
        assert_eq!(rendered.len(), TEMPLATE.len());
        let name = format!("\"name\":\"{}\"", app_id());
        assert_eq!(name, r#""name":"01994b3e-5c8a-7d3e-9a1b-2c3d4e5f6a7b""#);
        let at = TEMPLATE.find(NIL_NAME).unwrap();
        assert_eq!(&rendered[at..at + name.len()], name);
        assert_eq!(rendered[..at], TEMPLATE[..at]);
        assert_eq!(rendered[at + name.len()..], TEMPLATE[at + NIL_NAME.len()..]);
    }

    #[test]
    fn render_refuses_a_template_that_does_not_match_its_hash() {
        let longer = format!("{TEMPLATE} ");
        let err = render(&longer, &compose_hash(TEMPLATE), app_id()).unwrap_err();
        assert_eq!(err.code(), "template_mismatch");
        let err = render("", &compose_hash(TEMPLATE), app_id()).unwrap_err();
        assert_eq!(err.code(), "template_mismatch");
    }

    #[test]
    fn render_refuses_a_template_without_exactly_one_nil_name() {
        let twice = format!("[{TEMPLATE},{TEMPLATE}]");
        for template in [r#"{"name":"x"}"#, twice.as_str()] {
            let err = render(template, &compose_hash(template), app_id()).unwrap_err();
            assert_eq!(err.code(), "name_not_once", "{template}");
        }
    }

    #[test]
    fn signing_refuses_a_template_that_does_not_match_the_entry() {
        let err = sign(entry("{}"), TEMPLATE.into(), &key(11)).unwrap_err();
        assert_eq!(err.code(), "template_mismatch");
    }
}
