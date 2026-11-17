//! A catalog file is `{entry, signature, template, pod}`: a Kata init-data TOML (`template`) and
//! the pod spec that carries it, both written for the nil App id and the public name
//! [`PUBLIC_NAME`]. The signature covers the entry only; the entry binds both texts through their
//! SHA-256 and signs how often each placeholder occurs in them, so [`render`] varies nothing else.

use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Signer as _, SigningKey};
use serde::{Deserialize, Serialize};

use crate::{
    APP_ZONE, AppId, CatalogKey, ComposeHash, InitData, NamedSignature, compose_hash, context,
    is_slug, signing_digest,
};

pub const NIL_APP_ID: &str = "00000000-0000-0000-0000-000000000000";
/// Replaced by `<slug>.app.alphacompute.cc`.
pub const PUBLIC_NAME: &str = "__ALPHACOMPUTE_PUBLIC_NAME__";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resources {
    pub cpu: u32,
    pub memory_mib: u32,
}

/// How many times [`NIL_APP_ID`] and [`PUBLIC_NAME`] occur in the template and the pod together.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Substitutions {
    pub app_id: u32,
    pub public_name: u32,
}

impl Substitutions {
    pub fn count(template: &str, pod: &str) -> Result<Self, CatalogError> {
        let count = |placeholder: &str| {
            let n = template
                .matches(placeholder)
                .count()
                .saturating_add(pod.matches(placeholder).count());
            u32::try_from(n).map_err(|_| CatalogError::Malformed("too many placeholders".into()))
        };
        Ok(Self {
            app_id: count(NIL_APP_ID)?,
            public_name: count(PUBLIC_NAME)?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub catalog_id: String,
    pub version: String,
    pub title: String,
    pub template_sha256: ComposeHash,
    pub pod_sha256: ComposeHash,
    pub resources: Resources,
    pub substitutions: Substitutions,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogFile {
    pub entry: Entry,
    pub signature: NamedSignature,
    pub template: String,
    pub pod: String,
}

/// A catalog Revision for one App: `init_data` is registered, its SHA-256 is `revision`, and
/// `pod` is created with `init_data` in its `io.katacontainers.config.hypervisor.cc_init_data`
/// annotation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Rendered {
    pub revision: ComposeHash,
    pub init_data: String,
    pub pod: String,
}

/// `code()` is the verdict the shared vectors record and other implementations map to their own
/// errors.
#[derive(Debug, thiserror::Error)]
pub enum CatalogError {
    #[error("{0}")]
    SignatureInvalid(String),
    #[error("the template or the pod does not hash to the entry's digest")]
    TemplateMismatch,
    #[error("the placeholders occur {found:?} times, the entry signs {signed:?}")]
    SubstitutionsMismatch {
        found: Substitutions,
        signed: Substitutions,
    },
    #[error("{0}")]
    Malformed(String),
}

impl CatalogError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::SignatureInvalid(_) => "signature_invalid",
            Self::TemplateMismatch => "template_mismatch",
            Self::SubstitutionsMismatch { .. } => "substitutions_mismatch",
            Self::Malformed(_) => "malformed",
        }
    }
}

fn digest(entry: &Entry) -> Result<[u8; 32], CatalogError> {
    serde_json::to_value(entry)
        .and_then(|value| signing_digest(context::CATALOG, &value))
        .map_err(|e| CatalogError::Malformed(format!("entry does not canonicalize: {e}")))
}

/// Signs `entry` as given; [`render`] refuses a file whose texts do not match it.
pub fn sign(
    entry: Entry,
    template: String,
    pod: String,
    key: &SigningKey,
) -> Result<CatalogFile, CatalogError> {
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
        pod,
    })
}

/// Only `key` is tried: the caller passes the `catalog_key` of a verified platform document.
fn verify(file: &CatalogFile, key: &CatalogKey) -> Result<(), CatalogError> {
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

/// Verifies `file` under `key`, then replaces every nil App id with `app_id` and every
/// [`PUBLIC_NAME`] with `<slug>.app.alphacompute.cc`. Every other byte is kept, so the init-data
/// is exactly what is measured.
pub fn render(
    file: &CatalogFile,
    key: &CatalogKey,
    app_id: AppId,
    slug: &str,
) -> Result<Rendered, CatalogError> {
    verify(file, key)?;
    let entry = &file.entry;
    if compose_hash(&file.template) != entry.template_sha256
        || compose_hash(&file.pod) != entry.pod_sha256
    {
        return Err(CatalogError::TemplateMismatch);
    }
    let found = Substitutions::count(&file.template, &file.pod)?;
    if found != entry.substitutions {
        return Err(CatalogError::SubstitutionsMismatch {
            found,
            signed: entry.substitutions.clone(),
        });
    }
    if !is_slug(slug) {
        return Err(CatalogError::Malformed(format!("{slug:?} is not a slug")));
    }
    let public_name = format!("{slug}.{APP_ZONE}");
    let substitute = |text: &str| {
        text.replace(NIL_APP_ID, &app_id.to_string())
            .replace(PUBLIC_NAME, &public_name)
    };
    let init_data = substitute(&file.template);
    let parsed = InitData::parse(init_data.clone())
        .map_err(|e| CatalogError::Malformed(format!("template: {e}")))?;
    if parsed.app_id() != Some(app_id) {
        return Err(CatalogError::Malformed(
            "template: [data] app_id is not the nil App id".into(),
        ));
    }
    Ok(Rendered {
        revision: parsed.digest(),
        init_data,
        pod: substitute(&file.pod),
    })
}

#[cfg(test)]
mod tests {
    use base64::prelude::BASE64_URL_SAFE;

    use super::*;

    const TEMPLATE: &str = "algorithm = \"sha256\"\nversion = \"0.1.0\"\n\n[data]\n\"app_id\" = \"00000000-0000-0000-0000-000000000000\"\n\"policy.rego\" = '''\nENV=__ALPHACOMPUTE_PUBLIC_NAME__ é'''\n";
    const POD: &str =
        "env:\n- {name: ALPHACOMPUTE_PUBLIC_NAME, value: __ALPHACOMPUTE_PUBLIC_NAME__}\n";

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn catalog_key_of(key: &SigningKey) -> CatalogKey {
        CatalogKey::from(&key.verifying_key())
    }

    fn entry(template: &str, pod: &str) -> Entry {
        Entry {
            catalog_id: "confidential-container".into(),
            version: "1".into(),
            title: "Confidential container".into(),
            template_sha256: compose_hash(template),
            pod_sha256: compose_hash(pod),
            resources: Resources {
                cpu: 2,
                memory_mib: 4096,
            },
            substitutions: Substitutions::count(template, pod).unwrap(),
        }
    }

    fn signed(template: &str, pod: &str) -> CatalogFile {
        sign(entry(template, pod), template.into(), pod.into(), &key(11)).unwrap()
    }

    fn signed_by(seed: u8) -> CatalogFile {
        sign(
            entry(TEMPLATE, POD),
            TEMPLATE.into(),
            POD.into(),
            &key(seed),
        )
        .unwrap()
    }

    fn app_id() -> AppId {
        "01994b3e-5c8a-7d3e-9a1b-2c3d4e5f6a7b".parse().unwrap()
    }

    fn render_code(file: &CatalogFile, slug: &str) -> &'static str {
        render(file, &catalog_key_of(&key(11)), app_id(), slug)
            .unwrap_err()
            .code()
    }

    #[test]
    fn render_substitutes_the_app_id_and_public_name_and_nothing_else() {
        let rendered =
            render(&signed_by(11), &catalog_key_of(&key(11)), app_id(), "board").unwrap();
        let want = TEMPLATE
            .replace(NIL_APP_ID, "01994b3e-5c8a-7d3e-9a1b-2c3d4e5f6a7b")
            .replace(PUBLIC_NAME, "board.app.alphacompute.cc");
        assert_eq!(rendered.init_data, want);
        assert_eq!(rendered.revision, compose_hash(&want));
        assert_eq!(
            rendered.pod,
            POD.replace(PUBLIC_NAME, "board.app.alphacompute.cc")
        );
        assert_eq!(
            signed_by(11).entry.substitutions,
            Substitutions {
                app_id: 1,
                public_name: 2
            }
        );
    }

    #[test]
    fn an_entry_signed_by_another_key_is_refused() {
        let catalog_key = catalog_key_of(&key(11));
        let err = verify(&signed_by(12), &catalog_key).unwrap_err();
        assert_eq!(err.code(), "signature_invalid");
        let err = verify(&signed_by(11), &catalog_key_of(&key(12))).unwrap_err();
        assert_eq!(err.code(), "signature_invalid");
    }

    #[test]
    fn an_entry_changed_after_signing_is_refused() {
        let changes: [fn(&mut Entry); 8] = [
            |e| e.catalog_id.push('x'),
            |e| e.version = "2".into(),
            |e| e.title = "Confidential Container".into(),
            |e| e.resources.cpu = 3,
            |e| e.resources.memory_mib = 8192,
            |e| e.template_sha256 = compose_hash("{}"),
            |e| e.pod_sha256 = compose_hash("{}"),
            |e| e.substitutions.public_name = 0,
        ];
        for (i, change) in changes.into_iter().enumerate() {
            let mut file = signed_by(11);
            change(&mut file.entry);
            assert_eq!(render_code(&file, "board"), "signature_invalid", "{i}");
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
        let file = serde_json::to_value(signed_by(11)).unwrap();
        assert_eq!(
            serde_json::from_value::<CatalogFile>(file.clone()).unwrap(),
            signed_by(11)
        );
        let edits: [fn(&mut serde_json::Value); 7] = [
            |f| f["later"] = 1.into(),
            |f| f["entry"]["later"] = 1.into(),
            |f| f["entry"]["resources"]["gpu"] = 1.into(),
            |f| f["entry"]["substitutions"]["slug"] = 1.into(),
            |f| f["entry"]["resources"]["cpu"] = (-1).into(),
            |f| f["entry"]["template_sha256"] = "sha256:00".into(),
            |f| {
                f.as_object_mut().unwrap().remove("pod");
            },
        ];
        for (i, edit) in edits.into_iter().enumerate() {
            let mut bad = file.clone();
            edit(&mut bad);
            assert!(serde_json::from_value::<CatalogFile>(bad).is_err(), "{i}");
        }
    }

    #[test]
    fn render_refuses_texts_that_do_not_match_the_signed_entry() {
        let mut file = signed_by(11);
        file.template.push(' ');
        assert_eq!(render_code(&file, "board"), "template_mismatch");
        let mut file = signed_by(11);
        file.pod.push(' ');
        assert_eq!(render_code(&file, "board"), "template_mismatch");

        let mut miscounted = entry(TEMPLATE, POD);
        miscounted.substitutions.public_name = 1;
        let file = sign(miscounted, TEMPLATE.into(), POD.into(), &key(11)).unwrap();
        assert_eq!(render_code(&file, "board"), "substitutions_mismatch");
    }

    #[test]
    fn render_refuses_a_bad_slug_or_a_template_that_names_no_nil_app() {
        for slug in ["", "Board", "a--b", "sign", "b.c"] {
            assert_eq!(render_code(&signed_by(11), slug), "malformed", "{slug}");
        }
        let elsewhere = TEMPLATE.replacen(NIL_APP_ID, "01994b3e-0000-7000-8000-000000000000", 1);
        let file = signed(&elsewhere, &format!("{POD}# {NIL_APP_ID}\n"));
        assert_eq!(render_code(&file, "board"), "malformed");
        assert_eq!(render_code(&signed("not toml", POD), "board"), "malformed");
    }
}
