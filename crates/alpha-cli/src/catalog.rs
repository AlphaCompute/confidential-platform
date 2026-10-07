//! `alpha catalog sign`: the spec `alpha deploy` reads becomes a catalog file whose template is
//! that command's `app-compose.json` for the nil App id, signed with the catalog key.

use alpha_core::catalog::{CatalogFile, Entry, Resources};
use alpha_core::{AppId, CatalogKey, compose_hash};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use ed25519_dalek::SigningKey;

use crate::deploy::AppSpec;

pub fn sign(
    mut spec: AppSpec,
    catalog_id: &str,
    version: &str,
    title: &str,
    key: &SigningKey,
) -> Result<CatalogFile, String> {
    for (flag, value) in [
        ("--id", catalog_id),
        ("--version", version),
        ("--title", title),
    ] {
        if value.is_empty() {
            return Err(format!("{flag} is empty"));
        }
    }
    let resources: Resources =
        serde_json::from_value(spec.resources.clone()).map_err(|e| format!("resources: {e}"))?;
    spec.app_id = AppId::from(uuid::Uuid::nil());
    let template = crate::deploy::compose(&spec)?;
    let entry = Entry {
        catalog_id: catalog_id.into(),
        version: version.into(),
        title: title.into(),
        template_sha256: compose_hash(&template),
        resources,
    };
    alpha_core::catalog::sign(entry, template, key).map_err(|e| e.to_string())
}

/// The raw 32-byte public key, the form the platform document's `catalog_key` takes; the SPKI
/// a key file prints is not that form.
pub fn catalog_key(key: &SigningKey) -> CatalogKey {
    CatalogKey {
        algorithm: "ed25519".into(),
        public_key: BASE64_URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes()),
    }
}

/// The bare hex of `template_sha256`: a colon does not belong in a file name.
pub fn file_name(file: &CatalogFile) -> String {
    format!(
        "{}.json",
        hex::encode(file.entry.template_sha256.as_bytes())
    )
}

pub fn file_bytes(file: &CatalogFile) -> Result<Vec<u8>, String> {
    let mut bytes = serde_json::to_value(file)
        .and_then(|value| alpha_core::jcs(&value))
        .map_err(|e| e.to_string())?;
    bytes.push(b'\n');
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use alpha_core::catalog::{render, verify};

    use super::*;
    use crate::deploy::parse;

    fn vector() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/manifest/05-deploy")
    }

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[11u8; 32])
    }

    #[test]
    fn a_signed_template_renders_to_the_deploy_vector() {
        let spec = parse(&fs::read_to_string(vector().join("app.yaml")).unwrap()).unwrap();
        let app_id = spec.app_id;
        let key = signing_key();
        let file = sign(spec, "cpu-app", "1", "CPU App", &key).unwrap();
        let catalog_key: CatalogKey =
            serde_json::from_value(serde_json::to_value(catalog_key(&key)).unwrap()).unwrap();
        verify(&file, &catalog_key).unwrap();
        assert_eq!(
            file.template
                .matches("\"name\":\"00000000-0000-0000-0000-000000000000\"")
                .count(),
            1
        );
        assert_eq!(
            file.entry.resources,
            Resources {
                cpu: 1,
                memory_mib: 2048
            }
        );
        let expected = fs::read_to_string(vector().join("app-compose.json")).unwrap();
        assert_eq!(
            render(&file.template, &file.entry.template_sha256, app_id).unwrap(),
            expected
        );
    }

    #[test]
    fn the_file_is_named_by_its_template_hash() {
        let spec = parse(&fs::read_to_string(vector().join("app.yaml")).unwrap()).unwrap();
        let file = sign(spec, "cpu-app", "1", "CPU App", &signing_key()).unwrap();
        let name = file_name(&file);
        let hex = name.strip_suffix(".json").unwrap();
        assert_eq!(hex.len(), 64);
        assert!(hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
        assert_eq!(
            file.entry.template_sha256.to_string(),
            format!("sha256:{hex}")
        );
        let bytes = file_bytes(&file).unwrap();
        assert_eq!(bytes.last(), Some(&b'\n'));
        assert_eq!(serde_json::from_slice::<CatalogFile>(&bytes).unwrap(), file);
    }

    #[test]
    fn signing_refuses_empty_labels_missing_resources_or_a_tagged_image() {
        let base = fs::read_to_string(vector().join("app.yaml")).unwrap();
        let key = signing_key();
        let sign_yaml = |yaml: &str, id: &str, version: &str, title: &str| {
            sign(parse(yaml).unwrap(), id, version, title, &key).unwrap_err()
        };
        for (id, version, title, flag) in [
            ("", "1", "CPU App", "--id"),
            ("cpu-app", "", "CPU App", "--version"),
            ("cpu-app", "1", "", "--title"),
        ] {
            let err = sign_yaml(&base, id, version, title);
            assert!(err.contains(flag), "{err}");
        }
        let resources = "resources:\n  cpu: 1\n  memory_mib: 2048\n";
        assert!(base.contains(resources));
        for yaml in [
            base.replace(resources, ""),
            base.replace(resources, &format!("{resources}  gpu: 1\n")),
        ] {
            let err = sign_yaml(&yaml, "cpu-app", "1", "CPU App");
            assert!(err.starts_with("resources: "), "{err}");
        }
        let tagged = base.replace(
            "ghcr.io/acme/app@sha256:3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a",
            "ghcr.io/acme/app:latest",
        );
        let err = sign_yaml(&tagged, "cpu-app", "1", "CPU App");
        assert!(err.contains("digest"), "{err}");
        let taken = base.replace("  app:\n", "  alpha-runtime:\n");
        let err = sign_yaml(&taken, "cpu-app", "1", "CPU App");
        assert!(err.contains("added by alpha deploy"), "{err}");
    }
}
