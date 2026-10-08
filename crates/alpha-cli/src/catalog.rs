//! `alpha catalog sign`: the spec `alpha deploy` reads becomes a catalog file whose template is
//! that command's `app-compose.json` for the nil App id, signed with the catalog key.

use alpha_core::catalog::{CatalogFile, Entry, Resources};
use alpha_core::{AppId, compose_hash};
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

    use alpha_core::CatalogKey;
    use alpha_core::catalog::{render, verify};

    use super::*;
    use crate::deploy::parse;

    fn vector() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/manifest/05-deploy")
    }

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[11u8; 32])
    }

    const SPEC: &str = include_str!("../../../testdata/catalog/app.yaml");

    const APP_ID: &str = "01994b3e-5c8a-7d3e-9a1b-2c3d4e5f6a7b";

    fn catalog_vectors() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/catalog")
    }

    fn app_id() -> AppId {
        APP_ID.parse().unwrap()
    }

    fn valid() -> CatalogFile {
        sign(
            parse(SPEC).unwrap(),
            "cpu-app",
            "1",
            "CPU App",
            &signing_key(),
        )
        .unwrap()
    }

    /// Every file under `testdata/catalog`; each catalog file differs from `valid.json` in one
    /// respect only, so its refusal can come only from the check that respect exercises.
    fn vectors() -> Vec<(&'static str, Vec<u8>)> {
        let valid = valid();
        let rendered = render(&valid.template, &valid.entry.template_sha256, app_id()).unwrap();
        let signed = |template: String, seed: u8| {
            let entry = Entry {
                template_sha256: compose_hash(&template),
                ..valid.entry.clone()
            };
            alpha_core::catalog::sign(entry, template, &SigningKey::from_bytes(&[seed; 32]))
                .unwrap()
        };

        // `alpha catalog sign` cannot produce a template whose nil name is absent or repeated, since
        // `deploy::compose` refuses one; these are signed through the core function directly.
        let mut spec = parse(SPEC).unwrap();
        spec.app_id = app_id();
        let deployed = crate::deploy::compose(&spec).unwrap();
        assert_eq!(rendered, deployed);
        // Go's encoding/json escapes these unless told not to, so a consumer that re-marshals the
        // compose fails the byte comparison instead of passing by luck.
        for raw in ["&&", ">", "$("] {
            assert!(deployed.contains(raw), "{raw}");
        }
        let name_absent = signed(deployed, 11);

        let mut repeated: serde_json::Value = serde_json::from_str(&valid.template).unwrap();
        let previous = repeated.as_object_mut().unwrap().insert(
            "labels".into(),
            serde_json::json!({"name": "00000000-0000-0000-0000-000000000000"}),
        );
        assert!(previous.is_none());
        let name_repeated = signed(alpha_core::phala::canonicalize(&repeated).unwrap(), 11);

        let mut tampered = valid.clone();
        assert_eq!(tampered.template.matches("\"kms_enabled\":true").count(), 1);
        tampered.template = tampered
            .template
            .replace("\"kms_enabled\":true", "\"kms_enabled\":false");

        let catalog: Vec<(&'static str, CatalogFile, &str, &str)> = vec![
            ("valid.json", valid.clone(), "ok", "ok"),
            (
                "signed-by-other-key.json",
                signed(valid.template.clone(), 13),
                "signature_invalid",
                "ok",
            ),
            (
                "signed-by-release-key.json",
                signed(valid.template.clone(), 12),
                "signature_invalid",
                "ok",
            ),
            ("name-absent.json", name_absent, "ok", "name_not_once"),
            ("name-repeated.json", name_repeated, "ok", "name_not_once"),
            (
                "template-tampered.json",
                tampered,
                "ok",
                "template_mismatch",
            ),
        ];
        let verdicts: serde_json::Map<String, serde_json::Value> = catalog
            .iter()
            .map(|(name, _, signature, render)| {
                (
                    (*name).to_owned(),
                    serde_json::json!({"signature": signature, "render": render}),
                )
            })
            .collect();
        let expected = serde_json::json!({
            "app_id": APP_ID,
            "compose_hash": compose_hash(&rendered),
            "catalog_key": CatalogKey::from(&signing_key().verifying_key()),
            "release_key": CatalogKey::from(&SigningKey::from_bytes(&[12u8; 32]).verifying_key()),
            "vectors": verdicts,
        });
        let mut expected = alpha_core::jcs(&expected).unwrap();
        expected.push(b'\n');
        let mut files = vec![
            ("app.yaml", SPEC.as_bytes().to_vec()),
            ("app-compose.json", rendered.into_bytes()),
            ("expected.json", expected),
        ];
        for (name, file, _, _) in &catalog {
            files.push((*name, file_bytes(file).unwrap()));
        }
        files
    }

    #[test]
    fn catalog_vectors_regenerate_byte_for_byte() {
        let files = vectors();
        let dir = catalog_vectors();
        if std::env::var_os("WRITE_VECTORS").is_some() {
            fs::create_dir_all(&dir).unwrap();
            for (name, bytes) in &files {
                fs::write(dir.join(name), bytes).unwrap();
            }
            return;
        }
        for (name, bytes) in &files {
            let on_disk = fs::read(dir.join(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert!(on_disk == *bytes, "{name} does not regenerate");
        }
        let mut listed: Vec<String> = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        listed.sort();
        let mut generated: Vec<String> = files.iter().map(|(n, _)| (*n).to_owned()).collect();
        generated.sort();
        assert_eq!(listed, generated);
    }

    #[test]
    fn a_signed_template_renders_to_the_deploy_vector() {
        let spec = parse(&fs::read_to_string(vector().join("app.yaml")).unwrap()).unwrap();
        let app_id = spec.app_id;
        let key = signing_key();
        let file = sign(spec, "cpu-app", "1", "CPU App", &key).unwrap();
        let catalog_key: CatalogKey = serde_json::from_value(
            serde_json::to_value(CatalogKey::from(&key.verifying_key())).unwrap(),
        )
        .unwrap();
        verify(&file, &catalog_key).unwrap();
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
