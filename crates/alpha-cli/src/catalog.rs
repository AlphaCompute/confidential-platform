//! `alpha catalog sign`: the Pod `alpha coco render --app-id 00000000-0000-0000-0000-000000000000`
//! wrote becomes a catalog file: its init-data is the template, and the Pod without the init-data
//! annotation is the pod.

use alpha_core::catalog::{CatalogFile, Entry, Resources, Substitutions};
use alpha_core::{AppId, compose_hash};
use ed25519_dalek::SigningKey;
use serde_yaml_ng::Value as Yaml;

use crate::coco;

pub fn sign(
    rendered_pod: &str,
    catalog_id: &str,
    version: &str,
    title: &str,
    resources: Resources,
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
    if resources.cpu == 0 || resources.memory_mib == 0 {
        return Err("--cpu and --memory-mib must be positive".into());
    }
    let (app_id, _, template) = coco::rendered_init_data(rendered_pod)?;
    if app_id != AppId::from(uuid::Uuid::nil()) {
        return Err(format!(
            "init-data names App {app_id}; render with --app-id {}",
            alpha_core::catalog::NIL_APP_ID
        ));
    }
    let pod = without_init_data(rendered_pod)?;
    // Refuses a tagged image, among the rest of what render refuses, in case the file was edited.
    coco::parse(pod.as_bytes())?;
    let entry = Entry {
        catalog_id: catalog_id.into(),
        version: version.into(),
        title: title.into(),
        template_sha256: compose_hash(&template),
        pod_sha256: compose_hash(&pod),
        resources,
        substitutions: Substitutions::count(&template, &pod).map_err(|e| e.to_string())?,
    };
    alpha_core::catalog::sign(entry, template, pod, key).map_err(|e| e.to_string())
}

fn without_init_data(pod: &str) -> Result<String, String> {
    let mut spec: Yaml = serde_yaml_ng::from_str(pod).map_err(|e| format!("pod spec: {e}"))?;
    if let Some(Yaml::Mapping(annotations)) = spec
        .get_mut("metadata")
        .and_then(|m| m.get_mut("annotations"))
    {
        annotations.remove(coco::ANNOTATION);
    }
    serde_yaml_ng::to_string(&spec).map_err(|e| format!("pod spec: {e}"))
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
    use alpha_core::catalog::{PUBLIC_NAME, render};

    use super::*;

    const K3: &str = include_str!("../../../testdata/attest/b300-kata-4.0.0/k3-app.toml");
    const K3_POD: &str = include_str!("../../../testdata/attest/b300-kata-4.0.0/k3-pod.yaml");
    const APP_ID: &str = "01994b3e-5c8a-7d3e-9a1b-2c3d4e5f6a7b";
    const SLUG: &str = "board";

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[11u8; 32])
    }

    const LABELS: [&str; 3] = ["confidential-container", "1", "Confidential container"];

    fn signed(
        pod: &str,
        [id, version, title]: [&str; 3],
        resources: Resources,
    ) -> Result<CatalogFile, String> {
        sign(pod, id, version, title, resources, &signing_key())
    }

    fn resources() -> Resources {
        Resources {
            cpu: 2,
            memory_mib: 4096,
        }
    }

    /// k3's Pod and init-data, which genpolicy wrote for that Pod, with the public name in the
    /// container's env and `app_id` in `[data]`, as `alpha coco render` writes them.
    fn rendered_pod(app_id: AppId) -> String {
        use std::io::Write as _;
        let (rules, data) = K3.split_once("\npolicy_data := ").unwrap();
        let data = data.replacen(
            "\"HOSTNAME=$(host-name)\"",
            &format!(
                "\"HOSTNAME=$(host-name)\",\n            \"ALPHACOMPUTE_PUBLIC_NAME={PUBLIC_NAME}\""
            ),
            1,
        );
        let init_data = format!("{rules}\npolicy_data := {data}").replacen(
            "0199e000-0000-7000-8000-00000000a11d",
            &app_id.to_string(),
            1,
        );
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        gzip.write_all(init_data.as_bytes()).unwrap();
        let annotation =
            base64::Engine::encode(&base64::prelude::BASE64_STANDARD, gzip.finish().unwrap());
        let pod = K3_POD.replace(
            "    image: public",
            &format!(
                "    env:\n    - {{name: ALPHACOMPUTE_PUBLIC_NAME, value: {PUBLIC_NAME}}}\n    image: public"
            ),
        );
        let mut spec: Yaml = serde_yaml_ng::from_str(&pod).unwrap();
        spec["metadata"]["annotations"] =
            serde_yaml_ng::Mapping::from_iter([(coco::ANNOTATION.into(), annotation.into())])
                .into();
        serde_yaml_ng::to_string(&spec).unwrap()
    }

    fn template_pod() -> String {
        rendered_pod(AppId::from(uuid::Uuid::nil()))
    }

    fn catalog_vectors() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/catalog")
    }

    /// Every file under `testdata/catalog`. The page renders `valid.json` in wasm and must get
    /// `init-data.toml`; each other catalog file differs from it in one respect only.
    fn vectors() -> Vec<(&'static str, Vec<u8>)> {
        let valid = signed(&template_pod(), LABELS, resources()).unwrap();
        let catalog_key = CatalogKey::from(&signing_key().verifying_key());
        let rendered = render(&valid, &catalog_key, APP_ID.parse().unwrap(), SLUG).unwrap();
        assert!(rendered.init_data.contains("board.app.alphacompute.cc"));

        let resign = |entry: Entry, seed: u8| {
            alpha_core::catalog::sign(
                entry,
                valid.template.clone(),
                valid.pod.clone(),
                &SigningKey::from_bytes(&[seed; 32]),
            )
            .unwrap()
        };
        let mut tampered = valid.clone();
        tampered.template = tampered.template.replacen("(c) 2023", "(c) 2024", 1);
        let mut miscounted = valid.entry.clone();
        miscounted.substitutions.public_name = 1;

        let catalog = [
            ("valid.json", valid.clone(), "ok"),
            (
                "signed-by-other-key.json",
                resign(valid.entry.clone(), 13),
                "signature_invalid",
            ),
            ("template-tampered.json", tampered, "template_mismatch"),
            (
                "substitutions-miscounted.json",
                resign(miscounted, 11),
                "substitutions_mismatch",
            ),
        ];
        let verdicts: serde_json::Map<String, serde_json::Value> = catalog
            .iter()
            .map(|(name, _, verdict)| ((*name).to_owned(), (*verdict).into()))
            .collect();
        let mut expected = alpha_core::jcs(&serde_json::json!({
            "app_id": APP_ID,
            "slug": SLUG,
            "compose_hash": rendered.revision,
            "catalog_key": catalog_key,
            "vectors": verdicts,
        }))
        .unwrap();
        expected.push(b'\n');
        let mut files = vec![
            ("init-data.toml", rendered.init_data.into_bytes()),
            ("expected.json", expected),
        ];
        for (name, file, _) in &catalog {
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
    fn the_preview_entry_renders_once_its_inputs_are_set() {
        let template = include_str!("../../../deploy/kata/catalog/confidential-container.yaml")
            .replace(
                "${RUNTIME_IMAGE}",
                &format!(
                    "ghcr.io/alphacompute/alpha-runtime@sha256:{}",
                    "3a".repeat(32)
                ),
            );
        assert_eq!(template.matches(PUBLIC_NAME).count(), 1);
        coco::parse(template.as_bytes()).unwrap();
    }

    #[test]
    fn the_pod_drops_only_the_init_data_annotation() {
        let file = signed(&template_pod(), LABELS, resources()).unwrap();
        assert!(!file.pod.contains(coco::ANNOTATION));
        assert!(file.pod.contains(PUBLIC_NAME));
        let name = file_name(&file);
        assert_eq!(
            file.entry.template_sha256.to_string(),
            format!("sha256:{}", name.strip_suffix(".json").unwrap())
        );
    }

    #[test]
    fn signing_refuses_empty_labels_another_app_or_a_tagged_image() {
        let pod = template_pod();
        for (labels, flag) in [
            (["", "1", "Confidential container"], "--id"),
            (["confidential-container", "1", ""], "--title"),
        ] {
            let err = signed(&pod, labels, resources()).unwrap_err();
            assert!(err.contains(flag), "{err}");
        }
        let zero = Resources {
            cpu: 0,
            memory_mib: 4096,
        };
        assert!(signed(&pod, LABELS, zero).is_err());

        let other_app = rendered_pod(APP_ID.parse().unwrap());
        let err = signed(&other_app, LABELS, resources()).unwrap_err();
        assert!(err.contains("--app-id"), "{err}");

        let image = "public.ecr.aws/docker/library/alpine@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8";
        let tagged = pod.replace(image, "public.ecr.aws/docker/library/alpine:3");
        let err = signed(&tagged, LABELS, resources()).unwrap_err();
        assert!(err.contains("sha256"), "{err}");
    }
}
