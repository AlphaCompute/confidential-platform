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
        let hex = s.strip_prefix("sha256:").ok_or(ParseComposeHashError)?;
        if hex.len() != 64 {
            return Err(ParseComposeHashError);
        }
        let mut bytes = [0u8; 32];
        for (i, pair) in hex.as_bytes().chunks(2).enumerate() {
            let nibble = |b: u8| match b {
                b'0'..=b'9' => Ok(b - b'0'),
                b'a'..=b'f' => Ok(b - b'a' + 10),
                _ => Err(ParseComposeHashError),
            };
            bytes[i] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
        }
        Ok(Self(bytes))
    }
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
    YamlLoader::load_from_str(yaml)?
        .iter()
        .try_for_each(check_images)?;
    Ok(compose_hash(compose))
}

fn check_images(node: &Yaml) -> Result<(), RegistrationError> {
    match node {
        Yaml::Hash(map) => map.iter().try_for_each(|(key, value)| {
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
    image.rsplit_once("@sha256:").is_some_and(|(_, hex)| {
        hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
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
    fn registration_vector() {
        let expected: Value = serde_json::from_str(&read("01-canonical", "expected.json")).unwrap();
        let app_id: AppId = expected["app_id"].as_str().unwrap().parse().unwrap();
        let compose = read("01-canonical", "app-compose.json");

        let hash = check_registration(&compose, app_id).unwrap();
        assert_eq!(hash.to_string(), expected["compose_hash"]);
        assert_eq!(hash, compose_hash(&compose));

        let document = json!({"app_id": app_id, "compose": compose});
        assert_eq!(expected["signing_context"], context::REVISION);
        let digest = signing_digest(context::REVISION, &document);
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
        let hash = check_registration(&with_newline, app_id).unwrap();
        assert_ne!(hash, compose_hash(&canonical));
        assert!(check_registration(&read("01-canonical", "input.json"), app_id).is_ok());
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
