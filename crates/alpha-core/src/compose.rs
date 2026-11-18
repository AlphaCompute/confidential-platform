use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use sha2::{Digest, Sha256};
use yaml_rust2::parser::{Event, Parser};
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

pub fn compose_hash(compose: impl AsRef<[u8]>) -> ComposeHash {
    ComposeHash(Sha256::digest(compose.as_ref()).into())
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
    #[error("docker_compose_file expands to more than {MAX_YAML_BYTES} bytes")]
    TooLarge,
    #[error("docker_compose_file nests deeper than {MAX_YAML_DEPTH} levels")]
    TooDeep,
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
    load_yaml(yaml)?.iter().try_for_each(check_images)?;
    Ok(compose_hash(compose))
}

/// Far above any real compose, far below what hurts a node.
const MAX_YAML_BYTES: usize = 8 << 20;
/// A rough size of one `Yaml` node before its scalar text.
const NODE_BYTES: usize = 64;
/// The loader and `check_images` recurse once per level, so depth is bounded by the stack.
const MAX_YAML_DEPTH: usize = 64;

/// `YamlLoader` copies the anchored node into its anchor table and again for every alias, so
/// nested aliases grow exponentially ("billion laughs"). Estimate the bytes it would build on the
/// event stream first; compose files use anchors with `<<:` merges, so refusing aliases outright
/// would refuse real files.
pub fn load_yaml(yaml: &str) -> Result<Vec<Yaml>, RegistrationError> {
    let mut parser = Parser::new_from_str(yaml);
    // `tree` is what the documents hold, `copies` the loader's anchor table; an anchor's size is
    // its share of `tree` only, as the table entry does not hold its descendants' entries.
    let mut tree = 0usize;
    let mut copies = 0usize;
    let mut open: Vec<(usize, usize)> = Vec::new();
    let mut anchors: HashMap<usize, usize> = HashMap::new();
    loop {
        let anchored = match parser.next_token()?.0 {
            Event::StreamEnd => break,
            Event::Scalar(text, _, anchor, _) => {
                let size = NODE_BYTES.saturating_add(text.len());
                tree = tree.saturating_add(size);
                Some((anchor, size))
            }
            Event::SequenceStart(anchor, _) | Event::MappingStart(anchor, _) => {
                if open.len() >= MAX_YAML_DEPTH {
                    return Err(RegistrationError::TooDeep);
                }
                open.push((anchor, tree));
                tree = tree.saturating_add(NODE_BYTES);
                None
            }
            Event::SequenceEnd | Event::MappingEnd => open
                .pop()
                .map(|(anchor, start)| (anchor, tree.saturating_sub(start))),
            Event::Alias(anchor) => {
                let size = anchors.get(&anchor).copied().unwrap_or(NODE_BYTES);
                tree = tree.saturating_add(size);
                None
            }
            _ => None,
        };
        if let Some((anchor, size)) = anchored.filter(|(anchor, _)| *anchor != 0) {
            anchors.insert(anchor, size);
            copies = copies.saturating_add(size);
        }
        if tree.saturating_add(copies) > MAX_YAML_BYTES {
            return Err(RegistrationError::TooLarge);
        }
    }
    Ok(YamlLoader::load_from_str(yaml)?)
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

pub fn has_sha256_digest(image: &str) -> bool {
    image
        .rsplit_once("@sha256:")
        .is_some_and(|(_, hex)| hex_bytes::<32>(hex).is_some())
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
    fn an_alias_bomb_is_refused_before_it_expands() {
        let mut nested = "a0: &a0 [x, x, x, x, x, x, x, x, x, x]\n".to_owned();
        for i in 1..9 {
            let p = i - 1;
            nested += &format!("a{i}: &a{i} [{}]\n", vec![format!("*a{p}"); 10].join(", "));
        }
        let wide = format!(
            "a: &a {}\nb: [{}]\n",
            "x".repeat(10_000),
            vec!["*a"; 1000].join(", ")
        );
        for bomb in [nested, wide] {
            assert!(matches!(load_yaml(&bomb), Err(RegistrationError::TooLarge)));
        }
        assert!(matches!(
            load_yaml(&format!("{}{}", "[".repeat(100), "]".repeat(100))),
            Err(RegistrationError::TooDeep)
        ));
        let anchors: String = (0..16).map(|i| format!("&n{i} [")).collect();
        let nested = format!("a: {anchors}x{}\nb: *n0\n", "]".repeat(16));
        assert!(load_yaml(&nested).is_ok());
    }

    #[test]
    fn images_are_found_anywhere_in_the_yaml() {
        let ok = "@sha256:".to_owned() + &"0".repeat(64);
        let merged = format!("x-base: &b\n  image: a{ok}\nservices:\n  app:\n    <<: *b\n");
        assert!(check_images(&load_yaml(&merged).unwrap()[0]).is_ok());
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
