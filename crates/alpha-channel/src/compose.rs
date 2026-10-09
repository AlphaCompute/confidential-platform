//! Each service's image, environment, published ports, named volumes and the Secrets it
//! receives, read from the `app-compose.json` whose SHA-256 is the Revision, so a page shows what
//! was measured rather than what its own bundle claims. Which Secrets a service receives comes
//! from the `alpha-runtime` service's measured `ALPHACOMPUTE_SECRETS`, the list the runtime itself
//! delivers from.

use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::Value;
use yaml_rust2::{Yaml, YamlLoader};

use crate::Error;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Service {
    pub image: Option<String>,
    pub environment: BTreeMap<String, String>,
    pub ports: Vec<String>,
    pub volumes: Vec<String>,
    pub secrets: Vec<String>,
}

const RUNTIME: &str = "alpha-runtime";
const SECRETS: &str = "ALPHACOMPUTE_SECRETS";

fn malformed(m: &str) -> Error {
    Error::Malformed(format!("compose: {m}"))
}

fn get<'a>(map: &'a yaml_rust2::yaml::Hash, key: &str) -> Option<&'a Yaml> {
    map.get(&Yaml::String(key.into()))
}

pub fn services(compose: &str) -> Result<BTreeMap<String, Service>, Error> {
    let value: Value = serde_json::from_str(compose).map_err(|e| malformed(&e.to_string()))?;
    let yaml = value
        .get("docker_compose_file")
        .and_then(Value::as_str)
        .ok_or_else(|| malformed("docker_compose_file is missing or not a string"))?;
    let docs = YamlLoader::load_from_str(yaml).map_err(|e| malformed(&e.to_string()))?;
    let [Yaml::Hash(root)] = docs.as_slice() else {
        return Err(malformed("docker_compose_file is not one YAML map"));
    };
    let Some(Yaml::Hash(services)) = get(root, "services") else {
        return Err(malformed("services is not a map"));
    };
    let mut services = services
        .iter()
        .map(|(name, service)| {
            let name = name
                .as_str()
                .ok_or_else(|| malformed("a service name is not a string"))?;
            let Yaml::Hash(service) = service else {
                return Err(malformed(&format!("{name} is not a map")));
            };
            let image = match get(service, "image") {
                None => None,
                Some(Yaml::String(image)) => Some(image.clone()),
                Some(_) => return Err(malformed(&format!("{name}.image is not a string"))),
            };
            let environment = match get(service, "environment") {
                None => BTreeMap::new(),
                Some(Yaml::Hash(env)) => env
                    .iter()
                    .map(|(key, value)| match (key, value) {
                        (Yaml::String(key), Yaml::String(v) | Yaml::Real(v)) => {
                            Ok((key.clone(), v.clone()))
                        }
                        (Yaml::String(key), Yaml::Integer(v)) => Ok((key.clone(), v.to_string())),
                        (Yaml::String(key), Yaml::Boolean(v)) => Ok((key.clone(), v.to_string())),
                        _ => Err(malformed(&format!(
                            "{name}.environment holds a value that is not a scalar"
                        ))),
                    })
                    .collect::<Result<_, _>>()?,
                Some(_) => return Err(malformed(&format!("{name}.environment is not a map"))),
            };
            let service = Service {
                image,
                environment,
                ports: ports(name, get(service, "ports"))?,
                volumes: volumes(name, get(service, "volumes"))?,
                secrets: Vec::new(),
            };
            Ok((name.to_owned(), service))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;

    let declared = match services
        .get(RUNTIME)
        .and_then(|runtime| runtime.environment.get(SECRETS))
    {
        None => BTreeMap::new(),
        Some(text) => declared_secrets(text)?,
    };
    // A Secret declared for a service the compose lacks would still be awaited by the runtime,
    // so the page could not leave it out without the Instance never becoming healthy.
    for (name, secrets) in declared {
        services
            .get_mut(&name)
            .ok_or_else(|| malformed(&format!("{SECRETS} names {name}, which is not a service")))?
            .secrets = secrets;
    }
    Ok(services)
}

fn list<'a>(name: &str, field: &str, value: Option<&'a Yaml>) -> Result<&'a [Yaml], Error> {
    match value {
        None => Ok(&[]),
        Some(Yaml::Array(items)) => Ok(items),
        Some(_) => Err(malformed(&format!("{name}.{field} is not a list"))),
    }
}

fn ports(name: &str, value: Option<&Yaml>) -> Result<Vec<String>, Error> {
    list(name, "ports", value)?
        .iter()
        .map(|port| match port {
            Yaml::String(p) => Ok(p.clone()),
            Yaml::Integer(p) => Ok(p.to_string()),
            _ => Err(malformed(&format!(
                "{name}.ports holds an entry that is neither text nor a number"
            ))),
        })
        .collect()
}

/// Named volumes only: a bind mount names a host path, which says nothing about the Instance,
/// and an anonymous volume has no name to show.
fn volumes(name: &str, value: Option<&Yaml>) -> Result<Vec<String>, Error> {
    let mut named = Vec::new();
    for volume in list(name, "volumes", value)? {
        match volume {
            Yaml::String(short) => {
                if let Some((source, _)) = short.split_once(':')
                    && !source.starts_with(['/', '.', '~'])
                {
                    named.push(source.to_owned());
                }
            }
            Yaml::Hash(long) => match (get(long, "type"), get(long, "source")) {
                (Some(Yaml::String(kind)), Some(Yaml::String(source))) if kind == "volume" => {
                    named.push(source.clone());
                }
                (Some(Yaml::String(_)), None | Some(Yaml::String(_))) => {}
                _ => {
                    return Err(malformed(&format!(
                        "{name}.volumes holds a map without a text type and source"
                    )));
                }
            },
            _ => {
                return Err(malformed(&format!(
                    "{name}.volumes holds an entry that is neither text nor a map"
                )));
            }
        }
    }
    Ok(named)
}

fn declared_secrets(text: &str) -> Result<BTreeMap<String, Vec<String>>, Error> {
    let declared: BTreeMap<String, Vec<String>> = alpha_core::parse(text.as_bytes())
        .ok()
        .and_then(|v| serde_json::from_value(v).ok())
        .ok_or_else(|| malformed(&format!("{SECRETS} is not a JSON object of name lists")))?;
    // The runtime refuses at start what is not a lowercase path segment, so a compose naming one
    // would be approved and never become healthy.
    for (service, names) in &declared {
        if let Some(bad) = std::iter::once(service)
            .chain(names)
            .find(|n| !alpha_core::is_key_purpose(n))
        {
            return Err(malformed(&format!(
                "{SECRETS}: {bad:?} is not a lowercase path segment"
            )));
        }
    }
    Ok(declared)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEPLOY: &str = include_str!("../../../testdata/manifest/05-deploy/app-compose.json");
    const DOCKER: &str =
        include_str!("../../../testdata/manifest/07-deploy-docker/app-compose.json");
    const WRAP: &str = include_str!("../../../testdata/manifest/08-wrap/app-compose.json");

    fn compose(yaml: &str) -> String {
        serde_json::json!({ "docker_compose_file": yaml }).to_string()
    }

    #[wasm_bindgen_test::wasm_bindgen_test(unsupported = test)]
    fn reads_every_service_of_the_rendered_composes() {
        for compose in [DEPLOY, DOCKER] {
            let services = services(compose).unwrap();
            assert_eq!(
                services.keys().collect::<Vec<_>>(),
                ["alpha-runtime", "app"]
            );
            let app = &services["app"];
            assert!(app.image.as_deref().unwrap().ends_with(
                "@sha256:3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a"
            ));
            assert_eq!(app.environment["LOG_LEVEL"], "info");
            let runtime = &services["alpha-runtime"];
            assert!(runtime.environment["ALPHACOMPUTE_KMS_REVISIONS"].starts_with("sha256:e1e1"));
        }
    }

    #[wasm_bindgen_test::wasm_bindgen_test(unsupported = test)]
    fn scalars_read_as_text_and_the_list_form_is_refused() {
        let s = services(&compose(
            "services:\n  a:\n    environment:\n      N: 2\n      B: true\n",
        ))
        .unwrap();
        assert_eq!(s["a"].environment["N"], "2");
        assert_eq!(s["a"].environment["B"], "true");
        assert_eq!(s["a"].image, None);

        for yaml in [
            "services:\n  a:\n    environment:\n      - N=2\n",
            "services:\n  a:\n    environment:\n      N:\n",
            "services:\n  a:\n    image: [x]\n",
            "services: []\n",
            "a: 1\n---\nb: 2\n",
        ] {
            assert_eq!(services(&compose(yaml)).unwrap_err().code(), "malformed");
        }
        assert_eq!(services("{}").unwrap_err().code(), "malformed");
    }

    #[wasm_bindgen_test::wasm_bindgen_test(unsupported = test)]
    fn reads_ports_named_volumes_and_secrets_of_a_wrapped_compose() {
        let s = services(WRAP).unwrap();
        let strings = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();

        assert_eq!(s["web"].ports, strings(&["443:80"]));
        assert_eq!(s["web"].volumes, strings(&["alpha-secrets-web"]));
        assert_eq!(s["web"].secrets, strings(&["db_password", "session_key"]));
        assert!(
            s["web"]
                .image
                .as_deref()
                .unwrap()
                .starts_with("nginx:1.27@sha256:")
        );
        assert_eq!(s["web"].environment["MODE"], "production");

        assert!(s["db"].ports.is_empty());
        assert_eq!(s["db"].volumes, strings(&["pgdata", "alpha-secrets-db"]));
        assert_eq!(s["db"].secrets, strings(&["db_password"]));

        assert_eq!(s["cache"].volumes, strings(&["cachedata"]));
        assert!(s["cache"].secrets.is_empty());

        let runtime = &s["alpha-runtime"];
        assert_eq!(
            runtime.volumes,
            strings(&["alpha-run", "alpha-secrets-db", "alpha-secrets-web"])
        );
        assert!(runtime.secrets.is_empty());
        assert!(runtime.environment[SECRETS].starts_with("{\"db\""));
    }

    #[wasm_bindgen_test::wasm_bindgen_test(unsupported = test)]
    fn ports_volumes_and_declared_secrets_of_another_shape_are_refused() {
        let s = services(&compose(
            "services:\n  a:\n    ports: [8080, \"9000:9000\"]\n    volumes:\n      - ./x:/x\n      - ~/y:/y\n      - /z\n      - type: bind\n        source: /h\n        target: /h\n      - type: volume\n        target: /anon\n",
        ))
        .unwrap();
        assert_eq!(s["a"].ports, ["8080", "9000:9000"]);
        assert!(s["a"].volumes.is_empty());

        for yaml in [
            "services:\n  a:\n    ports:\n      - target: 80\n",
            "services:\n  a:\n    ports: \"80\"\n",
            "services:\n  a:\n    volumes:\n      - 3\n",
            "services:\n  a:\n    volumes:\n      - source: v\n        target: /v\n",
            "services:\n  alpha-runtime:\n    environment:\n      ALPHACOMPUTE_SECRETS: '[\"x\"]'\n",
            "services:\n  alpha-runtime:\n    environment:\n      ALPHACOMPUTE_SECRETS: '{\"alpha-runtime\":[1]}'\n",
            "services:\n  alpha-runtime:\n    environment:\n      ALPHACOMPUTE_SECRETS: '{\"alpha-runtime\":[\"a\"],\"alpha-runtime\":[\"b\"]}'\n",
            "services:\n  alpha-runtime:\n    environment:\n      ALPHACOMPUTE_SECRETS: '{\"web\":[\"a\"]}'\n",
            "services:\n  alpha-runtime:\n    environment:\n      ALPHACOMPUTE_SECRETS: '{\"Alpha-runtime\":[\"a\"]}'\n",
            "services:\n  alpha-runtime:\n    environment:\n      ALPHACOMPUTE_SECRETS: '{\"alpha-runtime\":[\"../a\"]}'\n",
        ] {
            assert_eq!(
                services(&compose(yaml)).unwrap_err().code(),
                "malformed",
                "{yaml}"
            );
        }
    }
}
