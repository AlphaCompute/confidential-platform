//! Each service's image and environment, read from the `app-compose.json` whose SHA-256 is the
//! Revision, so a page shows what was measured rather than what its own bundle claims.

use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::Value;
use yaml_rust2::{Yaml, YamlLoader};

use crate::Error;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Service {
    pub image: Option<String>,
    pub environment: BTreeMap<String, String>,
}

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
    services
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
                        (Yaml::String(key), Yaml::String(v)) => Ok((key.clone(), v.clone())),
                        (Yaml::String(key), Yaml::Integer(v)) => Ok((key.clone(), v.to_string())),
                        (Yaml::String(key), Yaml::Real(v)) => Ok((key.clone(), v.clone())),
                        (Yaml::String(key), Yaml::Boolean(v)) => Ok((key.clone(), v.to_string())),
                        _ => Err(malformed(&format!(
                            "{name}.environment holds a value that is not a scalar"
                        ))),
                    })
                    .collect::<Result<_, _>>()?,
                Some(_) => return Err(malformed(&format!("{name}.environment is not a map"))),
            };
            Ok((name.to_owned(), Service { image, environment }))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEPLOY: &str = include_str!("../../../testdata/manifest/05-deploy/app-compose.json");
    const DOCKER: &str =
        include_str!("../../../testdata/manifest/07-deploy-docker/app-compose.json");

    fn compose(yaml: &str) -> String {
        serde_json::json!({ "docker_compose_file": yaml }).to_string()
    }

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
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

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
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
}
