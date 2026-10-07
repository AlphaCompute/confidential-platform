//! A customer's plain docker-compose becomes a Revision through the same runtime service and
//! envelope as `alpha deploy`. What the compose may contain is an allowlist, and declared secrets
//! reach only the services that list them, as files `alpha-runtime` writes into a tmpfs volume.

use std::collections::{BTreeMap, BTreeSet};

use alpha_core::{AppId, ComposeHash, compose_hash, hex_bytes, is_key_purpose};
use serde::Serialize;
use serde_yaml_ng::{Mapping, Value as Yaml};

use super::{APP_PORT, RUNTIME_SERVICE, Runtime, key, strings};

const MAX_COMPOSE_BYTES: usize = 256 * 1024;
const SERVICE_KEYS: [&str; 12] = [
    "image",
    "environment",
    "ports",
    "command",
    "entrypoint",
    "volumes",
    "secrets",
    "depends_on",
    "healthcheck",
    "restart",
    "user",
    "working_dir",
];
/// ponytail: tags resolve only on these three public registries, anonymously; any other registry
/// needs a digest-pinned reference. Upgrade: a row per registry, or reading the registry's
/// `WWW-Authenticate` challenge.
const REGISTRIES: [&str; 3] = ["docker.io", "ghcr.io", "quay.io"];

/// A compose that passed the allowlist, in the customer's order.
#[derive(Debug)]
pub struct Plain {
    services: Vec<(String, Mapping)>,
    volumes: Vec<String>,
    secrets: BTreeMap<String, BTreeSet<String>>,
    endpoint: (String, u16),
}

#[derive(Debug, Serialize)]
pub struct Wrapped {
    pub compose_hash: ComposeHash,
    pub compose: String,
    pub secrets: BTreeSet<String>,
}

pub fn parse(bytes: &[u8]) -> Result<Plain, String> {
    if bytes.len() > MAX_COMPOSE_BYTES {
        return Err(format!(
            "compose: {} bytes is over the 256 KiB limit; make it smaller",
            bytes.len()
        ));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| "compose: not UTF-8; save it as UTF-8".to_owned())?;
    let mut root: Yaml =
        serde_yaml_ng::from_str(text).map_err(|e| format!("compose: {e}; fix the YAML"))?;
    if let Some(tag) = find(&root, &|v| match v {
        Yaml::Tagged(t) => Some(t.tag.to_string()),
        _ => None,
    }) {
        return Err(format!(
            "compose: the YAML tag {tag} is not supported; write the value itself"
        ));
    }
    root.apply_merge()
        .map_err(|e| format!("compose: {e}; fix the YAML"))?;
    let Yaml::Mapping(root) = root else {
        return Err("compose: not a mapping; write a docker-compose file".into());
    };
    let (mut services, mut volumes, mut secrets) = (None, None, None);
    for (k, v) in root {
        match k.as_str() {
            Some("services") => services = Some(v),
            Some("volumes") => volumes = Some(v),
            Some("secrets") => secrets = Some(v),
            Some(k) if k == "version" || k == "name" || k.starts_with("x-") => {}
            _ => {
                return Err(format!(
                    "compose: {} is not supported; remove it",
                    shown(&k)
                ));
            }
        }
    }
    let volumes = section(volumes, "volumes")?
        .into_iter()
        .map(|(name, v)| {
            unreserved(&name, "volumes")?;
            match option(&v, |_, _| false) {
                None => Ok(name),
                Some(what) => Err(format!(
                    "volumes.{name}: {what} is not supported; declare it as `{name}: {{}}`, a volume of this compose"
                )),
            }
        })
        .collect::<Result<Vec<_>, String>>()?;
    let declared = section(secrets, "secrets")?
        .into_iter()
        .map(|(name, v)| {
            match option(&v, |k, v| k.as_str() == Some("external") && v.as_bool() == Some(true)) {
                None => Ok(name),
                Some(what) => Err(format!(
                    "secrets.{name}: {what} is not supported; values come from the signing page, declare it as `{name}: {{}}`"
                )),
            }
        })
        .collect::<Result<BTreeSet<_>, String>>()?;

    let services = section(services, "services")?;
    let names: BTreeSet<String> = services.iter().map(|(name, _)| name.clone()).collect();
    let mut plain_services = Vec::new();
    let mut secrets = BTreeMap::new();
    let mut endpoints = Vec::new();
    for (service, value) in services {
        unreserved(&service, "services")?;
        let Yaml::Mapping(value) = value else {
            return Err(format!("services.{service}: not a mapping; write its keys"));
        };
        let mut targets = Vec::new();
        for (k, v) in &value {
            let Some(k) = k.as_str().filter(|k| SERVICE_KEYS.contains(k)) else {
                return Err(format!(
                    "services.{service}: {} is not supported; the keys allowed are {}",
                    shown(k),
                    SERVICE_KEYS.join(", ")
                ));
            };
            let place = format!("services.{service}.{k}");
            if let Some(s) = find(v, &|v| v.as_str().filter(|s| interpolates(s))) {
                return Err(format!(
                    "{place}: {s} interpolates; write the value, or `$$` for a literal `$`; the CVM has no environment for interpolation"
                ));
            }
            match k {
                "image" => {
                    let image = v
                        .as_str()
                        .ok_or_else(|| format!("{place}: not a string; name the image"))?;
                    if image.contains('@') && !pinned(image) {
                        return Err(format!(
                            "{place}: {image} has a malformed digest; write <image>@sha256:<64 lowercase hex digits>"
                        ));
                    }
                    if !pinned(image) && !REGISTRIES.contains(&registry(image)) {
                        return Err(format!(
                            "{place}: {image} is a tag outside Docker Hub, ghcr.io and quay.io; pin it as <image>@sha256:<digest>"
                        ));
                    }
                }
                "environment" => {
                    let unset = match v {
                        Yaml::Mapping(m) => m.iter().find(|(_, v)| v.is_null()).map(|(k, _)| k),
                        Yaml::Sequence(items) => items
                            .iter()
                            .find(|i| !i.as_str().is_some_and(|s| s.contains('='))),
                        _ => {
                            return Err(format!(
                                "{place}: not a list or mapping; write NAME: value"
                            ));
                        }
                    };
                    if let Some(name) = unset {
                        return Err(format!(
                            "{place}: {} has no value; give it a value, or declare it as a secret",
                            shown(name)
                        ));
                    }
                }
                "ports" => {
                    for item in list(v, &place)? {
                        let port = container_port(item).ok_or_else(|| {
                            format!(
                                "{place}: {} is not a TCP port; write \"<host port>:<container port>\"",
                                shown(item)
                            )
                        })?;
                        endpoints.push((service.clone(), port));
                    }
                }
                "volumes" => {
                    for item in list(v, &place)? {
                        let target = named_mount(item, &volumes).ok_or_else(|| {
                            format!(
                                "{place}: {} is not a named volume of this compose; declare it under top-level volumes and mount it by name",
                                shown(item)
                            )
                        })?;
                        targets.push(target);
                    }
                }
                "secrets" => {
                    let mut listed = BTreeSet::new();
                    for item in list(v, &place)? {
                        if item.is_mapping() {
                            return Err(format!(
                                "{place}: {} is not supported; list the secret by name, its file is /run/secrets/<name>",
                                shown(item)
                            ));
                        }
                        let name = name(item.clone(), &place)?;
                        if !declared.contains(&name) {
                            return Err(format!(
                                "{place}: {name} is not declared; declare it under top-level secrets"
                            ));
                        }
                        listed.insert(name);
                    }
                    if !listed.is_empty() {
                        secrets.insert(service.clone(), listed);
                    }
                }
                "depends_on" => {
                    let dependencies: Vec<&Yaml> = match v {
                        Yaml::Mapping(m) => m.keys().collect(),
                        Yaml::Sequence(items) => items.iter().collect(),
                        _ => {
                            return Err(format!(
                                "{place}: not a list or mapping; list the services it waits for"
                            ));
                        }
                    };
                    for dependency in dependencies {
                        match dependency.as_str() {
                            Some(RUNTIME_SERVICE) => {
                                return Err(format!(
                                    "{place}: {RUNTIME_SERVICE} is added by the platform; remove it, a service that lists secrets already waits for it"
                                ));
                            }
                            Some(d) if names.contains(d) => {}
                            _ => {
                                return Err(format!(
                                    "{place}: {} is not a service of this compose; remove it or add the service",
                                    shown(dependency)
                                ));
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        if !value.contains_key("image") {
            return Err(format!(
                "services.{service}: no image; name one, by tag or as <image>@sha256:<digest>"
            ));
        }
        if secrets.contains_key(&service)
            && let Some(target) = targets.iter().find(|t| {
                t.strip_prefix("/run/secrets")
                    .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
            })
        {
            return Err(format!(
                "services.{service}.volumes: {target} is where its secrets are mounted; mount the volume elsewhere"
            ));
        }
        plain_services.push((service, value));
    }
    let endpoint = <[(String, u16); 1]>::try_from(endpoints).map_err(|all| {
        format!(
            "services: {} ports are published; publish exactly one, the App's Endpoint",
            all.len()
        )
    })?;
    let [endpoint] = endpoint;
    Ok(Plain {
        services: plain_services,
        volumes,
        secrets,
        endpoint,
    })
}

/// `digests` maps a tagged image, as the customer wrote it, to `sha256:<hex>`.
pub fn wrap(
    plain: Plain,
    digests: &BTreeMap<String, String>,
    app_id: AppId,
    runtime: &Runtime,
) -> Result<Wrapped, String> {
    if !pinned(&runtime.image) {
        return Err(format!(
            "runtime image {}: not pinned; give it as <image>@sha256:<digest>",
            runtime.image
        ));
    }
    let Plain {
        services: plain_services,
        volumes,
        secrets,
        endpoint: (endpoint, port),
    } = plain;
    let mut services = Mapping::new();
    let mut declaring = Vec::new();
    for (name, service) in plain_services {
        let secrets_volume = secrets
            .contains_key(&name)
            .then(|| format!("alpha-secrets-{name}"));
        let mut out = Mapping::new();
        for (k, v) in service {
            let v = match k.as_str() {
                Some("secrets") => continue,
                Some("image") => {
                    let image = v.as_str().ok_or("image is not a string")?;
                    Yaml::String(pin(image, digests)?)
                }
                // ponytail: the published service must speak TLS itself; a stock plain-HTTP image
                // is not reachable over the Endpoint's TLS passthrough. Upgrade: `alpha-runtime`
                // terminates TLS with the Instance leaf and proxies to the service.
                Some("ports") if name == endpoint => strings(&[&format!("{APP_PORT}:{port}")]),
                Some("volumes") => match (&secrets_volume, v) {
                    (Some(volume), Yaml::Sequence(mut mounts)) => {
                        mounts.push(key(&format!("{volume}:/run/secrets:ro")));
                        Yaml::Sequence(mounts)
                    }
                    (_, v) => v,
                },
                Some("depends_on") if secrets_volume.is_some() => after_runtime(v)?,
                _ => v,
            };
            out.insert(k, v);
        }
        if let Some(volume) = secrets_volume {
            if !out.contains_key("volumes") {
                out.insert(
                    key("volumes"),
                    strings(&[&format!("{volume}:/run/secrets:ro")]),
                );
            }
            if !out.contains_key("depends_on") {
                out.insert(key("depends_on"), after_runtime(Yaml::Sequence(vec![]))?);
            }
            declaring.push(name.clone());
        }
        if !out.contains_key("restart") {
            out.insert(key("restart"), key("always"));
        }
        services.insert(key(&name), Yaml::Mapping(out));
    }

    let mut runtime_service = super::runtime_service(runtime)?;
    // Only when some service waits for its secrets: a runtime image without the `healthcheck`
    // subcommand ignores its arguments and would start a second runtime that takes the socket.
    if !secrets.is_empty() {
        let map = serde_json::to_string(&secrets).map_err(|e| e.to_string())?;
        let Some(Yaml::Mapping(environment)) = runtime_service.get_mut("environment") else {
            return Err("runtime service has no environment".into());
        };
        environment.insert(key("ALPHACOMPUTE_SECRETS"), key(&map));
        let Some(Yaml::Sequence(mounts)) = runtime_service.get_mut("volumes") else {
            return Err("runtime service has no volumes".into());
        };
        for name in &declaring {
            mounts.push(key(&format!(
                "alpha-secrets-{name}:/run/alpha-secrets/{name}"
            )));
        }
        // dstack runs `docker compose up` once and never again, and compose gives up on a
        // dependency that turns unhealthy, so a slow first attestation must not count against it.
        let mut healthcheck = Mapping::new();
        healthcheck.insert(
            key("test"),
            strings(&["CMD", "/alpha-runtime", "healthcheck"]),
        );
        healthcheck.insert(key("interval"), key("5s"));
        healthcheck.insert(key("start_period"), key("24h"));
        runtime_service.insert(key("healthcheck"), Yaml::Mapping(healthcheck));
    }
    services.insert(key(RUNTIME_SERVICE), Yaml::Mapping(runtime_service));

    let mut root_volumes = Mapping::new();
    for name in volumes.iter().map(String::as_str).chain(["alpha-run"]) {
        root_volumes.insert(key(name), Yaml::Mapping(Mapping::new()));
    }
    for name in &declaring {
        let mut tmpfs = Mapping::new();
        tmpfs.insert(key("type"), key("tmpfs"));
        tmpfs.insert(key("device"), key("tmpfs"));
        let mut volume = Mapping::new();
        volume.insert(key("driver_opts"), Yaml::Mapping(tmpfs));
        root_volumes.insert(key(&format!("alpha-secrets-{name}")), Yaml::Mapping(volume));
    }
    let mut root = Mapping::new();
    root.insert(key("services"), Yaml::Mapping(services));
    root.insert(key("volumes"), Yaml::Mapping(root_volumes));
    let yaml = serde_yaml_ng::to_string(&root).map_err(|e| e.to_string())?;
    let compose = super::envelope(app_id, yaml, &["ALPHACOMPUTE_KMS_ENDPOINTS"], false)?;
    Ok(Wrapped {
        compose_hash: compose_hash(&compose),
        compose,
        secrets: secrets.into_values().flatten().collect(),
    })
}

fn section(value: Option<Yaml>, place: &str) -> Result<Vec<(String, Yaml)>, String> {
    let mapping = match value {
        None | Some(Yaml::Null) => Mapping::new(),
        Some(Yaml::Mapping(m)) => m,
        Some(_) => return Err(format!("{place}: not a mapping")),
    };
    mapping
        .into_iter()
        .map(|(k, v)| Ok((name(k, place)?, v)))
        .collect()
}

fn name(value: Yaml, place: &str) -> Result<String, String> {
    match value {
        Yaml::String(s) if is_key_purpose(&s) => Ok(s),
        other => Err(format!(
            "{place}: {} is not a name; use 1 to 64 lowercase letters, digits, `.`, `_` or `-`, starting with a letter or digit",
            shown(&other)
        )),
    }
}

fn shown(value: &Yaml) -> String {
    match value {
        Yaml::String(s) => s.clone(),
        other => serde_json::to_string(other).unwrap_or_else(|_| format!("{other:?}")),
    }
}

/// The first part of a top-level volume or secret definition outside what `allowed` admits.
fn option(value: &Yaml, allowed: impl Fn(&Yaml, &Yaml) -> bool) -> Option<String> {
    match value {
        Yaml::Null => None,
        Yaml::Mapping(m) => m
            .iter()
            .find(|(k, v)| !allowed(k, v))
            .map(|(k, _)| shown(k)),
        other => Some(shown(other)),
    }
}

fn find<'a, T>(value: &'a Yaml, f: &impl Fn(&'a Yaml) -> Option<T>) -> Option<T> {
    f(value).or_else(|| match value {
        Yaml::Sequence(items) => items.iter().find_map(|v| find(v, f)),
        Yaml::Mapping(m) => m
            .iter()
            .find_map(|(k, v)| find(k, f).or_else(|| find(v, f))),
        Yaml::Tagged(t) => find(&t.value, f),
        _ => None,
    })
}

/// Compose substitutes `$NAME` and `${NAME}` from the environment `docker compose up` runs in,
/// which the host partly controls; only `$$`, a literal `$`, is safe.
fn interpolates(s: &str) -> bool {
    let mut rest = s;
    while let Some((_, after)) = rest.split_once('$') {
        match after.strip_prefix('$') {
            Some(after) => rest = after,
            None => return true,
        }
    }
    false
}

fn unreserved(name: &str, place: &str) -> Result<(), String> {
    if name.starts_with("alpha-") {
        return Err(format!(
            "{place}.{name}: names starting with alpha- are reserved; rename it"
        ));
    }
    Ok(())
}

fn list<'a>(value: &'a Yaml, place: &str) -> Result<&'a Vec<Yaml>, String> {
    value
        .as_sequence()
        .ok_or_else(|| format!("{place}: not a list"))
}

fn pinned(image: &str) -> bool {
    image
        .split_once('@')
        .and_then(|(_, digest)| digest.strip_prefix("sha256:"))
        .is_some_and(|hex| hex_bytes::<32>(hex).is_some())
}

/// The registry a reference names, split as Docker does: the first component is a registry only
/// when it looks like a host or has an upper-case letter (repositories are lower-case), otherwise
/// the image is on Docker Hub.
fn registry(image: &str) -> &str {
    match image.split_once('/') {
        Some(("index.docker.io", _)) => "docker.io",
        Some((first, _))
            if first.contains(['.', ':'])
                || first == "localhost"
                || first.bytes().any(|b| b.is_ascii_uppercase()) =>
        {
            first
        }
        _ => "docker.io",
    }
}

fn pin(image: &str, digests: &BTreeMap<String, String>) -> Result<String, String> {
    if pinned(image) {
        return Ok(image.to_owned());
    }
    digests
        .get(image)
        .map(|digest| format!("{image}@{digest}"))
        .ok_or_else(|| {
            format!("image {image}: the tag is not resolved; pin it as <image>@sha256:<digest>")
        })
}

fn after_runtime(depends_on: Yaml) -> Result<Yaml, String> {
    let condition = |c: &str| {
        let mut m = Mapping::new();
        m.insert(key("condition"), key(c));
        Yaml::Mapping(m)
    };
    let mut map = match depends_on {
        Yaml::Mapping(m) => m,
        Yaml::Sequence(items) => items
            .into_iter()
            .map(|s| (s, condition("service_started")))
            .collect(),
        _ => return Err("depends_on is not a list or mapping".into()),
    };
    map.insert(key(RUNTIME_SERVICE), condition("service_healthy"));
    Ok(Yaml::Mapping(map))
}

fn container_port(item: &Yaml) -> Option<u16> {
    match item {
        Yaml::String(s) => {
            let s = s.strip_suffix("/tcp").unwrap_or(s);
            match s.split_once(':') {
                None => number(s),
                Some((published, target)) => number(published).and(number(target)),
            }
        }
        Yaml::Mapping(m) => {
            let known = m
                .keys()
                .all(|k| matches!(k.as_str(), Some("target" | "published" | "protocol")));
            let tcp = m.get("protocol").is_none_or(|p| p.as_str() == Some("tcp"));
            let published = m.get("published").is_none_or(|p| port(p).is_some());
            if known && tcp && published {
                m.get("target").and_then(port)
            } else {
                None
            }
        }
        _ => port(item),
    }
}

fn port(value: &Yaml) -> Option<u16> {
    match value {
        Yaml::Number(n) => n
            .as_u64()
            .and_then(|p| u16::try_from(p).ok())
            .filter(|p| *p != 0),
        Yaml::String(s) => number(s),
        _ => None,
    }
}

fn number(s: &str) -> Option<u16> {
    if s.bytes().all(|b| b.is_ascii_digit()) {
        s.parse().ok().filter(|p| *p != 0)
    } else {
        None
    }
}

/// The container path of a mount of a declared named volume.
fn named_mount<'a>(item: &'a Yaml, declared: &[String]) -> Option<&'a str> {
    let is_declared = |source: &str| declared.iter().any(|d| d == source);
    let (valid, target) = match item {
        Yaml::String(s) => {
            let mut parts = s.split(':');
            let (Some(source), Some(target), mode, None) =
                (parts.next(), parts.next(), parts.next(), parts.next())
            else {
                return None;
            };
            (
                is_declared(source) && matches!(mode, None | Some("ro" | "rw")),
                target,
            )
        }
        Yaml::Mapping(m) => (
            m.keys()
                .all(|k| matches!(k.as_str(), Some("type" | "source" | "target" | "read_only")))
                && m.get("type").and_then(Yaml::as_str) == Some("volume")
                && m.get("source")
                    .and_then(Yaml::as_str)
                    .is_some_and(is_declared)
                && m.get("read_only").is_none_or(Yaml::is_bool),
            m.get("target").and_then(Yaml::as_str)?,
        ),
        _ => return None,
    };
    (valid && target.starts_with('/')).then_some(target)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use serde_json::{Value, json};

    use super::*;

    fn dir(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../testdata/manifest")
            .join(name)
    }

    fn deploy_spec() -> super::super::AppSpec {
        super::super::parse(&fs::read_to_string(dir("05-deploy").join("app.yaml")).unwrap())
            .unwrap()
    }

    fn vector_compose() -> String {
        fs::read_to_string(dir("08-wrap").join("compose.yaml")).unwrap()
    }

    fn wrap_text(text: &str, digests: &BTreeMap<String, String>) -> Result<Wrapped, String> {
        let spec = deploy_spec();
        wrap(parse(text.as_bytes())?, digests, spec.app_id, &spec.runtime)
    }

    fn compose_yaml(wrapped: &Wrapped) -> Yaml {
        let parsed: Value = serde_json::from_str(&wrapped.compose).unwrap();
        serde_yaml_ng::from_str(parsed["docker_compose_file"].as_str().unwrap()).unwrap()
    }

    fn keys(value: &Yaml) -> Vec<&str> {
        value
            .as_mapping()
            .unwrap()
            .keys()
            .map(|k| k.as_str().unwrap())
            .collect()
    }

    #[test]
    fn wrap_reproduces_the_vector() {
        let out = dir("08-wrap");
        let spec = deploy_spec();
        let wrapped = wrap_text(&vector_compose(), &BTreeMap::new()).unwrap();
        let expected = json!({
            "app_id": spec.app_id,
            "compose_hash": wrapped.compose_hash,
            "secrets": wrapped.secrets,
        });
        if std::env::var_os("WRITE_VECTORS").is_some() {
            fs::write(out.join("app-compose.json"), &wrapped.compose).unwrap();
            fs::write(
                out.join("expected.json"),
                serde_json::to_string_pretty(&expected).unwrap() + "\n",
            )
            .unwrap();
            return;
        }
        assert_eq!(
            wrapped.compose,
            fs::read_to_string(out.join("app-compose.json")).unwrap()
        );
        assert_eq!(
            serde_json::to_string_pretty(&expected).unwrap() + "\n",
            fs::read_to_string(out.join("expected.json")).unwrap()
        );
        let again = wrap_text(&vector_compose(), &BTreeMap::new()).unwrap();
        assert_eq!(again.compose, wrapped.compose);
        assert_eq!(compose_hash(&wrapped.compose), wrapped.compose_hash);

        let yaml = compose_yaml(&wrapped);
        assert_eq!(keys(&yaml), ["services", "volumes"]);
        let services = &yaml["services"];
        assert_eq!(keys(services), ["web", "db", "cache", RUNTIME_SERVICE]);
        for (service, own) in [("web", true), ("db", true), ("cache", false)] {
            let mounts = services[service]["volumes"].as_sequence();
            let secret_mounts: Vec<&str> = mounts
                .into_iter()
                .flatten()
                .filter_map(Yaml::as_str)
                .filter(|m| m.contains("alpha-secrets"))
                .collect();
            if own {
                assert_eq!(
                    secret_mounts,
                    [format!("alpha-secrets-{service}:/run/secrets:ro")]
                );
                assert_eq!(
                    mounts.unwrap().last().unwrap().as_str().unwrap(),
                    secret_mounts[0]
                );
            } else {
                assert!(secret_mounts.is_empty(), "{service}");
            }
            assert!(services[service].get("secrets").is_none());
        }
        let web = &services["web"];
        assert_eq!(web["ports"], strings(&["443:80"]));
        assert_eq!(web["restart"], key("unless-stopped"));
        assert_eq!(
            serde_yaml_ng::to_string(&web["depends_on"]).unwrap(),
            "db:\n  condition: service_started\ncache:\n  condition: service_started\nalpha-runtime:\n  condition: service_healthy\n"
        );
        assert_eq!(web["environment"]["LOG_LEVEL"], key("info"));
        assert_eq!(web["environment"]["MODE"], key("production"));
        let cache = &services["cache"];
        assert_eq!(cache["restart"], key("always"));
        assert!(cache.get("depends_on").is_none());
        let runtime = &services[RUNTIME_SERVICE];
        assert_eq!(
            runtime["environment"]["ALPHACOMPUTE_SECRETS"],
            key(r#"{"db":["db_password"],"web":["db_password","session_key"]}"#)
        );
        assert_eq!(
            runtime["healthcheck"]["test"],
            strings(&["CMD", "/alpha-runtime", "healthcheck"])
        );
        assert_eq!(
            keys(&yaml["volumes"]),
            [
                "pgdata",
                "cachedata",
                "alpha-run",
                "alpha-secrets-web",
                "alpha-secrets-db"
            ]
        );
        assert!(!wrapped.compose.contains("x-env"));
        assert_eq!(
            wrapped.secrets.iter().collect::<Vec<_>>(),
            ["db_password", "session_key"]
        );
    }

    #[derive(serde::Deserialize)]
    struct Case {
        compose: String,
        refusal: String,
    }

    #[test]
    fn wrap_refuses_every_vector() {
        let text = fs::read_to_string(dir("09-wrap-refusals").join("cases.yaml")).unwrap();
        let cases: BTreeMap<String, Case> = serde_yaml_ng::from_str(&text).unwrap();
        let mut decided = [
            "build",
            "runtime-service",
            "service-reserved",
            "service-name",
            "bind-short",
            "bind-long",
            "mount-image",
            "privileged",
            "network-host",
            "tag-other-registry",
            "digest-malformed",
            "volume-driver-opts",
            "volume-name",
            "volume-external",
            "volume-reserved",
            "secret-file",
            "secret-environment",
            "secret-long",
            "secret-undeclared",
            "secrets-mount-target",
            "ports-two",
            "ports-none",
            "port-host-ip",
            "interpolation",
            "env-no-value",
            "depends-on-runtime",
            "depends-on-missing",
            "top-level-key",
            "yaml-tag",
            "duplicate-key",
            "two-documents",
            "empty",
        ];
        decided.sort_unstable();
        assert_eq!(cases.keys().collect::<Vec<_>>(), decided);
        for (name, case) in &cases {
            let err = parse(case.compose.as_bytes()).unwrap_err();
            assert!(err.contains(&case.refusal), "{name}: {err}");
            assert!(err.contains("; "), "{name}: {err}");
        }
    }

    #[test]
    fn the_size_limit_comes_before_parsing() {
        let mut text = vector_compose();
        text.push_str("\n# ");
        let padding = MAX_COMPOSE_BYTES - text.len() - 1;
        text.push_str(&"x".repeat(padding));
        text.push('\n');
        assert_eq!(text.len(), MAX_COMPOSE_BYTES);
        parse(text.as_bytes()).unwrap();
        text.push('\n');
        let err = parse(text.as_bytes()).unwrap_err();
        assert!(err.contains("256 KiB"), "{err}");
        let err = parse(&[b'['; MAX_COMPOSE_BYTES + 1]).unwrap_err();
        assert!(err.contains("256 KiB"), "{err}");
    }

    #[test]
    fn bytes_that_are_not_utf8_are_refused() {
        let mut bytes = b"# \xff\n".to_vec();
        bytes.extend_from_slice(vector_compose().as_bytes());
        let err = parse(&bytes).unwrap_err();
        assert!(err.contains("UTF-8"), "{err}");
    }

    fn single(name: &str, port: &str) -> String {
        format!(
            "services:\n  {name}:\n    image: nginx@sha256:{}\n    ports: [{port}]\n",
            "ab".repeat(32)
        )
    }

    #[test]
    fn boundaries_of_names_and_ports() {
        for name in ["alphaweb", &"a".repeat(64)] {
            parse(single(name, "\"8080:80\"").as_bytes()).unwrap();
        }
        for name in ["alpha-web", &"a".repeat(65), "..", "Web"] {
            let err = parse(single(name, "\"8080:80\"").as_bytes()).unwrap_err();
            assert!(err.contains(name), "{err}");
        }
        let err = parse(single("Web", "\"8080:80\"").as_bytes()).unwrap_err();
        assert!(err.contains("lowercase"), "{err}");

        for (item, port) in [
            ("\"8080:65535\"", 65535),
            ("\"80\"", 80),
            ("80", 80),
            ("\"8080:80/tcp\"", 80),
            ("{target: 80, published: 8080}", 80),
        ] {
            let plain = parse(single("web", item).as_bytes()).unwrap();
            assert_eq!(plain.endpoint, ("web".to_owned(), port), "{item}");
        }
        for item in ["\"8080:0\"", "\"8080:65536\"", "\"8080:80/udp\""] {
            let err = parse(single("web", item).as_bytes()).unwrap_err();
            assert!(err.contains("not a TCP port"), "{item}: {err}");
        }
    }

    #[test]
    fn references_split_as_docker_does() {
        for (image, domain) in [
            ("nginx", "docker.io"),
            ("nginx:1.27", "docker.io"),
            ("docker.io/nginx", "docker.io"),
            ("index.docker.io/nginx", "docker.io"),
            ("acme/app:1", "docker.io"),
            ("ghcr.io/acme/app", "ghcr.io"),
            ("quay.io/prometheus/node-exporter:v1", "quay.io"),
            ("localhost:5000/app:1", "localhost:5000"),
            ("registry.example.com/app:1", "registry.example.com"),
            ("Acme/app:1", "Acme"),
        ] {
            assert_eq!(registry(image), domain, "{image}");
        }
        let with = |image: &str| replaced(&single("web", "\"8080:80\""), "nginx@sha256:", image);
        let hex = "ab".repeat(32);
        for image in [
            "nginx@sha256:",
            "nginx:1.27@sha256:",
            "registry.example.com/app@sha256:",
        ] {
            let plain = parse(with(image).as_bytes()).unwrap();
            let (_, service) = &plain.services[0];
            assert_eq!(service["image"], key(&format!("{image}{hex}")));
        }
        for image in [
            "localhost:5000/app:1",
            "registry.example.com/app:1",
            "Acme/app:1",
        ] {
            let text = with(image).replace(&hex, "");
            let err = parse(text.as_bytes()).unwrap_err();
            assert!(err.contains("a tag outside"), "{image}: {err}");
        }
        for digest in [
            format!("sha256:{}", "AB".repeat(32)),
            format!("sha512:{}", "ab".repeat(64)),
            format!("sha256:{}", "a".repeat(63)),
        ] {
            let text = with("nginx@").replace(&hex, &digest);
            let err = parse(text.as_bytes()).unwrap_err();
            assert!(err.contains("malformed digest"), "{digest}: {err}");
        }
    }

    fn replaced(text: &str, from: &str, to: &str) -> String {
        assert!(text.contains(from), "{from}");
        text.replace(from, to)
    }

    #[test]
    fn a_compose_without_secrets_gets_no_runtime_health() {
        let text = vector_compose();
        let (text, _) = text.split_once("\nsecrets:").unwrap();
        let text = replaced(text, "    secrets: [session_key, db_password]\n", "");
        let text = replaced(&text, "    secrets: [db_password]\n", "");
        let wrapped = wrap_text(&text, &BTreeMap::new()).unwrap();
        let yaml = compose_yaml(&wrapped);
        assert!(
            yaml["services"][RUNTIME_SERVICE]
                .get("healthcheck")
                .is_none()
        );
        for absent in ["ALPHACOMPUTE_SECRETS", "alpha-secrets", "service_healthy"] {
            assert!(!wrapped.compose.contains(absent), "{absent}");
        }
        assert!(wrapped.secrets.is_empty());
    }

    #[test]
    fn secret_order_does_not_change_the_bytes() {
        let text = vector_compose();
        let reordered = replaced(
            &text,
            "[session_key, db_password]",
            "[db_password, session_key]",
        );
        let reordered = replaced(
            &reordered,
            "  db_password:\n    external: true\n  session_key: {}\n",
            "  session_key: {}\n  db_password:\n    external: true\n",
        );
        assert_eq!(
            wrap_text(&reordered, &BTreeMap::new()).unwrap().compose,
            wrap_text(&text, &BTreeMap::new()).unwrap().compose
        );
    }

    #[test]
    fn a_tag_without_a_digest_is_refused_by_wrap() {
        let pinned = format!("nginx:1.27@sha256:{}", "ab".repeat(32));
        let text = replaced(&vector_compose(), &pinned, "nginx:1.27");
        let err = wrap_text(&text, &BTreeMap::new()).unwrap_err();
        assert!(
            err.contains("nginx:1.27") && err.contains("@sha256:"),
            "{err}"
        );
        let digest = format!("sha256:{}", "aa".repeat(32));
        let digests = BTreeMap::from([("nginx:1.27".to_owned(), digest.clone())]);
        let wrapped = wrap_text(&text, &digests).unwrap();
        assert_eq!(
            compose_yaml(&wrapped)["services"]["web"]["image"],
            key(&format!("nginx:1.27@{digest}"))
        );
    }

    #[test]
    fn a_bad_runtime_image_is_refused() {
        let mut spec = deploy_spec();
        spec.runtime.image = "ghcr.io/alphacompute/alpha-runtime:latest".into();
        let plain = parse(vector_compose().as_bytes()).unwrap();
        let err = wrap(plain, &BTreeMap::new(), spec.app_id, &spec.runtime).unwrap_err();
        assert!(
            err.contains("ghcr.io/alphacompute/alpha-runtime:latest"),
            "{err}"
        );
    }
}
