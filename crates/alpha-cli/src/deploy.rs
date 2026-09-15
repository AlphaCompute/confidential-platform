//! `alpha deploy`: the tenant's YAML → `app-compose.json` in Phala's form → registered as a
//! Revision under the admin key → shroud-go's deploy route under the organization's API key.

use alpha_client::{Client, sign};
use alpha_core::{AppId, ComposeHash, KeyId, check_registration, context, phala};
use ed25519_dalek::SigningKey;
use serde::Deserialize;
use serde_json::{Value, json};
use serde_yaml_ng::{Mapping, Value as Yaml};

pub const RUNTIME_SERVICE: &str = "alpha-runtime";
const SOCKET_VOLUME: &str = "alpha-run:/run/alpha";
const KMS_ENVS: [&str; 4] = [
    "ALPHACOMPUTE_DATABASE_URL",
    "ALPHACOMPUTE_KMS_ENDPOINTS",
    "ALPHACOMPUTE_PCCS_URL",
    "ALPHACOMPUTE_PLATFORM_DOCUMENT_URL",
];
const DEV_ROOT_ENV: &str = "ALPHACOMPUTE_KMS_DEV_ROOT_KEK";
const REGISTRY_TOKEN_ENV: &str = "ALPHACOMPUTE_GHCR_TOKEN";
/// dstack's `app-compose.sh` sources this before `docker compose up`, with the encrypted env
/// already filtered by `allowed_envs`; it is sourced, so it must not `exit`. It only logs in:
/// Phala's default script prunes every image before pulling, so a CVM rebooted after its
/// short-lived deploy token expired would lose the image it runs. ghcr checks the token, not
/// the user name.
const PRE_LAUNCH_SCRIPT: &str = "if [ -n \"${ALPHACOMPUTE_GHCR_TOKEN:-}\" ]; then printf '%s' \"$ALPHACOMPUTE_GHCR_TOKEN\" | docker login ghcr.io -u x-access-token --password-stdin; fi\n";
/// configfs-tsm for the quote, dstack's runtime events, the CCEL boot events: what any
/// container that produces evidence mounts.
const EVIDENCE_MOUNTS: [&str; 3] = [
    "/sys/kernel/config:/sys/kernel/config",
    "/run/log/dstack:/run/log/dstack:ro",
    "/sys/firmware/acpi/tables/data/CCEL:/sys/firmware/acpi/tables/data/CCEL:ro",
];

/// What the tenant writes.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppSpec {
    pub app_id: AppId,
    /// In the tenant's order; `alpha-runtime` is appended last.
    pub services: Mapping,
    pub runtime: Runtime,
    /// Passed to shroud-go as is: the CVM shape.
    #[serde(default)]
    pub resources: Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Service {
    pub image: String,
    #[serde(default)]
    pub environment: Mapping,
    /// Mounts `/run/alpha`; not for the container that runs model-written code.
    #[serde(default)]
    pub socket: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Runtime {
    pub image: String,
    pub kms_ca_spki_sha256: String,
    pub kms_revisions: Vec<ComposeHash>,
}

pub fn parse(yaml: &str) -> Result<AppSpec, String> {
    serde_yaml_ng::from_str(yaml).map_err(|e| e.to_string())
}

fn key(s: &str) -> Yaml {
    Yaml::String(s.to_owned())
}

fn strings(items: &[&str]) -> Yaml {
    Yaml::Sequence(items.iter().map(|s| key(s)).collect())
}

fn docker_compose_file(spec: &AppSpec) -> Result<String, String> {
    // alpha-runtime refuses these at start; a Revision that cannot boot is better refused here.
    if spec.runtime.kms_revisions.is_empty() {
        return Err("runtime.kms_revisions is empty".into());
    }
    if spec
        .runtime
        .kms_ca_spki_sha256
        .strip_prefix("sha256:")
        .and_then(alpha_core::hex_bytes::<32>)
        .is_none()
    {
        return Err("runtime.kms_ca_spki_sha256 is not sha256:<64 hex>".into());
    }
    let mut services = Mapping::new();
    for (name, service) in &spec.services {
        let name = name
            .as_str()
            .ok_or("services: a service name is not a string")?;
        if name == RUNTIME_SERVICE {
            return Err(format!(
                "services: {RUNTIME_SERVICE} is added by alpha deploy"
            ));
        }
        let service: Service = serde_yaml_ng::from_value(service.clone())
            .map_err(|e| format!("services.{name}: {e}"))?;
        let mut out = Mapping::new();
        out.insert(key("image"), key(&service.image));
        if !service.environment.is_empty() {
            out.insert(key("environment"), Yaml::Mapping(service.environment));
        }
        if service.socket {
            out.insert(key("volumes"), strings(&[SOCKET_VOLUME]));
        }
        services.insert(key(name), Yaml::Mapping(out));
    }
    let revisions: Vec<String> = spec
        .runtime
        .kms_revisions
        .iter()
        .map(|r| r.to_string())
        .collect();
    let mut environment = Mapping::new();
    environment.insert(
        key("ALPHACOMPUTE_KMS_CA_SPKI_SHA256"),
        key(&spec.runtime.kms_ca_spki_sha256),
    );
    environment.insert(key("ALPHACOMPUTE_KMS_REVISIONS"), key(&revisions.join(",")));
    environment.insert(
        key("ALPHACOMPUTE_KMS_ENDPOINTS"),
        key("${ALPHACOMPUTE_KMS_ENDPOINTS}"),
    );
    let mut runtime = Mapping::new();
    runtime.insert(key("image"), key(&spec.runtime.image));
    runtime.insert(key("environment"), Yaml::Mapping(environment));
    let mut mounts = EVIDENCE_MOUNTS.to_vec();
    mounts.push(SOCKET_VOLUME);
    runtime.insert(key("volumes"), strings(&mounts));
    services.insert(key(RUNTIME_SERVICE), Yaml::Mapping(runtime));
    let mut volumes = Mapping::new();
    volumes.insert(key("alpha-run"), Yaml::Mapping(Mapping::new()));
    let mut root = Mapping::new();
    root.insert(key("services"), Yaml::Mapping(services));
    root.insert(key("volumes"), Yaml::Mapping(volumes));
    serde_yaml_ng::to_string(&root).map_err(|e| e.to_string())
}

fn envelope(
    app_id: AppId,
    docker_compose_file: String,
    allowed_envs: &[&str],
) -> Result<String, String> {
    let mut allowed_envs = allowed_envs.to_vec();
    allowed_envs.push(REGISTRY_TOKEN_ENV);
    let envelope = json!({
        "manifest_version": 2,
        "name": app_id,
        "runner": "docker-compose",
        "docker_compose_file": docker_compose_file,
        "pre_launch_script": PRE_LAUNCH_SCRIPT,
        "kms_enabled": true,
        "gateway_enabled": true,
        "allowed_envs": allowed_envs,
        "public_tcbinfo": false,
        "no_instance_id": false,
        // Phala's API writes these fields when they are absent and changes the compose when
        // `key_provider` is present, so the bytes it measures would not be the signed ones.
        // Spelled out, with no `key_provider`, the compose is stored unchanged.
        "features": ["kms", "tproxy-net"],
        "local_key_provider_enabled": false,
        "public_logs": false,
        "public_sysinfo": false,
        "secure_time": false,
        "storage_fs": "zfs",
        "tproxy_enabled": true,
    });
    let compose = phala::canonicalize(&envelope).map_err(|e| e.to_string())?;
    check_registration(&compose, app_id).map_err(|e| e.to_string())?;
    Ok(compose)
}

/// The exact bytes that will be signed, measured and registered.
pub fn compose(spec: &AppSpec) -> Result<String, String> {
    envelope(
        spec.app_id,
        docker_compose_file(spec)?,
        &["ALPHACOMPUTE_KMS_ENDPOINTS"],
    )
}

/// The KMS node's own compose: the same envelope with one service, the KMS image, port 8443
/// published for the dstack gateway's TLS passthrough, the evidence mounts, and its config as
/// encrypted env. `dev_root` adds the root KEK variable the `dev-root` build reads.
pub fn kms_compose(app_id: AppId, image: &str, dev_root: bool) -> Result<String, String> {
    let mut envs = KMS_ENVS.to_vec();
    if dev_root {
        envs.push(DEV_ROOT_ENV);
    }
    let mut environment = Mapping::new();
    for name in &envs {
        environment.insert(key(name), key(&format!("${{{name}}}")));
    }
    let mut kms = Mapping::new();
    kms.insert(key("image"), key(image));
    kms.insert(key("environment"), Yaml::Mapping(environment));
    kms.insert(key("ports"), strings(&["8443:8443"]));
    kms.insert(key("restart"), key("always"));
    kms.insert(key("volumes"), strings(&EVIDENCE_MOUNTS));
    let mut services = Mapping::new();
    services.insert(key("alpha-kms"), Yaml::Mapping(kms));
    let mut root = Mapping::new();
    root.insert(key("services"), Yaml::Mapping(services));
    let yaml = serde_yaml_ng::to_string(&root).map_err(|e| e.to_string())?;
    envelope(app_id, yaml, &envs)
}

pub struct Shroud {
    pub url: String,
    pub api_key: String,
}

/// Registers the Revision, then deploys through shroud-go unless `shroud` is `None`
/// (`--register-only`). Returns both replies.
pub async fn run(
    client: &Client,
    spec: &AppSpec,
    key_id: KeyId,
    key: &SigningKey,
    shroud: Option<&Shroud>,
) -> Result<Value, String> {
    let compose = compose(spec)?;
    let signed = sign(
        context::REVISION,
        json!({ "app_id": spec.app_id, "compose": compose }),
        key_id,
        key,
    )
    .map_err(|e| e.to_string())?;
    let revision = client
        .register_revision(&signed)
        .await
        .map_err(|e| e.to_string())?;
    let Some(shroud) = shroud else {
        return Ok(json!({ "revision": revision }));
    };
    // ponytail: shroud-go does not serve this route yet, so the call has run against nothing;
    // first real deploy is the test.
    let response = reqwest::Client::new()
        .post(format!(
            "{}/v1/apps/{}/deploy",
            shroud.url.trim_end_matches('/'),
            spec.app_id
        ))
        .bearer_auth(&shroud.api_key)
        .json(&json!({
            "compose_hash": revision.compose_hash,
            "resources": spec.resources,
            "compose": compose,
        }))
        .send()
        .await
        .map_err(|e| format!("shroud-go: {e}"))?;
    let status = response.status();
    let body: Value = response.json().await.unwrap_or(Value::Null);
    if !status.is_success() {
        return Err(format!("shroud-go deploy: {status}: {body}"));
    }
    Ok(json!({ "revision": revision, "deploy": body }))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use super::*;

    fn vector() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/manifest/05-deploy")
    }

    #[test]
    fn generator_reproduces_the_vector() {
        let spec = parse(&fs::read_to_string(vector().join("app.yaml")).unwrap()).unwrap();
        let expected = fs::read_to_string(vector().join("app-compose.json")).unwrap();
        let compose = compose(&spec).unwrap();
        assert_eq!(compose, expected);
        let expected_hash: Value =
            serde_json::from_str(&fs::read_to_string(vector().join("expected.json")).unwrap())
                .unwrap();
        assert_eq!(
            alpha_core::compose_hash(&compose).to_string(),
            expected_hash["compose_hash"]
        );
        let yaml = docker_compose_file(&spec).unwrap();
        let runtime_at = yaml.find("  alpha-runtime:").unwrap();
        assert!(
            yaml.find("  app:").unwrap() < runtime_at,
            "runtime service is last"
        );
        assert!(yaml.contains("${ALPHACOMPUTE_KMS_ENDPOINTS}"));
        assert_eq!(
            yaml.matches(SOCKET_VOLUME).count(),
            2,
            "app and runtime mount the socket"
        );
    }

    #[test]
    fn kms_compose_reproduces_the_vector() {
        let dir = vector().with_file_name("06-kms-node");
        let expected: Value =
            serde_json::from_str(&fs::read_to_string(dir.join("expected.json")).unwrap()).unwrap();
        let app_id: AppId = expected["app_id"].as_str().unwrap().parse().unwrap();
        let image = expected["image"].as_str().unwrap();
        let compose = kms_compose(app_id, image, false).unwrap();
        assert_eq!(
            compose,
            fs::read_to_string(dir.join("app-compose.json")).unwrap()
        );
        assert_eq!(
            alpha_core::compose_hash(&compose).to_string(),
            expected["compose_hash"]
        );
        let parsed: Value = serde_json::from_str(&compose).unwrap();
        assert_eq!(phala::canonicalize(&parsed).unwrap(), compose);

        assert_eq!(parsed["pre_launch_script"], PRE_LAUNCH_SCRIPT);
        assert_eq!(parsed["allowed_envs"][4], REGISTRY_TOKEN_ENV);
        assert!(
            !parsed["docker_compose_file"]
                .as_str()
                .unwrap()
                .contains(REGISTRY_TOKEN_ENV),
            "the registry token reaches the pre-launch script, never a container"
        );

        let dev = kms_compose(app_id, image, true).unwrap();
        let parsed: Value = serde_json::from_str(&dev).unwrap();
        assert_eq!(parsed["allowed_envs"][4], DEV_ROOT_ENV);
        assert_eq!(parsed["allowed_envs"][5], REGISTRY_TOKEN_ENV);
        assert!(
            parsed["docker_compose_file"]
                .as_str()
                .unwrap()
                .contains(&format!("{DEV_ROOT_ENV}: ${{{DEV_ROOT_ENV}}}"))
        );
        assert!(kms_compose(app_id, "ghcr.io/alphacompute/alpha-kms:v1", false).is_err());
    }

    #[test]
    fn generator_refuses_what_registration_would() {
        let base = fs::read_to_string(vector().join("app.yaml")).unwrap();
        let tagged = base.replace(
            "ghcr.io/acme/app@sha256:3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a",
            "ghcr.io/acme/app:latest",
        );
        let spec = parse(&tagged).unwrap();
        assert!(compose(&spec).unwrap_err().contains("digest"));
        let taken = base.replace("  app:\n", "  alpha-runtime:\n");
        let spec = parse(&taken).unwrap();
        assert!(
            compose(&spec)
                .unwrap_err()
                .contains("added by alpha deploy")
        );
        let ca = base
            .lines()
            .find(|l| l.contains("kms_ca_spki_sha256"))
            .unwrap();
        let spec = parse(&base.replace(ca, "  kms_ca_spki_sha256: sha256:zz")).unwrap();
        assert!(compose(&spec).unwrap_err().contains("kms_ca_spki_sha256"));
        let mut spec = parse(&base).unwrap();
        spec.runtime.kms_revisions.clear();
        assert!(compose(&spec).unwrap_err().contains("kms_revisions"));
        assert!(parse(&(base + "extra: 1\n")).is_err());
    }
}
