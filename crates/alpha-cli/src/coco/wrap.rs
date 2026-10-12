//! `alpha coco wrap`: a customer's compose becomes one Kata confidential pod of a given shape,
//! with the init-data that pins it and the Revision v2 the customer approves. The contract is
//! rafay-plugins' `rafay-integration/coco-gpu.md` ("The `alpha coco wrap` contract"); its adapter
//! holds the output to `checkCocoWrapped` and `checkPodSpec`.
//!
//! The compose passes the same allowlist as `alpha compose wrap`. Each service becomes a
//! container of the pod, and `alpha-runtime` runs beside them as a native sidecar: it attests
//! with the pod's init-data, holds the leaf, writes the declared Secret files and terminates TLS
//! on 8443 in front of the published service, which it reaches at `127.0.0.1` (the pod's network
//! namespace; a name would go through the host-written `/etc/hosts`). The agent policy is
//! genpolicy 4.1.0's for exactly this pod spec, held to the PRD-02 baseline.

use std::collections::{BTreeMap, BTreeSet};

use alpha_core::coco::{GpuShape, InitData, RuntimeClass};
use alpha_core::{AppId, ComposeHash};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use serde_yaml_ng::{Mapping, Value as Yaml};

use super::policy::{self, GenpolicyError, PolicyContainer};
use crate::deploy::wrap::{Plain, pin, pinned_reference, shown};
use crate::deploy::{RUNTIME_SERVICE, Runtime};

/// The Kata annotation that carries base64(gzip(init-data)); the adapter sets it.
pub const INITDATA_ANNOTATION: &str = "io.katacontainers.config.hypervisor.cc_init_data";
/// The extended resource of a whole CC-mode GPU passed through (GPU Operator sandbox mode with
/// `P_GPU_ALIAS=pgpu`); `nvidia.com/gpu` is never advertised on the CoCo nodes.
pub const GPU_RESOURCE: &str = "nvidia.com/pgpu";
/// The runtime's TLS port in the pod, which the adapter's Service targets.
pub const TLS_PORT: u16 = alpha_client::runtime::TLS_PORT;
/// The namespace ConfigMap that carries the KMS endpoints; see
/// [`policy::KMS_ENDPOINTS_ENV_REGEX`] for why it need not be measured.
// ponytail: the adapter's manifest (coco-gpu.md, five objects) does not create it yet; until the
// adapter or PRD-01's blueprint does, the runtime container does not start (fails closed).
pub const KMS_CONFIG_MAP: &str = "alpha-kms";
pub const KMS_CONFIG_MAP_KEY: &str = "endpoints";
const KMS_ENDPOINTS_ENV: &str = "ALPHACOMPUTE_KMS_ENDPOINTS";
/// At most this many Secret names reach the approval request (shroud-go's limit).
pub const MAX_SECRETS: usize = 16;
/// The runtime's startup probe waits this long for attestation and the first Secret delivery,
/// as `alpha compose wrap`'s health check does with its 24-hour start period.
const STARTUP_PROBE_PERIOD: u32 = 5;
const STARTUP_PROBE_FAILURES: u32 = 17_280;
pub(crate) const SOCKET_VOLUME: &str = alpha_core::coco::policy::VOLUME_SOCKET_VOLUME;
const POD_VOLUME: &str = "alpha-pod";
const SECRETS_VOLUME_PREFIX: &str = "alpha-secrets-";
/// alpha-runtime's `SECRETS_DIR`: it writes each declaring service's files under
/// `<dir>/<service>`, which that service mounts read-only at `/run/secrets`.
const RUNTIME_SECRETS_DIR: &str = "/run/alpha-secrets";
/// A Kubernetes volume and container name (an RFC 1123 label).
const MAX_LABEL: usize = 63;

/// What the pod runs on, as the adapter writes it: `{runtime_class, gpu {model, count}, cpu,
/// memory_mib}`. A CPU shape (`kata-qemu-tdx`) has no `gpu`.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Shape {
    pub runtime_class: String,
    #[serde(default)]
    pub gpu: Option<GpuShape>,
    pub cpu: u32,
    pub memory_mib: u64,
}

impl Shape {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let value = alpha_core::parse(bytes).map_err(|e| format!("shape: {e}"))?;
        let shape: Self = serde_json::from_value(value).map_err(|e| format!("shape: {e}"))?;
        let class = RuntimeClass::from_name(&shape.runtime_class).ok_or_else(|| {
            format!(
                "shape: runtime_class {:?} is not a confidential runtime class",
                shape.runtime_class
            )
        })?;
        match (&shape.gpu, class.has_gpus()) {
            (Some(gpu), true) if alpha_core::coco::GPU_COUNTS.contains(&gpu.count) => {}
            (None, false) => {}
            _ => {
                return Err(format!(
                    "shape: {} takes {}",
                    shape.runtime_class,
                    if class.has_gpus() {
                        "a gpu of 1 or 8"
                    } else {
                        "no gpu"
                    }
                ));
            }
        }
        if !(1..=1024).contains(&shape.cpu) || !(256..=16_777_216).contains(&shape.memory_mib) {
            return Err("shape: cpu or memory_mib out of range".into());
        }
        Ok(shape)
    }

    fn gpus(&self) -> u32 {
        self.gpu.as_ref().map_or(0, |g| g.count)
    }
}

/// What `alpha coco wrap` prints.
#[derive(Debug, Serialize)]
pub struct Wrapped {
    /// The Revision v2 in JCS form, exactly `InitData::revision()` of `initdata`.
    pub revision: String,
    pub revision_hash: ComposeHash,
    /// Standard base64 of the init-data TOML, not gzipped.
    pub initdata: String,
    pub pod_spec: Value,
    pub secrets: BTreeSet<String>,
    /// The block-mode claims of the compose's persistent volumes. Absent when there are none, so
    /// a compose without them prints exactly the five keys of the adapter's contract; an adapter
    /// that does not know this key refuses the output, and so deploys no volume it cannot create.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub volume_claims: Vec<Value>,
}

/// The compose's persistent volumes (PRD-02 deliverable 25), by name and size, and the
/// `alpha-volume` image that opens them.
#[derive(Clone, Debug, Default)]
pub struct Persistent {
    pub volumes: BTreeMap<String, String>,
    /// `--volume-image`: one of `listed`.
    pub image: Option<String>,
    /// The `alpha-volume` images the release-signed platform document lists
    /// (`super::volume::listed_images`), the only ones a volume init container may run.
    pub listed: BTreeSet<String>,
}

/// The compose's top-level extension that makes named volumes persistent and encrypted:
/// `x-alphacompute-volumes: {<volume>: {size: 10Gi}}`. `alpha compose wrap` ignores `x-` keys.
pub const PERSISTENT_KEY: &str = "x-alphacompute-volumes";

/// Reads [`PERSISTENT_KEY`] from the compose's bytes, which `parse` has already accepted.
pub fn persistent_volumes(compose: &[u8]) -> Result<BTreeMap<String, String>, String> {
    let root: Yaml = serde_yaml_ng::from_slice(compose).map_err(|e| format!("compose: {e}"))?;
    let Some(section) = root.get(PERSISTENT_KEY) else {
        return Ok(BTreeMap::new());
    };
    let place = PERSISTENT_KEY;
    let section = section
        .as_mapping()
        .ok_or_else(|| format!("{place}: not a mapping; write <volume>: {{size: 10Gi}}"))?;
    let mut out = BTreeMap::new();
    for (name, spec) in section {
        let name = name
            .as_str()
            .ok_or_else(|| format!("{place}: {} is not a volume name", shown(name)))?;
        super::volume::check_name(name, place)?;
        let size = spec
            .as_mapping()
            .filter(|m| m.len() == 1)
            .and_then(|m| m.get("size"))
            .and_then(Yaml::as_str)
            .ok_or_else(|| format!("{place}.{name}: write {{size: <n>Gi}} and nothing else"))?;
        super::volume::check_size(size).map_err(|e| format!("{place}.{name}: {e}"))?;
        out.insert(name.to_owned(), size.to_owned());
    }
    Ok(out)
}

/// Why `wrap` produced nothing.
#[derive(Debug, PartialEq, Eq)]
pub enum WrapError {
    /// The compose cannot run as asked; the message is for the customer and names only the
    /// compose's own parts.
    Refused(String),
    /// Our side failed (genpolicy, its output, the generator itself); the customer sees the
    /// adapter's generic failure, not this message.
    Failed(String),
}

impl From<String> for WrapError {
    fn from(message: String) -> Self {
        Self::Refused(message)
    }
}

impl std::fmt::Display for WrapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(m) | Self::Failed(m) => f.write_str(m),
        }
    }
}

/// Where the agent policy comes from: genpolicy in production, a recording in tests.
pub trait PolicySource {
    fn generate(&self, resource_yaml: &str)
    -> impl Future<Output = Result<String, GenpolicyError>>;
}

impl PolicySource for policy::Genpolicy {
    async fn generate(&self, resource_yaml: &str) -> Result<String, GenpolicyError> {
        self.run(resource_yaml).await
    }
}

/// The namespace and Deployment name the adapter gives the App (coco-gpu.md, "The manifest");
/// genpolicy pins the sandbox's name and namespace to them.
pub fn workload_name(app_id: AppId) -> String {
    format!("app-{app_id}")
}

/// `digests` maps a tagged image, as the customer wrote it, to `sha256:<hex>`.
pub async fn wrap(
    plain: Plain,
    digests: &BTreeMap<String, String>,
    app_id: AppId,
    runtime: &Runtime,
    shape: &Shape,
    persistent: &Persistent,
    source: &impl PolicySource,
) -> Result<Wrapped, WrapError> {
    let secrets: BTreeSet<String> = plain.secrets.values().flatten().cloned().collect();
    if secrets.len() > MAX_SECRETS {
        return Err(WrapError::Refused(format!(
            "secrets: {} are declared; declare at most {MAX_SECRETS}",
            secrets.len()
        )));
    }
    let mut spec = pod_spec(&plain, digests, runtime, shape, persistent)?;
    let expected = containers(&spec);
    let mut attempts = expected.len().saturating_add(1);
    let policy = loop {
        let yaml = genpolicy_input(app_id, &spec).map_err(WrapError::Failed)?;
        match source.generate(&yaml).await {
            Ok(policy) => break policy,
            Err(GenpolicyError::Identity {
                container,
                uid,
                gid,
                groups,
            }) if attempts > 0 => {
                attempts = attempts.saturating_sub(1);
                set_identity(&mut spec, &container, uid, gid, &groups)?;
            }
            Err(GenpolicyError::Identity { container, .. }) => {
                return Err(WrapError::Refused(format!(
                    "services.{container}: the user its image runs as could not be pinned; set `user: <uid>:<gid>`"
                )));
            }
            Err(GenpolicyError::Image(_)) => {
                return Err(WrapError::Refused(
                    "an image could not be read from its registry; check that every image is public and built for linux/amd64, then try again"
                        .into(),
                ));
            }
            Err(GenpolicyError::Failed(reason)) => return Err(WrapError::Failed(reason)),
        }
    };
    let failed = |m: String| WrapError::Failed(m);
    let names: BTreeSet<String> = persistent.volumes.keys().cloned().collect();
    let policy = policy::pin_hostname(&policy);
    let policy = super::volume::propagate(&policy, &names).map_err(failed)?;
    let verified = policy::verify_with_volumes(&policy, &persistent.listed).map_err(failed)?;
    if verified.containers != expected {
        return Err(failed(format!(
            "agent policy: admits {:?}, not the pod's containers {:?}",
            verified.containers, expected
        )));
    }
    let containers: Vec<Yaml> = ["initContainers", "containers"]
        .iter()
        .filter_map(|k| spec.get(k).and_then(Value::as_array))
        .flatten()
        .map(serde_yaml_ng::to_value)
        .collect::<Result<_, _>>()
        .map_err(|e| failed(e.to_string()))?;
    // wrap has no DSM input: a compose cannot declare one (PRD-06 I1), so the policy pins none.
    super::check_dsm(&containers, &verified).map_err(failed)?;
    let volume_containers =
        super::volume::containers(persistent.volumes.keys(), persistent.image.as_deref());
    super::volume::check_elevated(&verified, &volume_containers).map_err(failed)?;

    let gpu = shape.gpu.clone();
    let alpha = super::alpha_json(app_id, &shape.runtime_class, gpu.clone()).map_err(failed)?;
    let initdata = super::build_initdata(&policy, &alpha).map_err(failed)?;
    let revision = InitData::parse(&initdata)
        .and_then(|i| i.revision())
        .map_err(|e| failed(e.to_string()))?;
    if revision.runtime_class != shape.runtime_class || revision.gpu != gpu {
        return Err(failed(
            "revision: not the shape's runtime class and GPUs".into(),
        ));
    }
    Ok(Wrapped {
        revision: revision.canonical().map_err(|e| failed(e.to_string()))?,
        revision_hash: revision.hash().map_err(|e| failed(e.to_string()))?,
        initdata: BASE64_STANDARD.encode(&initdata),
        pod_spec: spec,
        secrets,
        volume_claims: persistent
            .volumes
            .iter()
            .map(|(name, size)| super::volume::claim(name, size))
            .collect(),
    })
}

/// The pod spec the adapter deploys: the runtime as a native sidecar, then one container per
/// service, sized so the regular containers' limits are the shape exactly (Kata sizes the TD from
/// them, and RTMR0's reference value is per shape). The sidecar sets no limits, so it adds
/// nothing to that sum.
fn pod_spec(
    plain: &Plain,
    digests: &BTreeMap<String, String>,
    runtime: &Runtime,
    shape: &Shape,
    persistent: &Persistent,
) -> Result<Value, String> {
    if !pinned_reference(&runtime.image) {
        return Err(format!(
            "runtime image {:?}: not one pinned image reference; give it as <image>@sha256:<digest>",
            runtime.image
        ));
    }
    let (endpoint, port) = &plain.endpoint;
    if *port == TLS_PORT {
        return Err(format!(
            "services.{endpoint}.ports: container port {TLS_PORT} is where the pod terminates TLS; serve the App on another port"
        ));
    }
    let sizes = split(shape, plain.services.len())?;
    let mut volumes = vec![
        json!({ "name": SOCKET_VOLUME, "emptyDir": { "medium": "Memory", "sizeLimit": "1Mi" } }),
        json!({ "name": POD_VOLUME, "downwardAPI": { "items": [{
            "path": "cc_init_data",
            "fieldRef": { "fieldPath": format!("metadata.annotations['{INITDATA_ANNOTATION}']") },
        }]}}),
    ];
    for name in persistent.volumes.keys() {
        if !plain.volumes.contains(name) {
            return Err(format!(
                "{PERSISTENT_KEY}.{name}: not a volume of this compose; declare it under top-level volumes"
            ));
        }
    }
    let mut volume_inits = Vec::new();
    for name in &plain.volumes {
        label(name, "volumes")?;
        if persistent.volumes.contains_key(name) {
            let image = persistent.image.as_deref().ok_or_else(|| {
                format!(
                    "{PERSISTENT_KEY}.{name}: persistent volumes are not available for this App yet"
                )
            })?;
            if !pinned_reference(image) {
                return Err(format!(
                    "volume image {image:?}: not one pinned image reference; give it as <image>@sha256:<digest>"
                ));
            }
            super::volume::check_image(image, &persistent.listed)?;
            volumes.extend(super::volume::pod_volumes(name));
            volume_inits.push(super::volume::init_container(name, image, SOCKET_VOLUME));
        } else {
            // In the TD's memory: a volume on the host's disk would be readable by the host.
            volumes.push(json!({ "name": name, "emptyDir": { "medium": "Memory" } }));
        }
    }
    let mut runtime_mounts = vec![
        json!({ "name": SOCKET_VOLUME, "mountPath": "/run/alpha" }),
        json!({ "name": POD_VOLUME, "mountPath": "/run/alpha-pod", "readOnly": true }),
    ];
    let mut regular = Vec::new();
    for ((name, service), (cpu, memory)) in plain.services.iter().zip(sizes) {
        label(name, "services")?;
        let mut container = container(name, service, digests)?;
        let mut limits = Map::new();
        limits.insert("cpu".into(), json!(cpu));
        limits.insert("memory".into(), json!(memory));
        if name == endpoint && shape.gpus() > 0 {
            limits.insert(GPU_RESOURCE.into(), json!(shape.gpus().to_string()));
        }
        container.insert(
            "resources".into(),
            json!({ "limits": limits, "requests": limits }),
        );
        if plain.secrets.contains_key(name) {
            let volume = format!("{SECRETS_VOLUME_PREFIX}{name}");
            if volume.len() > MAX_LABEL {
                return Err(format!(
                    "services.{name}: a service with secrets has a name of at most {} characters; rename it",
                    MAX_LABEL.saturating_sub(SECRETS_VOLUME_PREFIX.len())
                ));
            }
            volumes.push(
                json!({ "name": volume, "emptyDir": { "medium": "Memory", "sizeLimit": "1Mi" } }),
            );
            runtime_mounts.push(json!({
                "name": volume, "mountPath": format!("{RUNTIME_SECRETS_DIR}/{name}"),
            }));
            push_mount(
                &mut container,
                json!({ "name": volume, "mountPath": "/run/secrets", "readOnly": true }),
            );
        }
        for mount in container
            .get_mut("volumeMounts")
            .and_then(Value::as_array_mut)
            .into_iter()
            .flatten()
        {
            let persistent_mount = mount
                .get("name")
                .and_then(Value::as_str)
                .is_some_and(|v| persistent.volumes.contains_key(v));
            if let (true, Some(m)) = (persistent_mount, mount.as_object_mut()) {
                m.insert(
                    "mountPropagation".into(),
                    json!(super::volume::APP_PROPAGATION),
                );
            }
        }
        regular.push(Value::Object(container));
    }
    for name in persistent.volumes.keys() {
        let mounted = regular.iter().any(|c| {
            c.get("volumeMounts")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .any(|m| m.get("name").and_then(Value::as_str) == Some(name))
        });
        if !mounted {
            return Err(format!(
                "{PERSISTENT_KEY}.{name}: no service mounts it; mount it or remove it"
            ));
        }
    }

    let mut env = vec![
        env_var(
            "ALPHACOMPUTE_KMS_CA_SPKI_SHA256",
            &runtime.kms_ca_spki_sha256,
        ),
        env_var(
            "ALPHACOMPUTE_KMS_REVISIONS",
            &runtime
                .kms_revisions
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(","),
        ),
        json!({ "name": KMS_ENDPOINTS_ENV, "valueFrom": { "configMapKeyRef": {
            "name": KMS_CONFIG_MAP, "key": KMS_CONFIG_MAP_KEY,
        }}}),
        env_var("ALPHACOMPUTE_QUOTE_SOURCE", "coco-aa"),
        env_var("ALPHACOMPUTE_TLS_UPSTREAM", &format!("127.0.0.1:{port}")),
    ];
    if runtime.kms_revisions.is_empty() {
        return Err("runtime.kms_revisions is empty".into());
    }
    if !plain.secrets.is_empty() {
        let map = serde_json::to_string(&plain.secrets).map_err(|e| e.to_string())?;
        env.push(env_var("ALPHACOMPUTE_SECRETS", &map));
    }
    let sidecar = json!({
        "name": RUNTIME_SERVICE,
        "image": runtime.image,
        // A native sidecar: the services start once its startup probe passes, which is when it
        // has attested and written every declared Secret (its TLS port opens only then).
        "restartPolicy": "Always",
        "env": env,
        "ports": [{ "name": "https", "containerPort": TLS_PORT }],
        "startupProbe": {
            "tcpSocket": { "port": TLS_PORT },
            "periodSeconds": STARTUP_PROBE_PERIOD,
            "failureThreshold": STARTUP_PROBE_FAILURES,
        },
        "securityContext": { "allowPrivilegeEscalation": false },
        "volumeMounts": runtime_mounts,
    });
    Ok(json!({
        "runtimeClassName": shape.runtime_class,
        "automountServiceAccountToken": false,
        "enableServiceLinks": false,
        "initContainers": std::iter::once(sidecar).chain(volume_inits).collect::<Vec<_>>(),
        "containers": regular,
        "volumes": volumes,
    }))
}

fn env_var(name: &str, value: &str) -> Value {
    json!({ "name": name, "value": value })
}

fn push_mount(container: &mut Map<String, Value>, mount: Value) {
    match container
        .get_mut("volumeMounts")
        .and_then(Value::as_array_mut)
    {
        Some(mounts) => mounts.push(mount),
        None => {
            container.insert("volumeMounts".into(), Value::Array(vec![mount]));
        }
    }
}

/// The CPU and memory limits of each service: the shape split evenly, the first service taking
/// what does not divide. CPU in whole cores or millicores, memory in MiB.
// ponytail: an even split; the upgrade is per-service sizes the customer states in the compose.
fn split(shape: &Shape, services: usize) -> Result<Vec<(String, String)>, String> {
    let n = u64::try_from(services).map_err(|e| e.to_string())?;
    let milli = u64::from(shape.cpu).saturating_mul(1000);
    let (cpu, cpu_rest) = (
        milli.checked_div(n).unwrap_or(0),
        milli.checked_rem(n).unwrap_or(0),
    );
    let (mem, mem_rest) = (
        shape.memory_mib.checked_div(n).unwrap_or(0),
        shape.memory_mib.checked_rem(n).unwrap_or(0),
    );
    if cpu < 100 || mem < 64 {
        return Err(format!(
            "services: {services} services do not fit this machine size; use fewer services or a larger size"
        ));
    }
    Ok((0..services)
        .map(|i| {
            let (c, m) = if i == 0 {
                (cpu.saturating_add(cpu_rest), mem.saturating_add(mem_rest))
            } else {
                (cpu, mem)
            };
            let c = match (c.checked_rem(1000), c.checked_div(1000)) {
                (Some(0), Some(cores)) => cores.to_string(),
                _ => format!("{c}m"),
            };
            (c, format!("{m}Mi"))
        })
        .collect())
}

/// An RFC 1123 label, which a container or volume name must be.
fn label(name: &str, place: &str) -> Result<(), String> {
    let edge = |b: Option<&u8>| b.is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    let ok = name.len() <= MAX_LABEL
        && edge(name.as_bytes().first())
        && edge(name.as_bytes().last())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if ok {
        Ok(())
    } else {
        Err(format!(
            "{place}.{name}: in a pod the name is lowercase letters, digits and `-`, at most {MAX_LABEL} characters; rename it"
        ))
    }
}

/// One service of the compose as a container; `parse` has already held it to the allowlist.
fn container(
    name: &str,
    service: &Mapping,
    digests: &BTreeMap<String, String>,
) -> Result<Map<String, Value>, String> {
    let mut out = Map::new();
    out.insert("name".into(), json!(name));
    for (k, v) in service {
        let key = k.as_str().unwrap_or_default();
        let place = format!("services.{name}.{key}");
        match key {
            "image" => {
                let image = v.as_str().ok_or_else(|| format!("{place}: not a string"))?;
                out.insert("image".into(), json!(pin(image, digests)?));
            }
            "entrypoint" => {
                out.insert("command".into(), json!(argv(v, &place)?));
            }
            "command" => {
                out.insert("args".into(), json!(argv(v, &place)?));
            }
            "environment" => {
                out.insert("env".into(), Value::Array(environment(v, &place)?));
            }
            "volumes" => {
                let items = v
                    .as_sequence()
                    .ok_or_else(|| format!("{place}: not a list"))?;
                let mut list = Vec::new();
                for item in items {
                    let (source, target, read_only) = volume_mount(item)
                        .ok_or_else(|| format!("{place}: {} is not a named volume", shown(item)))?;
                    let mut mount = json!({ "name": source, "mountPath": target });
                    if read_only && let Some(m) = mount.as_object_mut() {
                        m.insert("readOnly".into(), json!(true));
                    }
                    list.push(mount);
                }
                out.insert("volumeMounts".into(), Value::Array(list));
            }
            "user" => {
                let user = scalar(v).ok_or_else(|| format!("{place}: not a string"))?;
                let (uid, gid) = match user.split_once(':') {
                    Some((u, g)) => (u, Some(g)),
                    None => (user.as_str(), None),
                };
                let id = |s: &str| {
                    s.parse::<u32>().map_err(|_| {
                        format!("{place}: {user} names a user or group; give numeric ids, <uid> or <uid>:<gid>")
                    })
                };
                let mut context = Map::new();
                context.insert("runAsUser".into(), json!(id(uid)?));
                if let Some(gid) = gid {
                    context.insert("runAsGroup".into(), json!(id(gid)?));
                }
                out.insert("securityContext".into(), Value::Object(context));
            }
            // genpolicy 4.1.0 refuses a pod spec that sets it.
            "working_dir" => {
                return Err(format!(
                    "{place}: not supported in a confidential pod; set WORKDIR in the image"
                ));
            }
            "healthcheck" => {
                return Err(format!(
                    "{place}: a confidential pod refuses commands run inside its containers, so a health check could never pass; remove it"
                ));
            }
            // The runtime publishes the Endpoint; the pod restarts every container; secrets are
            // mounted below; containers start in the compose's order.
            "ports" | "restart" | "secrets" | "depends_on" => {}
            other => {
                return Err(format!(
                    "services.{name}: {other} is not supported in a confidential pod; remove it"
                ));
            }
        }
    }
    Ok(out)
}

/// A command as an argv. A string is split on spaces only: anything that needs a shell's quoting
/// is written as a list, so what runs is exactly what the policy pins.
fn argv(value: &Yaml, place: &str) -> Result<Vec<String>, String> {
    match value {
        Yaml::String(s) => {
            if s.contains(['"', '\'', '\\', '\n', '\t']) {
                return Err(format!(
                    "{place}: quoting in a string command is not supported; write it as a list"
                ));
            }
            Ok(s.split(' ')
                .filter(|a| !a.is_empty())
                .map(str::to_owned)
                .collect())
        }
        Yaml::Sequence(items) => items
            .iter()
            .map(|i| scalar(i).ok_or_else(|| format!("{place}: {} is not a string", shown(i))))
            .collect(),
        other => Err(format!(
            "{place}: {} is not a string or a list",
            shown(other)
        )),
    }
}

fn environment(value: &Yaml, place: &str) -> Result<Vec<Value>, String> {
    let pairs: Vec<(String, String)> = match value {
        Yaml::Mapping(m) => m
            .iter()
            .map(|(k, v)| {
                Ok((
                    scalar(k).ok_or_else(|| format!("{place}: {} is not a name", shown(k)))?,
                    scalar(v).ok_or_else(|| format!("{place}: {} is not a value", shown(v)))?,
                ))
            })
            .collect::<Result<_, String>>()?,
        Yaml::Sequence(items) => items
            .iter()
            .map(|i| {
                i.as_str()
                    .and_then(|s| s.split_once('='))
                    .map(|(k, v)| (k.to_owned(), v.to_owned()))
                    .ok_or_else(|| format!("{place}: {} is not NAME=value", shown(i)))
            })
            .collect::<Result<_, String>>()?,
        _ => return Err(format!("{place}: not a list or mapping")),
    };
    let mut seen = BTreeSet::new();
    pairs
        .into_iter()
        .map(|(k, v)| {
            if k == policy::DSM_ENV {
                return Err(format!(
                    "{place}: {k} cannot be set by a compose; a customer DSM is not available for this App yet"
                ));
            }
            if k.is_empty() || k.contains('=') || !seen.insert(k.clone()) {
                return Err(format!("{place}: {k} is not a name, or is set twice"));
            }
            Ok(env_var(&k, &v))
        })
        .collect()
}

fn scalar(value: &Yaml) -> Option<String> {
    match value {
        Yaml::String(s) => Some(s.clone()),
        Yaml::Number(n) => Some(n.to_string()),
        Yaml::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// A mount of a declared named volume, short or long syntax, as `parse` admitted it.
fn volume_mount(item: &Yaml) -> Option<(String, String, bool)> {
    match item {
        Yaml::String(s) => {
            let mut parts = s.split(':');
            let (source, target) = (parts.next()?, parts.next()?);
            Some((source.into(), target.into(), parts.next() == Some("ro")))
        }
        Yaml::Mapping(m) => Some((
            m.get("source")?.as_str()?.into(),
            m.get("target")?.as_str()?.into(),
            m.get("read_only").and_then(Yaml::as_bool).unwrap_or(false),
        )),
        _ => None,
    }
}

/// The containers a policy for `spec` must admit: every container and its image.
fn containers(spec: &Value) -> BTreeSet<PolicyContainer> {
    ["initContainers", "containers"]
        .iter()
        .filter_map(|k| spec.get(k).and_then(Value::as_array))
        .flatten()
        .filter_map(|c| {
            Some(PolicyContainer {
                name: c.get("name")?.as_str()?.to_owned(),
                image: c.get("image")?.as_str()?.to_owned(),
            })
        })
        .collect()
}

fn containers_mut(spec: &mut Map<String, Value>) -> impl Iterator<Item = &mut Value> {
    spec.iter_mut()
        .filter(|(k, _)| *k == "initContainers" || *k == "containers")
        .filter_map(|(_, v)| v.as_array_mut())
        .flatten()
}

/// Sets what genpolicy asked for: the container's user and group, and the image's supplementary
/// groups on the pod (Kubernetes has no per-container supplementary groups). Each is the image's
/// own value, so the container runs as it would have; the policy now pins it.
fn set_identity(
    spec: &mut Value,
    name: &str,
    uid: u32,
    gid: u32,
    groups: &BTreeSet<u32>,
) -> Result<(), String> {
    let before = spec.clone();
    let container = containers_mut(spec.as_object_mut().ok_or("pod spec is not an object")?)
        .find(|c| c.get("name").and_then(Value::as_str) == Some(name))
        .and_then(Value::as_object_mut)
        .ok_or_else(|| format!("genpolicy named a container {name} the pod does not have"))?;
    let context = container
        .entry("securityContext")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or("securityContext is not an object")?;
    if uid != 0 {
        context.insert("runAsUser".into(), json!(uid));
    }
    if gid != 0 {
        context.insert("runAsGroup".into(), json!(gid));
    }
    let pod = spec
        .as_object_mut()
        .ok_or("pod spec is not an object")?
        .entry("securityContext")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or("securityContext is not an object")?;
    let mut supplemental: BTreeSet<u32> = pod
        .get("supplementalGroups")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|g| g.as_u64().and_then(|g| u32::try_from(g).ok()))
        .collect();
    supplemental.extend(groups.iter().filter(|g| **g != gid));
    if !supplemental.is_empty() {
        pod.insert("supplementalGroups".into(), json!(supplemental));
    }
    if *spec == before {
        return Err(format!(
            "services.{name}: the user its image runs as could not be pinned; set `user: <uid>:<gid>`"
        ));
    }
    Ok(())
}

/// The one resource genpolicy reads: a Deployment named as the adapter names it, whose pod is
/// `spec` without the fields genpolicy 4.1.0 does not take (`automountServiceAccountToken`,
/// `enableServiceLinks` and a claim's `readOnly`; the settings admit neither a token mount nor
/// service-link variables, and the pod spec itself still mounts no token) and without the KMS endpoints variable, which the policy
/// admits by pattern instead.
pub fn genpolicy_input(app_id: AppId, spec: &Value) -> Result<String, String> {
    let mut pod = spec.clone();
    let fields = pod.as_object_mut().ok_or("pod spec is not an object")?;
    fields.remove("automountServiceAccountToken");
    fields.remove("enableServiceLinks");
    for volume in fields
        .get_mut("volumes")
        .and_then(Value::as_array_mut)
        .into_iter()
        .flatten()
    {
        if let Some(claim) = volume
            .get_mut("persistentVolumeClaim")
            .and_then(Value::as_object_mut)
        {
            claim.remove("readOnly");
        }
    }
    for container in containers_mut(fields) {
        if let Some(env) = container.get_mut("env").and_then(Value::as_array_mut) {
            env.retain(|e| e.get("name").and_then(Value::as_str) != Some(KMS_ENDPOINTS_ENV));
        }
    }
    let name = workload_name(app_id);
    let deployment = json!({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": { "name": name, "namespace": name },
        "spec": {
            "replicas": 1,
            "selector": { "matchLabels": { "alphacompute.ai/app": app_id } },
            "template": {
                "metadata": {
                    "labels": { "alphacompute.ai/app": app_id },
                    "annotations": { INITDATA_ANNOTATION: "" },
                },
                "spec": pod,
            },
        },
    });
    serde_yaml_ng::to_string(&deployment).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::fs;
    use std::path::PathBuf;

    use serde::Deserialize;
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::deploy::wrap::parse;

    fn dir(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../testdata")
            .join(name)
    }

    /// The runtime pins of `testdata/manifest/05-deploy`, with a public image standing in for
    /// `alpha-runtime` so genpolicy can read it when the vectors are recorded.
    fn runtime() -> Runtime {
        let spec = crate::deploy::parse(
            &fs::read_to_string(dir("manifest/05-deploy").join("app.yaml")).unwrap(),
        )
        .unwrap();
        Runtime {
            image: "alpine@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8"
                .into(),
            ..spec.runtime
        }
    }

    /// A public image standing in for `alpha-volume`, as alpine does for the runtime.
    const VOLUME_IMAGE: &str =
        "busybox@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e";

    /// The platform document's `alpha_volume_images`, listing the stand-in.
    fn listed() -> BTreeSet<String> {
        BTreeSet::from([VOLUME_IMAGE.to_owned()])
    }

    fn app_id() -> AppId {
        "01994b3e-5c8a-7d3e-9a1b-2c3d4e5f6a7b".parse().unwrap()
    }

    #[derive(Clone, Debug, Default, Deserialize, Serialize)]
    struct Run {
        input_sha256: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        identity: Option<(String, u32, u32, BTreeSet<u32>)>,
    }

    /// genpolicy as one vector recorded it (`genpolicy-runs.json`, `policy.rego`), or, under
    /// `WRITE_VECTORS=1` with `ALPHA_TEST_GENPOLICY` naming genpolicy 4.1.0, the binary itself,
    /// recorded.
    struct Recorded {
        dir: PathBuf,
        live: Option<policy::Genpolicy>,
        runs: RefCell<Vec<Run>>,
    }

    impl Recorded {
        fn new(dir: PathBuf) -> Self {
            let live = std::env::var_os("WRITE_VECTORS")
                .and(std::env::var_os("ALPHA_TEST_GENPOLICY"))
                .map(|path| policy::Genpolicy {
                    path: path.into(),
                    defaults: None,
                    ..policy::Genpolicy::pinned()
                });
            match live {
                Some(live) => Self {
                    dir,
                    live: Some(live),
                    runs: RefCell::new(Vec::new()),
                },
                None => Self::replay(dir),
            }
        }

        fn replay(dir: PathBuf) -> Self {
            let runs = serde_json::from_str(
                &fs::read_to_string(dir.join("genpolicy-runs.json")).unwrap_or_default(),
            )
            .unwrap_or_default();
            Self {
                dir,
                live: None,
                runs: RefCell::new(runs),
            }
        }

        fn save(&self) {
            if self.live.is_some() {
                let runs = serde_json::to_string_pretty(&*self.runs.borrow()).unwrap();
                fs::write(self.dir.join("genpolicy-runs.json"), runs + "\n").unwrap();
            }
        }
    }

    impl PolicySource for Recorded {
        async fn generate(&self, yaml: &str) -> Result<String, GenpolicyError> {
            let input_sha256 = hex::encode(Sha256::digest(yaml));
            let Some(live) = &self.live else {
                let runs = self.runs.borrow();
                let run = runs
                    .iter()
                    .find(|r| r.input_sha256 == input_sha256)
                    .unwrap_or_else(|| {
                        panic!(
                            "{}: genpolicy's input changed; record the vector again with WRITE_VECTORS=1 ALPHA_TEST_GENPOLICY=<genpolicy 4.1.0>",
                            self.dir.display()
                        )
                    });
                return match &run.identity {
                    Some((container, uid, gid, groups)) => Err(GenpolicyError::Identity {
                        container: container.clone(),
                        uid: *uid,
                        gid: *gid,
                        groups: groups.clone(),
                    }),
                    None => Ok(fs::read_to_string(self.dir.join("policy.rego")).unwrap()),
                };
            };
            let result = live.run(yaml).await;
            let identity = match &result {
                Ok(policy) => {
                    fs::write(self.dir.join("policy.rego"), policy).unwrap();
                    fs::write(self.dir.join("genpolicy-input.yaml"), yaml).unwrap();
                    None
                }
                Err(GenpolicyError::Identity {
                    container,
                    uid,
                    gid,
                    groups,
                }) => Some((container.clone(), *uid, *gid, groups.clone())),
                Err(GenpolicyError::Failed(m) | GenpolicyError::Image(m)) => {
                    panic!("genpolicy: {m}")
                }
            };
            self.runs.borrow_mut().push(Run {
                input_sha256,
                identity,
            });
            result
        }
    }

    async fn wrap_vector(name: &str) -> (Wrapped, Shape) {
        let out = dir("coco/wrap").join(name);
        let compose = fs::read(out.join("compose.yaml")).unwrap();
        let shape = Shape::parse(&fs::read(out.join("shape.json")).unwrap()).unwrap();
        let source = Recorded::new(out.clone());
        let persistent = Persistent {
            volumes: persistent_volumes(&compose).unwrap(),
            image: Some(VOLUME_IMAGE.into()),
            listed: listed(),
        };
        let wrapped = wrap(
            parse(&compose).unwrap(),
            &BTreeMap::new(),
            app_id(),
            &runtime(),
            &shape,
            &persistent,
            &source,
        )
        .await
        .unwrap();
        source.save();
        let text = serde_json::to_string_pretty(&wrapped).unwrap() + "\n";
        if std::env::var_os("WRITE_VECTORS").is_some() {
            fs::write(out.join("output.json"), &text).unwrap();
        } else {
            assert_eq!(text, fs::read_to_string(out.join("output.json")).unwrap());
            assert_eq!(
                genpolicy_input(app_id(), &wrapped.pod_spec).unwrap(),
                fs::read_to_string(out.join("genpolicy-input.yaml")).unwrap()
            );
        }
        (wrapped, shape)
    }

    /// rafay-plugins' `checkCocoWrapped` and `checkPodSpec`, as far as they read the output.
    fn check_contract(w: &Wrapped, shape: &Shape) {
        let initdata = BASE64_STANDARD.decode(&w.initdata).unwrap();
        assert!(!initdata.contains(&b'\r'));
        let init = InitData::parse(&initdata).unwrap();
        let revision = init.revision().unwrap();
        assert_eq!(revision.canonical().unwrap(), w.revision);
        assert_eq!(
            w.revision_hash,
            alpha_core::compose_hash(&w.revision),
            "revision_hash"
        );
        assert_eq!(revision.app_id, app_id());
        assert!(!init.policy().unwrap().is_empty());
        let alpha: Value = serde_json::from_str(&init.data["alpha.json"]).unwrap();
        assert_eq!(alpha["app_id"], json!(app_id().to_string()));

        let spec = &w.pod_spec;
        assert_eq!(spec["runtimeClassName"], json!(shape.runtime_class));
        assert_eq!(spec["automountServiceAccountToken"], json!(false));
        for key in [
            "nodeName",
            "hostNetwork",
            "hostPID",
            "hostIPC",
            "ephemeralContainers",
        ] {
            assert!(spec.get(key).is_none(), "{key}");
        }
        let (mut milli, mut bytes, mut gpus) = (0u64, 0u64, 0u64);
        for (kind, list) in [
            ("init", &spec["initContainers"]),
            ("regular", &spec["containers"]),
        ] {
            for c in list.as_array().unwrap() {
                assert!(pinned_reference(c["image"].as_str().unwrap()), "{c}");
                let limits = &c["resources"]["limits"];
                assert_eq!(c["resources"]["requests"], *limits);
                if kind == "init" {
                    assert!(
                        limits.is_null(),
                        "the sidecar adds nothing to the TD's size"
                    );
                    continue;
                }
                let cpu = limits["cpu"].as_str().unwrap();
                milli += match cpu.strip_suffix('m') {
                    Some(m) => m.parse::<u64>().unwrap(),
                    None => cpu.parse::<u64>().unwrap() * 1000,
                };
                bytes += limits["memory"]
                    .as_str()
                    .unwrap()
                    .strip_suffix("Mi")
                    .unwrap()
                    .parse::<u64>()
                    .unwrap()
                    << 20;
                if let Some(n) = limits.get(GPU_RESOURCE) {
                    gpus += n.as_str().unwrap().parse::<u64>().unwrap();
                }
            }
        }
        assert_eq!(milli, u64::from(shape.cpu) * 1000);
        assert_eq!(bytes, shape.memory_mib << 20);
        assert_eq!(gpus, u64::from(shape.gpus()));

        // The runtime reads the init-data where PRD-02's evidence source looks for it.
        let runtime = &spec["initContainers"][0];
        assert_eq!(runtime["name"], json!(RUNTIME_SERVICE));
        assert_eq!(runtime["restartPolicy"], json!("Always"));
        let pod_mount = runtime["volumeMounts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["name"] == json!(POD_VOLUME))
            .unwrap();
        assert_eq!(
            format!("{}/cc_init_data", pod_mount["mountPath"].as_str().unwrap()),
            alpha_tsm::coco::INITDATA_PATH
        );
        let volume = spec["volumes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["name"] == json!(POD_VOLUME))
            .unwrap();
        assert_eq!(
            volume["downwardAPI"]["items"][0]["fieldRef"]["fieldPath"],
            json!(format!("metadata.annotations['{INITDATA_ANNOTATION}']"))
        );
        assert!(w.secrets.len() <= MAX_SECRETS);
        for name in &w.secrets {
            assert!(alpha_core::is_key_purpose(name), "{name}");
        }
    }

    fn env(container: &Value) -> BTreeMap<String, Value> {
        container["env"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|e| {
                let value = e.get("value").cloned().unwrap_or(e["valueFrom"].clone());
                (e["name"].as_str().unwrap().to_owned(), value)
            })
            .collect()
    }

    #[tokio::test]
    async fn wrap_reproduces_the_gpu_vector() {
        let (w, shape) = wrap_vector("01-gpu").await;
        check_contract(&w, &shape);
        assert_eq!(w.secrets.iter().collect::<Vec<_>>(), ["api_key"]);
        let spec = &w.pod_spec;
        let containers = spec["containers"].as_array().unwrap();
        let names: Vec<_> = containers
            .iter()
            .map(|c| c["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["web", "worker"]);
        let (web, worker) = (&containers[0], &containers[1]);
        // The published service takes the GPU; the shape is split between the two.
        assert_eq!(
            web["resources"]["limits"],
            json!({ "cpu": "8", "memory": "98304Mi", GPU_RESOURCE: "1" })
        );
        assert_eq!(
            worker["resources"]["limits"],
            json!({ "cpu": "8", "memory": "98304Mi" })
        );
        assert_eq!(env(web)["WORKERS"], json!("4"));
        assert_eq!(
            worker["args"],
            json!(["sh", "-c", "while true; do ls /data; sleep 60; done"])
        );
        assert_eq!(
            worker["volumeMounts"],
            json!([{ "name": "scratch", "mountPath": "/data", "readOnly": true }])
        );
        assert!(web["volumeMounts"].as_array().unwrap().contains(
            &json!({ "name": "alpha-secrets-web", "mountPath": "/run/secrets", "readOnly": true })
        ));
        let runtime = env(&spec["initContainers"][0]);
        assert_eq!(runtime["ALPHACOMPUTE_TLS_UPSTREAM"], json!("127.0.0.1:80"));
        assert_eq!(runtime["ALPHACOMPUTE_QUOTE_SOURCE"], json!("coco-aa"));
        assert_eq!(
            runtime["ALPHACOMPUTE_SECRETS"],
            json!(r#"{"web":["api_key"]}"#)
        );
        assert_eq!(
            runtime["ALPHACOMPUTE_KMS_ENDPOINTS"],
            json!({ "configMapKeyRef": { "name": KMS_CONFIG_MAP, "key": KMS_CONFIG_MAP_KEY } })
        );
        // Every volume of the pod lives in the TD's memory or is the downward API.
        for v in spec["volumes"].as_array().unwrap() {
            assert!(
                v["emptyDir"]["medium"] == json!("Memory") || v.get("downwardAPI").is_some(),
                "{v}"
            );
        }
        // The policy admits exactly these containers, and the KMS endpoints only by pattern.
        let policy = policy::verify(
            &InitData::parse(&BASE64_STANDARD.decode(&w.initdata).unwrap())
                .unwrap()
                .data["policy.rego"],
        )
        .unwrap();
        assert_eq!(policy.containers, containers_of(spec));
        let input = genpolicy_input(app_id(), spec).unwrap();
        assert!(!input.contains("ALPHACOMPUTE_KMS_ENDPOINTS"));
        assert!(!input.contains("automountServiceAccountToken"));
    }

    fn containers_of(spec: &Value) -> BTreeSet<PolicyContainer> {
        containers(spec)
    }

    #[tokio::test]
    async fn wrap_reproduces_the_cpu_vector() {
        let (w, shape) = wrap_vector("02-cpu").await;
        check_contract(&w, &shape);
        assert!(w.secrets.is_empty());
        let app = &w.pod_spec["containers"][0];
        assert_eq!(
            app["resources"]["limits"],
            json!({ "cpu": "4", "memory": "8192Mi" })
        );
        let revision: Value = serde_json::from_str(&w.revision).unwrap();
        assert!(revision.get("gpu").is_none());
        assert!(!env(&w.pod_spec["initContainers"][0]).contains_key("ALPHACOMPUTE_SECRETS"));
    }

    /// Answers every input with the same policy; for refusals that come before or after it.
    struct Fixed(String);

    impl PolicySource for Fixed {
        async fn generate(&self, _: &str) -> Result<String, GenpolicyError> {
            Ok(self.0.clone())
        }
    }

    /// 01-gpu's recorded genpolicy runs, answering the last with `policy` instead.
    struct Replay(PathBuf, String);

    impl PolicySource for Replay {
        async fn generate(&self, yaml: &str) -> Result<String, GenpolicyError> {
            let recorded = Recorded::replay(self.0.clone());
            recorded.generate(yaml).await.map(|_| self.1.clone())
        }
    }

    #[derive(Deserialize)]
    struct Case {
        compose: String,
        refusal: String,
    }

    async fn wrap_with(compose: &[u8], shape: &Shape, source: &impl PolicySource) -> WrapError {
        match parse(compose) {
            Err(e) => WrapError::Refused(e),
            Ok(plain) => wrap(
                plain,
                &BTreeMap::new(),
                app_id(),
                &runtime(),
                shape,
                &Persistent::default(),
                source,
            )
            .await
            .unwrap_err(),
        }
    }

    #[tokio::test]
    async fn wrap_refuses_every_vector() {
        let text = fs::read_to_string(dir("coco/wrap-refusals").join("cases.yaml")).unwrap();
        let cases: BTreeMap<String, Case> = serde_yaml_ng::from_str(&text).unwrap();
        assert_eq!(cases.len(), 10);
        let shape = Shape::parse(&fs::read(dir("coco/wrap/01-gpu/shape.json")).unwrap()).unwrap();
        let source = Fixed(String::new());
        for (name, case) in cases {
            let WrapError::Refused(error) =
                wrap_with(case.compose.as_bytes(), &shape, &source).await
            else {
                panic!("{name}: not a refusal");
            };
            assert!(error.contains(&case.refusal), "{name}: {error}");
            assert!(!error.contains('\n'), "{name}: one line");
        }
    }

    #[tokio::test]
    async fn wrap_fails_rather_than_refuses_when_our_side_is_wrong() {
        let out = dir("coco/wrap/01-gpu");
        let shape = Shape::parse(&fs::read(out.join("shape.json")).unwrap()).unwrap();
        let compose = fs::read(dir("coco/wrap/02-cpu").join("compose.yaml")).unwrap();
        let failed = |e: WrapError| match e {
            WrapError::Failed(m) => m,
            WrapError::Refused(m) => panic!("refused: {m}"),
        };
        // 01's policy admits web, worker and the runtime: not 02's single app.
        let other = Fixed(fs::read_to_string(out.join("policy.rego")).unwrap());
        let error = failed(wrap_with(&compose, &shape, &other).await);
        assert!(error.contains("not the pod's containers"), "{error}");
        // A policy that loosens the baseline.
        let loose = fs::read_to_string(out.join("policy.rego"))
            .unwrap()
            .replacen(
                "\"ReadStreamRequest\": false",
                "\"ReadStreamRequest\": true",
                1,
            );
        let error = failed(wrap_with(&compose, &shape, &Fixed(loose)).await);
        assert!(error.contains("ReadStreamRequest"), "{error}");

        struct Answer(GenpolicyError);
        impl PolicySource for Answer {
            async fn generate(&self, _: &str) -> Result<String, GenpolicyError> {
                Err(self.0.clone())
            }
        }
        // A policy that pins a DSM the pod does not declare (PRD-06 I1).
        let dsm = fs::read_to_string(out.join("policy.rego"))
            .unwrap()
            .replacen(
                "\"ALPHACOMPUTE_QUOTE_SOURCE=coco-aa\"",
                "\"ALPHACOMPUTE_QUOTE_SOURCE=coco-aa\", \"ALPHACOMPUTE_DSM={}\"",
                1,
            );
        let compose01 = fs::read(out.join("compose.yaml")).unwrap();
        let error = failed(wrap_with(&compose01, &shape, &Replay(out.clone(), dsm)).await);
        assert!(error.contains("pins 1 ALPHACOMPUTE_DSM"), "{error}");
        // A missing or wrong genpolicy is ours.
        let missing = Answer(GenpolicyError::Failed(
            "genpolicy at /opt/kata/bin: gone".into(),
        ));
        assert!(failed(wrap_with(&compose, &shape, &missing).await).contains("gone"));
        // An image genpolicy cannot read is the customer's, and the line names nothing of ours.
        let private = Answer(GenpolicyError::Image(
            "registry authentication failure".into(),
        ));
        match wrap_with(&compose, &shape, &private).await {
            WrapError::Refused(m) => {
                assert!(!m.contains("genpolicy") && m.contains("public"), "{m}")
            }
            other => panic!("{other:?}"),
        }
        // genpolicy asking for the same identity again does not loop.
        let stubborn = Answer(GenpolicyError::Identity {
            container: "app".into(),
            uid: 0,
            gid: 0,
            groups: [0].into(),
        });
        let error = wrap_with(&compose, &shape, &stubborn).await.to_string();
        assert!(
            error.contains("services.app: the user its image runs as"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn wrap_reproduces_the_volume_vector() {
        let (w, shape) = wrap_vector("03-volume").await;
        let spec = &w.pod_spec;
        let inits = spec["initContainers"].as_array().unwrap();
        let names: Vec<_> = inits.iter().map(|c| c["name"].as_str().unwrap()).collect();
        assert_eq!(names, [RUNTIME_SERVICE, "alpha-volume-pgdata"]);
        let volume = &inits[1];
        assert_eq!(volume["image"], json!(VOLUME_IMAGE));
        assert_eq!(
            volume["args"],
            json!(["open", "pgdata", "/dev/alpha-volume", "/run/alpha-volume"])
        );
        assert_eq!(volume["securityContext"], json!({ "privileged": true }));
        assert!(
            volume["resources"].is_null(),
            "adds nothing to the TD's size"
        );
        assert_eq!(
            spec["containers"][0]["volumeMounts"],
            json!([{ "name": "pgdata", "mountPath": "/var/lib/data", "mountPropagation": "HostToContainer" }])
        );
        assert_eq!(
            w.volume_claims,
            [json!({
                "apiVersion": "v1",
                "kind": "PersistentVolumeClaim",
                "metadata": { "name": "alpha-volume-pgdata" },
                "spec": {
                    "accessModes": ["ReadWriteOnce"],
                    "volumeMode": "Block",
                    "resources": { "requests": { "storage": "20Gi" } },
                },
            })]
        );
        // The policy: the init container privileged with the claim's device, its mount shared
        // back to the guest, the App's slaved to it, and nothing else elevated.
        let initdata = BASE64_STANDARD.decode(&w.initdata).unwrap();
        let text = InitData::parse(&initdata).unwrap().data["policy.rego"].clone();
        let verified = policy::verify_with_volumes(&text, &listed()).unwrap();
        assert!(policy::verify(&text).is_err());
        assert_eq!(
            verified.elevated,
            BTreeSet::from(["alpha-volume-pgdata".to_owned()])
        );
        let containers = verified.data["containers"].as_array().unwrap();
        let mount = |name: &str, dest: &str| {
            containers
                .iter()
                .find(|c| {
                    c["OCI"]["Annotations"]["io.kubernetes.cri.container-name"] == json!(name)
                })
                .unwrap()["OCI"]["Mounts"]
                .as_array()
                .unwrap()
                .iter()
                .find(|m| m["destination"] == json!(dest))
                .unwrap()["options"]
                .clone()
        };
        assert_eq!(
            mount("alpha-volume-pgdata", "/run/alpha-volume"),
            json!(["rbind", "rshared", "rw"])
        );
        assert_eq!(
            mount("db", "/var/lib/data"),
            json!(["rbind", "rslave", "rw"])
        );
        // The adapter's contract has five keys; the claims make a sixth, which an adapter that
        // does not create claims refuses.
        let out: Value = serde_json::to_value(&w).unwrap();
        assert!(out.get("volume_claims").is_some());
        let _ = shape;
    }

    #[tokio::test]
    async fn persistent_volumes_are_refused_without_an_image_or_a_mount() {
        let shape = Shape::parse(&fs::read(dir("coco/wrap/02-cpu/shape.json")).unwrap()).unwrap();
        let compose = fs::read(dir("coco/wrap/03-volume/compose.yaml")).unwrap();
        let volumes = persistent_volumes(&compose).unwrap();
        let refuse = |persistent: Persistent, compose: Vec<u8>| {
            let shape = shape.clone();
            async move {
                wrap(
                    parse(&compose).unwrap(),
                    &BTreeMap::new(),
                    app_id(),
                    &runtime(),
                    &shape,
                    &persistent,
                    &Fixed(String::new()),
                )
                .await
                .unwrap_err()
                .to_string()
            }
        };
        let no_image = Persistent {
            volumes: volumes.clone(),
            image: None,
            listed: listed(),
        };
        assert!(
            refuse(no_image, compose.clone())
                .await
                .contains("not available for this App yet")
        );
        let unmounted = String::from_utf8(compose.clone())
            .unwrap()
            .replace("    volumes:\n      - pgdata:/var/lib/data\n", "");
        let persistent = Persistent {
            volumes,
            image: Some(VOLUME_IMAGE.into()),
            listed: listed(),
        };
        assert!(
            refuse(persistent, unmounted.into_bytes())
                .await
                .contains("no service mounts it")
        );
        for (bad, why) in [
            (
                "x-alphacompute-volumes: {pgdata: {size: 1G}}",
                "at least 1Gi",
            ),
            (
                "x-alphacompute-volumes: {pgdata: {size: 2Gi, ro: true}}",
                "nothing else",
            ),
            (
                "x-alphacompute-volumes: {pg.data: {size: 2Gi}}",
                "persistent volume's name",
            ),
        ] {
            let error = persistent_volumes(bad.as_bytes()).unwrap_err();
            assert!(error.contains(why), "{why}: {error}");
        }
    }

    /// ACC-FD-100: `--volume-image` is not trusted for itself. An image the platform document
    /// does not list is refused before genpolicy runs; and a policy whose `alpha-volume-*`
    /// container runs another image, other args or more mounts than the opener's is refused
    /// after it, though the name is right.
    #[tokio::test]
    async fn wrap_runs_only_a_listed_volume_image_as_the_opener() {
        let out = dir("coco/wrap/03-volume");
        let shape = Shape::parse(&fs::read(out.join("shape.json")).unwrap()).unwrap();
        let compose = fs::read(out.join("compose.yaml")).unwrap();
        let recorded = fs::read_to_string(out.join("policy.rego")).unwrap();
        let attacker = format!(
            "registry.example/attacker/volume@sha256:{}",
            "ab".repeat(32)
        );
        let run = |image: &str, listed: BTreeSet<String>, policy: String| {
            let persistent = Persistent {
                volumes: persistent_volumes(&compose).unwrap(),
                image: Some(image.to_owned()),
                listed,
            };
            let (compose, shape) = (compose.clone(), shape.clone());
            async move {
                wrap(
                    parse(&compose).unwrap(),
                    &BTreeMap::new(),
                    app_id(),
                    &runtime(),
                    &shape,
                    &persistent,
                    &Fixed(policy),
                )
                .await
            }
        };
        let refused = |r: Result<Wrapped, WrapError>, why: &str| {
            let error = r.err().unwrap_or_else(|| panic!("wrapped; expected {why}"));
            assert!(error.to_string().contains(why), "{why}: {error}");
            error
        };
        let e = refused(
            run(&attacker, listed(), String::new()).await,
            "not an alpha-volume image",
        );
        assert!(matches!(e, WrapError::Refused(_)));
        refused(
            run(VOLUME_IMAGE, BTreeSet::new(), String::new()).await,
            "lists no alpha-volume image",
        );
        // The recorded policy with its volume container edited.
        let edited = |edit: &dyn Fn(&mut Value)| {
            use alpha_core::coco::policy::DATA_PREFIX;
            let data = recorded
                .strip_prefix(policy::RULES)
                .and_then(|d| d.strip_prefix(DATA_PREFIX))
                .unwrap();
            let mut data: Value = serde_json::from_str(data).unwrap();
            let container = data["containers"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|c| {
                    c["OCI"]["Annotations"]["io.kubernetes.cri.container-name"]
                        == json!("alpha-volume-pgdata")
                })
                .unwrap();
            edit(container);
            let data = serde_json::to_string_pretty(&data).unwrap();
            format!("{}{DATA_PREFIX}{data}\n", policy::RULES)
        };
        run(VOLUME_IMAGE, listed(), edited(&|_| {})).await.unwrap();
        let swapped = edited(&|c| {
            c["OCI"]["Annotations"]["io.kubernetes.cri.image-name"] = json!(attacker);
        });
        refused(
            run(VOLUME_IMAGE, listed(), swapped).await,
            "not an alpha-volume image",
        );
        let shell = edited(&|c| {
            c["OCI"]["Process"]["Args"] = json!(["sh", "-c", "id", "open", "pgdata"]);
        });
        refused(run(VOLUME_IMAGE, listed(), shell).await, "runs");
        let extra_arg = edited(&|c| {
            c["OCI"]["Process"]["Args"]
                .as_array_mut()
                .unwrap()
                .push(json!("--debug"));
        });
        refused(run(VOLUME_IMAGE, listed(), extra_arg).await, "runs");
        let extra_mount = edited(&|c| {
            c["OCI"]["Mounts"].as_array_mut().unwrap().push(json!({
                "destination": "/host", "source": "/", "type_": "bind",
                "options": ["rbind", "rprivate", "rw"],
            }));
        });
        refused(
            run(VOLUME_IMAGE, listed(), extra_mount).await,
            "mounts / at /host",
        );
    }

    #[test]
    fn shapes_are_held_to_their_class() {
        for good in [
            r#"{"runtime_class":"kata-qemu-nvidia-gpu-tdx","gpu":{"model":"B300","count":8},"cpu":128,"memory_mib":1572864}"#,
            r#"{"runtime_class":"kata-qemu-tdx","cpu":1,"memory_mib":2048}"#,
            r#"{"runtime_class":"kata-qemu-tdx","gpu":null,"cpu":1,"memory_mib":2048}"#,
        ] {
            Shape::parse(good.as_bytes()).unwrap();
        }
        for (bad, why) in [
            (
                r#"{"runtime_class":"kata-qemu-tdx","gpu":{"model":"B300","count":1},"cpu":1,"memory_mib":2048}"#,
                "no gpu",
            ),
            (
                r#"{"runtime_class":"kata-qemu-nvidia-gpu-tdx","cpu":1,"memory_mib":2048}"#,
                "a gpu of 1 or 8",
            ),
            (
                r#"{"runtime_class":"kata-qemu-nvidia-gpu-tdx","gpu":{"model":"B300","count":2},"cpu":1,"memory_mib":2048}"#,
                "a gpu of 1 or 8",
            ),
            (
                r#"{"runtime_class":"runc","cpu":1,"memory_mib":2048}"#,
                "not a confidential runtime class",
            ),
            (
                r#"{"runtime_class":"kata-qemu-tdx","cpu":0,"memory_mib":2048}"#,
                "out of range",
            ),
            (
                r#"{"runtime_class":"kata-qemu-tdx","cpu":1,"memory_mib":2048,"disk":1}"#,
                "unknown field",
            ),
            (
                r#"{"runtime_class":"kata-qemu-tdx","cpu":1,"cpu":2,"memory_mib":2048}"#,
                "duplicate",
            ),
        ] {
            let error = Shape::parse(bad.as_bytes()).unwrap_err();
            assert!(error.contains(why), "{why}: {error}");
        }
    }

    #[test]
    fn split_sums_to_the_shape() {
        let shape = Shape::parse(br#"{"runtime_class":"kata-qemu-tdx","cpu":3,"memory_mib":1000}"#)
            .unwrap();
        assert_eq!(
            split(&shape, 2).unwrap(),
            [
                ("1500m".into(), "500Mi".into()),
                ("1500m".into(), "500Mi".into())
            ]
        );
        assert_eq!(
            split(&shape, 7).unwrap()[0],
            ("432m".to_owned(), "148Mi".to_owned())
        );
        assert!(split(&shape, 31).unwrap_err().contains("do not fit"));
    }

    #[test]
    fn set_identity_pins_the_images_user() {
        let mut spec = json!({ "containers": [{ "name": "app", "image": "x" }] });
        set_identity(&mut spec, "app", 1000, 1000, &[10, 1000].into()).unwrap();
        assert_eq!(
            spec["containers"][0]["securityContext"],
            json!({ "runAsUser": 1000, "runAsGroup": 1000 })
        );
        assert_eq!(spec["securityContext"]["supplementalGroups"], json!([10]));
        assert!(set_identity(&mut spec, "app", 1000, 1000, &[10, 1000].into()).is_err());
        assert!(set_identity(&mut spec, "nope", 1, 1, &[].into()).is_err());
    }
}
