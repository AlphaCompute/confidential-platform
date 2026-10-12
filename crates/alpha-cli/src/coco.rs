//! `alpha coco render`: pod-spec template + agent policy + env files → rendered manifest,
//! init-data TOML, and the Revision v2 that gets registered with the KMS. `alpha coco wrap`
//! ([`wrap`]) builds the same three from a customer's compose and a shape, running genpolicy
//! itself; both hold the agent policy to the PRD-02 baseline ([`policy`]).
//!
//! The pod's only Kata annotation, `io.katacontainers.config.hypervisor.cc_init_data`, holds
//! base64(gzip(init-data)). Kata binds the digest of the raw init-data bytes into the TD's
//! MRCONFIGID at launch, so the Revision v2 is a pure function of the init-data bytes and
//! nothing the host controls can change it after boot.
//!
//! See also: `deploy/coco/render-interim.py` (the Python script this replaces).

pub mod policy;
pub mod volume;
pub mod wrap;

use std::collections::{BTreeSet, HashMap};
use std::io::Write;
use std::path::Path;

use alpha_core::coco::{
    ALPHA_ENTRY_FORMAT, AlphaEntry, CocoRevision, GPU_COUNTS, GpuShape, INITDATA_VERSION,
    RUNTIME_CLASSES,
};
use alpha_core::{AppId, ComposeHash, jcs};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use flate2::Compression;
use flate2::write::GzEncoder;
use serde::Deserialize;

/// Variables the renderer computes; env files must not set them.
const COMPUTED: &[&str] = &["CC_INIT_DATA"];

/// Characters that break YAML or shell when substituted into a pod spec.
const FORBIDDEN: &[char] = &['"', '\'', '`', '\\', '$', '\n', '\r'];

#[derive(Debug)]
pub struct RenderOutput {
    pub manifest: String,
    pub revision: CocoRevision,
    pub revision_canonical: String,
    pub revision_hash: ComposeHash,
}

/// Reads `KEY=VALUE` files (# comments; blank lines ignored); rejects duplicates and computed names.
pub fn read_env_files(paths: &[&Path]) -> Result<HashMap<String, String>, String> {
    let mut out: HashMap<String, String> = HashMap::new();
    for path in paths {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        for (idx, raw) in text.lines().enumerate() {
            let line = raw.trim_end_matches('\n');
            if line.trim().is_empty() || line.trim_start().starts_with('#') {
                continue;
            }
            let line_no = idx.saturating_add(1);
            let (name, value) = line
                .split_once('=')
                .ok_or_else(|| format!("{}:{line_no}: not NAME=value", path.display()))?;
            if !is_var_name(name) {
                return Err(format!(
                    "{}:{line_no}: {name:?} is not a valid NAME ([A-Z][A-Z0-9_]*)",
                    path.display(),
                ));
            }
            if COMPUTED.contains(&name) {
                return Err(format!(
                    "{}: {name} is computed by the renderer, not set in env files",
                    path.display()
                ));
            }
            if out.contains_key(name) {
                return Err(format!(
                    "{}:{line_no}: {name} is already set (from an earlier file)",
                    path.display(),
                ));
            }
            out.insert(name.to_owned(), value.to_owned());
        }
    }
    Ok(out)
}

fn is_var_name(s: &str) -> bool {
    let b = s.as_bytes();
    matches!(b.first(), Some(c) if c.is_ascii_uppercase())
        && b.iter()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == b'_')
}

/// Substitutes all `${VAR}` occurrences in `template`, collecting every missing name before
/// returning an error. Values that still contain `<` or `>` (placeholder markers) or forbidden
/// characters are also refused.
pub fn substitute(template: &str, env: &HashMap<String, String>) -> Result<String, String> {
    let mut out = String::with_capacity(template.len());
    let mut missing: Vec<String> = Vec::new();
    let mut rest = template;
    loop {
        let Some(dollar) = rest.find("${") else {
            out.push_str(rest);
            break;
        };
        out.push_str(&rest[..dollar]);
        // rest[dollar..] starts with "${"; advance past those two bytes.
        let after = rest.get(dollar.saturating_add(2)..).unwrap_or_default();
        let close = after
            .find('}')
            .ok_or_else(|| "unclosed '${' in template".to_owned())?;
        let name = &after[..close];
        if !is_var_name(name) {
            return Err(format!("template: invalid variable reference ${{{name}}}"));
        }
        match env.get(name) {
            Some(v) => {
                if v.contains('<') || v.contains('>') {
                    return Err(format!("{name} still holds a placeholder: {v}"));
                }
                if v.chars().any(|c| FORBIDDEN.contains(&c)) {
                    return Err(format!(
                        "{name} contains a character that would break YAML or the shell"
                    ));
                }
                out.push_str(v);
            }
            None => {
                let s = name.to_owned();
                if !missing.contains(&s) {
                    missing.push(s);
                }
            }
        }
        rest = after.get(close.saturating_add(1)..).unwrap_or_default();
    }
    if !missing.is_empty() {
        missing.sort();
        return Err(format!("not set: {}", missing.join(", ")));
    }
    Ok(out)
}

/// Extracts the single `runtimeClassName` and the total `nvidia.com/pgpu` count from the rendered
/// YAML text. Refuses specs that name `nvidia.com/gpu` (the non-passthrough resource), or that
/// sum to a GPU count other than 1 or 8.
fn extract_shape(rendered: &str) -> Result<(String, u32), String> {
    let classes: Vec<&str> = rendered
        .lines()
        .filter_map(|l| {
            l.trim_start()
                .strip_prefix("runtimeClassName:")
                .map(|v| v.split('#').next().unwrap_or("").trim())
        })
        .filter(|v| !v.is_empty())
        .collect();

    let runtime_class = match classes.as_slice() {
        [only] => only.to_string(),
        _ => {
            return Err(format!(
                "spec must name exactly one runtimeClassName; found {}: {:?}",
                classes.len(),
                classes,
            ));
        }
    };

    if rendered
        .lines()
        .any(|l| l.trim_start().starts_with("nvidia.com/gpu:"))
    {
        return Err("use nvidia.com/pgpu (whole GPU passthrough), not nvidia.com/gpu".into());
    }

    let gpus: u32 = rendered
        .lines()
        .filter_map(|l| {
            l.trim_start()
                .strip_prefix("nvidia.com/pgpu:")
                .and_then(|v| v.split_whitespace().next())
                .and_then(|n| n.parse::<u32>().ok())
        })
        .fold(0u32, |a, n| a.saturating_add(n));

    if gpus > 0 && !GPU_COUNTS.contains(&gpus) {
        return Err(format!(
            "{gpus} total nvidia.com/pgpu: a pod must request 1 or 8"
        ));
    }
    if !RUNTIME_CLASSES.contains(&runtime_class.as_str()) {
        return Err(format!(
            "runtimeClassName {runtime_class:?} is not a supported CoCo runtime class"
        ));
    }

    Ok((runtime_class, gpus))
}

/// Every container (and init container) in the pod templates of a rendered manifest, which may
/// hold several YAML documents (a Deployment, its Service, ...).
fn manifest_containers(rendered: &str) -> Result<Vec<serde_yaml_ng::Value>, String> {
    fn walk(value: &serde_yaml_ng::Value, out: &mut Vec<serde_yaml_ng::Value>) {
        let serde_yaml_ng::Value::Mapping(map) = value else {
            if let serde_yaml_ng::Value::Sequence(items) = value {
                items.iter().for_each(|v| walk(v, out));
            }
            return;
        };
        for (k, v) in map {
            if matches!(k.as_str(), Some("containers" | "initContainers"))
                && let Some(items) = v.as_sequence()
            {
                out.extend(items.iter().cloned());
            }
            walk(v, out);
        }
    }
    let mut out = Vec::new();
    for document in serde_yaml_ng::Deserializer::from_str(rendered) {
        let value = serde_yaml_ng::Value::deserialize(document)
            .map_err(|e| format!("spec: not YAML: {e}"))?;
        walk(&value, &mut out);
    }
    Ok(out)
}

/// The name and image of each container, as a policy for them admits them.
pub(crate) fn admitted(containers: &[serde_yaml_ng::Value]) -> BTreeSet<policy::PolicyContainer> {
    containers
        .iter()
        .filter_map(|c| {
            Some(policy::PolicyContainer {
                name: c.get("name")?.as_str()?.to_owned(),
                image: c.get("image")?.as_str()?.to_owned(),
            })
        })
        .collect()
}

/// PRD-06 I1 on a Kata pod: a customer DSM is declared only as a literal `ALPHACOMPUTE_DSM` on
/// the `alpha-runtime` container, so genpolicy pins it, and the policy pins exactly the values
/// the spec declares (none, when it declares none). A declaration through `valueFrom`, through
/// `envFrom` on the runtime, or on another container would be the host's to set, and is refused.
pub(crate) fn check_dsm(
    containers: &[serde_yaml_ng::Value],
    verified: &policy::Verified,
) -> Result<(), String> {
    use serde_yaml_ng::Value as Yaml;
    let env = policy::DSM_ENV;
    let runtime = crate::deploy::RUNTIME_SERVICE;
    let mut declared = BTreeSet::new();
    for c in containers {
        let name = c.get("name").and_then(Yaml::as_str).unwrap_or_default();
        if name == runtime && c.get("envFrom").is_some() {
            return Err(format!(
                "{runtime}: envFrom could set {env} without the policy pinning it; list its variables in env"
            ));
        }
        let entries = c
            .get("env")
            .and_then(Yaml::as_sequence)
            .into_iter()
            .flatten();
        for entry in entries.filter(|e| e.get("name").and_then(Yaml::as_str) == Some(env)) {
            if name != runtime {
                return Err(format!(
                    "{name}: {env} is read only by {runtime}; declare the DSM there"
                ));
            }
            let value = entry
                .get("value")
                .and_then(Yaml::as_str)
                .filter(|_| entry.get("valueFrom").is_none())
                .ok_or_else(|| {
                    format!("{runtime}: {env} must be a literal value, which the agent policy pins")
                })?;
            check_dsm_value(value)?;
            declared.insert(value);
        }
    }
    let pinned = verified.listed(env);
    if pinned != declared {
        return Err(format!(
            "agent policy: pins {} {env} value(s), the spec declares {}; generate the policy from this spec",
            pinned.len(),
            declared.len()
        ));
    }
    Ok(())
}

/// The shape #72's `alpha_dsm::DsmConfig` requires before anything else: a JSON object naming
/// its `binding`, `revision` or `app` (there is no CA-only binding). The runtime parses the rest.
fn check_dsm_value(value: &str) -> Result<(), String> {
    let config = alpha_core::parse(value.as_bytes())
        .map_err(|e| format!("{}: not JSON: {e}", policy::DSM_ENV))?;
    match config.get("binding").and_then(serde_json::Value::as_str) {
        Some("revision" | "app") => Ok(()),
        _ => Err(format!(
            "{}: binding must be \"revision\" or \"app\"",
            policy::DSM_ENV
        )),
    }
}

/// Builds the `alpha.json` init-data entry in JCS (JSON Canonicalization Scheme) form.
pub(crate) fn alpha_json(
    app_id: AppId,
    runtime_class: &str,
    gpu: Option<GpuShape>,
) -> Result<String, String> {
    let entry = AlphaEntry {
        format: ALPHA_ENTRY_FORMAT.to_owned(),
        app_id,
        runtime_class: runtime_class.to_owned(),
        gpu,
    };
    let value = serde_json::to_value(&entry).map_err(|e| e.to_string())?;
    let bytes = jcs(&value).map_err(|e| e.to_string())?;
    String::from_utf8(bytes).map_err(|e| e.to_string())
}

/// Builds the CoCo init-data TOML document as raw bytes (version 0.1.0, algorithm sha384).
/// The document has exactly two entries: `alpha.json` and `policy.rego`.
pub fn build_initdata(policy: &str, alpha: &str) -> Result<Vec<u8>, String> {
    if policy.trim().is_empty() {
        return Err("the agent policy is empty".into());
    }
    // TOML multi-line literal strings cannot contain ''' or end with a lone '.
    if policy.contains("'''") || policy.ends_with('\'') {
        return Err(
            "the agent policy cannot be embedded as a TOML literal string: \
             it contains ''' or ends with '"
                .into(),
        );
    }
    if policy
        .bytes()
        .any(|b| matches!(b, 0x00..=0x08 | 0x0b..=0x1f | 0x7f))
    {
        return Err("the agent policy contains a control character".into());
    }
    // The newline right after the opening ''' is dropped by TOML, so the policy is stored
    // byte for byte. alpha.json is a single-line JCS string with no quotes or newlines.
    let toml = format!(
        "algorithm = \"sha384\"\nversion = \"{INITDATA_VERSION}\"\n\n[data]\n\
         \"alpha.json\" = '''{alpha}'''\n\
         \"policy.rego\" = '''\n{policy}'''\n"
    );
    Ok(toml.into_bytes())
}

/// Encodes init-data bytes as `base64(gzip(bytes))` for the pod's Kata annotation.
pub fn encode_annotation(initdata: &[u8]) -> Result<String, String> {
    let mut gz = GzEncoder::new(Vec::new(), Compression::best());
    gz.write_all(initdata).map_err(|e| e.to_string())?;
    let compressed = gz.finish().map_err(|e| e.to_string())?;
    Ok(BASE64_STANDARD.encode(compressed))
}

/// Renders `template` with an empty `CC_INIT_DATA` annotation for genpolicy input.
/// The output is what genpolicy reads to generate the agent policy; admission will refuse it as is.
pub fn render_for_genpolicy(
    template: &str,
    env: &HashMap<String, String>,
) -> Result<String, String> {
    render_volumes_for_genpolicy(template, env, &Volumes::default())
}

/// As [`render_for_genpolicy`], with encrypted persistent volumes added to the pod.
pub fn render_volumes_for_genpolicy(
    template: &str,
    env: &HashMap<String, String>,
    volumes: &Volumes,
) -> Result<String, String> {
    let mut values = env.clone();
    values.insert("CC_INIT_DATA".to_owned(), String::new());
    volumes.inject(&substitute(template, &values)?)
}

/// Encrypted persistent volumes `render` adds to the spec's one pod (PRD-02 deliverable 25):
/// per volume, the block-mode claim as a document of its own, the `alpha-volume` init container
/// after the template's, the pod's volumes, and the mount in the container that uses it.
#[derive(Clone, Debug, Default)]
pub struct Volumes {
    pub image: Option<String>,
    pub volumes: Vec<RenderVolume>,
}

#[derive(Clone, Debug)]
pub struct RenderVolume {
    pub name: String,
    pub size: String,
    pub container: String,
    pub path: String,
}

impl RenderVolume {
    /// `<name>:<size>:<container>:<mount path>`.
    pub fn parse(flag: &str) -> Result<Self, String> {
        let parts: Vec<&str> = flag.splitn(4, ':').collect();
        let [name, size, container, path] = parts.as_slice() else {
            return Err(format!(
                "--volume {flag}: write <name>:<size>:<container>:<mount path>"
            ));
        };
        volume::check_name(name, "--volume")?;
        volume::check_size(size)?;
        if !path.starts_with('/') {
            return Err(format!("--volume {flag}: the mount path is absolute"));
        }
        Ok(Self {
            name: (*name).to_owned(),
            size: (*size).to_owned(),
            container: (*container).to_owned(),
            path: (*path).to_owned(),
        })
    }
}

impl Volumes {
    fn names(&self) -> BTreeSet<String> {
        self.volumes.iter().map(|v| v.name.clone()).collect()
    }

    /// The rendered manifest with the volumes added; unchanged, comments and all, without any.
    fn inject(&self, rendered: &str) -> Result<String, String> {
        use serde_yaml_ng::Value as Yaml;
        if self.volumes.is_empty() {
            return Ok(rendered.to_owned());
        }
        let image = self
            .image
            .as_deref()
            .ok_or("--volume needs --volume-image, the alpha-volume image pinned by digest")?;
        if !crate::deploy::wrap::pinned_reference(image) {
            return Err(format!("--volume-image {image:?} is not pinned by digest"));
        }
        let to_yaml = |v: serde_json::Value| serde_yaml_ng::to_value(v).map_err(|e| e.to_string());
        let mut docs = Vec::new();
        for document in serde_yaml_ng::Deserializer::from_str(rendered) {
            docs.push(Yaml::deserialize(document).map_err(|e| format!("spec: not YAML: {e}"))?);
        }
        let mut pods: Vec<&mut serde_yaml_ng::Mapping> = Vec::new();
        for doc in &mut docs {
            pod_specs(doc, &mut pods);
        }
        let [pod] = pods.as_mut_slice() else {
            return Err(format!(
                "--volume: the spec has {} pod templates; volumes go into a spec with one",
                pods.len()
            ));
        };
        let socket = crate::coco::wrap::SOCKET_VOLUME;
        for v in &self.volumes {
            let volumes = sequence(pod, "volumes")?;
            if volumes
                .iter()
                .any(|x| x.get("name").and_then(Yaml::as_str) == Some(&v.name))
            {
                return Err(format!(
                    "--volume {}: the spec already has a volume of that name",
                    v.name
                ));
            }
            for item in volume::pod_volumes(&v.name) {
                volumes.push(to_yaml(item)?);
            }
            sequence(pod, "initContainers")?
                .push(to_yaml(volume::init_container(&v.name, image, socket))?);
            let container = sequence(pod, "containers")?
                .iter_mut()
                .find(|c| c.get("name").and_then(Yaml::as_str) == Some(&v.container))
                .and_then(Yaml::as_mapping_mut)
                .ok_or_else(|| {
                    format!(
                        "--volume {}: the spec has no container {}",
                        v.name, v.container
                    )
                })?;
            sequence(container, "volumeMounts")?.push(to_yaml(serde_json::json!({
                "name": v.name, "mountPath": v.path, "mountPropagation": volume::APP_PROPAGATION,
            }))?);
        }
        let mut out = String::new();
        let claims = self
            .volumes
            .iter()
            .map(|v| to_yaml(volume::claim(&v.name, &v.size)));
        for doc in docs.into_iter().map(Ok).chain(claims) {
            out.push_str("---\n");
            out.push_str(&serde_yaml_ng::to_string(&doc?).map_err(|e| e.to_string())?);
        }
        Ok(out)
    }
}

/// The sequence under `key` in `map`, made empty if it is absent.
fn sequence<'a>(
    map: &'a mut serde_yaml_ng::Mapping,
    key: &str,
) -> Result<&'a mut Vec<serde_yaml_ng::Value>, String> {
    use serde_yaml_ng::Value as Yaml;
    if map.get(key).is_none_or(Yaml::is_null) {
        map.insert(key.into(), Yaml::Sequence(Vec::new()));
    }
    map.get_mut(key)
        .and_then(Yaml::as_sequence_mut)
        .ok_or_else(|| format!("spec: {key} is not a list"))
}

/// Every mapping that holds a pod's `containers`.
fn pod_specs<'a>(
    value: &'a mut serde_yaml_ng::Value,
    out: &mut Vec<&'a mut serde_yaml_ng::Mapping>,
) {
    use serde_yaml_ng::Value as Yaml;
    match value {
        Yaml::Mapping(map) => {
            if map.get("containers").is_some_and(Yaml::is_sequence) {
                out.push(map);
            } else {
                map.values_mut().for_each(|v| pod_specs(v, out));
            }
        }
        Yaml::Sequence(items) => items.iter_mut().for_each(|v| pod_specs(v, out)),
        _ => {}
    }
}

/// Full render: init-data from `policy_text` and the env's `APP_ID` / `GPU_MODEL`, then the
/// `CC_INIT_DATA` annotation substituted into `template`.
pub fn render(
    template: &str,
    policy_text: &str,
    env: &HashMap<String, String>,
) -> Result<RenderOutput, String> {
    render_volumes(template, policy_text, env, &Volumes::default())
}

/// As [`render`], with encrypted persistent volumes added to the pod. `policy_text` is
/// genpolicy's output for [`render_volumes_for_genpolicy`]; the init-data carries it with the
/// volumes' mount propagation set ([`volume::propagate`]).
pub fn render_volumes(
    template: &str,
    policy_text: &str,
    env: &HashMap<String, String>,
    volumes: &Volumes,
) -> Result<RenderOutput, String> {
    let for_shape = render_volumes_for_genpolicy(template, env, volumes)?;
    let (runtime_class, gpu_count) = extract_shape(&for_shape)?;
    let policy_text = &volume::propagate(&policy::pin_hostname(policy_text), &volumes.names())?;
    let verified = policy::verify(policy_text)?;
    let containers = manifest_containers(&for_shape)?;
    let running = admitted(&containers);
    if verified.containers != running {
        return Err(format!(
            "agent policy: admits {:?}, but the spec runs {:?}; run genpolicy on this spec's --for-genpolicy rendering",
            verified.containers, running
        ));
    }
    check_dsm(&containers, &verified)?;
    let volume_containers = running
        .iter()
        .filter(|c| {
            c.name
                .starts_with(alpha_core::coco::policy::VOLUME_CONTAINER_PREFIX)
        })
        .cloned()
        .collect();
    volume::check_elevated(&verified, &volume_containers)?;

    let app_id_str = env
        .get("APP_ID")
        .ok_or("APP_ID must be set in an env file")?;
    let app_id: AppId = app_id_str
        .parse()
        .map_err(|_| format!("APP_ID {app_id_str:?} is not a valid App id"))?;

    let gpu_shape = if gpu_count > 0 {
        let model = env
            .get("GPU_MODEL")
            .ok_or("GPU_MODEL must be set when the spec requests nvidia.com/pgpu")?;
        Some(GpuShape {
            count: gpu_count,
            model: model.clone(),
        })
    } else {
        None
    };

    let alpha = alpha_json(app_id, &runtime_class, gpu_shape)?;
    let initdata_bytes = build_initdata(policy_text, &alpha)?;
    let annotation = encode_annotation(&initdata_bytes)?;

    let mut values = env.clone();
    values.insert("CC_INIT_DATA".to_owned(), annotation);
    let manifest = volumes.inject(&substitute(template, &values)?)?;

    let initdata = alpha_core::coco::InitData::parse(&initdata_bytes).map_err(|e| e.to_string())?;
    let revision = initdata.revision().map_err(|e| e.to_string())?;
    let revision_canonical = revision.canonical().map_err(|e| e.to_string())?;
    let revision_hash = revision.hash().map_err(|e| e.to_string())?;

    Ok(RenderOutput {
        manifest,
        revision,
        revision_canonical,
        revision_hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const APP: &str = "01994b3e-5c8a-7d3e-9a1b-2c3d4e5f6a7b";

    fn base_env() -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert("APP_ID".into(), APP.into());
        m.insert("GPU_MODEL".into(), "B300".into());
        m.insert("RUNTIME_IMAGE".into(), RUNTIME.into());
        m
    }

    const RUNTIME: &str = "ghcr.io/alphacompute/alpha-runtime@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    const MINIMAL_SPEC: &str = "\
spec:
  runtimeClassName: kata-qemu-nvidia-gpu-tdx
  containers:
    - name: app
      image: ${RUNTIME_IMAGE}
      resources:
        limits:
          nvidia.com/pgpu: 1
  annotations:
    io.katacontainers.config.hypervisor.cc_init_data: \"${CC_INIT_DATA}\"
";

    const MINIMAL_POLICY: &str = "package agent_policy\ndefault ExecProcessRequest := false\n";

    fn baseline_policy() -> String {
        policy::test_policy(&[("app", RUNTIME)])
    }

    #[test]
    fn read_env_parses_key_value_and_rejects_duplicates() {
        let dir = std::env::temp_dir();
        let a = dir.join("a.env");
        let b = dir.join("b.env");
        std::fs::write(&a, "FOO=bar\n# comment\nBAR=baz=extra\n").unwrap();
        std::fs::write(&b, "QUX=1\n").unwrap();
        let env = read_env_files(&[a.as_path(), b.as_path()]).unwrap();
        assert_eq!(env["FOO"], "bar");
        assert_eq!(env["BAR"], "baz=extra");
        assert_eq!(env["QUX"], "1");

        std::fs::write(&b, "FOO=other\n").unwrap();
        assert!(read_env_files(&[a.as_path(), b.as_path()]).is_err());

        let cc = dir.join("cc.env");
        std::fs::write(&cc, "CC_INIT_DATA=x\n").unwrap();
        assert!(read_env_files(&[cc.as_path()]).is_err());
    }

    #[test]
    fn substitute_fills_vars_and_rejects_missing_and_forbidden() {
        let mut env = HashMap::new();
        env.insert("FOO".into(), "hello".into());
        env.insert("BAR".into(), "world".into());
        assert_eq!(substitute("${FOO} ${BAR}", &env).unwrap(), "hello world");

        let err = substitute("${FOO} ${MISSING}", &env).unwrap_err();
        assert!(err.contains("MISSING"), "{err}");

        env.insert("BAD".into(), "a\"b".into());
        let err = substitute("${BAD}", &env).unwrap_err();
        assert!(err.contains("BAD"), "{err}");

        env.insert("PLACEHOLDER".into(), "<fill me>".into());
        let err = substitute("${PLACEHOLDER}", &env).unwrap_err();
        assert!(err.contains("placeholder"), "{err}");
    }

    #[test]
    fn extract_shape_reads_runtime_class_and_gpu_count() {
        let (class, gpus) = extract_shape(MINIMAL_SPEC).unwrap();
        assert_eq!(class, "kata-qemu-nvidia-gpu-tdx");
        assert_eq!(gpus, 1);

        let eight = MINIMAL_SPEC.replace("nvidia.com/pgpu: 1", "nvidia.com/pgpu: 8");
        assert_eq!(extract_shape(&eight).unwrap().1, 8);

        let none = MINIMAL_SPEC.replace("nvidia.com/pgpu: 1", "");
        assert_eq!(extract_shape(&none).unwrap().1, 0);

        let bad = MINIMAL_SPEC.replace("nvidia.com/pgpu: 1", "nvidia.com/pgpu: 2");
        assert!(extract_shape(&bad).is_err());

        let wrong_gpu = MINIMAL_SPEC.replace("nvidia.com/pgpu: 1", "nvidia.com/gpu: 1");
        assert!(extract_shape(&wrong_gpu).is_err());
    }

    #[test]
    fn build_initdata_produces_parseable_toml() {
        let alpha = alpha_json(APP.parse().unwrap(), "kata-qemu-tdx", None).unwrap();
        let bytes = build_initdata(MINIMAL_POLICY, &alpha).unwrap();
        let parsed = alpha_core::coco::InitData::parse(&bytes).unwrap();
        let revision = parsed.revision().unwrap();
        assert_eq!(revision.app_id.to_string(), APP);
        assert!(revision.gpu.is_none());

        assert!(build_initdata("", &alpha).is_err());
        assert!(build_initdata("x'''y", &alpha).is_err());
        assert!(build_initdata("x'", &alpha).is_err());
    }

    #[test]
    fn encode_annotation_round_trips_through_decode() {
        let bytes = b"algorithm = \"sha384\"\nversion = \"0.1.0\"\n";
        let annotation = encode_annotation(bytes).unwrap();
        assert!(!annotation.is_empty());
        // Decode via alpha-tsm's decoder (which the runtime uses).
        let decoded = alpha_core::coco::InitData::parse(
            &alpha_tsm::coco::decode_annotation(&annotation).unwrap(),
        );
        assert!(decoded.is_ok());
    }

    #[test]
    fn render_for_genpolicy_substitutes_empty_annotation() {
        let env = base_env();
        let out = render_for_genpolicy(MINIMAL_SPEC, &env).unwrap();
        assert!(out.contains("cc_init_data: \"\""), "{out}");
        assert!(!out.contains("${CC_INIT_DATA}"));
    }

    #[test]
    fn render_produces_manifest_with_annotation_and_correct_revision() {
        let env = base_env();
        let output = render(MINIMAL_SPEC, &baseline_policy(), &env).unwrap();

        assert!(!output.manifest.contains("${CC_INIT_DATA}"));
        assert!(output.manifest.contains("cc_init_data: \""));

        assert_eq!(output.revision.app_id.to_string(), APP);
        assert_eq!(
            output.revision.gpu,
            Some(GpuShape {
                count: 1,
                model: "B300".into()
            })
        );
        assert_eq!(output.revision.runtime_class, "kata-qemu-nvidia-gpu-tdx");

        let hash = output.revision.hash().unwrap();
        assert_eq!(hash, output.revision_hash);

        let canonical = output.revision.canonical().unwrap();
        assert_eq!(canonical, output.revision_canonical);

        // Rebuild the init-data from the same inputs and verify the revision round-trips.
        let alpha = alpha_json(
            APP.parse().unwrap(),
            "kata-qemu-nvidia-gpu-tdx",
            Some(GpuShape {
                count: 1,
                model: "B300".into(),
            }),
        )
        .unwrap();
        let initdata_bytes = build_initdata(&baseline_policy(), &alpha).unwrap();
        let parsed = alpha_core::coco::InitData::parse(&initdata_bytes).unwrap();
        assert_eq!(parsed.revision().unwrap(), output.revision);
    }

    #[test]
    fn render_refuses_a_policy_without_the_baseline_or_for_other_containers() {
        let env = base_env();
        let error = render(MINIMAL_SPEC, MINIMAL_POLICY, &env).unwrap_err();
        assert!(error.contains("Alpha rules patch"), "{error}");
        let other = policy::test_policy(&[("app", RUNTIME), ("debug", RUNTIME)]);
        let error = render(MINIMAL_SPEC, &other, &env).unwrap_err();
        assert!(error.contains("but the spec runs"), "{error}");
        let loose = baseline_policy().replace(
            "\"ReadStreamRequest\": false",
            "\"ReadStreamRequest\": true",
        );
        let error = render(MINIMAL_SPEC, &loose, &env).unwrap_err();
        assert!(error.contains("ReadStreamRequest"), "{error}");
    }

    #[test]
    fn render_takes_a_dsm_only_as_a_literal_on_the_runtime_that_the_policy_pins() {
        let dsm = r#"{"binding":"revision","endpoint":"https://dsm.example"}"#;
        let entry = format!("{}={dsm}", policy::DSM_ENV);
        let mut env = base_env();
        env.insert("DSM".into(), "unused".into());
        let spec = |container: &str, declaration: &str| {
            MINIMAL_SPEC.replace(
                "    - name: app\n",
                &format!("    - name: {container}\n      env:\n{declaration}"),
            )
        };
        let literal = format!(
            "        - name: {}\n          value: '{dsm}'\n",
            policy::DSM_ENV
        );
        let pinned = policy::test_policy_env(&[("alpha-runtime", RUNTIME, &[entry.as_str()])]);
        let unpinned = policy::test_policy(&[("alpha-runtime", RUNTIME)]);

        render(&spec("alpha-runtime", &literal), &pinned, &env).unwrap();
        // Declared but not pinned, pinned but not declared.
        let error = render(&spec("alpha-runtime", &literal), &unpinned, &env).unwrap_err();
        assert!(error.contains("pins 0"), "{error}");
        let none = spec("alpha-runtime", "        - { name: X, value: y }\n");
        assert!(render(&none, &pinned, &env).unwrap_err().contains("pins 1"));
        // Through valueFrom, on another container, or without a binding.
        let from = format!(
            "        - name: {}\n          valueFrom: {{ configMapKeyRef: {{ name: x, key: y }} }}\n",
            policy::DSM_ENV
        );
        let error = render(&spec("alpha-runtime", &from), &pinned, &env).unwrap_err();
        assert!(error.contains("literal value"), "{error}");
        let other = policy::test_policy_env(&[("app", RUNTIME, &[entry.as_str()])]);
        let error = render(&spec("app", &literal), &other, &env).unwrap_err();
        assert!(error.contains("read only by alpha-runtime"), "{error}");
        let unbound = literal.replace("revision", "ca");
        let error = render(&spec("alpha-runtime", &unbound), &pinned, &env).unwrap_err();
        assert!(error.contains("binding"), "{error}");
    }

    fn vector(name: &str) -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../testdata/coco/render")
            .join(name)
    }

    /// `testdata/coco/render/01-pod`: a template, its values, and the policy genpolicy 4.1.0
    /// printed under `genpolicy-settings` for its `--for-genpolicy` rendering. Under
    /// `WRITE_VECTORS=1` with `ALPHA_TEST_GENPOLICY` naming genpolicy 4.1.0, the policy is
    /// generated again.
    fn vector_volumes(name: &str) -> Volumes {
        match name {
            "02-volume" => Volumes {
                image: Some(
                    "busybox@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e"
                        .into(),
                ),
                volumes: vec![RenderVolume::parse("pgdata:20Gi:app:/var/lib/data").unwrap()],
            },
            _ => Volumes::default(),
        }
    }

    /// `testdata/coco/render/<name>`: a template, its values, and the policy genpolicy 4.1.0
    /// printed under `genpolicy-settings` for its `--for-genpolicy` rendering. Under
    /// `WRITE_VECTORS=1` with `ALPHA_TEST_GENPOLICY` naming genpolicy 4.1.0, the policy is
    /// generated again.
    async fn render_vector(name: &str) -> RenderOutput {
        let dir = vector(name);
        let template = std::fs::read_to_string(dir.join("spec.yaml")).unwrap();
        let env = read_env_files(&[dir.join("values.env").as_path()]).unwrap();
        let volumes = vector_volumes(name);
        let write = std::env::var_os("WRITE_VECTORS").is_some();
        if let (true, Some(path)) = (write, std::env::var_os("ALPHA_TEST_GENPOLICY")) {
            let genpolicy = policy::Genpolicy {
                path: path.into(),
                defaults: None,
                ..policy::Genpolicy::pinned()
            };
            let input = render_volumes_for_genpolicy(&template, &env, &volumes).unwrap();
            let text = genpolicy.run(&input).await.unwrap();
            std::fs::write(dir.join("policy.rego"), text).unwrap();
        }
        let policy_text = std::fs::read_to_string(dir.join("policy.rego")).unwrap();
        let out = render_volumes(&template, &policy_text, &env, &volumes).unwrap();
        let expected = format!("{}\n{}\n", out.revision_canonical, out.revision_hash);
        if write {
            std::fs::write(dir.join("manifest.yaml"), &out.manifest).unwrap();
            std::fs::write(dir.join("revision.txt"), &expected).unwrap();
        } else {
            assert_eq!(
                out.manifest,
                std::fs::read_to_string(dir.join("manifest.yaml")).unwrap()
            );
            assert_eq!(
                expected,
                std::fs::read_to_string(dir.join("revision.txt")).unwrap()
            );
        }
        out
    }

    #[tokio::test]
    async fn render_reproduces_the_vector() {
        let out = render_vector("01-pod").await;
        assert_eq!(out.revision.runtime_class, "kata-qemu-tdx");
        assert_eq!(out.revision.gpu, None);
    }

    #[tokio::test]
    async fn render_adds_an_encrypted_volume() {
        let out = render_vector("02-volume").await;
        let docs: Vec<serde_yaml_ng::Value> = serde_yaml_ng::Deserializer::from_str(&out.manifest)
            .map(|d| serde_yaml_ng::Value::deserialize(d).unwrap())
            .collect();
        assert_eq!(docs.len(), 2);
        assert_eq!(
            docs[1]["kind"],
            serde_yaml_ng::Value::from("PersistentVolumeClaim")
        );
        assert_eq!(
            docs[1]["spec"]["volumeMode"],
            serde_yaml_ng::Value::from("Block")
        );
        let pod = &docs[0]["spec"]["template"]["spec"];
        assert_eq!(
            pod["initContainers"][1]["name"],
            serde_yaml_ng::Value::from("alpha-volume-pgdata")
        );
        assert_eq!(
            pod["containers"][0]["volumeMounts"][0]["mountPropagation"],
            serde_yaml_ng::Value::from("HostToContainer")
        );
        // Without --volume the same policy admits a container the spec does not run.
        let dir = vector("02-volume");
        let template = std::fs::read_to_string(dir.join("spec.yaml")).unwrap();
        let env = read_env_files(&[dir.join("values.env").as_path()]).unwrap();
        let policy_text = std::fs::read_to_string(dir.join("policy.rego")).unwrap();
        assert!(render(&template, &policy_text, &env).is_err());
        // A volume init container without the volume's shared mount is refused by the baseline.
        let mut volumes = vector_volumes("02-volume");
        volumes.image = None;
        assert!(
            render_volumes(&template, &policy_text, &env, &volumes)
                .unwrap_err()
                .contains("--volume-image")
        );
    }
}
