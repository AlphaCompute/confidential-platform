//! `alpha coco render`: pod-spec template + agent policy + env files → rendered manifest,
//! init-data TOML, and the Revision v2 that gets registered with the KMS.
//!
//! The pod's only Kata annotation, `io.katacontainers.config.hypervisor.cc_init_data`, holds
//! base64(gzip(init-data)). Kata binds the digest of the raw init-data bytes into the TD's
//! MRCONFIGID at launch, so the Revision v2 is a pure function of the init-data bytes and
//! nothing the host controls can change it after boot.
//!
//! See also: `deploy/coco/render-interim.py` (the Python script this replaces).

use std::collections::HashMap;
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

/// Variables the renderer computes; env files must not set them.
const COMPUTED: &[&str] = &["CC_INIT_DATA"];

/// Characters that break YAML or shell when substituted into a pod spec.
const FORBIDDEN: &[char] = &['"', '\'', '`', '\\', '$', '\n', '\r'];

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

    // Count only GPUs from `limits:` blocks; `requests:` may repeat the same count and must
    // not be double-counted.
    let mut gpus: u32 = 0;
    let mut in_limits = false;
    let mut limits_indent: usize = 0;
    for line in rendered.lines() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() {
            continue;
        }
        let indent = line.len().saturating_sub(trimmed.len());
        // Leave the limits context when we return to the same or a shallower indentation level.
        if in_limits && indent <= limits_indent {
            in_limits = false;
        }
        if trimmed.starts_with("limits:") {
            in_limits = true;
            limits_indent = indent;
        } else if in_limits
            && let Some(n) = trimmed
                .strip_prefix("nvidia.com/pgpu:")
                .and_then(|v| v.split_whitespace().next())
                .and_then(|n| n.parse::<u32>().ok())
        {
            gpus = gpus.saturating_add(n);
        }
    }

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

/// Builds the `alpha.json` init-data entry in JCS (JSON Canonicalization Scheme) form.
fn alpha_json(app_id: AppId, runtime_class: &str, gpu: Option<GpuShape>) -> Result<String, String> {
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
    // TOML multi-line literal strings cannot contain '''.  One or two trailing single quotes
    // before the closing ''' terminator are valid per TOML 1.0, so do not reject them.
    if policy.contains("'''") {
        return Err(
            "the agent policy cannot be embedded as a TOML literal string: \
             it contains '''"
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
    let mut values = env.clone();
    values.insert("CC_INIT_DATA".to_owned(), String::new());
    substitute(template, &values)
}

/// Full render: init-data from `policy_text` and the env's `APP_ID` / `GPU_MODEL`, then the
/// `CC_INIT_DATA` annotation substituted into `template`.
pub fn render(
    template: &str,
    policy_text: &str,
    env: &HashMap<String, String>,
) -> Result<RenderOutput, String> {
    let for_shape = render_for_genpolicy(template, env)?;
    let (runtime_class, gpu_count) = extract_shape(&for_shape)?;

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
    let manifest = substitute(template, &values)?;

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
        m.insert(
            "RUNTIME_IMAGE".into(),
            "ghcr.io/alphacompute/alpha-runtime@sha256:aaaa".into(),
        );
        m
    }

    const MINIMAL_SPEC: &str = "\
spec:
  runtimeClassName: kata-qemu-nvidia-gpu-tdx
  containers:
    - image: ${RUNTIME_IMAGE}
      resources:
        limits:
          nvidia.com/pgpu: 1
  annotations:
    io.katacontainers.config.hypervisor.cc_init_data: \"${CC_INIT_DATA}\"
";

    const MINIMAL_POLICY: &str = "package agent_policy\ndefault ExecProcessRequest := false\n";

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
        let alpha = alpha_json(APP.parse().unwrap(), "kata-qemu-nvidia-gpu-tdx", None).unwrap();
        let bytes = build_initdata(MINIMAL_POLICY, &alpha).unwrap();
        let parsed = alpha_core::coco::InitData::parse(&bytes).unwrap();
        let revision = parsed.revision().unwrap();
        assert_eq!(revision.app_id.to_string(), APP);
        assert!(revision.gpu.is_none());

        assert!(build_initdata("", &alpha).is_err());
        assert!(build_initdata("x'''y", &alpha).is_err());
        // A single trailing quote is valid TOML (one or two quotes before ''' terminator are ok).
        assert!(build_initdata("x'", &alpha).is_ok());
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
        let output = render(MINIMAL_SPEC, MINIMAL_POLICY, &env).unwrap();

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
        let initdata_bytes = build_initdata(MINIMAL_POLICY, &alpha).unwrap();
        let parsed = alpha_core::coco::InitData::parse(&initdata_bytes).unwrap();
        assert_eq!(parsed.revision().unwrap(), output.revision);
    }
}
