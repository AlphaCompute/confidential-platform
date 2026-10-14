//! A tenant's Kata pod spec becomes a Revision: the agent policy genpolicy derives from it, in an
//! init-data TOML whose SHA-256 the shim puts in `MRCONFIGID`, and the pod spec carrying that
//! init-data. genpolicy, its rules and settings are pinned: they decide what the policy allows.

pub mod measure;

use std::fs;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use alpha_core::{AppId, ComposeHash, InitData, has_sha256_digest};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use flate2::Compression;
use flate2::write::GzEncoder;
use serde::Serialize;
use serde_yaml_ng::{Mapping, Value as Yaml};
use sha2::{Digest, Sha256};

const ANNOTATION: &str = "io.katacontainers.config.hypervisor.cc_init_data";

/// `bin/genpolicy` of `kata-tools-static-4.0.0-amd64.tar.zst`, the Kata 4.0.0 release build.
const GENPOLICY_SHA256: &str = "4fa1cabd8d6e757c271caa991b889e1c2ccdbbdce58872b8b581720b3867be36";
/// `rules.rego` and `genpolicy-settings.json` of the same tarball, identical to tag 4.0.0.
const RULES_SHA256: &str = "c3e17ef9f1e8c1accde820774033459580c0fa431056fca2a51283beb9aad1d6";
const SETTINGS_SHA256: &str = "c7d95bc2e45be20643304cb4915a7ab1a3f070c6b270f685b0f0970faf23d5b1";
const PATCHED_RULES_SHA256: &str =
    "bd577f47615b580ec481dc1f5574c55d84f088231851d413897602a36cfc1e50";

/// The upstream rules check neither the image a container pulls, nor that every pinned variable
/// is set, nor HOSTNAME and the sandbox hostname: the host could swap the image, drop or add
/// env, and rename the pod without changing the measurement. They also match a mount's source
/// against an unanchored pattern, and genpolicy writes a disk emptyDir's as `""`, so the host
/// could put a directory it filled at any such destination; anchored, an emptyDir mount must
/// come from a block storage under the sandbox's storage path.
const RULE_EDITS: [(&str, &str); 7] = [
    (
        "    allow_anno(p_container, i_oci)\n",
        "    allow_anno(p_container, i_oci)\n    allow_image(p_oci, i_oci, i_storages)\n",
    ),
    (
        "        allow_var(p_process, i_process, i_var, s_name, s_namespace)\n    }\n",
        "        allow_var(p_process, i_process, i_var, s_name, s_namespace)\n    }\n\n    every p_var in p_process.Env {\n        allow_env_present(p_var, i_process)\n    }\n",
    ),
    (
        r#"    always_allowed := ["$(host-name)", "$(node-name)", "$(pod-uid)"]"#,
        r#"    always_allowed := ["$(node-name)", "$(pod-uid)"]"#,
    ),
    (
        "    i_kata_type == \"pod_sandbox\"\n\n    allow_sandbox_container_name(p_oci, i_oci)\n",
        "    i_kata_type == \"pod_sandbox\"\n\n    print(\"allow_by_container_type 1: Hostname =\", i_oci.Hostname, \"s_name =\", s_name)\n    i_oci.Hostname == s_name\n\n    allow_sandbox_container_name(p_oci, i_oci)\n",
    ),
    (
        "    i_storage.mount_point == i_mount.source\n",
        "    i_storage.mount_point == i_mount.source\n    i_storage.driver in [\"blk\", \"scsi\"]\n    p_mount.source == \"\"\n    startswith(i_mount.source, concat(\"\", [policy_data.common.spath, \"/\"]))\n",
    ),
    (
        "regex4 =\", regex4)\n    regex.match(regex4, i_mount.source)\n\n    print(\"mount_source_allows 1",
        "regex4 =\", regex4)\n    regex.match(concat(\"\", [\"^(?:\", regex4, \")$\"]), i_mount.source)\n\n    print(\"mount_source_allows 1",
    ),
    (
        "regex4 =\", regex4)\n    regex.match(regex4, i_mount.source)\n\n    print(\"mount_source_allows 2",
        "regex4 =\", regex4)\n    regex.match(concat(\"\", [\"^(?:\", regex4, \")$\"]), i_mount.source)\n\n    print(\"mount_source_allows 2",
    ),
];
const RULE_ADDITIONS: &str = include_str!("coco/rules-additions.rego");
const SETTINGS_DROP_INS: [(&str, &str); 2] = [
    ("20-node.json", include_str!("coco/20-node.json")),
    ("50-closed.json", include_str!("coco/50-closed.json")),
];
const POLICY_DATA: &str = "\npolicy_data := ";

/// A pod spec that passed the checks, and the copy genpolicy reads.
pub struct Pod {
    spec: Mapping,
    genpolicy_input: String,
}

/// genpolicy and its settings as the Kata 4.0.0 tools tarball ships them, with our rules.
pub struct Kata {
    genpolicy: Vec<u8>,
    settings: Vec<u8>,
    rules: String,
}

#[derive(Debug, Serialize)]
pub struct Rendered {
    pub revision: ComposeHash,
    pub init_data: String,
    pub annotation: String,
    /// What the KMS pins: the policy's text before `policy_data`, and its data minus
    /// `containers` as JCS.
    pub rules_sha256: String,
    pub policy_data_sha256: String,
    #[serde(skip)]
    pub pod: String,
}

pub fn parse(bytes: &[u8]) -> Result<Pod, String> {
    let Yaml::Mapping(mut spec) =
        serde_yaml_ng::from_slice(bytes).map_err(|e| format!("pod spec: {e}; fix the YAML"))?
    else {
        return Err("pod spec: not a mapping; write one Pod".into());
    };
    let template = template_mut(&mut spec)?;
    if template
        .get("metadata")
        .and_then(|m| m.get("annotations"))
        .and_then(|a| a.get(ANNOTATION))
        .is_some()
    {
        return Err(format!(
            "pod spec: already carries {ANNOTATION}; render the tenant's own spec"
        ));
    }
    let Some(Yaml::Mapping(pod)) = template.get_mut("spec") else {
        return Err("pod spec: no spec mapping".into());
    };
    // The rules accept HOSTNAME only as the sandbox name, which the host chooses.
    if pod.get("hostname").is_some() {
        return Err("spec.hostname: remove it; the pod's hostname is its name".into());
    }
    for list in ["initContainers", "containers"] {
        let containers = match pod.get(list) {
            None => &[][..],
            Some(Yaml::Sequence(containers)) => containers,
            Some(_) => return Err(format!("spec.{list}: not a list")),
        };
        for container in containers {
            if container
                .get("env")
                .and_then(Yaml::as_sequence)
                .into_iter()
                .flatten()
                .any(|e| e.get("name").and_then(Yaml::as_str) == Some("HOSTNAME"))
            {
                return Err(format!(
                    "{list}: HOSTNAME is set by the pod's name; remove it from env"
                ));
            }
            // genpolicy panics on a ConfigMap or Secret reference it is given nothing to resolve
            // from, and writes the rest (fieldRef, resourceFieldRef) as placeholders such as
            // `$(pod-ip)` that our rules never find among the variables the node sends.
            let refers = container.get("envFrom").is_some()
                || container
                    .get("env")
                    .and_then(Yaml::as_sequence)
                    .into_iter()
                    .flatten()
                    .any(|e| e.get("valueFrom").is_some());
            if refers {
                return Err(format!(
                    "{list}: envFrom and env valueFrom are unsupported; write the values into env"
                ));
            }
            let image = container.get("image").and_then(Yaml::as_str).unwrap_or("");
            if !fully_qualified(image) {
                return Err(format!(
                    "{list}: image {image:?} is not <registry>/<repository>@sha256:<64 lowercase hex>; the policy compares the reference the node pulls byte for byte"
                ));
            }
        }
    }
    if pod
        .get("securityContext")
        .and_then(|s| s.get("supplementalGroups"))
        .and_then(Yaml::as_sequence)
        .is_none()
    {
        return Err("spec.securityContext.supplementalGroups: missing; list the groups explicitly, guest pull cannot reproduce the image's".into());
    }
    // genpolicy 4.0.0 refuses both fields; the policy is the same with or without them, and
    // kubelet must see them false, or it mounts the token and links services the policy refuses.
    for field in ["automountServiceAccountToken", "enableServiceLinks"] {
        match pod.remove(field) {
            None | Some(Yaml::Bool(false)) => {}
            Some(_) => return Err(format!("spec.{field}: must be false")),
        }
    }
    let genpolicy_input = serde_yaml_ng::to_string(&spec).map_err(|e| format!("pod spec: {e}"))?;
    if let Some(Yaml::Mapping(pod)) = template_mut(&mut spec)?.get_mut("spec") {
        pod.insert("automountServiceAccountToken".into(), false.into());
        pod.insert("enableServiceLinks".into(), false.into());
    }
    Ok(Pod {
        spec,
        genpolicy_input,
    })
}

/// The mapping holding the pod's `metadata` and `spec`: a Pod itself, or a workload's template,
/// which genpolicy renders the policy for and every pod of the workload is created from.
fn template_mut(spec: &mut Mapping) -> Result<&mut Mapping, String> {
    match spec.get("kind").and_then(Yaml::as_str) {
        Some("Pod") => Ok(spec),
        Some("StatefulSet") => match spec.get_mut("spec").and_then(|s| s.get_mut("template")) {
            Some(Yaml::Mapping(template)) => Ok(template),
            _ => Err("spec.template: missing or not a mapping".into()),
        },
        _ => Err("pod spec: kind is not Pod or StatefulSet".into()),
    }
}

/// A short name, `docker.io/<name>`, `index.docker.io`, a tag beside the digest, or a registry or
/// repository off the lowercase grammar may reach the node rewritten, and the rules compare the
/// pulled reference with the policy's byte for byte.
fn fully_qualified(image: &str) -> bool {
    let Some((name, _)) = image.rsplit_once("@sha256:") else {
        return false;
    };
    let Some((registry, repository)) = name.split_once('/') else {
        return false;
    };
    let (host, port) = registry.split_once(':').unwrap_or((registry, "0"));
    has_sha256_digest(image)
        && (host.contains('.') || registry.contains(':') || host == "localhost")
        && host.split('.').all(|label| {
            !label.is_empty()
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
        && !port.is_empty()
        && port.bytes().all(|b| b.is_ascii_digit())
        && registry != "index.docker.io"
        && repository.split('/').all(|component| {
            !component.is_empty()
                && component
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
        })
        && (registry != "docker.io" || repository.contains('/'))
}

impl Kata {
    /// `dir` is `opt/kata` of the extracted tools tarball.
    pub fn read(dir: &Path) -> Result<Self, String> {
        let defaults = dir.join("share/defaults/kata-containers");
        Ok(Self {
            genpolicy: pinned(&dir.join("bin/genpolicy"), GENPOLICY_SHA256)?,
            settings: pinned(&defaults.join("genpolicy-settings.json"), SETTINGS_SHA256)?,
            rules: patch_rules(pinned(&defaults.join("rules.rego"), RULES_SHA256)?)?,
        })
    }

    /// Runs the pinned genpolicy from a private copy, so the bytes checked are the bytes run.
    pub fn genpolicy(&self, pod: &Pod) -> Result<String, String> {
        let dir = std::env::temp_dir().join(format!(
            "alpha-coco-{}",
            hex::encode(crate::random::<16>()?)
        ));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .map_err(|e| format!("{}: {e}", dir.display()))?;
        let out = self.run_in(&dir, pod);
        let _ = fs::remove_dir_all(&dir);
        out
    }

    fn run_in(&self, dir: &Path, pod: &Pod) -> Result<String, String> {
        let settings = dir.join("settings");
        let drop_ins = settings.join("genpolicy-settings.d");
        fs::DirBuilder::new()
            .recursive(true)
            .create(&drop_ins)
            .map_err(|e| format!("{}: {e}", drop_ins.display()))?;
        let write = |path: PathBuf, bytes: &[u8]| {
            fs::write(&path, bytes).map_err(|e| format!("{}: {e}", path.display()))
        };
        write(dir.join("rules.rego"), self.rules.as_bytes())?;
        write(dir.join("pod.yaml"), pod.genpolicy_input.as_bytes())?;
        write(settings.join("genpolicy-settings.json"), &self.settings)?;
        for (name, json) in SETTINGS_DROP_INS {
            write(drop_ins.join(name), json.as_bytes())?;
        }
        let binary = dir.join("genpolicy");
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .open(&binary)
            .and_then(|mut f| f.write_all(&self.genpolicy))
            .map_err(|e| format!("{}: {e}", binary.display()))?;
        let output = Command::new(&binary)
            .current_dir(dir)
            .args(["-r", "-j", "settings", "-p", "rules.rego", "-y", "pod.yaml"])
            .output()
            .map_err(|e| format!("genpolicy: {e}; it runs on Linux x86_64 only"))?;
        if !output.status.success() {
            return Err(format!(
                "genpolicy: {}; {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        String::from_utf8(output.stdout).map_err(|_| "genpolicy: output is not UTF-8".into())
    }
}

fn sha256_hex(bytes: impl AsRef<[u8]>) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn pinned(path: &Path, sha256: &str) -> Result<Vec<u8>, String> {
    let bytes = fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if sha256_hex(&bytes) != sha256 {
        return Err(format!(
            "{}: not the Kata 4.0.0 release file (sha256 {sha256}); extract kata-tools-static-4.0.0-amd64.tar.zst",
            path.display()
        ));
    }
    Ok(bytes)
}

fn patch_rules(upstream: Vec<u8>) -> Result<String, String> {
    let mut rules = String::from_utf8(upstream).map_err(|_| "rules.rego: not UTF-8")?;
    for (old, new) in RULE_EDITS {
        rules = rules.replacen(old, new, 1);
    }
    rules.push('\n');
    rules.push_str(RULE_ADDITIONS);
    if sha256_hex(&rules) != PATCHED_RULES_SHA256 {
        return Err("rules.rego: the patch did not apply".into());
    }
    Ok(rules)
}

/// Builds the init-data in one fixed layout: genpolicy's own keeps `[data]` in a hash map, so
/// the same inputs could give two Revisions.
pub fn render(mut pod: Pod, app_id: AppId, policy: &str) -> Result<Rendered, String> {
    let (rules, data) = policy
        .split_once(POLICY_DATA)
        .ok_or("genpolicy: no policy_data in its output")?;
    let rules_sha256 = sha256_hex(rules);
    if rules_sha256 != PATCHED_RULES_SHA256 {
        return Err("genpolicy: its output does not start with the pinned rules".into());
    }
    let mut data = alpha_core::parse(data.as_bytes())
        .map_err(|e| format!("genpolicy: policy_data is not one JSON value: {e}"))?;
    data.as_object_mut()
        .and_then(|d| d.remove("containers"))
        .ok_or("genpolicy: policy_data has no containers")?;
    let data = alpha_core::jcs(&data).map_err(|e| format!("policy_data: {e}"))?;
    if policy.contains("'''") {
        return Err(
            "genpolicy: its output contains ''', which a TOML literal string cannot hold".into(),
        );
    }
    let toml = format!(
        "algorithm = \"sha256\"\nversion = \"0.1.0\"\n\n[data]\n\"app_id\" = \"{app_id}\"\n\"policy.rego\" = '''\n{policy}'''\n"
    );
    let init_data = InitData::parse(toml.clone()).map_err(|e| format!("init-data: {e}"))?;
    if init_data.app_id() != Some(app_id) {
        return Err("init-data: app_id does not read back".into());
    }
    let mut gzip = GzEncoder::new(Vec::new(), Compression::best());
    gzip.write_all(toml.as_bytes())
        .map_err(|e| format!("gzip: {e}"))?;
    let annotation = BASE64_STANDARD.encode(gzip.finish().map_err(|e| format!("gzip: {e}"))?);
    let metadata = template_mut(&mut pod.spec)?
        .entry("metadata".into())
        .or_insert_with(|| Mapping::new().into());
    let Yaml::Mapping(metadata) = metadata else {
        return Err("pod spec: metadata is not a mapping".into());
    };
    let annotations = metadata
        .entry("annotations".into())
        .or_insert_with(|| Mapping::new().into());
    let Yaml::Mapping(annotations) = annotations else {
        return Err("pod spec: metadata.annotations is not a mapping".into());
    };
    annotations.insert(ANNOTATION.into(), annotation.clone().into());
    Ok(Rendered {
        revision: init_data.digest(),
        init_data: toml,
        annotation,
        rules_sha256: format!("sha256:{rules_sha256}"),
        policy_data_sha256: format!("sha256:{}", sha256_hex(data)),
        pod: serde_yaml_ng::to_string(&pod.spec).map_err(|e| format!("pod spec: {e}"))?,
    })
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use flate2::read::GzDecoder;
    use serde_json::Value;

    use super::*;

    const POD: &str = include_str!("../../../testdata/coco/pod.yaml");
    /// genpolicy 4.0.0's output for `POD` with the pinned rules and settings, recorded on B300.
    const GENPOLICY: &str = include_str!("../../../testdata/coco/genpolicy.rego");
    const EXPECTED: &str = include_str!("../../../testdata/coco/expected.json");
    const APP_ID: &str = "01a133a7-0246-7786-915d-e8306b2d57b3";

    fn render_golden() -> Rendered {
        render(
            parse(POD.as_bytes()).unwrap(),
            APP_ID.parse().unwrap(),
            GENPOLICY,
        )
        .unwrap()
    }

    #[test]
    fn golden_render_is_deterministic_and_names_its_app() {
        let first = render_golden();
        let expected: Value = serde_json::from_str(EXPECTED).unwrap();
        let printed = serde_json::to_value(&first).unwrap();
        for key in ["revision", "rules_sha256", "policy_data_sha256"] {
            assert_eq!(printed[key], expected[key], "{key}");
        }
        let again = render_golden();
        assert_eq!(
            (&first.init_data, &first.annotation, &first.pod),
            (&again.init_data, &again.annotation, &again.pod)
        );
        assert!(
            first
                .init_data
                .contains(&format!("\n\"app_id\" = \"{APP_ID}\"\n"))
        );
        let gzip = BASE64_STANDARD.decode(&first.annotation).unwrap();
        let mut toml = String::new();
        GzDecoder::new(gzip.as_slice())
            .read_to_string(&mut toml)
            .unwrap();
        assert_eq!(toml, first.init_data);
        let pod: Yaml = serde_yaml_ng::from_str(&first.pod).unwrap();
        assert_eq!(
            pod["metadata"]["annotations"][ANNOTATION].as_str(),
            Some(first.annotation.as_str())
        );
        assert_eq!(
            pod["spec"]["automountServiceAccountToken"],
            Yaml::Bool(false)
        );
        assert_eq!(pod["spec"]["enableServiceLinks"], Yaml::Bool(false));
        let input = parse(POD.as_bytes()).unwrap().genpolicy_input;
        assert!(!input.contains("automountServiceAccountToken"));
        assert!(!input.contains("enableServiceLinks"));
    }

    #[test]
    fn stateful_set_carries_the_init_data_in_its_pod_template() {
        let pod: Yaml = serde_yaml_ng::from_str(POD).unwrap();
        let set = serde_yaml_ng::to_string(&serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "StatefulSet",
            "metadata": {"name": "render"},
            "spec": {
                "serviceName": "render",
                "selector": {"matchLabels": {"app": "render"}},
                "template": {"metadata": {"labels": {"app": "render"}}, "spec": pod["spec"]},
            },
        }))
        .unwrap();
        let parsed = parse(set.as_bytes()).unwrap();
        let input: Yaml = serde_yaml_ng::from_str(&parsed.genpolicy_input).unwrap();
        assert_eq!(input["kind"].as_str(), Some("StatefulSet"));
        assert!(
            input["spec"]["template"]["spec"]
                .get("automountServiceAccountToken")
                .is_none()
        );
        let rendered = render(parsed, APP_ID.parse().unwrap(), GENPOLICY).unwrap();
        assert_eq!(rendered.revision, render_golden().revision);
        let out: Yaml = serde_yaml_ng::from_str(&rendered.pod).unwrap();
        assert!(out["metadata"].get("annotations").is_none());
        let template = &out["spec"]["template"];
        assert_eq!(
            template["metadata"]["annotations"][ANNOTATION].as_str(),
            Some(rendered.annotation.as_str())
        );
        assert_eq!(template["spec"]["enableServiceLinks"], Yaml::Bool(false));
        let hostname = set.replace("    spec:\n", "    spec:\n      hostname: evil\n");
        assert!(
            parse(hostname.as_bytes())
                .err()
                .unwrap()
                .contains("hostname")
        );
    }

    #[test]
    fn refuses_what_the_policy_cannot_pin() {
        let digest =
            "alpine@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8";
        let full = format!("public.ecr.aws/docker/library/{digest}");
        let (name, hex) = digest.split_once('@').unwrap();
        for image in [
            "public.ecr.aws/docker/library/alpine:3.22".to_owned(),
            digest.to_owned(),
            format!("library/{digest}"),
            format!("docker.io/{digest}"),
            format!("index.docker.io/library/{digest}"),
            format!("public.ecr.aws/docker//library/{digest}"),
            format!("public.ecr.aws/docker/Library/{digest}"),
            format!("Public.ECR.aws/docker/library/{digest}"),
            format!("a b.example/library/{digest}"),
            format!("registry.example:/library/{digest}"),
            format!("public.ecr.aws/docker/library/{name}:3.22@{hex}"),
        ] {
            let pod = POD.replace(&full, &image);
            let err = parse(pod.as_bytes()).err().unwrap();
            assert!(err.contains("<registry>/<repository>@sha256"), "{image}");
        }
        assert!(fully_qualified(&format!("localhost:5000/{digest}")));
        let groups = POD.replace("supplementalGroups", "runAsGroup: 0\n    other");
        assert!(
            parse(groups.as_bytes())
                .err()
                .unwrap()
                .contains("supplementalGroups")
        );
        let token = POD.replace("Token: false", "Token: true");
        assert!(parse(token.as_bytes()).is_err());
        let hostname = POD.replace("  containers:", "  hostname: evil\n  containers:");
        assert!(
            parse(hostname.as_bytes())
                .err()
                .unwrap()
                .contains("hostname")
        );
        let env = POD.replace("name: MODE", "name: HOSTNAME");
        assert!(parse(env.as_bytes()).err().unwrap().contains("HOSTNAME"));
        let env_from = POD.replace(
            "    env:",
            "    envFrom:\n    - configMapRef: {name: cfg}\n    env:",
        );
        assert!(
            parse(env_from.as_bytes())
                .err()
                .unwrap()
                .contains("envFrom")
        );
        let field_ref = POD.replace(
            "value: golden",
            "valueFrom: {fieldRef: {fieldPath: status.podIP}}",
        );
        assert!(
            parse(field_ref.as_bytes())
                .err()
                .unwrap()
                .contains("valueFrom")
        );
        let not_list = POD.replace("  containers:", "  initContainers: {}\n  containers:");
        assert!(
            parse(not_list.as_bytes())
                .err()
                .unwrap()
                .contains("not a list")
        );
        let other_rules = GENPOLICY.replacen("package agent_policy", "package other", 1);
        let pod = parse(POD.as_bytes()).unwrap();
        let err = render(pod, APP_ID.parse().unwrap(), &other_rules).unwrap_err();
        assert!(err.contains("pinned rules"));
    }

    #[test]
    fn patch_turns_the_upstream_rules_into_the_pinned_ones() {
        let (patched, _) = GENPOLICY.split_once(POLICY_DATA).unwrap();
        let upstream = upstream_policy(GENPOLICY);
        let (upstream, _) = upstream.split_once(POLICY_DATA).unwrap();
        assert_eq!(patch_rules(upstream.into()).unwrap(), patched);
        let err = patch_rules(b"package agent_policy\n".to_vec()).unwrap_err();
        assert!(err.contains("the patch did not apply"));
    }

    #[test]
    fn refuses_a_genpolicy_that_is_not_the_release_build() {
        let dir = std::env::temp_dir().join(format!(
            "alpha-coco-test-{}",
            hex::encode(crate::random::<8>().unwrap())
        ));
        fs::create_dir_all(dir.join("bin")).unwrap();
        fs::write(dir.join("bin/genpolicy"), b"#!/bin/sh\n").unwrap();
        let err = Kata::read(&dir).err().unwrap();
        fs::remove_dir_all(&dir).unwrap();
        assert!(err.contains("genpolicy: not the Kata 4.0.0 release file"));
    }

    const DIND_POD: &str = include_str!("../../../testdata/coco/docker-in-kata/pod.yaml");
    /// genpolicy 4.0.0 (built from the tag) for `DIND_POD`, pinned rules and settings.
    const DIND_GENPOLICY: &str =
        include_str!("../../../testdata/coco/docker-in-kata/genpolicy.rego");
    /// The `CreateContainerRequest`s the shim sends for `DIND_POD`, in order: B300 captures of
    /// containerd 2.3.6 and Kata 4.0.0, changed only as containerd and the shim change them for
    /// this spec (a privileged container, Memory emptyDirs, a downward API volume).
    const DIND_REQUESTS: &str = include_str!("../../../testdata/coco/docker-in-kata/requests.json");

    /// Evaluates requests the way the Kata 4.0.0 agent does (`src/agent/policy/src/policy.rs`):
    /// a rule's `ops` patch the policy state only when it allows.
    struct Agent {
        engine: regorus::Engine,
        state: serde_json::Map<String, Value>,
    }

    impl Agent {
        fn new(policy: &str) -> Self {
            let mut engine = regorus::Engine::new();
            engine.set_strict_builtin_errors(false);
            engine.set_policy_length_config(regorus::PolicyLengthConfig {
                max_col: (64 * 1024).try_into().unwrap(),
                max_file_bytes: (16 * 1024 * 1024).try_into().unwrap(),
                max_lines: 200_000.try_into().unwrap(),
            });
            engine
                .add_policy("agent_policy".into(), policy.into())
                .unwrap();
            Self {
                engine,
                state: Default::default(),
            }
        }

        fn allows(&mut self, endpoint: &str, request: &Value) -> bool {
            self.engine.clear_data();
            let data = serde_json::from_value(serde_json::json!({ "pstate": self.state })).unwrap();
            self.engine.add_data(data).unwrap();
            self.engine.set_input_json(&request.to_string()).unwrap();
            let results = self
                .engine
                .eval_query(format!("data.agent_policy.{endpoint}"), false)
                .unwrap();
            let value = serde_json::to_value(&results.result[0].expressions[0].value).unwrap();
            if let Value::Bool(allowed) = value {
                return allowed;
            }
            for op in value["ops"].as_array().unwrap() {
                assert_eq!(op["op"], "add", "{op}");
                let key = op["path"]
                    .as_str()
                    .unwrap()
                    .strip_prefix("/pstate/")
                    .unwrap();
                self.state.insert(key.into(), op["value"].clone());
            }
            value["allowed"] == Value::Bool(true)
        }

        fn creates(&mut self, request: &Value) -> bool {
            self.allows("CreateContainerRequest", request)
        }
    }

    #[test]
    fn docker_in_kata_pod_runs_under_the_pinned_policy() {
        let rendered = render(
            parse(DIND_POD.as_bytes()).unwrap(),
            APP_ID.parse().unwrap(),
            DIND_GENPOLICY,
        )
        .unwrap();
        let golden: Value = serde_json::from_str(EXPECTED).unwrap();
        assert_eq!(
            rendered.policy_data_sha256,
            golden["policy_data_sha256"].as_str().unwrap()
        );
        // The recorded policy is this pod's: a spec edited without regenerating it fails here.
        let pod: Yaml = serde_yaml_ng::from_str(DIND_POD).unwrap();
        let mut in_pod: Vec<_> = ["initContainers", "containers"]
            .iter()
            .flat_map(|list| pod["spec"][list].as_sequence().unwrap())
            .map(|c| (c["name"].as_str().unwrap(), c["image"].as_str().unwrap()))
            .collect();
        let data: Value =
            serde_json::from_str(DIND_GENPOLICY.split_once(POLICY_DATA).unwrap().1).unwrap();
        let mut in_policy: Vec<_> = data["containers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| &c["OCI"]["Annotations"])
            .filter_map(|a| {
                Some((
                    a["io.kubernetes.cri.container-name"].as_str()?,
                    a["io.kubernetes.cri.image-name"].as_str().unwrap(),
                ))
            })
            .collect();
        in_pod.sort();
        in_policy.sort();
        assert_eq!(in_pod, in_policy);
        let requests: Vec<Value> = serde_json::from_str(DIND_REQUESTS).unwrap();
        let mut agent = launched(DIND_GENPOLICY, &requests);
        // With shared_fs=none the shim copies the downward API volume into the guest file by
        // file, in WalkDir order, under the mount source it gives the runtime container.
        let runtime = &requests[1]["OCI"]["Mounts"];
        let base = runtime
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["destination"] == "/run/alpha-init-data")
            .unwrap()["source"]
            .as_str()
            .unwrap();
        let stamp = "..2026_10_14_09_00_00.123456789";
        for (file_type, path, target) in [
            ("Directory", base.to_owned(), None),
            ("Directory", format!("{base}/{stamp}"), None),
            ("Regular", format!("{base}/{stamp}/cc_init_data"), None),
            ("Symlink", format!("{base}/..data"), Some(stamp)),
            (
                "Symlink",
                format!("{base}/cc_init_data"),
                Some("..data/cc_init_data"),
            ),
        ] {
            let request = copy(file_type, &path, target);
            assert!(agent.allows("CopyFileRequest", &request), "{path}");
        }
    }

    #[test]
    fn docker_in_kata_policy_pins_the_privileged_container() {
        let requests: Vec<Value> = serde_json::from_str(DIND_REQUESTS).unwrap();
        let dockerd = 2;
        let launch = 3;
        let mut tcp = requests[dockerd].clone();
        tcp["OCI"]["Process"]["Args"]
            .as_array_mut()
            .unwrap()
            .push("--host=tcp://0.0.0.0:2375".into());
        let mut image = requests[dockerd].clone();
        let other = "docker.io/library/docker@sha256:0000000000000000000000000000000000000000000000000000000000000000";
        image["OCI"]["Annotations"]["io.kubernetes.cri.image-name"] = other.into();
        image["storages"][0]["source"] = other.into();
        let mut escalated = requests[launch].clone();
        escalated["OCI"]["Process"]["Capabilities"] =
            requests[dockerd]["OCI"]["Process"]["Capabilities"].clone();
        // What containerd adds to a privileged container when the runtime handler does not set
        // privileged_without_host_devices.
        let mut device = requests[dockerd].clone();
        device["OCI"]["Linux"]["Devices"] = serde_json::json!([{
            "Path": "/dev/kvm", "Type": "c", "Major": 10, "Minor": 232,
            "FileMode": 0o660, "UID": 0, "GID": 0,
        }]);
        for (index, tampered) in [
            (dockerd, tcp),
            (dockerd, image),
            (dockerd, device),
            (launch, escalated),
        ] {
            let mut agent = launched(DIND_GENPOLICY, &requests[..index]);
            assert!(!agent.creates(&tampered));
        }
    }

    const B300_POD: &str = include_str!("../../../testdata/coco/b300/pod.yaml");
    /// genpolicy 4.0.0 for `B300_POD`, pinned rules and settings.
    const B300_GENPOLICY: &str = include_str!("../../../testdata/coco/b300/genpolicy.rego");
    /// The sandbox, `alpha-runtime` and `app` `CreateContainerRequest`s a B300 node sent for
    /// `B300_POD`, taken from its policy denials with each tampering undone.
    const B300_REQUESTS: &str = include_str!("../../../testdata/coco/b300/requests.json");
    const SANDBOX: usize = 0;
    const RUNTIME: usize = 1;
    const APP: usize = 2;

    fn b300_requests() -> Vec<Value> {
        serde_json::from_str(B300_REQUESTS).unwrap()
    }

    fn copy(file_type: &str, path: &str, target: Option<&str>) -> Value {
        serde_json::json!({
            "path": path, "file_type": file_type, "symlink_target": target,
            "file_size": 0, "file_mode": 0o644, "dir_mode": 0o755, "uid": 0, "gid": 0, "offset": 0,
        })
    }

    fn launched(policy: &str, requests: &[Value]) -> Agent {
        let mut agent = Agent::new(policy);
        for request in requests {
            let name = &request["OCI"]["Annotations"]["io.kubernetes.cri.container-name"];
            assert!(agent.creates(request), "{name}");
        }
        agent
    }

    /// What genpolicy 4.0.0's own rules make of the same policy data.
    fn upstream_policy(policy: &str) -> String {
        let (patched, data) = policy.split_once(POLICY_DATA).unwrap();
        let mut rules = patched
            .strip_suffix(RULE_ADDITIONS)
            .and_then(|r| r.strip_suffix('\n'))
            .unwrap()
            .to_owned();
        for (old, new) in RULE_EDITS {
            rules = rules.replacen(new, old, 1);
        }
        assert_eq!(sha256_hex(&rules), RULES_SHA256);
        format!("{rules}{POLICY_DATA}{data}")
    }

    /// One request of the launch, changed the way a malicious host would change it.
    fn tampered(
        requests: &[Value],
        index: usize,
        change: impl FnOnce(&mut Value),
    ) -> (usize, Value) {
        let mut request = requests[index].clone();
        change(&mut request);
        (index, request)
    }

    fn env(request: &mut Value) -> &mut Vec<Value> {
        request["OCI"]["Process"]["Env"].as_array_mut().unwrap()
    }

    fn mounts(request: &mut Value) -> &mut Vec<Value> {
        request["OCI"]["Mounts"].as_array_mut().unwrap()
    }

    fn mount_source(request: &mut Value, destination: &str, source: &str) {
        for m in mounts(request)
            .iter_mut()
            .filter(|m| m["destination"] == destination)
        {
            m["source"] = source.into();
        }
    }

    fn host_tampering(requests: &[Value]) -> Vec<(&'static str, (usize, Value))> {
        let other = "public.ecr.aws/docker/library/alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000";
        let share = "/run/kata-containers/shared/containers/0000000000000000000000000000000000000000000000000000000000000000-0000000000000000-x";
        vec![
            (
                "image swap",
                tampered(requests, APP, |r| {
                    r["OCI"]["Annotations"]["io.kubernetes.cri.image-name"] = other.into();
                    r["storages"][0]["source"] = other.into();
                }),
            ),
            (
                "image swap under the pinned name",
                tampered(requests, APP, |r| r["storages"][0]["source"] = other.into()),
            ),
            (
                "env added",
                tampered(requests, APP, |r| {
                    env(r).push("LD_PRELOAD=/tmp/x.so".into())
                }),
            ),
            (
                "env removed",
                tampered(requests, APP, |r| {
                    env(r).retain(|v| v != "APP_MODE=baseline")
                }),
            ),
            (
                "env changed",
                tampered(requests, APP, |r| {
                    for v in env(r).iter_mut().filter(|v| *v == "APP_MODE=baseline") {
                        *v = "APP_MODE=tampered".into();
                    }
                }),
            ),
            (
                "pause image pulled from a registry",
                tampered(requests, SANDBOX, |r| {
                    let pull = &mut r["storages"][0];
                    pull["source"] = "docker.io/attacker/pause:latest".into();
                    let options = pull["driver_options"][0].as_str().unwrap().replace(
                        r#""io.kubernetes.cri.container-type":"sandbox""#,
                        r#""io.kubernetes.cri.container-type":"container""#,
                    );
                    pull["driver_options"][0] = options.into();
                }),
            ),
            (
                "volume moved",
                tampered(requests, APP, |r| {
                    for m in mounts(r)
                        .iter_mut()
                        .filter(|m| m["destination"] == "/run/alpha")
                    {
                        m["destination"] = "/etc".into();
                    }
                }),
            ),
            (
                "disk emptyDir swapped for a host share",
                tampered(requests, APP, |r| mount_source(r, "/run/alpha", share)),
            ),
            (
                "disk emptyDir bound to the image rootfs",
                tampered(requests, APP, |r| {
                    mount_source(r, "/run/alpha", "/run/kata-containers/app/rootfs")
                }),
            ),
            (
                "disk emptyDir bound to an image pulled under the storage path",
                tampered(requests, APP, |r| {
                    let image = "/run/kata-containers/sandbox/storage/image";
                    r["storages"][0]["mount_point"] = image.into();
                    mount_source(r, "/run/alpha", image)
                }),
            ),
            (
                "configfs-tsm swapped for a host share",
                tampered(requests, RUNTIME, |r| {
                    mount_source(
                        r,
                        "/sys/kernel/config",
                        &format!("{share}/sys/kernel/config"),
                    )
                }),
            ),
            (
                "/dev/shm swapped for a host share",
                tampered(requests, APP, |r| {
                    let shm = format!("{share}/run/kata-containers/sandbox/shm");
                    mount_source(r, "/dev/shm", &shm)
                }),
            ),
            (
                "extra bind mount",
                tampered(requests, APP, |r| {
                    mounts(r).push(serde_json::json!({
                        "destination": "/etc/ld.so.preload", "source": share,
                        "type_": "bind", "options": ["rbind", "rprivate", "ro"],
                    }))
                }),
            ),
            (
                "extra storage",
                tampered(requests, APP, |r| {
                    let mut extra = r["storages"][1].clone();
                    extra["mount_point"] = "/run/kata-containers/sandbox/storage/extra".into();
                    r["storages"].as_array_mut().unwrap().push(extra);
                }),
            ),
            (
                "host device",
                tampered(requests, APP, |r| {
                    r["OCI"]["Linux"]["Devices"] = serde_json::json!([{
                        "Path": "/dev/kvm", "Type": "c", "Major": 10, "Minor": 232,
                        "FileMode": 0o660, "UID": 0, "GID": 0,
                    }]);
                }),
            ),
            (
                "prestart hook",
                tampered(requests, APP, |r| {
                    r["OCI"]["Hooks"] =
                        serde_json::json!({ "Prestart": [{ "Path": "/bin/sh", "Args": ["sh"] }] });
                }),
            ),
            (
                "seccomp profile",
                tampered(requests, APP, |r| {
                    r["OCI"]["Linux"]["Seccomp"] =
                        serde_json::json!({ "DefaultAction": "SCMP_ACT_ALLOW" });
                }),
            ),
            (
                "sysctl",
                tampered(requests, APP, |r| {
                    r["OCI"]["Linux"]["Sysctl"] =
                        serde_json::json!({ "kernel.core_pattern": "|/bin/sh" });
                }),
            ),
            (
                "/proc/kcore unmasked",
                tampered(requests, APP, |r| {
                    let masked = r["OCI"]["Linux"]["MaskedPaths"].as_array_mut().unwrap();
                    masked.retain(|p| p != "/proc/kcore");
                }),
            ),
            (
                "/proc/sys writable",
                tampered(requests, APP, |r| {
                    let readonly = r["OCI"]["Linux"]["ReadonlyPaths"].as_array_mut().unwrap();
                    readonly.retain(|p| p != "/proc/sys");
                }),
            ),
            (
                "shared pid namespace",
                tampered(requests, APP, |r| r["sandbox_pidns"] = true.into()),
            ),
        ]
    }

    #[test]
    fn b300_pod_renders_and_launches_under_the_pinned_policy() {
        let rendered = render(
            parse(B300_POD.as_bytes()).unwrap(),
            APP_ID.parse().unwrap(),
            B300_GENPOLICY,
        )
        .unwrap();
        let golden: Value = serde_json::from_str(EXPECTED).unwrap();
        assert_eq!(
            rendered.policy_data_sha256,
            golden["policy_data_sha256"].as_str().unwrap()
        );
        launched(B300_GENPOLICY, &b300_requests());
    }

    #[test]
    fn pinned_policy_denies_a_malicious_host() {
        let requests = b300_requests();
        for (scenario, (index, request)) in host_tampering(&requests) {
            let mut agent = launched(B300_GENPOLICY, &requests[..index]);
            assert!(!agent.creates(&request), "{scenario}");
        }

        let mut agent = launched(B300_GENPOLICY, &requests);
        let app = &requests[APP];
        let id = &app["container_id"];
        let mut shell = app["OCI"]["Process"].clone();
        shell["Args"] = serde_json::json!(["sh"]);
        let exec = |process: &Value| serde_json::json!({ "container_id": id, "exec_id": "x", "string_user": null, "process": process });
        let read = serde_json::json!({ "container_id": id, "exec_id": "", "len": 4096 });
        let write = serde_json::json!({ "container_id": id, "exec_id": "", "data": "aWQK" });
        let close = serde_json::json!({ "container_id": id, "exec_id": "" });
        for (scenario, endpoint, request) in [
            ("exec of a shell", "ExecProcessRequest", exec(&shell)),
            (
                "exec of the container's own command",
                "ExecProcessRequest",
                exec(&app["OCI"]["Process"]),
            ),
            ("logs", "ReadStreamRequest", read),
            ("attach", "WriteStreamRequest", write),
            ("stdin close", "CloseStdinRequest", close),
        ] {
            assert!(!agent.allows(endpoint, &request), "{scenario}");
        }

        let shared = "/run/kata-containers/shared/containers/0000000000000000000000000000000000000000000000000000000000000000-0000000000000000-hostname";
        assert!(agent.allows("CopyFileRequest", &copy("Regular", shared, None)));
        for (scenario, request) in [
            (
                "into the app's guest-pulled rootfs",
                copy(
                    "Regular",
                    "/run/kata-containers/app/rootfs/etc/ld.so.preload",
                    None,
                ),
            ),
            (
                "into an in-guest volume",
                copy(
                    "Regular",
                    "/run/kata-containers/sandbox/storage/MDow/x",
                    None,
                ),
            ),
            (
                "out of the shared directory",
                copy("Regular", &format!("{shared}/../../../sandbox/x"), None),
            ),
            ("relative path", copy("Regular", &shared[1..], None)),
            (
                "symlink out of the guest",
                copy("Symlink", &format!("{shared}/x"), Some("/etc/passwd")),
            ),
        ] {
            assert!(!agent.allows("CopyFileRequest", &request), "{scenario}");
        }
    }

    /// Our rules exist because genpolicy 4.0.0's own do not refuse these; when they start to,
    /// the edits may be redundant.
    #[test]
    fn upstream_rules_still_allow_what_our_edits_refuse() {
        let requests = b300_requests();
        let upstream = upstream_policy(B300_GENPOLICY);
        launched(&upstream, &requests);
        let tampering = host_tampering(&requests);
        for wanted in [
            "image swap under the pinned name",
            "env removed",
            "pause image pulled from a registry",
            "disk emptyDir swapped for a host share",
            "configfs-tsm swapped for a host share",
            "/dev/shm swapped for a host share",
        ] {
            let (_, (index, request)) = tampering.iter().find(|(s, _)| *s == wanted).unwrap();
            let mut agent = launched(&upstream, &requests[..*index]);
            assert!(agent.creates(request), "{wanted}");
        }
    }
}
