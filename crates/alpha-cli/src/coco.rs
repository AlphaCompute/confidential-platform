//! A tenant's Kata pod spec becomes a Revision: the agent policy genpolicy derives from it, in an
//! init-data TOML whose SHA-256 the shim puts in `MRCONFIGID`, and the pod spec carrying that
//! init-data. genpolicy, its rules and settings are pinned: they decide what the policy allows.

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
    "0986ca3f6f867c0f339152bdf509dbe010db43676123184d2d9851a0f55fbec7";

/// The upstream rules check neither the image a container pulls, nor that every pinned variable
/// is set, nor HOSTNAME and the sandbox hostname: the host could swap the image, drop or add
/// env, and rename the pod without changing the measurement.
const RULE_EDITS: [(&str, &str); 4] = [
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
    if spec.get("kind").and_then(Yaml::as_str) != Some("Pod") {
        return Err("pod spec: kind is not Pod; render one Pod".into());
    }
    if spec
        .get("metadata")
        .and_then(|m| m.get("annotations"))
        .and_then(|a| a.get(ANNOTATION))
        .is_some()
    {
        return Err(format!(
            "pod spec: already carries {ANNOTATION}; render the tenant's own spec"
        ));
    }
    let Some(Yaml::Mapping(pod)) = spec.get_mut("spec") else {
        return Err("pod spec: no spec mapping".into());
    };
    for list in ["initContainers", "containers"] {
        for container in pod
            .get(list)
            .and_then(Yaml::as_sequence)
            .into_iter()
            .flatten()
        {
            let image = container.get("image").and_then(Yaml::as_str).unwrap_or("");
            if !has_sha256_digest(image) {
                return Err(format!(
                    "{list}: image {image:?} has no digest; write <image>@sha256:<64 lowercase hex>, the policy pins it"
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
    if let Some(Yaml::Mapping(pod)) = spec.get_mut("spec") {
        pod.insert("automountServiceAccountToken".into(), false.into());
        pod.insert("enableServiceLinks".into(), false.into());
    }
    Ok(Pod {
        spec,
        genpolicy_input,
    })
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
    let metadata = pod
        .spec
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
    fn refuses_what_the_policy_cannot_pin() {
        let digest =
            "alpine@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8";
        let tag = POD.replace(digest, "alpine:3.22");
        assert!(parse(tag.as_bytes()).err().unwrap().contains("no digest"));
        let groups = POD.replace("supplementalGroups", "runAsGroup: 0\n    other");
        assert!(
            parse(groups.as_bytes())
                .err()
                .unwrap()
                .contains("supplementalGroups")
        );
        let token = POD.replace("Token: false", "Token: true");
        assert!(parse(token.as_bytes()).is_err());
        let other_rules = GENPOLICY.replacen("package agent_policy", "package other", 1);
        let pod = parse(POD.as_bytes()).unwrap();
        let err = render(pod, APP_ID.parse().unwrap(), &other_rules).unwrap_err();
        assert!(err.contains("pinned rules"));
    }

    #[test]
    fn patch_turns_the_upstream_rules_into_the_pinned_ones() {
        let (patched, _) = GENPOLICY.split_once(POLICY_DATA).unwrap();
        let mut upstream = patched
            .strip_suffix(RULE_ADDITIONS)
            .and_then(|r| r.strip_suffix('\n'))
            .unwrap()
            .to_owned();
        for (old, new) in RULE_EDITS {
            upstream = upstream.replacen(new, old, 1);
        }
        assert_eq!(sha256_hex(&upstream), RULES_SHA256);
        assert_eq!(patch_rules(upstream.into_bytes()).unwrap(), patched);
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
}
