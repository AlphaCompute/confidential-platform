//! Option B (PRD-02 deliverable 26), policy layer: what a hostile host can ask the Kata agent to
//! do to a pod that uses the Confidential Data Hub, refused by the agent policy its init-data
//! carries.
//!
//! The pods are `alpha coco render`'s `render/03-kbs` and `alpha coco wrap`'s `wrap/04-kbs`
//! (`testdata/coco`): genpolicy 4.1.0's policies, with the Alpha baseline, for a service that takes
//! a sealed secret (which the agent has CDH unseal before the container starts) and an encrypted
//! scratch volume (a block device CDH formats with LUKS2 under a key generated in the TD). They are
//! evaluated as #82's malicious-host suite evaluates its pods (`tests/agent_policy.rs` there, with
//! the same engine, options and `testdata/agent-policy/requests.json`): as the Kata 4.1.0 agent
//! does, the requests serialized with every field Kata's types give them. Each pod first launches
//! with what a host legitimately sends, so a policy that refuses CDH's own paths fails here too.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::num::{NonZeroU32, NonZeroUsize};
use std::path::PathBuf;

use base64::Engine;
use base64::prelude::{BASE64_URL_SAFE, BASE64_URL_SAFE_NO_PAD};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

fn testdata(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata")
        .join(path)
}

/// The agent's `AgentPolicy`, line for line where it decides.
#[derive(Clone)]
struct Agent {
    engine: regorus::Engine,
}

#[derive(serde::Deserialize)]
struct MetadataResponse {
    allowed: bool,
    ops: Option<json_patch::Patch>,
}

impl Agent {
    /// `AgentPolicy::set_policy`, with the init-data's `policy.rego`.
    fn boot(policy: &str) -> Self {
        let mut engine = regorus::Engine::new();
        engine.set_strict_builtin_errors(false);
        engine.set_gather_prints(true);
        engine.set_policy_length_config(regorus::PolicyLengthConfig {
            max_col: NonZeroU32::new(64 * 1024).unwrap(),
            max_file_bytes: NonZeroUsize::new(16 * 1024 * 1024).unwrap(),
            max_lines: NonZeroUsize::new(200_000).unwrap(),
        });
        engine
            .add_data(regorus::Value::from_json_str(r#"{"pstate": {}}"#).unwrap())
            .unwrap();
        engine
            .add_policy("agent_policy".to_owned(), policy.to_owned())
            .unwrap();
        let mut agent = Self { engine };
        assert!(
            !matches!(
                agent.allow_request("AllowRequestsFailingPolicy", "{}"),
                Ok((true, _))
            ),
            "the policy allows requests that fail it"
        );
        agent
    }

    /// `AgentPolicy::allow_request`. An `Err` is the agent's INTERNAL error: refused.
    fn allow_request(&mut self, ep: &str, input: &str) -> Result<(bool, String), String> {
        self.engine
            .set_input_json(input)
            .map_err(|e| e.to_string())?;
        let results = self
            .engine
            .eval_query(format!("data.agent_policy.{ep}"), false)
            .map_err(|e| e.to_string())?;
        let prints = self
            .engine
            .take_prints()
            .map(|p| p.join(" "))
            .unwrap_or_default();
        if results.result.len() != 1 || results.result[0].expressions.len() != 1 {
            return Err(format!("unexpected eval_query result {results:?}"));
        }
        let allow = match &results.result[0].expressions[0].value {
            regorus::Value::Bool(b) => *b,
            regorus::Value::Object(obj) => {
                let text = serde_json::to_string(obj).map_err(|e| e.to_string())?;
                let response: MetadataResponse =
                    serde_json::from_str(&text).map_err(|e| e.to_string())?;
                if response.allowed
                    && let Some(ops) = response.ops
                {
                    let mut state =
                        serde_json::to_value(self.engine.get_data()).map_err(|e| e.to_string())?;
                    json_patch::patch(&mut state, &ops).map_err(|e| e.to_string())?;
                    self.engine.clear_data();
                    self.engine
                        .add_data(
                            regorus::Value::from_json_str(&state.to_string())
                                .map_err(|e| e.to_string())?,
                        )
                        .map_err(|e| e.to_string())?;
                }
                response.allowed
            }
            _ => return Err(format!("unexpected eval_query result type {results:?}")),
        };
        Ok((allow, prints))
    }

    fn must_allow(&mut self, ep: &str, request: &Value, what: &str) {
        match self.allow_request(ep, &request.to_string()) {
            Ok((true, _)) => {}
            Ok((false, prints)) => {
                let tail = &prints[prints.len().saturating_sub(3000)..];
                panic!(
                    "{what}: {ep} was refused, but a host legitimately sends it; policy log ends: {tail}"
                )
            }
            Err(e) => panic!("{what}: {ep} failed in the policy engine: {e}"),
        }
    }
}

fn hex(data: &str) -> String {
    hex::encode(Sha256::digest(data.as_bytes()))
}

fn unanchor(regex: &str) -> String {
    regex
        .trim_start_matches('^')
        .trim_end_matches('$')
        .replace("\\.", ".")
}

/// Replaces genpolicy's Deployment and ReplicaSet hash classes with samples.
fn pod_name_from(regex: &str) -> String {
    let class = "[bcdfghjklmnpqrstvwxz2456789]+";
    let mut out = unanchor(regex);
    for sample in ["6d9f8b7c5", "x2x4z"] {
        out = out.replacen(class, sample, 1);
    }
    assert!(
        !out.contains('['),
        "unexpected sandbox-name pattern {regex}"
    );
    out
}

const SHARED: &str = "/run/kata-containers/shared/containers";
const NETNS: &str = "/var/run/netns/cni-3b9a2d4e-5f60-4a71-8b92-c3d4e5f60718";
const POD_UID: &str = "5d0b7c3e-91a2-4f6b-8c1d-2e3f4a5b6c7d";
const APP: &str = "01994b3e-5c8a-7d3e-9a1b-2c3d4e5f6a7b";

struct Pod {
    label: &'static str,
    policy: String,
    data: Value,
    templates: Value,
    pod_name: String,
    namespace: String,
    sandbox_id: String,
}

impl Pod {
    /// The policy the pod runs: the one in its measured init-data, as render and wrap made it from
    /// genpolicy's `policy.rego`.
    fn measured_policy(label: &str) -> String {
        let dir = testdata(&format!("coco/{label}"));
        let initdata = if label.starts_with("wrap/") {
            let output: Value =
                serde_json::from_str(&std::fs::read_to_string(dir.join("output.json")).unwrap())
                    .unwrap();
            base64::prelude::BASE64_STANDARD
                .decode(output["initdata"].as_str().unwrap())
                .unwrap()
        } else {
            let manifest = std::fs::read_to_string(dir.join("manifest.yaml")).unwrap();
            let annotation = manifest
                .lines()
                .find_map(|l| {
                    l.trim()
                        .strip_prefix("io.katacontainers.config.hypervisor.cc_init_data:")
                })
                .unwrap()
                .trim()
                .trim_matches('"');
            alpha_tsm::coco::decode_annotation(annotation).unwrap()
        };
        let init = alpha_core::coco::InitData::parse(&initdata).unwrap();
        assert!(init.kbs().unwrap().is_some(), "{label} has the KBS");
        init.policy().unwrap().to_owned()
    }

    fn load(label: &'static str) -> Self {
        Self::with_policy(label, Self::measured_policy(label))
    }

    fn with_policy(label: &'static str, policy: String) -> Self {
        let start = policy.find("\npolicy_data := ").unwrap();
        let data: Value =
            serde_json::from_str(&policy[start + "\npolicy_data := ".len()..]).unwrap();
        let templates: Value = serde_json::from_str(
            &std::fs::read_to_string(testdata("agent-policy/requests.json")).unwrap(),
        )
        .unwrap();
        let pause = &data["containers"][0]["OCI"]["Annotations"];
        assert_eq!(pause["io.kubernetes.cri.container-type"], "sandbox");
        let pod_name = pod_name_from(pause["io.kubernetes.cri.sandbox-name"].as_str().unwrap());
        let namespace = unanchor(
            pause["io.kubernetes.cri.sandbox-namespace"]
                .as_str()
                .unwrap(),
        );
        Self {
            label,
            policy,
            data,
            templates,
            pod_name,
            namespace,
            sandbox_id: hex(&format!("{label}/sandbox")),
        }
    }

    fn template(&self, label: &str) -> Value {
        let t = self.templates[label].clone();
        assert!(!t.is_null(), "no {label} in requests.json");
        t
    }

    fn containers(&self) -> &[Value] {
        self.data["containers"].as_array().unwrap()
    }

    fn container_name(&self, idx: usize) -> &str {
        self.containers()[idx]["OCI"]["Annotations"]["io.kubernetes.cri.container-name"]
            .as_str()
            .unwrap_or("pause")
    }

    fn index(&self, name: &str) -> usize {
        (0..self.containers().len())
            .find(|&i| self.container_name(i) == name)
            .unwrap_or_else(|| panic!("{}: no container {name}", self.label))
    }

    fn container_id(&self, idx: usize) -> String {
        if idx == 0 {
            self.sandbox_id.clone()
        } else {
            hex(&format!("{}/{}", self.label, self.container_name(idx)))
        }
    }

    fn mount_source(&self, source: &str, cid: &str, destination: &str) -> String {
        if let Some(name) = source.strip_prefix("$(sfprefix)") {
            let random = &hex(&format!("{cid}{destination}"))[..16];
            format!("{SHARED}/{cid}-{random}-{}", unanchor(name))
        } else {
            unanchor(source)
        }
    }

    fn caps(&self, caps: &Value) -> Value {
        let caps: Vec<Value> = caps
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|c| match c.as_str().unwrap() {
                "$(default_caps)" => self.data["common"]["default_caps"]
                    .as_array()
                    .unwrap()
                    .clone(),
                "$(privileged_caps)" => self.data["common"]["privileged_caps"]
                    .as_array()
                    .unwrap()
                    .clone(),
                _ => vec![c.clone()],
            })
            .collect();
        Value::Array(caps)
    }

    fn create_sandbox(&self) -> Value {
        let mut req = self.template("CreateSandboxRequest");
        req["hostname"] = json!(self.pod_name);
        req["sandbox_id"] = json!(self.sandbox_id);
        req["storages"] = self.data["sandbox"]["storages"].clone();
        req["dns"] = json!(["nameserver 10.96.0.10"]);
        req
    }

    /// The block device the Kata runtime hot-plugs for a disk-backed `emptyDir` in
    /// `block-encrypted` mode: virtio-blk at a PCI path, mounted where the policy's
    /// `$(spath)/$(b64_device_id)` says.
    fn block_device(&self, idx: usize) -> (String, String) {
        let source = format!("02/{idx:02x}");
        let spath = self.data["common"]["spath"].as_str().unwrap();
        let mount_point = format!("{spath}/{}", BASE64_URL_SAFE.encode(&source));
        (source, mount_point)
    }

    /// The CreateContainerRequest the Kata shim sends for policy container `idx`.
    fn create_container(&self, idx: usize) -> Value {
        let cid = self.container_id(idx);
        let p = &self.containers()[idx];
        let p_oci = &p["OCI"];
        let sandbox = p_oci["Annotations"]["io.kubernetes.cri.container-type"] == "sandbox";
        let mut req = self.template(if sandbox {
            "CreateContainerRequest/sandbox"
        } else {
            "CreateContainerRequest/container"
        });

        let mut annotations = Map::new();
        for (key, value) in p_oci["Annotations"].as_object().unwrap() {
            let value = value.as_str().unwrap();
            let value = match key.as_str() {
                "io.katacontainers.pkg.oci.bundle_path" => value.replace("$(bundle-id)", &cid),
                "io.kubernetes.cri.sandbox-id" => self.sandbox_id.clone(),
                "io.kubernetes.cri.sandbox-name" => self.pod_name.clone(),
                "io.kubernetes.cri.sandbox-namespace" => self.namespace.clone(),
                "io.kubernetes.cri.sandbox-log-directory" => format!(
                    "/var/log/pods/{}_{}_{POD_UID}",
                    self.namespace, self.pod_name
                ),
                "nerdctl/network-namespace" => NETNS.to_owned(),
                _ => value.to_owned(),
            };
            annotations.insert(key.clone(), json!(value));
        }
        annotations.insert("io.kubernetes.cri.sandbox-uid".into(), json!(POD_UID));
        if sandbox {
            annotations.insert(
                "io.kubernetes.cri.podsandbox.image-name".into(),
                json!("registry.k8s.io/pause:3.10"),
            );
        }

        let (block_source, block_mount) = self.block_device(idx);
        let oci = &mut req["OCI"];
        oci["Annotations"] = Value::Object(annotations.clone());
        oci["Version"] = p_oci["Version"].clone();
        oci["Root"] = json!({
            "Path": self.data["common"]["root_path"].as_str().unwrap().replace("$(bundle-id)", &cid),
            "Readonly": p_oci["Root"]["Readonly"],
        });
        oci["Mounts"] = Value::Array(
            p_oci["Mounts"]
                .as_array()
                .unwrap()
                .iter()
                .map(|m| {
                    let mut m = m.clone();
                    let source = m["source"].as_str().unwrap();
                    // A block emptyDir's mount is of the device's mount point.
                    m["source"] = json!(if source.is_empty() {
                        block_mount.clone()
                    } else {
                        self.mount_source(source, &cid, m["destination"].as_str().unwrap())
                    });
                    m
                })
                .collect(),
        );

        let p_process = &p_oci["Process"];
        let process = &mut oci["Process"];
        process["Terminal"] = p_process["Terminal"].clone();
        process["User"] = json!({
            "UID": p_process["User"]["UID"],
            "GID": p_process["User"]["GID"],
            "AdditionalGids": p_process["User"]["AdditionalGids"],
            "Username": "",
        });
        process["Args"] = Value::Array(
            p_process["Args"]
                .as_array()
                .unwrap()
                .iter()
                .map(|a| json!(a.as_str().unwrap().replace("$$", "$")))
                .collect(),
        );
        let mut env: Vec<Value> = p_process["Env"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| {
                json!(
                    e.as_str()
                        .unwrap()
                        .replace("$(sandbox-name)", &self.pod_name)
                        .replace("$(host-name)", &self.pod_name)
                )
            })
            .collect();
        // containerd sets HOSTNAME, the pod's name, in every container, whether or not the
        // policy lists it (the generators' policies do not).
        if !env
            .iter()
            .any(|e| e.as_str().unwrap().starts_with("HOSTNAME="))
        {
            env.push(json!(format!("HOSTNAME={}", self.pod_name)));
        }
        if !sandbox {
            env.push(json!("KUBERNETES_SERVICE_HOST=10.96.0.1"));
            env.push(json!("KUBERNETES_SERVICE_PORT=443"));
            if self.container_name(idx) == "alpha-runtime" {
                env.push(json!(
                    "ALPHACOMPUTE_KMS_ENDPOINTS=https://kms-1.example:8443"
                ));
            }
        }
        process["Env"] = Value::Array(env);
        process["Cwd"] = p_process["Cwd"].clone();
        process["NoNewPrivileges"] = p_process["NoNewPrivileges"].clone();
        let caps = &p_process["Capabilities"];
        process["Capabilities"] = json!({
            "Ambient": self.caps(&caps["Ambient"]),
            "Bounding": self.caps(&caps["Bounding"]),
            "Effective": self.caps(&caps["Effective"]),
            "Inheritable": self.caps(&caps["Inheritable"]),
            "Permitted": self.caps(&caps["Permitted"]),
        });

        let linux = &mut oci["Linux"];
        for key in [
            "Namespaces",
            "MaskedPaths",
            "ReadonlyPaths",
            "Devices",
            "Sysctl",
        ] {
            linux[key] = p_oci["Linux"][key].clone();
        }
        linux["CgroupsPath"] = json!(format!(
            "kubepods-pod{}.slice:cri-containerd:{cid}",
            POD_UID.replace('-', "_")
        ));

        let mut storages: Vec<Value> = p["storages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| {
                let mut s = s.clone();
                if s["mount_point"] == json!("$(spath)/$(b64_device_id)") {
                    s["driver"] = json!("blk");
                    s["source"] = json!(block_source);
                    s["mount_point"] = json!(block_mount);
                } else {
                    s["mount_point"] = json!(unanchor(s["mount_point"].as_str().unwrap()));
                }
                s
            })
            .collect();
        let image = if sandbox {
            "pause".to_owned()
        } else {
            p_oci["Annotations"]["io.kubernetes.cri.image-name"]
                .as_str()
                .unwrap()
                .to_owned()
        };
        storages.push(json!({
            "driver": "image_guest_pull",
            "driver_options": [format!("image_guest_pull={}", json!({"metadata": annotations}))],
            "fs_group": null,
            "fstype": "overlay",
            "mount_point": self.data["common"]["root_path"].as_str().unwrap().replace("$(bundle-id)", &cid),
            "options": [],
            "shared": false,
            "source": image,
        }));
        req["storages"] = Value::Array(storages);
        req["devices"] = json!([]);
        req["container_id"] = json!(cid);
        req["exec_id"] = json!(cid);
        req["sandbox_pidns"] = p["sandbox_pidns"].clone();
        req
    }

    fn with_container(&self, label: &str, idx: usize) -> Value {
        let mut req = self.template(label);
        req["container_id"] = json!(self.container_id(idx));
        if req.get("exec_id").is_some() {
            req["exec_id"] = json!(self.container_id(idx));
        }
        req
    }

    fn copy_file(path: &str, file_type: &str, symlink_target: Option<&str>) -> Value {
        json!({
            "dir_mode": 0o750, "file_mode": 0o644, "file_size": 64, "file_type": file_type,
            "gid": 0, "offset": 0, "path": path, "symlink_target": symlink_target, "uid": 0,
        })
    }

    fn copy_files(&self, idx: usize) -> Vec<Value> {
        let cid = self.container_id(idx);
        let mut out = Vec::new();
        for m in self.containers()[idx]["OCI"]["Mounts"].as_array().unwrap() {
            let source = m["source"].as_str().unwrap();
            if !source.starts_with("$(sfprefix)") {
                continue;
            }
            let path = self.mount_source(source, &cid, m["destination"].as_str().unwrap());
            if path.ends_with("-alpha-pod") {
                let stamp = "..2026_10_12_04_00_00.123456789";
                out.push(Self::copy_file(&path, "Directory", None));
                out.push(Self::copy_file(
                    &format!("{path}/{stamp}"),
                    "Directory",
                    None,
                ));
                out.push(Self::copy_file(
                    &format!("{path}/{stamp}/cc_init_data"),
                    "Regular",
                    None,
                ));
                out.push(Self::copy_file(
                    &format!("{path}/..data"),
                    "Symlink",
                    Some(stamp),
                ));
                out.push(Self::copy_file(
                    &format!("{path}/cc_init_data"),
                    "Symlink",
                    Some("..data/cc_init_data"),
                ));
            } else {
                out.push(Self::copy_file(&path, "Regular", None));
            }
        }
        out
    }

    /// The agent with the sandbox and every container before `upto` created as a host that means
    /// no harm creates them.
    fn launch_upto(&self, upto: usize) -> Agent {
        let mut agent = Agent::boot(&self.policy);
        let what = format!("{} launch", self.label);
        agent.must_allow("CreateSandboxRequest", &self.create_sandbox(), &what);
        for idx in 0..upto {
            let what = format!("{what}, container {}", self.container_name(idx));
            for copy in self.copy_files(idx) {
                agent.must_allow("CopyFileRequest", &copy, &what);
            }
            agent.must_allow("CreateContainerRequest", &self.create_container(idx), &what);
            agent.must_allow(
                "StartContainerRequest",
                &self.with_container("StartContainerRequest", idx),
                &what,
            );
        }
        agent
    }

    /// The App's container, which takes the sealed secret and the scratch volume.
    fn app(&self) -> usize {
        self.index("app")
    }

    /// Sends `request` for the App's container, created in place of its legitimate one.
    fn refused(&self, request: &Value, what: &str) {
        let idx = self.app();
        let mut agent = self.launch_upto(idx);
        for copy in self.copy_files(idx) {
            agent.must_allow("CopyFileRequest", &copy, what);
        }
        if let Ok((true, _)) = agent.allow_request("CreateContainerRequest", &request.to_string()) {
            panic!("{}: {what}: CreateContainerRequest was allowed", self.label);
        }
    }
}

fn pods() -> [Pod; 2] {
    [Pod::load("render/03-kbs"), Pod::load("wrap/04-kbs")]
}

/// What a hostile host changes in a request, and what the test calls it.
type Change = Box<dyn Fn(&mut Value)>;

fn env_mut(req: &mut Value) -> &mut Vec<Value> {
    req["OCI"]["Process"]["Env"].as_array_mut().unwrap()
}

fn sealed_index(req: &Value) -> usize {
    req["OCI"]["Process"]["Env"]
        .as_array()
        .unwrap()
        .iter()
        .position(|e| e.as_str().unwrap().starts_with("DB_PASSWORD=sealed."))
        .unwrap()
}

/// A sealed secret of this App, well formed, naming the Secret `name`.
fn sealed(name: &str) -> String {
    let b64 = |v: Value| BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&v).unwrap());
    format!(
        "sealed.{}.{}.{}",
        b64(json!({ "alg": "ES256", "kid": format!("kbs:///{APP}/sealed-secret-key/sealing") })),
        b64(json!({
            "version": "0.1.0", "type": "vault", "name": format!("kbs:///{APP}/secret/{name}"),
            "provider": "kbs", "provider_settings": {}, "annotations": {},
        })),
        BASE64_URL_SAFE_NO_PAD.encode([7u8; 64])
    )
}

fn block_storage(req: &mut Value) -> &mut Value {
    req["storages"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|s| s["driver"] == json!("blk"))
        .unwrap()
}

fn cache_mount(req: &mut Value) -> &mut Value {
    req["OCI"]["Mounts"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|m| m["destination"] == json!("/var/cache/app"))
        .unwrap()
}

#[test]
fn a_host_that_means_no_harm_launches_the_sealed_secret_and_the_encrypted_scratch_volume() {
    for pod in pods() {
        let mut agent = pod.launch_upto(pod.containers().len());
        let req = pod.create_container(pod.app());
        assert!(sealed_index(&req) > 0);
        assert_eq!(
            req["storages"][0]["driver_options"],
            json!(["encryption_key=ephemeral", "create_filesystem"])
        );
        let what = format!("{} restart", pod.label);
        agent.must_allow("CreateContainerRequest", &req, &what);
    }
}

#[test]
fn the_host_cannot_change_the_sealed_secret() {
    for pod in pods() {
        let legit = pod.create_container(pod.app());
        let at = sealed_index(&legit);
        let pod_name = pod.pod_name.clone();
        let cases: Vec<(&str, Change)> = vec![
            (
                "another of this App's sealed secrets in its place",
                Box::new(move |r| {
                    env_mut(r)[at] = json!(format!("DB_PASSWORD={}", sealed("other")))
                }),
            ),
            (
                "a plaintext value in its place",
                Box::new(move |r| env_mut(r)[at] = json!("DB_PASSWORD=chosen-by-the-host")),
            ),
            (
                "the sealed secret dropped",
                Box::new(move |r| {
                    env_mut(r).remove(at);
                }),
            ),
            (
                "a second sealed secret added",
                Box::new(|r| env_mut(r).push(json!(format!("EXTRA={}", sealed("db_password"))))),
            ),
            (
                "a sealed value as the pod's hostname",
                Box::new(|r| {
                    for e in env_mut(r).iter_mut() {
                        if e.as_str().unwrap().starts_with("HOSTNAME=") {
                            *e = json!(format!("HOSTNAME={}", sealed("db_password")));
                        }
                    }
                }),
            ),
            (
                "a sealed value with the pod's name as the pod's hostname",
                Box::new(move |r| {
                    for e in env_mut(r).iter_mut() {
                        if e.as_str().unwrap().starts_with("HOSTNAME=") {
                            *e = json!(format!("HOSTNAME={}.{pod_name}", sealed("db_password")));
                        }
                    }
                }),
            ),
            (
                "a sealed value in a variable the host may set",
                Box::new(|r| {
                    env_mut(r).retain(|e| !e.as_str().unwrap().starts_with("HOSTNAME="));
                    env_mut(r).push(json!(format!("HOSTNAME={}", sealed("db_password"))));
                }),
            ),
        ];
        for (what, change) in cases {
            let mut req = legit.clone();
            change(&mut req);
            pod.refused(&req, what);
        }
    }
}

#[test]
fn the_scratch_volume_is_encrypted_in_the_guest_or_not_mounted() {
    for pod in pods() {
        let legit = pod.create_container(pod.app());
        let cases: Vec<(&str, Change)> = vec![
            (
                "the block device mounted without CDH's encryption",
                Box::new(|r| block_storage(r)["driver_options"] = json!(["create_filesystem"])),
            ),
            (
                "the encryption option alone, no fresh filesystem",
                Box::new(|r| {
                    block_storage(r)["driver_options"] = json!(["encryption_key=ephemeral"])
                }),
            ),
            (
                "another key option",
                Box::new(|r| {
                    block_storage(r)["driver_options"] =
                        json!(["encryption_key=kbs:///default/key/1", "create_filesystem"])
                }),
            ),
            (
                "the volume as a host directory shared into the guest",
                Box::new(|r| {
                    r["storages"]
                        .as_array_mut()
                        .unwrap()
                        .retain(|s| s["driver"] != json!("blk"));
                    cache_mount(r)["source"] = json!(format!("{SHARED}/0123456789abcdef-cache"));
                }),
            ),
            (
                "the volume as shared-fs local storage",
                Box::new(|r| {
                    let s = block_storage(r);
                    s["driver"] = json!("local");
                    s["source"] = json!("local");
                    s["fstype"] = json!("local");
                    s["driver_options"] = json!([]);
                }),
            ),
            (
                "the mount pointed at another directory than the device's",
                Box::new(|r| {
                    cache_mount(r)["source"] = json!("/run/kata-containers/sandbox/storage/other")
                }),
            ),
            (
                "the device at a mount point its id does not name",
                Box::new(|r| {
                    block_storage(r)["source"] = json!("02/1f");
                }),
            ),
        ];
        for (what, change) in cases {
            let mut req = legit.clone();
            change(&mut req);
            pod.refused(&req, what);
        }
    }
}

/// The guest components' sockets and the init-data's extracted `aa.toml` and `cdh.toml` live in
/// the guest under `/run/confidential-containers`; no container reaches them.
#[test]
fn no_container_reaches_the_guest_components() {
    let paths = [
        "/run/confidential-containers",
        "/run/confidential-containers/cdh.sock",
        "/run/confidential-containers/attestation-agent",
        "/run/confidential-containers/initdata",
    ];
    for pod in pods() {
        for idx in 1..pod.containers().len() {
            let legit = pod.create_container(idx);
            for path in paths {
                let mut req = legit.clone();
                req["OCI"]["Mounts"].as_array_mut().unwrap().push(json!({
                    "destination": "/run/guest", "source": path, "type_": "bind",
                    "options": ["rbind", "rprivate", "rw"],
                }));
                let mut agent = pod.launch_upto(idx);
                for copy in pod.copy_files(idx) {
                    agent.must_allow("CopyFileRequest", &copy, "copy");
                }
                if let Ok((true, _)) =
                    agent.allow_request("CreateContainerRequest", &req.to_string())
                {
                    panic!(
                        "{}: {path} mounted into {} was allowed",
                        pod.label,
                        pod.container_name(idx)
                    );
                }
            }
        }
        let mut agent = pod.launch_upto(pod.containers().len());
        for path in [
            "/run/confidential-containers/initdata/cdh.toml",
            "/run/confidential-containers/initdata/aa.toml",
            "/run/confidential-containers/initdata/initdata.toml",
            "/run/confidential-containers/cdh/sealed-secret/sealing",
            "/etc/ocicrypt_config.json",
        ] {
            let copy = Pod::copy_file(path, "Regular", None);
            assert!(
                !matches!(
                    agent.allow_request("CopyFileRequest", &copy.to_string()),
                    Ok((true, _))
                ),
                "{}: a copy to {path} was allowed",
                pod.label
            );
        }
        // Nor can the host replace the policy that refuses all of the above.
        let mut set = pod.template("SetPolicyRequest");
        set["policy"] = json!("package agent_policy\ndefault CreateContainerRequest := true\n");
        assert!(!matches!(
            agent.allow_request("SetPolicyRequest", &set.to_string()),
            Ok((true, _))
        ));
    }
}

/// Why the generators take `HOSTNAME` out of the policy and narrow its pattern: under genpolicy's own output for the
/// same pod (`policy.rego`), the host may set it to a sealed value copied from the policy, and the
/// agent would have CDH unseal the App's Secret into the container's environment.
#[test]
fn genpolicys_policy_alone_lets_the_host_unseal_a_secret_into_hostname() {
    let pod = Pod::with_policy(
        "wrap/04-kbs",
        std::fs::read_to_string(testdata("coco/wrap/04-kbs/policy.rego")).unwrap(),
    );
    let mut agent = pod.launch_upto(pod.app());
    let mut req = pod.create_container(pod.app());
    for e in env_mut(&mut req).iter_mut() {
        if e.as_str().unwrap().starts_with("HOSTNAME=") {
            *e = json!(format!("HOSTNAME={}", sealed("db_password")));
        }
    }
    assert!(matches!(
        agent.allow_request("CreateContainerRequest", &req.to_string()),
        Ok((true, _))
    ));
}
