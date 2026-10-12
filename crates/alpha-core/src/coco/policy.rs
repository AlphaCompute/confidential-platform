//! The PRD-02 baseline of a Kata agent policy, checked where the policy is made (`alpha coco
//! render` and `wrap`) and where a value it pins is relied on (`alpha-runtime`).
//!
//! genpolicy's output is its rules file followed by `policy_data`, the per-pod data those rules
//! read. The rules here are genpolicy 4.1.0's own, byte for byte, so a policy is accepted only as
//! those rules plus data, and the baseline is a property of the data: exec, log reads and stdin
//! refused, file copies only into the shared-files prefix, images pulled in the guest and pinned by
//! digest, and no environment variable the host may add beyond the two listed below. A policy
//! that edits the rules, or whose data loosens any of that, is refused rather than repaired.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};

/// genpolicy 4.1.0's `rules.rego` (kata-containers' `kata-tools-static-4.1.0-amd64.tar.zst`), as
/// released.
#[cfg(test)]
const UPSTREAM_RULES: &str = include_str!("genpolicy/rules.rego");
/// The Alpha rules patch (`alpha-rules.patch`, byte for byte as in #82's
/// `testdata/agent-policy/`, which holds its regression tests): the guest pulls exactly the image
/// the policy names (`allow_guest_pull_image`), and every variable the policy lists is set
/// (`allow_env_complete`).
pub const RULES_PATCH: &str = include_str!("genpolicy/alpha-rules.patch");
/// genpolicy 4.1.0's `rules.rego` with [`RULES_PATCH`] applied, which every accepted policy
/// starts with.
pub const RULES: &str = include_str!("genpolicy/alpha-rules.rego");
/// What genpolicy prints between the rules and the data.
pub const DATA_PREFIX: &str = "\npolicy_data := ";
/// `ALPHACOMPUTE_KMS_ENDPOINTS` comes from the namespace's `alpha-kms` ConfigMap, not the policy:
/// the endpoints are only where to connect, since the runtime pins the KMS CA and Revisions. The
/// policy admits the variable only as a list of `https://host[:port]` (alpha-cli's `40-` settings
/// drop-in).
pub const KMS_ENDPOINTS_ENV_REGEX: &str = "^ALPHACOMPUTE_KMS_ENDPOINTS=https://[a-z0-9.-]{1,253}(:[1-9][0-9]{0,3}|:[1-5][0-9]{4}|:6[0-4][0-9]{3}|:65[0-4][0-9]{2}|:655[0-2][0-9]|:6553[0-5])?(,https://[a-z0-9.-]{1,253}(:[1-9][0-9]{0,3}|:[1-5][0-9]{4}|:6[0-4][0-9]{3}|:65[0-4][0-9]{2}|:655[0-2][0-9]|:6553[0-5])?){0,7}$";
/// `HOSTNAME` as the host may set it: the pod's name, one lowercase DNS label (alpha-cli's `50-`
/// settings drop-in). genpolicy's `$(dns_label)` also admits `.` and `_`, so a host could set
/// `HOSTNAME=sealed.<JWS>` copied from the policy and have the agent unseal one of the App's
/// Secrets into a container that was never given it (Option B, sealed secrets).
pub const HOSTNAME_ENV_REGEX: &str = "^HOSTNAME=[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$";
/// Placeholders genpolicy's rules (`allow_var`, "always_allowed") let the host fill with any
/// value at all. genpolicy writes `HOSTNAME=$(host-name)` into every container; a host could
/// then set `HOSTNAME=sealed.<JWS>` copied from the policy and have the agent unseal one of the
/// App's Secrets into a container never given it. The generators take that entry out instead
/// (alpha-cli's `coco::policy::pin_hostname`).
pub const ANY_VALUE_PLACEHOLDERS: [&str; 3] = ["$(host-name)", "$(node-name)", "$(pod-uid)"];
/// genpolicy 4.1.0's own `HOSTNAME` pattern, which the `50-` drop-in replaces.
const GENPOLICY_HOSTNAME_ENV_REGEX: &str = "^HOSTNAME=$(dns_label)$";
/// The only environment variables the host may add to a container beyond those the policy
/// lists: the pod's hostname, the API server's `KUBERNETES_*` (#82's baseline drop-in), and the
/// KMS endpoints. Service links and the cloud identity variables genpolicy admits by default are
/// not among them, and none admits a value that starts `sealed.`. A policy may admit fewer.
pub const ALLOWED_ENV_REGEX: [&str; 10] = [
    HOSTNAME_ENV_REGEX,
    "^KUBERNETES_PORT_$(ip_p)_TCP=tcp://$(ipv4_a):$(ip_p)$",
    "^KUBERNETES_PORT_$(ip_p)_TCP_PROTO=tcp$",
    "^KUBERNETES_PORT_$(ip_p)_TCP_PORT=$(ip_p)$",
    "^KUBERNETES_PORT_$(ip_p)_TCP_ADDR=$(ipv4_a)$",
    "^KUBERNETES_SERVICE_HOST=$(ipv4_a)$",
    "^KUBERNETES_SERVICE_PORT=$(ip_p)$",
    "^KUBERNETES_SERVICE_PORT_HTTPS=$(ip_p)$",
    "^KUBERNETES_PORT=tcp://$(ipv4_a):$(ip_p)$",
    KMS_ENDPOINTS_ENV_REGEX,
];
/// Mounts genpolicy admits by default for a host-provided identity token; a confidential pod
/// takes none.
pub const TOKEN_MOUNTS: [&str; 2] = [
    "/var/run/secrets/kubernetes.io/serviceaccount",
    "/var/run/secrets/azure/tokens",
];
/// Rules the patch adds; a policy without them has genpolicy's unpatched rules.
const PATCH_RULES: [&str; 2] = [
    "\nallow_guest_pull_image(p_oci, i_oci, i_storages) if {\n",
    "\nallow_env_complete(p_process, i_process) if {\n",
];
/// Requests the baseline refuses outright (logs, stdin, diagnostics, remounts).
pub const REFUSED_REQUESTS: [&str; 5] = [
    "ReadStreamRequest",
    "WriteStreamRequest",
    "CloseStdinRequest",
    "GetDiagnosticDataRequest",
    "UpdateEphemeralMountsRequest",
];
/// The one place the host may copy files into the guest: the per-container shared files
/// (resolv.conf, hosts, the downward-API init-data), each bound to one container's bundle.
pub const COPY_FILE_PATHS: [&str; 1] = ["$(sfprefix)"];
pub const IMAGE_ANNOTATION: &str = "io.kubernetes.cri.image-name";
pub const NAME_ANNOTATION: &str = "io.kubernetes.cri.container-name";
pub const TYPE_ANNOTATION: &str = "io.kubernetes.cri.container-type";
/// The runtime's declaration of a customer's Fortanix DSM (PRD-06 I1), as `alpha-runtime` reads
/// it on the `prd06/dsm-customer-keys` branch (#72): a JSON object with the endpoint, the DSM
/// App, its CA, the keys and the required `binding`. On a Kata pod the host writes the
/// environment, so the value counts only as the agent policy pins it ([`dsm_pinned`]).
pub const DSM_ENV: &str = "ALPHACOMPUTE_DSM";
/// The init containers that open encrypted persistent volumes (`alpha-volume`, PRD-02
/// deliverable 25), the only ones the baseline lets run privileged in the TD and share a mount
/// back to the guest (the opened volume, which the App's container then mounts).
pub const VOLUME_CONTAINER_PREFIX: &str = "alpha-volume-";
/// genpolicy's capability set for an unprivileged container.
const DEFAULT_CAPS: &str = "$(default_caps)";
/// genpolicy's placeholders, which let a listed variable take a value the policy does not spell
/// out (the sandbox's name, the pod's IP, ...).
const PLACEHOLDER: &str = "$(";

/// One container the policy lets the host create, as the policy pins it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PolicyContainer {
    pub name: String,
    pub image: String,
}

/// A policy that holds the baseline, and the containers it admits (the sandbox's pause
/// container left out).
#[derive(Debug)]
pub struct Verified {
    pub containers: BTreeSet<PolicyContainer>,
    /// Each admitted container's environment as the policy lists it, by container name.
    pub env: BTreeMap<String, Vec<String>>,
    /// The containers with more than the default capabilities (privileged), by name: only
    /// `alpha-volume-*`, which opens a LUKS volume with device-mapper inside the TD.
    pub elevated: BTreeSet<String>,
    /// `policy_data`, parsed, for checks that belong to one caller.
    pub data: Value,
}

/// Accepts `policy` only as genpolicy 4.1.0's rules followed by `policy_data` that holds the
/// baseline; a single trailing newline, which an editor adds, is allowed.
pub fn verify(policy: &str) -> Result<Verified, String> {
    let bad = |m: &str| format!("agent policy: {m}");
    let data = policy
        .strip_prefix(RULES)
        .and_then(|rest| rest.strip_prefix(DATA_PREFIX))
        .ok_or_else(|| {
            if PATCH_RULES.iter().any(|r| !policy.contains(r)) {
                bad("its rules lack the Alpha rules patch (allow_guest_pull_image, allow_env_complete); regenerate it with the rules `alpha coco genpolicy-settings` writes")
            } else {
                bad("not genpolicy 4.1.0's rules.rego with the Alpha patch, followed by policy_data; regenerate it with `alpha coco genpolicy-settings` and genpolicy 4.1.0 rather than editing the rules")
            }
        })?;
    let data = data.strip_suffix('\n').unwrap_or(data);
    let data = crate::parse(data.as_bytes()).map_err(|e| bad(&format!("policy_data: {e}")))?;
    let at = |pointer: &str| data.pointer(pointer).unwrap_or(&Value::Null);

    if *at("/request_defaults/ExecProcessRequest") != json!({ "allowed_commands": [], "regex": [] })
    {
        return Err(bad(
            "ExecProcessRequest allows commands; exec must be refused",
        ));
    }
    for request in REFUSED_REQUESTS {
        if *at(&format!("/request_defaults/{request}")) != json!(false) {
            return Err(bad(&format!("{request} is not refused")));
        }
    }
    if *at("/request_defaults/CopyFileRequest") != json!(COPY_FILE_PATHS) {
        return Err(bad(
            "CopyFileRequest allows paths outside the shared-files prefix",
        ));
    }
    let admitted_env = at("/request_defaults/CreateContainerRequest/allow_env_regex");
    if admitted_env
        .as_array()
        .is_some_and(|list| list.contains(&json!(GENPOLICY_HOSTNAME_ENV_REGEX)))
    {
        return Err(bad(
            "allow_env_regex admits genpolicy's HOSTNAME pattern, under which the host may set HOSTNAME to a sealed secret; regenerate it with the 50-alpha-hostname.json drop-in `alpha coco genpolicy-settings` writes",
        ));
    }
    if !admitted_env.as_array().is_some_and(|list| {
        list.iter()
            .all(|r| r.as_str().is_some_and(|r| ALLOWED_ENV_REGEX.contains(&r)))
    }) {
        return Err(bad(
            "allow_env_regex admits host-provided environment variables beyond HOSTNAME, KUBERNETES_* and the KMS endpoints",
        ));
    }
    if *at("/cluster_config/guest_pull") != json!(true) {
        return Err(bad(
            "images are not pulled in the guest, so their digests would not bind the root filesystems",
        ));
    }
    let containers = at("/containers")
        .as_array()
        .ok_or_else(|| bad("policy_data has no containers"))?;
    let mut admitted = BTreeSet::new();
    let mut env = BTreeMap::new();
    let mut elevated = BTreeSet::new();
    for container in containers {
        let commands = container.get("exec_commands").unwrap_or(&Value::Null);
        if !commands.as_array().is_some_and(Vec::is_empty) {
            return Err(bad(
                "a container allows exec commands (an exec probe or hook)",
            ));
        }
        let token = container
            .pointer("/OCI/Mounts")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|m| m.get("destination").and_then(Value::as_str))
            .find(|d| TOKEN_MOUNTS.contains(d));
        if let Some(token) = token {
            return Err(bad(&format!("a container may mount the token at {token}")));
        }
        let annotation = |key: &str| {
            container
                .pointer(&format!("/OCI/Annotations/{}", key.replace('/', "~1")))
                .and_then(Value::as_str)
        };
        let listed = || {
            container
                .pointer("/OCI/Process/Env")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
        };
        if let Some(var) = listed().find(|e| ANY_VALUE_PLACEHOLDERS.iter().any(|p| e.contains(p))) {
            return Err(bad(&format!(
                "{var} lets the host set any value; regenerate it with alpha coco render or wrap"
            )));
        }
        // `$(sandbox-name)` and the like: the rules match the value as an unanchored pattern.
        if let Some(var) = listed().find(|e| e.starts_with("HOSTNAME=") && e.contains("$(")) {
            return Err(bad(&format!(
                "{var} lets the host set HOSTNAME to more than one DNS label; regenerate it with alpha coco render or wrap"
            )));
        }
        if annotation(TYPE_ANNOTATION) == Some("sandbox") {
            continue;
        }
        let name =
            annotation(NAME_ANNOTATION).ok_or_else(|| bad("a container has no name annotation"))?;
        let image = annotation(IMAGE_ANNOTATION)
            .ok_or_else(|| bad(&format!("container {name} has no image annotation")))?;
        if !pinned(image) {
            return Err(bad(&format!(
                "container {name}'s image {image} is not pinned by digest"
            )));
        }
        let listed: Vec<String> = container
            .pointer("/OCI/Process/Env")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect();
        env.insert(name.to_owned(), listed);
        let bounding = container
            .pointer("/OCI/Process/Capabilities/Bounding")
            .and_then(Value::as_array)
            .into_iter()
            .flatten();
        let is_elevated = bounding.clone().any(|c| c.as_str() != Some(DEFAULT_CAPS));
        let shares_mounts = container
            .pointer("/OCI/Mounts")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|m| m.get("options").and_then(Value::as_array))
            .flatten()
            .any(|o| o.as_str() == Some("rshared"));
        if (is_elevated || shares_mounts) && !name.starts_with(VOLUME_CONTAINER_PREFIX) {
            return Err(bad(&format!(
                "container {name} is privileged or shares mounts back to the guest; only {VOLUME_CONTAINER_PREFIX}* may"
            )));
        }
        if is_elevated {
            elevated.insert(name.to_owned());
        }
        if !admitted.insert(PolicyContainer {
            name: name.to_owned(),
            image: image.to_owned(),
        }) {
            return Err(bad(&format!("container {name} is listed twice")));
        }
    }
    if admitted.is_empty() {
        return Err(bad("admits no container"));
    }
    Ok(Verified {
        containers: admitted,
        env,
        elevated,
        data,
    })
}

fn pinned(image: &str) -> bool {
    image.split_once('@').is_some_and(|(name, digest)| {
        !name.is_empty()
            && digest
                .strip_prefix("sha256:")
                .is_some_and(|hex| crate::hex_bytes::<32>(hex).is_some())
    })
}

impl Verified {
    /// Every `NAME=value` entry the policy lists for `name`, in any container.
    pub fn listed(&self, name: &str) -> BTreeSet<&str> {
        self.env
            .values()
            .flatten()
            .filter_map(|e| {
                e.split_once('=')
                    .filter(|(n, _)| *n == name)
                    .map(|(_, v)| v)
            })
            .collect()
    }
}

/// Accepts `value` of [`DSM_ENV`] only if the measured agent policy pins it: the policy holds the
/// baseline (so no `allow_env_regex` admits the variable), lists `ALPHACOMPUTE_DSM=<value>` for
/// some container, and lists the variable nowhere with a genpolicy placeholder, which would let
/// the host choose part of it. Whatever value a container then receives is one the customer
/// approved with the Revision.
pub fn dsm_pinned(policy: &str, value: &str) -> Result<(), String> {
    let verified = verify(policy)?;
    let listed = verified.listed(DSM_ENV);
    if listed.iter().any(|v| v.contains(PLACEHOLDER)) {
        return Err(format!(
            "{DSM_ENV}: the agent policy lets the host fill part of it"
        ));
    }
    if !listed.contains(value) {
        return Err(format!(
            "{DSM_ENV} is set, but the measured agent policy does not pin this value; declare the DSM in the pod spec the policy was generated from"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A policy that holds the baseline, with one container whose environment is `env`.
    pub(crate) fn policy(env: &[&str]) -> String {
        let mut defaults = json!({
            "ExecProcessRequest": { "allowed_commands": [], "regex": [] },
            "CopyFileRequest": COPY_FILE_PATHS,
            "CreateContainerRequest": { "allow_env_regex": ALLOWED_ENV_REGEX },
        });
        for request in REFUSED_REQUESTS {
            defaults[request] = json!(false);
        }
        let data = json!({
            "containers": [{
                "OCI": {
                    "Annotations": {
                        TYPE_ANNOTATION: "container",
                        NAME_ANNOTATION: "alpha-runtime",
                        IMAGE_ANNOTATION: format!("r@sha256:{}", "ab".repeat(32)),
                    },
                    "Process": { "Env": env },
                },
                "exec_commands": [],
            }],
            "request_defaults": defaults,
            "cluster_config": { "guest_pull": true },
        });
        format!("{RULES}{DATA_PREFIX}{data:#}")
    }

    const DSM: &str = r#"{"binding":"revision","endpoint":"https://dsm.example"}"#;

    /// `patch` for a unified diff that only adds lines, as `alpha-rules.patch` does.
    fn apply(original: &str, patch: &str) -> String {
        let lines: Vec<&str> = original.split_inclusive('\n').collect();
        let (mut out, mut at, mut in_hunk) = (String::new(), 0, false);
        for line in patch.split_inclusive('\n') {
            if let Some(header) = line.strip_prefix("@@ -") {
                let start: usize = header.split([',', ' ']).next().unwrap().parse().unwrap();
                while at + 1 < start {
                    out.push_str(lines[at]);
                    at += 1;
                }
                in_hunk = true;
            } else if !in_hunk {
                continue;
            } else if let Some(added) = line.strip_prefix('+') {
                out.push_str(added);
            } else {
                assert_eq!(lines[at], &line[1..], "context");
                out.push_str(lines[at]);
                at += 1;
            }
        }
        lines[at..].iter().for_each(|l| out.push_str(l));
        out
    }

    #[test]
    fn only_a_volume_container_runs_privileged_or_shares_a_mount() {
        let caps = r#""Process": { "Capabilities": { "Bounding": ["$(privileged_caps)"] }, "#;
        let base = policy(&["PATH=/bin"]);
        let as_volume = base
            .replace("\"alpha-runtime\"", "\"alpha-volume-pg\"")
            .replace("\"Process\": {", caps);
        let verified = verify(&as_volume).unwrap();
        assert_eq!(
            verified.elevated,
            BTreeSet::from(["alpha-volume-pg".to_owned()])
        );
        let as_app = base.replace("\"Process\": {", caps);
        assert!(verify(&as_app).unwrap_err().contains("privileged"));
        let shared = base.replace(
            "\"Process\": {",
            r#""Mounts": [{ "destination": "/data", "options": ["rbind", "rshared", "rw"] }], "Process": {"#,
        );
        assert!(verify(&shared).unwrap_err().contains("shares mounts"));
    }

    #[test]
    fn the_rules_are_genpolicy_4_1_0s_with_82s_patch() {
        use sha2::{Digest, Sha256};
        let sha = |s: &str| {
            Sha256::digest(s.as_bytes())
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        };
        assert_eq!(
            sha(UPSTREAM_RULES),
            "a1ad4280a7d1db83649de18640fb30f08cc160fadd7f4360d1dde09977b090b7"
        );
        assert_eq!(
            sha(RULES_PATCH),
            "970cf8d718ccb660c76c08cdcdafbffdc0a71e4638d1cd819bce9f28808a1e59"
        );
        assert_eq!(apply(UPSTREAM_RULES, RULES_PATCH), RULES);
        for rule in PATCH_RULES {
            assert!(RULES.contains(rule) && !UPSTREAM_RULES.contains(rule));
        }
        let unpatched = policy(&[]).replacen(RULES, UPSTREAM_RULES, 1);
        assert!(
            verify(&unpatched)
                .unwrap_err()
                .contains("Alpha rules patch")
        );
    }

    #[test]
    fn hostname_is_held_to_one_dns_label() {
        // genpolicy's HOSTNAME, which the rules let the host fill with anything.
        let any = policy(&["PATH=/bin", "HOSTNAME=$(host-name)"]);
        assert!(
            verify(&any)
                .unwrap_err()
                .contains("lets the host set any value")
        );
        for placeholder in ANY_VALUE_PLACEHOLDERS {
            let any = policy(&["PATH=/bin", &format!("X={placeholder}")]);
            assert!(verify(&any).is_err(), "{placeholder}");
        }
        // $(sandbox-name), which the rules match as an unanchored pattern.
        let sandbox = policy(&["PATH=/bin", "HOSTNAME=$(sandbox-name)"]);
        assert!(
            verify(&sandbox)
                .unwrap_err()
                .contains("more than one DNS label")
        );
        verify(&policy(&["PATH=/bin", "HOSTNAME=pinned"])).unwrap();
        // genpolicy's own HOSTNAME pattern, which admits a sealed secret's dots and underscores.
        let base = policy(&["PATH=/bin"]);
        let loose = base.replace(
            &format!("{HOSTNAME_ENV_REGEX:?}"),
            "\"^HOSTNAME=$(dns_label)$\"",
        );
        assert_ne!(loose, base);
        assert!(
            verify(&loose)
                .unwrap_err()
                .contains("genpolicy's HOSTNAME pattern")
        );
    }

    #[test]
    fn a_dsm_counts_only_as_the_policy_pins_it() {
        let pinned = policy(&["PATH=/bin", &format!("{DSM_ENV}={DSM}")]);
        dsm_pinned(&pinned, DSM).unwrap();
        // Another value, or none in the policy: the host set it.
        let other = DSM.replace("dsm.example", "attacker.example");
        assert!(
            dsm_pinned(&pinned, &other)
                .unwrap_err()
                .contains("does not pin")
        );
        assert!(dsm_pinned(&policy(&["PATH=/bin"]), DSM).is_err());
        // A placeholder would let the host fill part of it.
        let placeholder = policy(&[&format!("{DSM_ENV}=$(sandbox-name)")]);
        assert!(
            dsm_pinned(&placeholder, DSM)
                .unwrap_err()
                .contains("fill part")
        );
        // A policy that lets the host add variables pins nothing.
        let loose = pinned.replace(
            &format!("{HOSTNAME_ENV_REGEX:?}"),
            &format!("{HOSTNAME_ENV_REGEX:?}, \"^.*$\""),
        );
        assert!(
            dsm_pinned(&loose, DSM)
                .unwrap_err()
                .contains("allow_env_regex")
        );
        assert_eq!(
            verify(&pinned).unwrap().listed(DSM_ENV),
            BTreeSet::from([DSM])
        );
    }
}
