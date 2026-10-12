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

/// genpolicy 4.1.0's `rules.rego` (kata-containers' `kata-tools-static-4.1.0-amd64.tar.zst`),
/// which every accepted policy starts with.
pub const RULES: &str = include_str!("genpolicy/rules.rego");
/// What genpolicy prints between the rules and the data.
pub const DATA_PREFIX: &str = "\npolicy_data := ";
/// `ALPHACOMPUTE_KMS_ENDPOINTS` comes from the namespace's `alpha-kms` ConfigMap, not the policy:
/// the endpoints are only where to connect, since the runtime pins the KMS CA and Revisions. The
/// policy admits the variable only as a list of `https://host[:port]`.
pub const KMS_ENDPOINTS_ENV_REGEX: &str = "^ALPHACOMPUTE_KMS_ENDPOINTS=https://[a-z0-9.-]{1,253}(:[0-9]{1,5})?(,https://[a-z0-9.-]{1,253}(:[0-9]{1,5})?){0,7}$";
/// The only environment variables the host may add to a container beyond those the policy
/// lists: the pod's hostname (set by the runtime) and the KMS endpoints. Kubernetes service links
/// and the cloud identity variables genpolicy admits by default are not among them.
pub const ALLOWED_ENV_REGEX: [&str; 2] = ["^HOSTNAME=$(dns_label)$", KMS_ENDPOINTS_ENV_REGEX];
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
            bad("not genpolicy 4.1.0's rules.rego followed by policy_data; regenerate it with `alpha coco genpolicy-settings` and genpolicy 4.1.0 rather than editing the rules")
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
    if *at("/request_defaults/CreateContainerRequest/allow_env_regex") != json!(ALLOWED_ENV_REGEX) {
        return Err(bad(
            "allow_env_regex admits host-provided environment variables beyond HOSTNAME and the KMS endpoints",
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
    for container in containers {
        let commands = container.get("exec_commands").unwrap_or(&Value::Null);
        if !commands.as_array().is_some_and(Vec::is_empty) {
            return Err(bad(
                "a container allows exec commands (an exec probe or hook)",
            ));
        }
        let annotation = |key: &str| {
            container
                .pointer(&format!("/OCI/Annotations/{}", key.replace('/', "~1")))
                .and_then(Value::as_str)
        };
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
            "\"^HOSTNAME=$(dns_label)$\"",
            "\"^HOSTNAME=$(dns_label)$\", \"^.*$\"",
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
