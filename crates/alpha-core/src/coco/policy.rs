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
/// back to the guest (the opened volume, which the App's container then mounts). The name is
/// reserved, not a credential: a container under it is admitted only as exactly the volume
/// opener ([`verify_with_volumes`]), with an image the release-signed platform document lists.
pub const VOLUME_CONTAINER_PREFIX: &str = "alpha-volume-";
/// The `alpha-volume` image's `ENTRYPOINT` (`images/volume/Dockerfile`), which genpolicy puts
/// before the container's args; a stand-in image without one runs the args as they are.
pub const VOLUME_ENTRYPOINT: &str = "/alpha-volume";
/// Where the claim's block device appears in the volume container.
pub const VOLUME_DEVICE_PATH: &str = "/dev/alpha-volume";
/// Where the volume container mounts the opened filesystem, shared back to the guest.
pub const VOLUME_MOUNT_DIR: &str = "/run/alpha-volume";
/// Where the volume container reaches `alpha-runtime`'s socket.
pub const VOLUME_SOCKET_DIR: &str = "/run/alpha";
/// The pod volume holding `alpha-runtime`'s socket (alpha-cli's `coco::wrap::SOCKET_VOLUME`).
pub const VOLUME_SOCKET_VOLUME: &str = "alpha-run";
/// The longest volume name `alpha-volume` takes.
pub const VOLUME_MAX_NAME: usize = 40;
/// The only environment the volume container may list: the image's `PATH` (Alpine's).
pub const VOLUME_ENV: [&str; 1] =
    ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"];
/// Where genpolicy puts a memory `emptyDir`, as the pattern its policy matches the source with.
const EPHEMERAL_SOURCE: &str = "^/run/kata-containers/sandbox/ephemeral/";
/// The mounts genpolicy 4.1.0 gives every container, by destination and source; the volume
/// container may have these besides its two bind mounts and nothing else.
const STANDARD_MOUNTS: [(&str, &str); 11] = [
    ("/proc", "proc"),
    ("/dev", "tmpfs"),
    ("/dev/pts", "devpts"),
    ("/dev/shm", "/run/kata-containers/sandbox/shm"),
    ("/dev/mqueue", "mqueue"),
    ("/sys", "sysfs"),
    ("/sys/fs/cgroup", "cgroup"),
    ("/etc/hosts", "$(sfprefix)hosts$"),
    ("/dev/termination-log", "$(sfprefix)termination-log$"),
    ("/etc/hostname", "$(sfprefix)hostname$"),
    ("/etc/resolv.conf", "$(sfprefix)resolv.conf$"),
];
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
/// baseline; a single trailing newline, which an editor adds, is allowed. No container may be
/// privileged, share a mount back to the guest or be named `alpha-volume-*`: a pod with
/// encrypted volumes is checked with [`verify_with_volumes`].
pub fn verify(policy: &str) -> Result<Verified, String> {
    verify_with_volumes(policy, &BTreeSet::new())
}

/// [`verify`], admitting `alpha-volume-<name>` containers that open encrypted persistent
/// volumes. `volume_images` are the `alpha-volume` images the release-signed platform document
/// lists (`alpha_volume_images`), never ones the pod's author chose: such a container must run
/// one of them, exactly as `alpha-volume open <name>` with only its device, its socket and the
/// volume's mount, and it is then the only container that may be privileged or share a mount.
pub fn verify_with_volumes(
    policy: &str,
    volume_images: &BTreeSet<String>,
) -> Result<Verified, String> {
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
        match name.strip_prefix(VOLUME_CONTAINER_PREFIX) {
            Some(volume) => volume_container(container, name, volume, image, volume_images)
                .map_err(|m| bad(&m))?,
            None if is_elevated || shares_mounts => {
                return Err(bad(&format!(
                    "container {name} is privileged or shares mounts back to the guest; only {VOLUME_CONTAINER_PREFIX}* may"
                )));
            }
            None => {}
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

/// A volume's name as `alpha-volume` takes it: lowercase letters, digits and `-`, starting and
/// ending with a letter or digit, at most [`VOLUME_MAX_NAME`] characters.
pub fn is_volume_name(name: &str) -> bool {
    let edge = |b: Option<u8>| b.is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    name.len() <= VOLUME_MAX_NAME
        && edge(name.bytes().next())
        && edge(name.bytes().last())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// `alpha-volume-<volume>` as the policy admits it must be exactly the volume opener: an
/// image from `volume_images`, the args `open <volume> <device> <mount dir>` (after the image's
/// entrypoint, or alone), the image's `PATH` and nothing else in its environment, the claim's
/// device and no other, and besides genpolicy's standard mounts only the runtime's socket and
/// the volume's own `emptyDir`, which alone it shares back (`rshared`).
fn volume_container(
    container: &Value,
    name: &str,
    volume: &str,
    image: &str,
    volume_images: &BTreeSet<String>,
) -> Result<(), String> {
    if !is_volume_name(volume) {
        return Err(format!(
            "container {name}: {volume:?} is not a volume name; {VOLUME_CONTAINER_PREFIX}* is reserved for alpha-volume"
        ));
    }
    if !volume_images.contains(image) {
        return Err(format!(
            "container {name}'s image {image} is not an alpha-volume image the platform document lists; {VOLUME_CONTAINER_PREFIX}* runs only those"
        ));
    }
    let strings = |pointer: &str| -> Option<Vec<&str>> {
        container
            .pointer(pointer)
            .and_then(Value::as_array)?
            .iter()
            .map(Value::as_str)
            .collect()
    };
    let args = strings("/OCI/Process/Args").unwrap_or_default();
    let open = ["open", volume, VOLUME_DEVICE_PATH, VOLUME_MOUNT_DIR];
    let entry = [VOLUME_ENTRYPOINT];
    if args != open && args != [entry.as_slice(), open.as_slice()].concat() {
        return Err(format!(
            "container {name} runs {args:?}, not alpha-volume open {volume} {VOLUME_DEVICE_PATH} {VOLUME_MOUNT_DIR}"
        ));
    }
    let env = strings("/OCI/Process/Env").unwrap_or_default();
    if let Some(var) = env.iter().find(|e| !VOLUME_ENV.contains(e)) {
        return Err(format!(
            "container {name} lists {var}; the volume container takes only its image's PATH"
        ));
    }
    let paths = |pointer: &str, key: &str| -> Option<Vec<&str>> {
        container
            .pointer(pointer)
            .and_then(Value::as_array)?
            .iter()
            .map(|d| d.get(key).and_then(Value::as_str))
            .collect()
    };
    let devices = paths("/OCI/Linux/Devices", "Path");
    let device_paths = paths("/devices", "container_path");
    let only = Some(vec![VOLUME_DEVICE_PATH]);
    if devices != only || device_paths != only {
        return Err(format!(
            "container {name} takes devices {devices:?}; the volume container takes only {VOLUME_DEVICE_PATH}"
        ));
    }
    let volume_source = format!("{EPHEMERAL_SOURCE}{volume}$");
    let socket_source = format!("{EPHEMERAL_SOURCE}{VOLUME_SOCKET_VOLUME}$");
    let (mut opened, mut socket) = (0usize, 0usize);
    let mounts = container
        .pointer("/OCI/Mounts")
        .and_then(Value::as_array)
        .ok_or_else(|| format!("container {name} has no mounts"))?;
    for mount in mounts {
        let field = |key: &str| mount.get(key).and_then(Value::as_str).unwrap_or_default();
        let (destination, source) = (field("destination"), field("source"));
        let options = mount
            .get("options")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let shared = options.iter().any(|o| o.as_str() == Some("rshared"));
        if destination == VOLUME_MOUNT_DIR && source == volume_source {
            if *options != [json!("rbind"), json!("rshared"), json!("rw")] {
                return Err(format!(
                    "container {name}'s mount of {volume} is not rbind, rshared, rw"
                ));
            }
            opened = opened.saturating_add(1);
        } else if shared {
            return Err(format!(
                "container {name} shares {destination} back to the guest; only {VOLUME_MOUNT_DIR} may be"
            ));
        } else if destination == VOLUME_SOCKET_DIR && source == socket_source {
            socket = socket.saturating_add(1);
        } else if !STANDARD_MOUNTS.contains(&(destination, source)) {
            return Err(format!(
                "container {name} mounts {source} at {destination}; the volume container mounts only the runtime's socket and its volume"
            ));
        }
    }
    if (opened, socket) != (1, 1) {
        return Err(format!(
            "container {name} does not mount the runtime's socket and its volume once each"
        ));
    }
    Ok(())
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

    const VOLUME_IMAGE: &str = "ghcr.io/alphacompute/alpha-volume@sha256:1111111111111111111111111111111111111111111111111111111111111111";

    /// `base` with `extra` added to its containers.
    fn with_container(base: &str, extra: Value) -> String {
        let data = base
            .strip_prefix(RULES)
            .and_then(|d| d.strip_prefix(DATA_PREFIX))
            .unwrap();
        let mut data: Value = serde_json::from_str(data).unwrap();
        data["containers"].as_array_mut().unwrap().push(extra);
        format!("{RULES}{DATA_PREFIX}{data:#}")
    }

    /// `alpha-volume-<volume>` as genpolicy 4.1.0 writes it for the alpha-volume image.
    fn volume_container(volume: &str, image: &str) -> Value {
        let mut mounts: Vec<Value> = STANDARD_MOUNTS
            .iter()
            .map(|(d, s)| json!({ "destination": d, "source": s, "options": ["rbind"] }))
            .collect();
        mounts.push(json!({
            "destination": VOLUME_SOCKET_DIR,
            "source": format!("{EPHEMERAL_SOURCE}{VOLUME_SOCKET_VOLUME}$"),
            "options": ["rbind", "rprivate", "rw"],
        }));
        mounts.push(json!({
            "destination": VOLUME_MOUNT_DIR,
            "source": format!("{EPHEMERAL_SOURCE}{volume}$"),
            "options": ["rbind", "rshared", "rw"],
        }));
        json!({
            "OCI": {
                "Annotations": {
                    TYPE_ANNOTATION: "container",
                    NAME_ANNOTATION: format!("{VOLUME_CONTAINER_PREFIX}{volume}"),
                    IMAGE_ANNOTATION: image,
                },
                "Process": {
                    "Args": [VOLUME_ENTRYPOINT, "open", volume, VOLUME_DEVICE_PATH, VOLUME_MOUNT_DIR],
                    "Env": VOLUME_ENV,
                    "Capabilities": { "Bounding": ["$(privileged_caps)"] },
                },
                "Mounts": mounts,
                "Linux": { "Devices": [{ "Type": "", "Path": VOLUME_DEVICE_PATH }] },
            },
            "devices": [{ "container_path": VOLUME_DEVICE_PATH, "options": [] }],
            "exec_commands": [],
        })
    }

    fn listed() -> BTreeSet<String> {
        BTreeSet::from([VOLUME_IMAGE.to_owned()])
    }

    #[test]
    fn only_a_volume_container_runs_privileged_or_shares_a_mount() {
        let base = policy(&["PATH=/bin"]);
        let good = with_container(&base, volume_container("pg", VOLUME_IMAGE));
        let verified = verify_with_volumes(&good, &listed()).unwrap();
        assert_eq!(
            verified.elevated,
            BTreeSet::from(["alpha-volume-pg".to_owned()])
        );
        // A stand-in image without the entrypoint runs the args alone.
        let mut bare = volume_container("pg", VOLUME_IMAGE);
        bare["OCI"]["Process"]["Args"] =
            json!(["open", "pg", VOLUME_DEVICE_PATH, VOLUME_MOUNT_DIR]);
        verify_with_volumes(&with_container(&base, bare), &listed()).unwrap();

        let caps = r#""Process": { "Capabilities": { "Bounding": ["$(privileged_caps)"] }, "#;
        let as_app = base.replace("\"Process\": {", caps);
        assert!(
            verify_with_volumes(&as_app, &listed())
                .unwrap_err()
                .contains("privileged")
        );
        let shared = base.replace(
            "\"Process\": {",
            r#""Mounts": [{ "destination": "/data", "options": ["rbind", "rshared", "rw"] }], "Process": {"#,
        );
        assert!(
            verify_with_volumes(&shared, &listed())
                .unwrap_err()
                .contains("shares mounts")
        );
    }

    /// ACC-FD-100: the `alpha-volume-` name is not what grants privilege. A container under it
    /// that runs an image the platform document does not list is refused, digest-pinned or not,
    /// and so is every one when no list is given.
    #[test]
    fn a_volume_container_runs_only_a_listed_image() {
        let base = policy(&["PATH=/bin"]);
        let attacker = format!(
            "registry.example/attacker/volume@sha256:{}",
            "ab".repeat(32)
        );
        let spoofed = with_container(&base, volume_container("x", &attacker));
        let error = verify_with_volumes(&spoofed, &listed()).unwrap_err();
        assert!(error.contains("not an alpha-volume image"), "{error}");
        // The listed image under the same name passes; with no list, nothing does.
        let good = with_container(&base, volume_container("x", VOLUME_IMAGE));
        verify_with_volumes(&good, &listed()).unwrap();
        assert!(
            verify(&good)
                .unwrap_err()
                .contains("not an alpha-volume image")
        );
        assert!(dsm_pinned(&good, DSM).is_err());
        // Unprivileged and sharing nothing, the name is still reserved.
        let mut quiet = volume_container("x", &attacker);
        quiet["OCI"]["Process"]["Capabilities"] = json!({ "Bounding": [DEFAULT_CAPS] });
        assert!(verify_with_volumes(&with_container(&base, quiet), &listed()).is_err());
    }

    /// The listed image is held to the opener's exact args, environment, device and mounts, so
    /// a policy cannot run a shell from it or hand it more of the guest.
    #[test]
    fn a_volume_container_is_exactly_the_opener() {
        let base = policy(&["PATH=/bin"]);
        let refused = |edit: &dyn Fn(&mut Value), why: &str| {
            let mut container = volume_container("pg", VOLUME_IMAGE);
            edit(&mut container);
            let error =
                verify_with_volumes(&with_container(&base, container), &listed()).unwrap_err();
            assert!(error.contains(why), "{why}: {error}");
        };
        fn args(c: &mut Value) -> &mut Value {
            &mut c["OCI"]["Process"]["Args"]
        }
        fn mounts(c: &mut Value) -> &mut Vec<Value> {
            c["OCI"]["Mounts"].as_array_mut().unwrap()
        }
        refused(
            &|c| {
                *args(c) = json!([
                    "/bin/sh",
                    "-c",
                    "id",
                    "open",
                    "pg",
                    VOLUME_DEVICE_PATH,
                    VOLUME_MOUNT_DIR
                ])
            },
            "runs",
        );
        refused(
            &|c| args(c).as_array_mut().unwrap().push(json!("--debug")),
            "runs",
        );
        refused(
            &|c| {
                *args(c) = json!([
                    VOLUME_ENTRYPOINT,
                    "open",
                    "other",
                    VOLUME_DEVICE_PATH,
                    VOLUME_MOUNT_DIR
                ])
            },
            "runs",
        );
        refused(
            &|c| c["OCI"]["Process"]["Env"] = json!([VOLUME_ENV[0], "LD_PRELOAD=/run/alpha/x.so"]),
            "LD_PRELOAD",
        );
        refused(
            &|c| {
                c["OCI"]["Linux"]["Devices"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({ "Type": "", "Path": "/dev/sda" }));
            },
            "devices",
        );
        refused(&|c| c["devices"] = json!([]), "devices");
        refused(
            &|c| {
                mounts(c).push(json!({
                    "destination": "/host", "source": "/", "options": ["rbind", "rprivate", "rw"],
                }));
            },
            "mounts / at /host",
        );
        refused(
            &|c| {
                mounts(c).push(json!({
                    "destination": "/data",
                    "source": format!("{EPHEMERAL_SOURCE}app-data$"),
                    "options": ["rbind", "rprivate", "rw"],
                }));
            },
            "mounts",
        );
        refused(
            &|c| {
                mounts(c).push(json!({
                    "destination": VOLUME_SOCKET_DIR,
                    "source": format!("{EPHEMERAL_SOURCE}{VOLUME_SOCKET_VOLUME}$"),
                    "options": ["rbind", "rshared", "rw"],
                }));
            },
            "shares /run/alpha",
        );
        refused(
            &|c| {
                mounts(c).retain(|m| m["destination"] != json!(VOLUME_MOUNT_DIR));
            },
            "once each",
        );
        refused(
            &|c| {
                let opened = mounts(c).last().unwrap().clone();
                mounts(c).push(opened);
            },
            "once each",
        );
        // A name the policy would read as a pattern over other emptyDirs.
        let mut wild = volume_container("pg", VOLUME_IMAGE);
        wild["OCI"]["Annotations"][NAME_ANNOTATION] = json!("alpha-volume-.*");
        let error = verify_with_volumes(&with_container(&base, wild), &listed()).unwrap_err();
        assert!(error.contains("not a volume name"), "{error}");
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
