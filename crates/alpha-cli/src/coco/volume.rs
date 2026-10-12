//! Encrypted persistent volumes for a Kata confidential pod (PRD-02 deliverable 25, Option A):
//! what `render` and `wrap` add to a pod for each one, and the one change they make to
//! genpolicy's policy for it.
//!
//! For a volume `<name>` the pod gets:
//! - a block-mode claim, `alpha-volume-<name>`, which the host provides and sees only as
//!   ciphertext;
//! - the init container `alpha-volume-<name>` (the `alpha-volume` image, privileged inside the
//!   TD for device-mapper and mount), after the runtime sidecar has attested: it opens or formats
//!   the LUKS2 volume under the App's key for `volume.<name>` and mounts it on a memory-backed
//!   `emptyDir` named `<name>` with `Bidirectional` propagation;
//! - in each container that mounts `<name>`, that `emptyDir` with `HostToContainer` propagation,
//!   so it sees the opened filesystem.
//!
//! genpolicy 4.1.0 writes every `emptyDir` bind mount as `rprivate` whatever the spec's
//! propagation, which would refuse these two mounts. [`propagate`] sets exactly them, by
//! container and volume, to what containerd sends for the spec (`rshared` and `rslave`), and the
//! baseline lets only `alpha-volume-*` share a mount or run privileged.

use std::collections::{BTreeMap, BTreeSet};

use alpha_core::coco::policy::{DATA_PREFIX, VOLUME_CONTAINER_PREFIX};
use serde_json::{Value, json};

use super::policy::{self, PolicyContainer};

/// Where the claim's block device appears in the init container.
pub const DEVICE_PATH: &str = "/dev/alpha-volume";
/// Where the init container mounts the opened filesystem.
pub const MOUNT_DIR: &str = "/run/alpha-volume";
/// The source genpolicy gives a memory `emptyDir` named `<name>`.
const EPHEMERAL_SOURCE: &str = "/run/kata-containers/sandbox/ephemeral/";
/// The volume's name, as `alpha-volume` takes it.
pub const MAX_NAME: usize = 40;

pub fn container_name(name: &str) -> String {
    format!("{VOLUME_CONTAINER_PREFIX}{name}")
}

pub fn claim_name(name: &str) -> String {
    format!("alpha-volume-{name}")
}

fn device_volume(name: &str) -> String {
    format!("alpha-pv-{name}")
}

/// `<n>Mi`, `<n>Gi` or `<n>Ti`, at least 1 GiB, as a claim's request.
pub fn check_size(size: &str) -> Result<(), String> {
    let (n, unit) = size.split_at(size.len().saturating_sub(2));
    let mib = match unit {
        "Mi" => 1u64,
        "Gi" => 1024,
        "Ti" => 1024 * 1024,
        _ => 0,
    };
    let ok = !n.is_empty()
        && !n.starts_with('0')
        && n.bytes().all(|b| b.is_ascii_digit())
        && n.parse::<u64>()
            .ok()
            .and_then(|n| n.checked_mul(mib))
            .is_some_and(|m| (1024..=1 << 30).contains(&m));
    if ok {
        Ok(())
    } else {
        Err(format!(
            "size {size:?}: a whole number of Mi, Gi or Ti, at least 1Gi"
        ))
    }
}

pub fn check_name(name: &str, place: &str) -> Result<(), String> {
    let ok = !name.is_empty()
        && name.len() <= MAX_NAME
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && name
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphanumeric())
        && name
            .bytes()
            .last()
            .is_some_and(|b| b.is_ascii_alphanumeric());
    if ok {
        Ok(())
    } else {
        Err(format!(
            "{place}.{name}: a persistent volume's name is lowercase letters, digits and `-`, at most {MAX_NAME} characters; rename it"
        ))
    }
}

/// The block-mode claim the host provides; the cluster's default storage class serves it.
// ponytail: the storage class is the cluster's default until PRD-01 names one for CoCo volumes.
pub fn claim(name: &str, size: &str) -> Value {
    json!({
        "apiVersion": "v1",
        "kind": "PersistentVolumeClaim",
        "metadata": { "name": claim_name(name) },
        "spec": {
            "accessModes": ["ReadWriteOnce"],
            "volumeMode": "Block",
            "resources": { "requests": { "storage": size } },
        },
    })
}

/// The init container that opens volume `name`.
pub fn init_container(name: &str, image: &str, socket_volume: &str) -> Value {
    json!({
        "name": container_name(name),
        "image": image,
        "args": ["open", name, DEVICE_PATH, MOUNT_DIR],
        // In the TD only: device-mapper and mount. The policy pins it by image digest and args.
        "securityContext": { "privileged": true },
        "volumeDevices": [{ "name": device_volume(name), "devicePath": DEVICE_PATH }],
        "volumeMounts": [
            { "name": socket_volume, "mountPath": "/run/alpha" },
            { "name": name, "mountPath": MOUNT_DIR, "mountPropagation": "Bidirectional" },
        ],
    })
}

/// The pod's volumes for `name`: the memory `emptyDir` the filesystem is mounted on, and the
/// claim.
pub fn pod_volumes(name: &str) -> [Value; 2] {
    [
        json!({ "name": name, "emptyDir": { "medium": "Memory", "sizeLimit": "1Mi" } }),
        json!({ "name": device_volume(name), "persistentVolumeClaim": { "claimName": claim_name(name) } }),
    ]
}

/// The propagation a container that mounts the volume needs to see the opened filesystem.
pub const APP_PROPAGATION: &str = "HostToContainer";

/// Sets, in genpolicy's `policy_data`, the propagation of each volume's two kinds of mount:
/// `rshared` for `alpha-volume-<name>`'s mount at [`MOUNT_DIR`], `rslave` for every other
/// container's mount of the `<name>` emptyDir. Each must be found and must be `rprivate`.
pub fn propagate(policy: &str, names: &BTreeSet<String>) -> Result<String, String> {
    if names.is_empty() {
        return Ok(policy.to_owned());
    }
    let bad = |m: String| format!("agent policy: {m}");
    let data = policy
        .strip_prefix(policy::RULES)
        .and_then(|rest| rest.strip_prefix(DATA_PREFIX))
        .ok_or_else(|| bad("not the Alpha rules followed by policy_data".into()))?;
    let mut data: Value = alpha_core::parse(data.trim_end_matches('\n').as_bytes())
        .map_err(|e| bad(e.to_string()))?;
    let mut changed: BTreeMap<&str, (usize, usize)> =
        names.iter().map(|n| (n.as_str(), (0, 0))).collect();
    let containers = data
        .get_mut("containers")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| bad("no containers".into()))?;
    for container in containers {
        let name = container
            .pointer("/OCI/Annotations/io.kubernetes.cri.container-name")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let Some(mounts) = container
            .pointer_mut("/OCI/Mounts")
            .and_then(Value::as_array_mut)
        else {
            continue;
        };
        for mount in mounts {
            let source = mount
                .get("source")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let destination = mount
                .get("destination")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let Some((volume, count)) = changed
                .iter_mut()
                .find(|(v, _)| source == format!("^{EPHEMERAL_SOURCE}{v}$"))
            else {
                continue;
            };
            let (from, to) = if name == container_name(volume) && destination == MOUNT_DIR {
                count.0 = count.0.saturating_add(1);
                ("rprivate", "rshared")
            } else {
                count.1 = count.1.saturating_add(1);
                ("rprivate", "rslave")
            };
            let option = mount
                .get_mut("options")
                .and_then(Value::as_array_mut)
                .and_then(|o| o.iter_mut().find(|o| o.as_str() == Some(from)))
                .ok_or_else(|| bad(format!("{name}'s mount of {volume} is not {from}")))?;
            *option = json!(to);
        }
    }
    if let Some((volume, _)) = changed
        .iter()
        .find(|(_, (own, users))| *own != 1 || *users == 0)
    {
        return Err(bad(format!(
            "volume {volume} is not mounted once by its init container and by at least one other"
        )));
    }
    let data = serde_json::to_string_pretty(&data).map_err(|e| bad(e.to_string()))?;
    Ok(format!("{}{DATA_PREFIX}{data}", policy::RULES))
}

/// The privileged containers the policy admits must be exactly the volume init containers the
/// pod declares, each with the image it declares.
pub fn check_elevated(
    verified: &policy::Verified,
    volume_containers: &BTreeSet<PolicyContainer>,
) -> Result<(), String> {
    let elevated: BTreeSet<&PolicyContainer> = verified
        .containers
        .iter()
        .filter(|c| verified.elevated.contains(&c.name))
        .collect();
    if elevated != volume_containers.iter().collect() {
        return Err(format!(
            "agent policy: privileged containers {:?}, the pod's volume containers {:?}",
            elevated, volume_containers
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_and_names() {
        for good in ["1Gi", "1024Mi", "10Gi", "2Ti"] {
            check_size(good).unwrap();
        }
        for bad in [
            "", "Gi", "0Gi", "01Gi", "512Mi", "1G", "1.5Gi", "-1Gi", "2048Ti",
        ] {
            assert!(check_size(bad).is_err(), "{bad}");
        }
        check_name("pgdata", "volumes").unwrap();
        for bad in ["", "-a", "a-", "a.b", "A", &"a".repeat(41)] {
            assert!(check_name(bad, "volumes").is_err(), "{bad}");
        }
    }
}
