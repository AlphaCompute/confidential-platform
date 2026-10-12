//! Option B (PRD-02 deliverable 26): what a pod asks of the Confidential Data Hub, and the
//! generator's side of it.
//!
//! - **The KBS.** An App that opts in gets `aa.toml` and `cdh.toml` in its init-data
//!   ([`alpha_core::coco::kbs`]), pointing the attestation agent and CDH at Trustee's KBS. Its URL
//!   and certificate are generator inputs (`--kbs-url`, `--kbs-cert`) and end up measured; without
//!   them an App that asks for the KBS is refused, never given a default.
//! - **Sealed secrets.** An environment value `sealed.<JWS>` that the Kata agent has CDH unseal
//!   before the container starts. The agent policy pins the sealed value like any other, so the
//!   host can neither swap nor add one; [`check_sealed`] holds it to the resource contract (a
//!   `vault` secret of this App's `secret/<name>`, signed under its `sealed-secret-key/<name>`).
//! - **Encrypted images.** Nothing here: CDH pulls and decrypts in the guest with the key-encryption
//!   key its layer annotations name (`image-key/<name>`), and the policy pins the image by digest.
//! - **Encrypted scratch volumes** (`x-alphacompute-scratch`): a disk-backed `emptyDir`, which Kata
//!   4.1.0's CoCo runtime classes (`emptydir_mode = "block-encrypted"`) hand the agent as a block
//!   device that CDH formats with LUKS2 under a random key generated in the TD. The baseline
//!   ([`alpha_core::coco::policy::verify`]) refuses any other disk-backed storage.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use alpha_core::AppId;
use alpha_core::coco::kbs::{KbsConfig, Resource, ResourceType};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use serde_yaml_ng::Value as Yaml;

use super::policy::Verified;

/// The compose's top-level opt-in: `x-alphacompute-kbs: true`.
pub const KBS_KEY: &str = "x-alphacompute-kbs";
/// The compose's encrypted scratch volumes: `x-alphacompute-scratch: {<volume>: {size: 50Gi}}`.
pub const SCRATCH_KEY: &str = "x-alphacompute-scratch";
/// What the Kata agent looks for to unseal an environment value.
pub const SEALED_PREFIX: &str = "sealed.";
/// The sealed-secret format version CDH reads.
const SEALED_VERSION: &str = "0.1.0";

/// The KBS from the generator's flags: both or neither.
pub fn kbs_from_flags(url: Option<&str>, cert: Option<&Path>) -> Result<Option<KbsConfig>, String> {
    match (url, cert) {
        (None, None) => Ok(None),
        (Some(url), Some(cert)) => {
            let pem =
                std::fs::read_to_string(cert).map_err(|e| format!("{}: {e}", cert.display()))?;
            KbsConfig::new(url, &pem).map(Some)
        }
        _ => Err("--kbs-url and --kbs-cert come together".into()),
    }
}

/// Whether the compose opts in to the KBS ([`KBS_KEY`]).
pub fn kbs_requested(compose: &[u8]) -> Result<bool, String> {
    let root: Yaml = serde_yaml_ng::from_slice(compose).map_err(|e| format!("compose: {e}"))?;
    match root.get(KBS_KEY) {
        None => Ok(false),
        Some(Yaml::Bool(b)) => Ok(*b),
        Some(_) => Err(format!("{KBS_KEY}: write true or false")),
    }
}

/// Reads [`SCRATCH_KEY`] from the compose's bytes, which `parse` has already accepted.
pub fn scratch_volumes(compose: &[u8]) -> Result<BTreeMap<String, String>, String> {
    let root: Yaml = serde_yaml_ng::from_slice(compose).map_err(|e| format!("compose: {e}"))?;
    let Some(section) = root.get(SCRATCH_KEY) else {
        return Ok(BTreeMap::new());
    };
    let place = SCRATCH_KEY;
    let section = section
        .as_mapping()
        .ok_or_else(|| format!("{place}: not a mapping; write <volume>: {{size: 50Gi}}"))?;
    let mut out = BTreeMap::new();
    for (name, spec) in section {
        let name = name.as_str().ok_or_else(|| {
            format!(
                "{place}: {} is not a volume name",
                crate::deploy::wrap::shown(name)
            )
        })?;
        super::volume::check_name(name, place)?;
        let size = spec
            .as_mapping()
            .filter(|m| m.len() == 1)
            .and_then(|m| m.get("size"))
            .and_then(Yaml::as_str)
            .ok_or_else(|| format!("{place}.{name}: write {{size: <n>Gi}} and nothing else"))?;
        super::volume::check_size(size).map_err(|e| format!("{place}.{name}: {e}"))?;
        out.insert(name.to_owned(), size.to_owned());
    }
    Ok(out)
}

/// A scratch volume in the pod: disk-backed, so the runtime class serves it as a block device
/// that CDH encrypts in the guest.
pub fn scratch_volume(name: &str, size: &str) -> Value {
    json!({ "name": name, "emptyDir": { "sizeLimit": size } })
}

/// genpolicy's `HOSTNAME=$(host-name)`, which its rules let the host set to anything (a sealed
/// value copied from the policy included), pinned to the sandbox's name: the rules then match it
/// against the policy's sandbox-name pattern. Kubernetes sets a pod's `HOSTNAME` to the pod's
/// name, which is the sandbox's.
// ponytail: G0 — confirm containerd 2.3.x sets HOSTNAME to the full pod name on the pinned
// stack; a pod name over 63 characters is truncated and would refuse every container (closed).
/// Anything but the Alpha rules followed by data is returned as it is, for `verify` to refuse.
pub fn pin_hostname(policy: &str) -> String {
    use alpha_core::coco::policy::{DATA_PREFIX, RULES};
    match policy
        .strip_prefix(RULES)
        .and_then(|rest| rest.strip_prefix(DATA_PREFIX))
    {
        Some(data) => {
            let data = data.replace("\"HOSTNAME=$(host-name)\"", "\"HOSTNAME=$(sandbox-name)\"");
            format!("{RULES}{DATA_PREFIX}{data}")
        }
        None => policy.to_owned(),
    }
}

/// What a sealed secret refers to.
#[derive(Debug, PartialEq, Eq)]
pub struct Sealed {
    /// `secret/<name>`: the value CDH unseals.
    pub secret: Resource,
    /// `sealed-secret-key/<name>`: the public JWK its signature verifies under.
    pub signing_key: Resource,
}

/// `value` is a sealed secret that CDH at [`alpha_core::coco::kbs::GUEST_COMPONENTS`] unseals
/// from this App's resources and nothing else: a `vault` secret of provider `kbs`, signed ES256
/// (CDH verifies the signature; this checks only its form).
pub fn check_sealed(value: &str, app: AppId) -> Result<Sealed, String> {
    let bad = |m: &str| format!("sealed secret: {m}");
    let jws = value
        .strip_prefix(SEALED_PREFIX)
        .ok_or_else(|| bad("does not start with sealed."))?;
    let parts: Vec<&str> = jws.split('.').collect();
    let [header, payload, signature] = parts.as_slice() else {
        return Err(bad("not sealed.<header>.<payload>.<signature>"));
    };
    let decode = |part: &str, what: &str| {
        BASE64_URL_SAFE_NO_PAD
            .decode(part)
            .map_err(|_| bad(&format!("{what} is not base64url")))
    };
    let object = |part: &str, what: &str| -> Result<serde_json::Map<String, Value>, String> {
        let bytes = decode(part, what)?;
        match alpha_core::parse(&bytes) {
            Ok(Value::Object(map)) => Ok(map),
            _ => Err(bad(&format!("{what} is not a JSON object"))),
        }
    };
    let own = |uri: Option<&Value>, kind: ResourceType, what: &str| -> Result<Resource, String> {
        let uri = uri
            .and_then(Value::as_str)
            .ok_or_else(|| bad(&format!("no {what}")))?;
        let resource = Resource::parse(uri).map_err(|e| bad(&format!("{what}: {e}")))?;
        if resource.kind != kind || resource.app != app {
            return Err(bad(&format!(
                "{what} {uri} is not this App's {}/<name>",
                kind.name()
            )));
        }
        Ok(resource)
    };

    let header = object(header, "header")?;
    let keys: BTreeSet<&str> = header.keys().map(String::as_str).collect();
    if keys != BTreeSet::from(["alg", "kid"]) || header.get("alg") != Some(&json!("ES256")) {
        return Err(bad("the header is not {alg: ES256, kid}"));
    }
    let signing_key = own(header.get("kid"), ResourceType::SealedSecretKey, "kid")?;

    let payload = object(payload, "payload")?;
    let keys: BTreeSet<&str> = payload.keys().map(String::as_str).collect();
    let expected = BTreeSet::from([
        "version",
        "type",
        "name",
        "provider",
        "provider_settings",
        "annotations",
    ]);
    let empty = Some(&json!({}));
    if keys != expected
        || payload.get("version") != Some(&json!(SEALED_VERSION))
        || payload.get("type") != Some(&json!("vault"))
        || payload.get("provider") != Some(&json!("kbs"))
        || payload.get("provider_settings") != empty
        || payload.get("annotations") != empty
    {
        return Err(bad(
            "only a vault secret of provider kbs, with no provider settings or annotations, is unsealed from the KBS",
        ));
    }
    let secret = own(payload.get("name"), ResourceType::Secret, "name")?;
    if decode(signature, "signature")?.len() != 64 {
        return Err(bad("the signature is not an ES256 signature"));
    }
    Ok(Sealed {
        secret,
        signing_key,
    })
}

/// A sealed environment value of one container.
#[derive(Debug)]
pub struct SealedEnv {
    pub container: String,
    pub name: String,
    pub value: String,
}

/// Every sealed environment value in `containers`: allowed only when the pod has the KBS, and
/// each a well-formed sealed secret of this App, set as a literal on a container.
pub fn sealed_env(containers: &[Yaml], app: AppId, kbs: bool) -> Result<Vec<SealedEnv>, String> {
    let mut out = Vec::new();
    for c in containers {
        let container = c.get("name").and_then(Yaml::as_str).unwrap_or_default();
        for entry in c
            .get("env")
            .and_then(Yaml::as_sequence)
            .into_iter()
            .flatten()
        {
            let name = entry.get("name").and_then(Yaml::as_str).unwrap_or_default();
            let Some(value) = entry
                .get("value")
                .and_then(Yaml::as_str)
                .filter(|v| v.starts_with(SEALED_PREFIX))
            else {
                continue;
            };
            let place = format!("{container}: {name}");
            if !kbs {
                return Err(format!(
                    "{place}: a sealed secret is unsealed from the KBS, which this App has not opted in to ({KBS_KEY})"
                ));
            }
            check_sealed(value, app).map_err(|e| format!("{place}: {e}"))?;
            out.push(SealedEnv {
                container: container.to_owned(),
                name: name.to_owned(),
                value: value.to_owned(),
            });
        }
    }
    Ok(out)
}

/// The policy pins each sealed value exactly, on its container.
pub fn check_pinned(sealed: &[SealedEnv], verified: &Verified) -> Result<(), String> {
    for s in sealed {
        let entry = format!("{}={}", s.name, s.value);
        if !verified
            .env
            .get(&s.container)
            .is_some_and(|env| env.contains(&entry))
        {
            return Err(format!(
                "{}: {}: the agent policy does not pin this sealed value; generate the policy from this spec",
                s.container, s.name
            ));
        }
    }
    Ok(())
}

/// [`sealed_env`], then [`check_pinned`].
pub fn check_sealed_env(
    containers: &[Yaml],
    app: AppId,
    kbs: bool,
    verified: &Verified,
) -> Result<(), String> {
    check_pinned(&sealed_env(containers, app, kbs)?, verified)
}

#[cfg(test)]
pub(crate) mod tests;
