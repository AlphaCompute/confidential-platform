//! A Kata confidential pod's identity: its init-data and the Revision v2 derived from it.
//!
//! Kata binds the digest of the init-data document into the TD's MRCONFIGID at launch, and the
//! agent policy the pod runs under is one of its entries. So the init-data, and nothing the host
//! controls, says what may run in the pod. Our own entry, `alpha.json`, names the App, the runtime
//! class and the GPUs the pod expects; every field of the Revision v2 document is therefore either
//! inside the measured init-data or a digest of it, and the Revision v2 is a pure function of the
//! init-data bytes. The KMS rebuilds it from verified evidence and looks its hash up exactly as it
//! looks up a compose hash today: same `revisions` table, same signature, same leaf SAN.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256, Sha384};

use crate::{AppId, ComposeHash};

/// The `format` of a Revision v2 document. Its SHA-256 over the JCS bytes is the Revision hash.
pub const REVISION_FORMAT: &str = "alphacompute-coco-revision/1";
/// The `format` of our entry in the init-data.
pub const ALPHA_ENTRY_FORMAT: &str = "alphacompute-initdata/1";
/// The init-data entry that carries [`AlphaEntry`].
pub const ALPHA_ENTRY: &str = "alpha.json";
/// The init-data entry that carries the Kata agent policy (Rego), as Kata names it.
pub const POLICY_ENTRY: &str = "policy.rego";
/// The only init-data document version the pinned Kata reads.
pub const INITDATA_VERSION: &str = "0.1.0";
/// The runtime classes a Revision v2 may name; `kata-qemu-nvidia-gpu-snp` waits for the
/// `kata-snp/1` profile (PRD-02, P2).
pub const RUNTIME_CLASSES: [&str; 1] = ["kata-qemu-nvidia-gpu-tdx"];
/// Whole GPUs only (no MIG in CC mode), one or a full eight-GPU node.
pub const GPU_COUNTS: [u32; 2] = [1, 8];
/// Init-data larger than this is refused before it is parsed.
pub const MAX_INITDATA_BYTES: usize = 512 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum CocoError {
    #[error("init-data is over {MAX_INITDATA_BYTES} bytes")]
    TooLarge,
    #[error("init-data is not UTF-8")]
    NotUtf8,
    #[error("init-data is not a CoCo init-data document: {0}")]
    Toml(String),
    #[error("init-data version {0:?} is not {INITDATA_VERSION:?}")]
    Version(String),
    #[error("init-data algorithm {0:?} is not sha256 or sha384")]
    Algorithm(String),
    #[error("init-data has no {0} entry")]
    MissingEntry(&'static str),
    #[error("init-data {ALPHA_ENTRY}: {0}")]
    AlphaEntry(String),
    #[error("revision: {0}")]
    Revision(String),
}

/// The digest algorithm the init-data document declares for its own binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitDataAlgorithm {
    Sha256,
    Sha384,
}

/// A parsed CoCo init-data document, with the exact bytes it was parsed from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitData {
    bytes: Vec<u8>,
    pub algorithm: InitDataAlgorithm,
    pub data: BTreeMap<String, String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InitDataToml {
    algorithm: String,
    version: String,
    #[serde(default)]
    data: BTreeMap<String, String>,
}

impl InitData {
    pub fn parse(bytes: &[u8]) -> Result<Self, CocoError> {
        if bytes.len() > MAX_INITDATA_BYTES {
            return Err(CocoError::TooLarge);
        }
        let text = std::str::from_utf8(bytes).map_err(|_| CocoError::NotUtf8)?;
        let doc: InitDataToml =
            toml::from_str(text).map_err(|e| CocoError::Toml(e.message().to_owned()))?;
        if doc.version != INITDATA_VERSION {
            return Err(CocoError::Version(doc.version));
        }
        let algorithm = match doc.algorithm.as_str() {
            "sha256" => InitDataAlgorithm::Sha256,
            "sha384" => InitDataAlgorithm::Sha384,
            _ => return Err(CocoError::Algorithm(doc.algorithm)),
        };
        Ok(Self {
            bytes: bytes.to_vec(),
            algorithm,
            data: doc.data,
        })
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// What the TD's 48-byte MRCONFIGID holds for this init-data on the pinned Kata: the digest
    /// under the declared algorithm, zero-padded to 48 bytes (a SHA-384 digest fills it).
    // ponytail: Q10 — proven on the pinned Kata at M1 with a golden vector from a B300 pod; if
    // Kata binds it differently, this one function changes.
    pub fn mrconfigid(&self) -> [u8; 48] {
        let mut out = [0u8; 48];
        match self.algorithm {
            InitDataAlgorithm::Sha256 => {
                for (dst, src) in out.iter_mut().zip(Sha256::digest(&self.bytes)) {
                    *dst = src;
                }
            }
            InitDataAlgorithm::Sha384 => out = Sha384::digest(&self.bytes).into(),
        }
        out
    }

    /// SHA-256 of the exact init-data bytes, whatever algorithm the document declares: the
    /// Revision v2's `initdata_sha256`.
    pub fn sha256(&self) -> ComposeHash {
        ComposeHash::from(<[u8; 32]>::from(Sha256::digest(&self.bytes)))
    }

    pub fn policy(&self) -> Result<&str, CocoError> {
        self.data
            .get(POLICY_ENTRY)
            .map(String::as_str)
            .ok_or(CocoError::MissingEntry(POLICY_ENTRY))
    }

    pub fn policy_sha256(&self) -> Result<ComposeHash, CocoError> {
        Ok(crate::compose_hash(self.policy()?))
    }

    pub fn alpha(&self) -> Result<AlphaEntry, CocoError> {
        let text = self
            .data
            .get(ALPHA_ENTRY)
            .ok_or(CocoError::MissingEntry(ALPHA_ENTRY))?;
        let value =
            crate::parse(text.as_bytes()).map_err(|e| CocoError::AlphaEntry(e.to_string()))?;
        let entry: AlphaEntry =
            serde_json::from_value(value).map_err(|e| CocoError::AlphaEntry(e.to_string()))?;
        entry.check().map_err(CocoError::AlphaEntry)?;
        Ok(entry)
    }

    /// The Revision v2 this init-data stands for.
    pub fn revision(&self) -> Result<CocoRevision, CocoError> {
        let alpha = self.alpha()?;
        Ok(CocoRevision {
            format: REVISION_FORMAT.into(),
            app_id: alpha.app_id,
            initdata_sha256: self.sha256(),
            policy_sha256: self.policy_sha256()?,
            runtime_class: alpha.runtime_class,
            gpu: alpha.gpu,
        })
    }
}

/// `alpha.json` inside the init-data.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlphaEntry {
    pub format: String,
    pub app_id: AppId,
    pub runtime_class: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu: Option<GpuShape>,
}

impl AlphaEntry {
    fn check(&self) -> Result<(), String> {
        if self.format != ALPHA_ENTRY_FORMAT {
            return Err(format!("format {:?}", self.format));
        }
        check_shape(&self.runtime_class, self.gpu.as_ref())
    }
}

/// The GPUs a pod expects, every one of them the same model.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GpuShape {
    pub count: u32,
    /// As the GPU policy and the verifier name it, e.g. `B300`.
    pub model: String,
}

fn check_shape(runtime_class: &str, gpu: Option<&GpuShape>) -> Result<(), String> {
    if !RUNTIME_CLASSES.contains(&runtime_class) {
        return Err(format!("runtime_class {runtime_class:?} is not supported"));
    }
    if let Some(gpu) = gpu {
        if !GPU_COUNTS.contains(&gpu.count) {
            return Err(format!("gpu.count {} is not 1 or 8", gpu.count));
        }
        let model_ok = !gpu.model.is_empty()
            && gpu.model.len() <= 32
            && gpu
                .model
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-');
        if !model_ok {
            return Err(format!(
                "gpu.model {:?} is not an upper-case model name",
                gpu.model
            ));
        }
    }
    Ok(())
}

/// The Revision v2 document. Its registered bytes are its JCS form; its hash, the Revision hash
/// the leaf names, is SHA-256 over those bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CocoRevision {
    pub format: String,
    pub app_id: AppId,
    pub initdata_sha256: ComposeHash,
    pub policy_sha256: ComposeHash,
    pub runtime_class: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu: Option<GpuShape>,
}

impl CocoRevision {
    /// The JCS bytes, as registered and as hashed.
    pub fn canonical(&self) -> Result<String, CocoError> {
        let value = serde_json::to_value(self).map_err(|e| CocoError::Revision(e.to_string()))?;
        let bytes = crate::jcs(&value).map_err(|e| CocoError::Revision(e.to_string()))?;
        String::from_utf8(bytes).map_err(|e| CocoError::Revision(e.to_string()))
    }

    pub fn hash(&self) -> Result<ComposeHash, CocoError> {
        Ok(crate::compose_hash(&self.canonical()?))
    }

    /// A registered Revision v2: well formed, of `app_id`, and exactly its own canonical bytes, so
    /// one document has one hash.
    pub fn check_registered(text: &str, app_id: AppId) -> Result<Self, CocoError> {
        let bad = |m: String| CocoError::Revision(m);
        let value = crate::parse(text.as_bytes()).map_err(|e| bad(e.to_string()))?;
        let revision: Self = serde_json::from_value(value).map_err(|e| bad(e.to_string()))?;
        if revision.format != REVISION_FORMAT {
            return Err(bad(format!("format {:?}", revision.format)));
        }
        if revision.app_id != app_id {
            return Err(bad(format!(
                "app_id {} is not the registering App {app_id}",
                revision.app_id
            )));
        }
        check_shape(&revision.runtime_class, revision.gpu.as_ref()).map_err(bad)?;
        if revision.canonical()? != text {
            return Err(bad("not in canonical (JCS) form".into()));
        }
        Ok(revision)
    }
}

/// Whether a registered document is a Revision v2 rather than a compose: a JSON object whose
/// `format` is [`REVISION_FORMAT`].
pub fn is_revision_v2(text: &str) -> bool {
    serde_json::from_str::<Value>(text)
        .ok()
        .and_then(|v| v.get("format").and_then(Value::as_str).map(str::to_owned))
        .is_some_and(|f| f == REVISION_FORMAT)
}

#[cfg(test)]
mod tests {
    use super::*;

    const APP: &str = "01994b3e-5c8a-7d3e-9a1b-2c3d4e5f6a7b";

    fn initdata(algorithm: &str, alpha: &str) -> String {
        format!(
            "algorithm = \"{algorithm}\"\nversion = \"0.1.0\"\n\n[data]\n\"policy.rego\" = '''\npackage agent_policy\ndefault ExecProcessRequest := false\n'''\n\"alpha.json\" = '''{alpha}'''\n"
        )
    }

    fn alpha(gpu: &str) -> String {
        format!(
            "{{\"app_id\":\"{APP}\",\"format\":\"alphacompute-initdata/1\",{gpu}\"runtime_class\":\"kata-qemu-nvidia-gpu-tdx\"}}"
        )
    }

    #[test]
    fn revision_is_a_function_of_the_initdata_bytes() {
        let text = initdata(
            "sha384",
            &alpha("\"gpu\":{\"count\":8,\"model\":\"B300\"},"),
        );
        let init = InitData::parse(text.as_bytes()).unwrap();
        let revision = init.revision().unwrap();
        assert_eq!(revision.app_id.to_string(), APP);
        assert_eq!(
            revision.gpu,
            Some(GpuShape {
                count: 8,
                model: "B300".into()
            })
        );
        assert_eq!(revision.initdata_sha256, crate::compose_hash(&text));
        assert_eq!(
            revision.policy_sha256,
            crate::compose_hash("package agent_policy\ndefault ExecProcessRequest := false\n")
        );
        let canonical = revision.canonical().unwrap();
        assert!(canonical.starts_with("{\"app_id\":"), "{canonical}");
        assert_eq!(revision.hash().unwrap(), crate::compose_hash(&canonical));
        let app: AppId = APP.parse().unwrap();
        assert_eq!(
            CocoRevision::check_registered(&canonical, app).unwrap(),
            revision
        );
        assert!(is_revision_v2(&canonical));
        assert!(!is_revision_v2("{\"name\":\"x\"}"));

        // One byte of init-data changes the Revision.
        let other = InitData::parse(format!("{text}\n").as_bytes()).unwrap();
        assert_ne!(
            other.revision().unwrap().hash().unwrap(),
            revision.hash().unwrap()
        );
    }

    #[test]
    fn mrconfigid_pads_sha256_and_fills_with_sha384() {
        let a = alpha("");
        let t256 = initdata("sha256", &a);
        let m = InitData::parse(t256.as_bytes()).unwrap().mrconfigid();
        assert_eq!(&m[..32], Sha256::digest(t256.as_bytes()).as_slice());
        assert_eq!(m[32..], [0u8; 16]);
        let t384 = initdata("sha384", &a);
        let m = InitData::parse(t384.as_bytes()).unwrap().mrconfigid();
        assert_eq!(m.as_slice(), Sha384::digest(t384.as_bytes()).as_slice());
    }

    #[test]
    fn refuses_malformed_initdata_and_entries() {
        let a = alpha("");
        assert!(matches!(
            InitData::parse(initdata("sha512", &a).as_bytes()),
            Err(CocoError::Algorithm(_))
        ));
        let v2 = initdata("sha384", &a).replace("0.1.0", "0.2.0");
        assert!(matches!(
            InitData::parse(v2.as_bytes()),
            Err(CocoError::Version(_))
        ));
        assert!(matches!(InitData::parse(b"\xff"), Err(CocoError::NotUtf8)));
        assert!(matches!(
            InitData::parse(b"algorithm = \"sha384\"\nversion = \"0.1.0\"\nextra = 1\n"),
            Err(CocoError::Toml(_))
        ));
        let no_policy = InitData::parse(b"algorithm = \"sha384\"\nversion = \"0.1.0\"\n").unwrap();
        assert!(matches!(
            no_policy.revision(),
            Err(CocoError::MissingEntry(_))
        ));

        for (bad, why) in [
            (
                alpha("\"gpu\":{\"count\":4,\"model\":\"B300\"},"),
                "gpu.count",
            ),
            (
                alpha("\"gpu\":{\"count\":1,\"model\":\"b300\"},"),
                "gpu.model",
            ),
            (
                alpha("").replace("kata-qemu-nvidia-gpu-tdx", "runc"),
                "runtime_class",
            ),
            (alpha("").replace("initdata/1", "initdata/9"), "format"),
            (alpha("\"extra\":1,"), "unknown field"),
            (
                alpha("").replace("\"format\"", "\"app_id\":\"x\",\"format\""),
                "duplicate",
            ),
        ] {
            let init = InitData::parse(initdata("sha384", &bad).as_bytes()).unwrap();
            let error = init.revision().unwrap_err().to_string();
            assert!(error.contains(why), "{why}: {error}");
        }
    }

    #[test]
    fn registration_refuses_another_app_and_non_canonical_bytes() {
        let init = InitData::parse(initdata("sha384", &alpha("")).as_bytes()).unwrap();
        let canonical = init.revision().unwrap().canonical().unwrap();
        let app: AppId = APP.parse().unwrap();
        let other = AppId::mint();
        assert!(
            CocoRevision::check_registered(&canonical, other)
                .unwrap_err()
                .to_string()
                .contains("registering App")
        );
        let spaced = canonical.replacen(",", ", ", 1);
        assert!(
            CocoRevision::check_registered(&spaced, app)
                .unwrap_err()
                .to_string()
                .contains("canonical")
        );
    }
}
