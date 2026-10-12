//! A Kata confidential pod's identity: its init-data and the Revision v2 derived from it.
//!
//! Kata binds the digest of the init-data document into the TD's MRCONFIGID at launch, and the
//! agent policy the pod runs under is one of its entries. So the init-data, and nothing the host
//! controls, says what may run in the pod. Our own entry, `alpha.json`, names the App, the runtime
//! class and the GPUs the pod expects (none on the CPU class); every field of the Revision v2
//! document is therefore either inside the measured init-data or a digest of it, and the Revision
//! v2 is a pure function of the init-data bytes. The KMS rebuilds it from verified evidence and
//! looks its hash up exactly as it looks up a compose hash today: same `revisions` table, same
//! signature, same leaf SAN.
//!
//! The init-data holds exactly the entries the Revision accounts for ([`ENTRIES`]): our entry and
//! the policy always, and for a pod that opts in to Option B the guest components' configuration
//! (`aa.toml`, `cdh.toml`, see [`kbs`]), which the Revision summarizes as its `kbs` section. Any
//! other entry is refused, so no part of the init-data has a meaning the Revision does not state.

pub mod kbs;
pub mod policy;

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
/// Every entry an init-data document may hold. Kata 4.1.0's agent reads `policy.rego`,
/// `aa.toml` and `cdh.toml` and ignores the rest; we read `alpha.json`.
pub const ENTRIES: [&str; 4] = [ALPHA_ENTRY, POLICY_ENTRY, kbs::AA_ENTRY, kbs::CDH_ENTRY];
/// The only init-data document version the pinned Kata reads.
pub const INITDATA_VERSION: &str = "0.1.0";
/// The confidential runtime class for pods with GPUs: a Kata TD on TDX with the NVIDIA guest image
/// and whole GPUs in CC mode passed through (`nvidia.com/pgpu`).
pub const GPU_RUNTIME_CLASS: &str = "kata-qemu-nvidia-gpu-tdx";
/// The confidential runtime class for CPU-only pods: a Kata TD on TDX with no device passed
/// through (the KMS, broker, signer, guard, inference front and Corpus supervisor).
pub const CPU_RUNTIME_CLASS: &str = "kata-qemu-tdx";
/// The runtime classes a Revision v2 may name; `kata-qemu-nvidia-gpu-snp` waits for the
/// `kata-snp/1` profile (PRD-02, P2).
pub const RUNTIME_CLASSES: [&str; 2] = [GPU_RUNTIME_CLASS, CPU_RUNTIME_CLASS];
/// Whole GPUs only (no MIG in CC mode), one or a full eight-GPU node.
pub const GPU_COUNTS: [u32; 2] = [1, 8];
/// Init-data larger than this is refused before it is parsed.
pub const MAX_INITDATA_BYTES: usize = 512 * 1024;

/// A runtime class a Revision v2 may name, and what it says about GPUs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeClass {
    /// [`CPU_RUNTIME_CLASS`]: no GPU, so a Revision on it has no `gpu` section.
    Cpu,
    /// [`GPU_RUNTIME_CLASS`]: a `gpu` section with [`GPU_COUNTS`] whole GPUs of one model.
    Gpu,
}

impl RuntimeClass {
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            CPU_RUNTIME_CLASS => Some(Self::Cpu),
            GPU_RUNTIME_CLASS => Some(Self::Gpu),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Cpu => CPU_RUNTIME_CLASS,
            Self::Gpu => GPU_RUNTIME_CLASS,
        }
    }

    /// Whether a pod of this class runs with GPUs passed through, and so must prove them.
    pub fn has_gpus(self) -> bool {
        self == Self::Gpu
    }
}

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
    #[error("init-data entry {0:?} is not one a Revision v2 accounts for")]
    UnknownEntry(String),
    #[error("init-data guest components: {0}")]
    Kbs(String),
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

    /// The KBS the guest components are configured for: `None` without `aa.toml` and
    /// `cdh.toml`, refused with only one of them or with anything but the generator's form.
    pub fn kbs(&self) -> Result<Option<kbs::KbsConfig>, CocoError> {
        match (self.data.get(kbs::AA_ENTRY), self.data.get(kbs::CDH_ENTRY)) {
            (None, None) => Ok(None),
            (Some(aa), Some(cdh)) => kbs::KbsConfig::from_entries(aa, cdh)
                .map(Some)
                .map_err(CocoError::Kbs),
            _ => Err(CocoError::Kbs(format!(
                "{} and {} come together",
                kbs::AA_ENTRY,
                kbs::CDH_ENTRY
            ))),
        }
    }

    /// The Revision v2 this init-data stands for.
    pub fn revision(&self) -> Result<CocoRevision, CocoError> {
        if let Some(entry) = self.data.keys().find(|k| !ENTRIES.contains(&k.as_str())) {
            return Err(CocoError::UnknownEntry(entry.clone()));
        }
        let alpha = self.alpha()?;
        Ok(CocoRevision {
            format: REVISION_FORMAT.into(),
            app_id: alpha.app_id,
            initdata_sha256: self.sha256(),
            policy_sha256: self.policy_sha256()?,
            runtime_class: alpha.runtime_class,
            gpu: alpha.gpu,
            kbs: self.kbs()?.map(|k| k.revision()),
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
    /// Required on [`GPU_RUNTIME_CLASS`], refused on [`CPU_RUNTIME_CLASS`].
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

/// The runtime class decides the GPU section: none on the CPU class (not even a zero count, so one
/// pod has one Revision), and one or eight GPUs of one model on the GPU class.
fn check_shape(runtime_class: &str, gpu: Option<&GpuShape>) -> Result<(), String> {
    let class = RuntimeClass::from_name(runtime_class)
        .ok_or_else(|| format!("runtime_class {runtime_class:?} is not supported"))?;
    let gpu = match (class, gpu) {
        (RuntimeClass::Cpu, None) => return Ok(()),
        (RuntimeClass::Cpu, Some(gpu)) => {
            return Err(format!(
                "runtime_class {CPU_RUNTIME_CLASS} runs no GPU, so a gpu section (count {}) is not allowed",
                gpu.count
            ));
        }
        (RuntimeClass::Gpu, None) => {
            return Err(format!(
                "runtime_class {GPU_RUNTIME_CLASS} needs a gpu section with count 1 or 8"
            ));
        }
        (RuntimeClass::Gpu, Some(gpu)) => gpu,
    };
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
    /// Present only for a pod whose init-data configures the guest components for a KBS
    /// (Option B): the KBS and the certificate the guest trusts for it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kbs: Option<kbs::RevisionKbs>,
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

    /// The runtime class this Revision names; `None` only for a document that was built by hand
    /// rather than by [`InitData::revision`] or [`Self::check_registered`].
    pub fn class(&self) -> Option<RuntimeClass> {
        RuntimeClass::from_name(&self.runtime_class)
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
        if let Some(kbs) = &revision.kbs {
            kbs.check().map_err(bad)?;
        }
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

    fn alpha_on(class: &str, gpu: &str) -> String {
        format!(
            "{{\"app_id\":\"{APP}\",\"format\":\"alphacompute-initdata/1\",{gpu}\"runtime_class\":\"{class}\"}}"
        )
    }

    /// `alpha.json` on the GPU class.
    fn alpha(gpu: &str) -> String {
        alpha_on(GPU_RUNTIME_CLASS, gpu)
    }

    /// `alpha.json` on the CPU class, which has no `gpu` section.
    fn cpu_alpha() -> String {
        alpha_on(CPU_RUNTIME_CLASS, "")
    }

    const GPU1: &str = "\"gpu\":{\"count\":1,\"model\":\"B300\"},";
    const GPU0: &str = "\"gpu\":{\"count\":0,\"model\":\"B300\"},";

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
        let a = cpu_alpha();
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
        let a = cpu_alpha();
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
            (alpha_on("kata-qemu-tdx-2", ""), "runtime_class"),
            (alpha_on("kata-qemu-snp", ""), "runtime_class"),
            // The GPU class with no GPU, and the CPU class with any gpu section at all.
            (alpha(""), "needs a gpu section"),
            (alpha(GPU0), "gpu.count 0"),
            (alpha_on(CPU_RUNTIME_CLASS, GPU1), "runs no GPU"),
            (alpha_on(CPU_RUNTIME_CLASS, GPU0), "runs no GPU"),
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
        let init = InitData::parse(initdata("sha384", &cpu_alpha()).as_bytes()).unwrap();
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

    #[test]
    fn cpu_class_revision_has_no_gpu_section() {
        let text = initdata("sha384", &cpu_alpha());
        let revision = InitData::parse(text.as_bytes())
            .unwrap()
            .revision()
            .unwrap();
        assert_eq!(revision.runtime_class, CPU_RUNTIME_CLASS);
        assert_eq!(revision.class(), Some(RuntimeClass::Cpu));
        assert_eq!(revision.gpu, None);
        let canonical = revision.canonical().unwrap();
        assert!(!canonical.contains("gpu"), "{canonical}");
        assert!(
            canonical.ends_with("\"runtime_class\":\"kata-qemu-tdx\"}"),
            "{canonical}"
        );
        let app: AppId = APP.parse().unwrap();
        assert_eq!(
            CocoRevision::check_registered(&canonical, app).unwrap(),
            revision
        );

        // The same pod on the GPU class is a different Revision.
        let gpu = InitData::parse(initdata("sha384", &alpha(GPU1)).as_bytes())
            .unwrap()
            .revision()
            .unwrap();
        assert_eq!(gpu.class(), Some(RuntimeClass::Gpu));
        assert_ne!(gpu.hash().unwrap(), revision.hash().unwrap());
    }

    /// The Revision v2 bytes and hash, pinned for one pod of each class from fixed init-data.
    /// `alpha coco render`, the Rafay plugin and the signer page must produce exactly these; the
    /// GPU-class value is the one this crate produced before the CPU class existed.
    #[test]
    fn revision_v2_canonical_bytes_and_hash_are_pinned() {
        const POLICY: &str = "package agent_policy\ndefault ExecProcessRequest := false\n";
        let init = |alpha: &str| {
            format!(
                "algorithm = \"sha384\"\nversion = \"0.1.0\"\n\n[data]\n\"policy.rego\" = '''\n{POLICY}'''\n\"alpha.json\" = '''{alpha}'''\n"
            )
        };
        let gpu8 = init(
            r#"{"app_id":"01994b3e-5c8a-7d3e-9a1b-2c3d4e5f6a7b","format":"alphacompute-initdata/1","gpu":{"count":8,"model":"B300"},"runtime_class":"kata-qemu-nvidia-gpu-tdx"}"#,
        );
        let cpu = init(
            r#"{"app_id":"01994b3e-5c8a-7d3e-9a1b-2c3d4e5f6a7b","format":"alphacompute-initdata/1","runtime_class":"kata-qemu-tdx"}"#,
        );
        let app: AppId = APP.parse().unwrap();
        for (text, canonical, hash) in [
            (
                gpu8,
                r#"{"app_id":"01994b3e-5c8a-7d3e-9a1b-2c3d4e5f6a7b","format":"alphacompute-coco-revision/1","gpu":{"count":8,"model":"B300"},"initdata_sha256":"sha256:8532ca9f7ef14d40f1d7db617501a593bbfd8875e67d5604cb6bd62627975fed","policy_sha256":"sha256:08e5cddd39ec034ef3d1d88c739baf4e1bfb9f261cf1c7d489d98a414156ff34","runtime_class":"kata-qemu-nvidia-gpu-tdx"}"#,
                "sha256:e8bc4961b8bcd0d0d48804c5e8ae0d1e6c296cd1c02846d4e263f362bf39e851",
            ),
            (
                cpu,
                r#"{"app_id":"01994b3e-5c8a-7d3e-9a1b-2c3d4e5f6a7b","format":"alphacompute-coco-revision/1","initdata_sha256":"sha256:2dd2fc499fa19fe358c137e82b2a4099a680454048341517385b2282186f81b0","policy_sha256":"sha256:08e5cddd39ec034ef3d1d88c739baf4e1bfb9f261cf1c7d489d98a414156ff34","runtime_class":"kata-qemu-tdx"}"#,
                "sha256:ddf58ccc19f168abd767f70e0ed46dba42c07d0830dbeede37a4944256ec2575",
            ),
        ] {
            let revision = InitData::parse(text.as_bytes())
                .unwrap()
                .revision()
                .unwrap();
            assert_eq!(revision.canonical().unwrap(), canonical);
            assert_eq!(revision.hash().unwrap().to_string(), hash);
            assert_eq!(
                crate::check_registration(canonical, app)
                    .unwrap()
                    .to_string(),
                hash
            );
        }
    }

    #[test]
    fn registration_holds_each_class_to_its_gpu_section() {
        let app = AppId::mint();
        let revision = |class: &str, gpu: Option<u32>| CocoRevision {
            format: REVISION_FORMAT.into(),
            app_id: app,
            initdata_sha256: crate::compose_hash("initdata"),
            policy_sha256: crate::compose_hash("policy"),
            runtime_class: class.into(),
            gpu: gpu.map(|count| GpuShape {
                count,
                model: "B300".into(),
            }),
            kbs: None,
        };
        let registered = |r: CocoRevision| {
            let text = r.canonical().unwrap();
            CocoRevision::check_registered(&text, app).map_err(|e| e.to_string())
        };
        assert!(registered(revision(CPU_RUNTIME_CLASS, None)).is_ok());
        assert!(registered(revision(GPU_RUNTIME_CLASS, Some(1))).is_ok());
        assert!(registered(revision(GPU_RUNTIME_CLASS, Some(8))).is_ok());
        for (class, gpu, why) in [
            (CPU_RUNTIME_CLASS, Some(1), "runs no GPU"),
            (CPU_RUNTIME_CLASS, Some(8), "runs no GPU"),
            (CPU_RUNTIME_CLASS, Some(0), "runs no GPU"),
            (GPU_RUNTIME_CLASS, None, "needs a gpu section"),
            (GPU_RUNTIME_CLASS, Some(0), "gpu.count 0"),
            (GPU_RUNTIME_CLASS, Some(2), "gpu.count 2"),
        ] {
            let error = registered(revision(class, gpu)).unwrap_err();
            assert!(error.contains(why), "{class} {gpu:?}: {error}");
        }
    }

    /// `initdata` with the guest components' entries for the test KBS appended.
    fn with_kbs(text: &str) -> String {
        let c = kbs::KbsConfig::new(kbs::tests::URL, kbs::tests::CERT).unwrap();
        format!(
            "{text}\"aa.toml\" = '''\n{}'''\n\"cdh.toml\" = '''\n{}'''\n",
            c.aa_toml(),
            c.cdh_toml()
        )
    }

    #[test]
    fn the_guest_components_entries_are_measured_and_named_in_the_revision() {
        let plain = initdata("sha384", &cpu_alpha());
        let text = with_kbs(&plain);
        let init = InitData::parse(text.as_bytes()).unwrap();
        let revision = init.revision().unwrap();
        let named = revision.kbs.clone().unwrap();
        assert_eq!(named.url, kbs::tests::URL);
        assert_eq!(revision.initdata_sha256, crate::compose_hash(&text));
        let canonical = revision.canonical().unwrap();
        assert!(
            canonical.contains("\"kbs\":{\"cert_spki_sha256\":"),
            "{canonical}"
        );
        let app: AppId = APP.parse().unwrap();
        assert_eq!(
            CocoRevision::check_registered(&canonical, app).unwrap(),
            revision
        );
        // Without them, the same pod is another Revision with no kbs section.
        let bare = InitData::parse(plain.as_bytes())
            .unwrap()
            .revision()
            .unwrap();
        assert_eq!(bare.kbs, None);
        assert_ne!(bare.hash().unwrap(), revision.hash().unwrap());
        assert!(!bare.canonical().unwrap().contains("kbs"));

        // Pinned: alpha coco render and wrap, the KMS and the signer page must agree on these.
        assert_eq!(
            revision.hash().unwrap().to_string(),
            "sha256:e0a40fb0755413caf310f791eb240fc26aec45ad42208e275de7fc8eeb097a77"
        );
    }

    #[test]
    fn init_data_holds_only_entries_the_revision_accounts_for() {
        let plain = initdata("sha384", &cpu_alpha());
        let c = kbs::KbsConfig::new(kbs::tests::URL, kbs::tests::CERT).unwrap();
        let entry = |name: &str, body: &str| format!("{plain}\"{name}\" = '''\n{body}'''\n");
        for (text, why) in [
            (entry("extra.toml", "x = 1\n"), "extra.toml"),
            (entry("aa.toml", &c.aa_toml()), "come together"),
            (entry("cdh.toml", &c.cdh_toml()), "come together"),
            (
                with_kbs(&plain)
                    .replace("[kbc]\n", "skip_sealed_secret_verification = true\n[kbc]\n"),
                "cdh.toml",
            ),
            (
                with_kbs(&plain).replacen(kbs::tests::URL, "https://kbs.attacker.example", 1),
                "different",
            ),
        ] {
            let init = InitData::parse(text.as_bytes()).unwrap();
            let error = init.revision().unwrap_err().to_string();
            assert!(error.contains(why), "{why}: {error}");
        }
    }

    #[test]
    fn registration_holds_the_kbs_section_to_an_https_url() {
        let text = with_kbs(&initdata("sha384", &cpu_alpha()));
        let revision = InitData::parse(text.as_bytes())
            .unwrap()
            .revision()
            .unwrap();
        let app: AppId = APP.parse().unwrap();
        let mut value = serde_json::to_value(&revision).unwrap();
        value["kbs"]["url"] = "http://kbs.example".into();
        let edited = String::from_utf8(crate::jcs(&value).unwrap()).unwrap();
        assert!(
            CocoRevision::check_registered(&edited, app)
                .unwrap_err()
                .to_string()
                .contains("https")
        );
        value["kbs"]["url"] = kbs::tests::URL.into();
        value["kbs"]["extra"] = 1.into();
        let edited = String::from_utf8(crate::jcs(&value).unwrap()).unwrap();
        assert!(CocoRevision::check_registered(&edited, app).is_err());
    }

    #[test]
    fn runtime_class_names_round_trip() {
        for class in [RuntimeClass::Cpu, RuntimeClass::Gpu] {
            assert_eq!(RuntimeClass::from_name(class.name()), Some(class));
            assert!(RUNTIME_CLASSES.contains(&class.name()));
        }
        assert!(RuntimeClass::Gpu.has_gpus());
        assert!(!RuntimeClass::Cpu.has_gpus());
        assert_eq!(RuntimeClass::from_name("kata-qemu-nvidia-gpu-snp"), None);
        assert_eq!(RuntimeClass::from_name("KATA-QEMU-TDX"), None);
    }
}
