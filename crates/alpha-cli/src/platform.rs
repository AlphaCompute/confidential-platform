//! The highest platform-document version this machine has accepted, per document URL: a
//! rolled-back document is still release-signed, so only a remembered version refuses it.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

#[derive(Serialize, Deserialize)]
struct Accepted {
    version: u64,
    /// SHA-256 of the JCS of the signed `document`, so a second document under one version is
    /// refused; the signatures are left out, as one more signature changes no pin.
    sha256: String,
}

/// `$XDG_STATE_HOME/alphacompute/platform-documents.json`, else under `~/.local/state`.
pub fn state_file() -> Result<PathBuf, String> {
    let base = match std::env::var_os("XDG_STATE_HOME").filter(|v| !v.is_empty()) {
        Some(dir) => PathBuf::from(dir),
        None => std::env::var_os("HOME")
            .filter(|v| !v.is_empty())
            .map(|home| Path::new(&home).join(".local/state"))
            .ok_or("neither XDG_STATE_HOME nor HOME is set")?,
    };
    Ok(base.join("alphacompute/platform-documents.json"))
}

/// Refuses a version below the remembered one, or the remembered version with another digest;
/// remembers a higher one.
// ponytail: two concurrent runs read and write without a lock, so the later write wins even
// when it is the lower version. Take a file lock when runs are scripted in parallel.
pub fn remember(path: &Path, url: &str, document: &Value, version: u64) -> Result<(), String> {
    let digest = alpha_core::jcs(document)
        .map(|bytes| hex::encode(Sha256::digest(bytes)))
        .map_err(|e| format!("platform document: {e}"))?;
    let failed = |p: &Path, e: &dyn std::fmt::Display| format!("{}: {e}", p.display());
    let mut state: BTreeMap<String, Accepted> = match fs::read(path) {
        Ok(text) => serde_json::from_slice(&text).map_err(|e| failed(path, &e))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
        Err(e) => return Err(failed(path, &e)),
    };
    let reset = format!("if the rollback is deliberate, delete {}", path.display());
    if let Some(seen) = state.get(url) {
        if version < seen.version {
            return Err(format!(
                "platform document version {version} from {url} is below version {} accepted \
                 before; {reset}",
                seen.version
            ));
        }
        if version == seen.version {
            if seen.sha256 == digest {
                return Ok(());
            }
            return Err(format!(
                "platform document version {version} from {url} is not the one accepted before \
                 under that version (sha256 {digest}, was {}); {reset}",
                seen.sha256
            ));
        }
    }
    state.insert(
        url.to_owned(),
        Accepted {
            version,
            sha256: digest,
        },
    );
    let text = serde_json::to_vec_pretty(&state).map_err(|e| e.to_string())?;
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|e| failed(dir, &e))?;
    }
    let tmp = path.with_extension(format!("{}.tmp", std::process::id()));
    fs::write(&tmp, text).map_err(|e| failed(&tmp, &e))?;
    fs::rename(&tmp, path).map_err(|e| failed(path, &e))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn rollback_and_equivocation_are_refused_and_a_newer_version_is_remembered() {
        let dir =
            std::env::temp_dir().join(format!("alpha-platform-{}", alpha_core::AppId::mint()));
        let path = dir.join("state/platform-documents.json");
        let url = "https://example.test/platform.json";
        let doc = |version: u64, ca: &str| json!({ "version": version, "kms_ca_pem": ca });

        remember(&path, url, &doc(5, "a"), 5).unwrap();
        remember(&path, url, &doc(5, "a"), 5).unwrap();
        remember(&path, "https://other.test/p.json", &doc(1, "a"), 1).unwrap();

        let rollback = remember(&path, url, &doc(4, "old"), 4).unwrap_err();
        assert!(
            rollback.contains("version 4") && rollback.contains("version 5"),
            "{rollback}"
        );
        let forked = remember(&path, url, &doc(5, "b"), 5).unwrap_err();
        assert!(forked.contains("not the one accepted"), "{forked}");

        remember(&path, url, &doc(6, "c"), 6).unwrap();
        assert!(remember(&path, url, &doc(5, "a"), 5).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }
}
