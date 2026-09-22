//! Customer-owned monotonic platform document journal. Never put this state in Rafay.
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::Path;
use std::time::SystemTime;

use alpha_attest::PlatformDocument;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    version: u64,
    digest: String,
}

/// The customer provisions an absolute journal path and a minimum version from
/// an independent source. OS locking serializes concurrent CLI processes; fsync
/// precedes returning any pin. Torn or corrupt records fail closed.
pub fn remember(
    path: &Path,
    doc: &PlatformDocument,
    minimum: u64,
    max_age_seconds: u64,
    now: SystemTime,
) -> Result<(), String> {
    if !path.is_absolute() || minimum == 0 || max_age_seconds == 0 || max_age_seconds > 86400 {
        return Err("absolute customer platform-state, positive minimum version and age <= 86400 seconds required".into());
    }
    let issued = chrono::DateTime::parse_from_rfc3339(&doc.issued_at).map_err(|e| e.to_string())?;
    let age = chrono::DateTime::<chrono::Utc>::from(now)
        .signed_duration_since(issued)
        .num_seconds();
    if age < 0 || age as u64 > max_age_seconds || doc.version < minimum {
        return Err(
            "platform document is expired, future-dated or below the customer minimum".into(),
        );
    }
    let digest = crate::sha256_prefixed(&serde_json::to_vec(doc).map_err(|e| e.to_string())?);
    let mut file = OpenOptions::new()
        .read(true)
        .append(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    file.try_lock()
        .map_err(|e| format!("platform-state lock: {e}"))?;
    let mut history = String::new();
    file.read_to_string(&mut history)
        .map_err(|e| e.to_string())?;
    if !history.is_empty() && !history.ends_with('\n') {
        return Err("incomplete platform-state journal; recover from customer checkpoint".into());
    }
    let mut highest = 0;
    let mut remembered = None;
    for line in history.lines() {
        let old: Checkpoint =
            serde_json::from_str(line).map_err(|e| format!("platform-state: {e}"))?;
        if old.version <= highest {
            return Err("platform-state journal is not monotonic".into());
        }
        highest = old.version;
        remembered = Some(old);
    }
    if doc.version < highest {
        return Err("platform document rollback refused".into());
    }
    if let Some(old) = remembered
        && doc.version == old.version
    {
        return if old.digest == digest {
            Ok(())
        } else {
            Err("platform version equivocation refused".into())
        };
    }
    let record = serde_json::to_string(&Checkpoint {
        version: doc.version,
        digest,
    })
    .map_err(|e| e.to_string())?;
    writeln!(file, "{record}")
        .and_then(|()| file.sync_all())
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::time::Duration;

    #[test]
    fn restart_expiry_equivocation_rotation_and_missing_journal_fail_closed() {
        let path =
            std::env::temp_dir().join(format!("alpha-platform-{}", alpha_core::AppId::mint()));
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let mut doc: PlatformDocument =
            serde_json::from_value(json!({"version":4,"issued_at":crate::rfc3339(now),
            "policy":{"tcb_statuses":["UpToDate"],"tolerated_advisories":[]},
            "reference_values":[],"kms_ca_pem":"first-ca","kms_revisions":[]}))
            .unwrap();
        assert!(remember(&path, &doc, 4, 86400, now).is_err());
        std::fs::File::create(&path).unwrap();
        remember(&path, &doc, 4, 86400, now).unwrap();
        remember(&path, &doc, 4, 86400, now).unwrap();
        doc.version = 3;
        assert!(
            remember(&path, &doc, 1, 86400, now)
                .unwrap_err()
                .contains("rollback")
        );
        doc.version = 4;
        doc.kms_ca_pem = "rotated-ca".into();
        assert!(
            remember(&path, &doc, 1, 86400, now)
                .unwrap_err()
                .contains("equivocation")
        );
        doc.version = 5;
        remember(&path, &doc, 4, 86400, now).unwrap();
        assert!(remember(&path, &doc, 4, 86400, now + Duration::from_secs(86401)).is_err());
        assert!(remember(&path, &doc, 6, 86400, now).is_err());
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"{partial")
            .unwrap();
        assert!(remember(&path, &doc, 4, 86400, now).is_err());
        std::fs::remove_file(path).unwrap();
    }
}
