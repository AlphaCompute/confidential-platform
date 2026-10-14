//! The customer's append-only journal of platform-document versions: a document below the
//! highest recorded version, or a different document under a recorded version, is refused.
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::Path;
use std::time::SystemTime;

use alpha_attest::PlatformDocument;
use serde::{Deserialize, Serialize};

pub const MAX_AGE_LIMIT_SECONDS: u64 = 86400;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    version: u64,
    digest: String,
}

/// The journal must already exist: a lost journal is recovered from the customer's checkpoint,
/// never silently re-created, or a rollback would pass. The OS lock serializes concurrent CLI
/// processes, and the new record is fsynced before the caller uses any pin from `doc`.
pub fn remember(
    path: &Path,
    doc: &PlatformDocument,
    minimum: u64,
    max_age_seconds: u64,
    now: SystemTime,
) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("--platform-state must be an absolute path".into());
    }
    if minimum == 0 {
        return Err("--platform-min-version must be positive".into());
    }
    if max_age_seconds == 0 || max_age_seconds > MAX_AGE_LIMIT_SECONDS {
        return Err(format!(
            "--platform-max-age-seconds must be between 1 and {MAX_AGE_LIMIT_SECONDS}"
        ));
    }
    let issued = chrono::DateTime::parse_from_rfc3339(&doc.issued_at)
        .map_err(|e| format!("platform document issued_at: {e}"))?;
    let age = chrono::DateTime::<chrono::Utc>::from(now)
        .signed_duration_since(issued)
        .num_seconds();
    match u64::try_from(age) {
        Ok(age) if age <= max_age_seconds => {}
        _ => return Err("platform document is expired or future-dated".into()),
    }
    if doc.version < minimum {
        return Err(format!(
            "platform document version {} is below the customer minimum {minimum}",
            doc.version
        ));
    }
    let digest = alpha_channel::sha256_label(
        &serde_json::to_vec(doc).map_err(|e| format!("platform document: {e}"))?,
    );
    let mut file = OpenOptions::new()
        .read(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("platform-state {}: {e}", path.display()))?;
    file.lock()
        .map_err(|e| format!("platform-state lock: {e}"))?;
    let mut history = String::new();
    file.read_to_string(&mut history)
        .map_err(|e| format!("platform-state: {e}"))?;
    if !history.is_empty() && !history.ends_with('\n') {
        return Err(
            "platform-state journal is torn; recover it from the customer checkpoint".into(),
        );
    }
    let mut last: Option<Checkpoint> = None;
    for line in history.lines() {
        let record: Checkpoint =
            serde_json::from_str(line).map_err(|e| format!("platform-state: {e}"))?;
        if last.as_ref().is_some_and(|l| record.version <= l.version) {
            return Err("platform-state journal is not monotonic".into());
        }
        last = Some(record);
    }
    if let Some(last) = last {
        if doc.version < last.version {
            return Err(format!(
                "platform document version {} is below the recorded {}",
                doc.version, last.version
            ));
        }
        if doc.version == last.version {
            return if last.digest == digest {
                Ok(())
            } else {
                Err(format!(
                    "platform document version {} differs from the one recorded under it",
                    doc.version
                ))
            };
        }
    }
    let record = serde_json::to_string(&Checkpoint {
        version: doc.version,
        digest,
    })
    .map_err(|e| format!("platform-state: {e}"))?;
    writeln!(file, "{record}")
        .and_then(|()| file.sync_all())
        .map_err(|e| format!("platform-state write: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::time::Duration;

    #[test]
    fn rollback_equivocation_expiry_and_a_missing_or_torn_journal_are_refused() {
        let path =
            std::env::temp_dir().join(format!("alpha-platform-{}", alpha_core::AppId::mint()));
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let mut doc: PlatformDocument = serde_json::from_value(json!({
            "version": 4, "issued_at": crate::rfc3339(now),
            "policy": {"tcb_statuses": ["UpToDate"], "tolerated_advisories": []},
            "reference_values": [], "kms_ca_pem": "first-ca", "kms_revisions": []
        }))
        .unwrap();
        let day = MAX_AGE_LIMIT_SECONDS;
        let check = |doc: &PlatformDocument, minimum, now| remember(&path, doc, minimum, day, now);

        assert!(check(&doc, 4, now).unwrap_err().contains("platform-state"));
        std::fs::File::create(&path).unwrap();
        check(&doc, 4, now).unwrap();
        check(&doc, 4, now).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 1);

        doc.version = 3;
        assert!(
            check(&doc, 1, now)
                .unwrap_err()
                .contains("below the recorded 4")
        );
        doc.version = 4;
        doc.kms_ca_pem = "rotated-ca".into();
        assert!(check(&doc, 1, now).unwrap_err().contains("differs"));
        doc.version = 5;
        check(&doc, 4, now).unwrap();
        let later = now + Duration::from_secs(day + 1);
        assert!(check(&doc, 4, later).unwrap_err().contains("expired"));
        let earlier = now - Duration::from_secs(1);
        assert!(
            check(&doc, 4, earlier)
                .unwrap_err()
                .contains("future-dated")
        );
        assert!(
            check(&doc, 6, now)
                .unwrap_err()
                .contains("customer minimum 6")
        );
        assert!(remember(&path, &doc, 4, day + 1, now).is_err());
        assert!(remember(Path::new("relative"), &doc, 4, day, now).is_err());

        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"{partial")
            .unwrap();
        assert!(check(&doc, 4, now).unwrap_err().contains("torn"));
        std::fs::remove_file(path).unwrap();
    }
}
