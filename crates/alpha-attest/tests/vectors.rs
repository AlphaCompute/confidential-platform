use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alpha_attest::{Appraised, Collateral, EVIDENCE_FORMAT, Evidence, PlatformDocument, appraise};
use serde_json::{Value, json};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/attest")
}

/// A vector directory overrides files of the capture it names in `expected.json`.
struct Case {
    dir: PathBuf,
    capture: PathBuf,
    expected: Value,
}

impl Case {
    fn load(name: &str) -> Self {
        let dir = root().join(name);
        let expected: Value =
            serde_json::from_str(&fs::read_to_string(dir.join("expected.json")).unwrap()).unwrap();
        let capture = root().join(expected["capture"].as_str().unwrap());
        Self {
            dir,
            capture,
            expected,
        }
    }

    fn file(&self, name: &str) -> Vec<u8> {
        let path = self.dir.join(name);
        let path = if path.exists() {
            path
        } else {
            self.capture.join(name)
        };
        fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
    }

    fn json<T: serde::de::DeserializeOwned>(&self, name: &str) -> T {
        serde_json::from_slice(&self.file(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
    }

    fn kind(&self) -> &str {
        self.expected["quote"].as_str().unwrap()
    }

    fn evidence(&self) -> Evidence {
        Evidence {
            format: EVIDENCE_FORMAT.into(),
            quote: hex::decode(
                String::from_utf8(self.file(&format!("quote.{}.hex", self.kind())))
                    .unwrap()
                    .trim(),
            )
            .unwrap(),
            event_log: self.json("event_log.json"),
        }
    }

    fn now(&self) -> SystemTime {
        let text = String::from_utf8(self.file("captured_at.txt")).unwrap();
        UNIX_EPOCH + Duration::from_secs(rfc3339_secs(text.trim()))
    }

    fn run(&self) -> Result<Appraised, alpha_attest::AppraisalError> {
        let nonce: [u8; 32] = self.file("nonce.bin").try_into().unwrap();
        let node_spki = self.file("node_xwing_spki.der");
        appraise(
            &self.evidence(),
            &nonce,
            &self.file("runtime_spki.der"),
            (self.kind() == "node").then_some(node_spki.as_slice()),
            &self.json::<PlatformDocument>("platform-document.json"),
            &self.json::<Collateral>("collateral.json"),
            self.now(),
        )
    }
}

fn rfc3339_secs(s: &str) -> u64 {
    let (date, time) = s.trim_end_matches('Z').split_once('T').unwrap();
    let [y, m, d]: [u64; 3] = date
        .split('-')
        .map(|p| p.parse().unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let [hh, mm, ss]: [u64; 3] = time
        .split(':')
        .map(|p| p.parse().unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    // Days from civil, Howard Hinnant's algorithm.
    let (y, m) = if m <= 2 { (y - 1, m + 9) } else { (y, m - 3) };
    let era = y / 400;
    let yoe = y - era * 400;
    let doy = (153 * m + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    days * 86400 + hh * 3600 + mm * 60 + ss
}

fn positive(name: &str) {
    let case = Case::load(name);
    let appraised = case.run().unwrap_or_else(|e| panic!("{name}: {e}"));
    assert_eq!(json!(appraised), case.expected["appraised"], "{name}");
}

fn negative(name: &str) {
    let case = Case::load(name);
    let error = case
        .run()
        .err()
        .unwrap_or_else(|| panic!("{name}: appraised"));
    assert_eq!(error.code(), case.expected["error"], "{name}: {error}");
    let reason = case.expected["reason"].as_str().unwrap();
    assert!(
        error.to_string().contains(reason),
        "{name}: {error} does not mention {reason:?}"
    );
}

#[test]
fn instance_quote_is_appraised() {
    positive("01-instance");
}

#[test]
fn kms_node_quote_is_appraised() {
    positive("02-node");
}

#[test]
fn production_image_instance_quote_is_appraised() {
    positive("07-prod-instance");
}

#[test]
fn production_image_kms_node_quote_is_appraised() {
    positive("08-prod-node");
}

#[test]
fn wrong_nonce_fails() {
    negative("03-wrong-report-data");
}

#[test]
fn tampered_event_log_fails() {
    negative("04-tampered-event-log");
}

#[test]
fn unknown_image_is_unknown() {
    negative("05-unknown-image");
}

#[test]
fn unknown_kms_revision_is_unknown() {
    negative("06-unknown-kms-revision");
}

#[test]
fn wrong_evidence_format_is_unknown() {
    let case = Case::load("01-instance");
    let mut evidence = case.evidence();
    evidence.format = "alphacompute-evidence/2".into();
    let nonce: [u8; 32] = case.file("nonce.bin").try_into().unwrap();
    let error = appraise(
        &evidence,
        &nonce,
        &case.file("runtime_spki.der"),
        None,
        &case.json::<PlatformDocument>("platform-document.json"),
        &case.json::<Collateral>("collateral.json"),
        case.now(),
    )
    .err()
    .unwrap();
    assert_eq!(error.code(), "attestation_unknown");
}

#[test]
fn expired_collateral_fails() {
    let case = Case::load("01-instance");
    let nonce: [u8; 32] = case.file("nonce.bin").try_into().unwrap();
    let error = appraise(
        &case.evidence(),
        &nonce,
        &case.file("runtime_spki.der"),
        None,
        &case.json::<PlatformDocument>("platform-document.json"),
        &case.json::<Collateral>("collateral.json"),
        case.now() + Duration::from_secs(10 * 365 * 86400),
    )
    .err()
    .unwrap();
    assert_eq!(error.code(), "attestation_failed");
}

#[test]
fn evidence_round_trips_as_json() {
    let case = Case::load("01-instance");
    let evidence = case.evidence();
    let text = serde_json::to_string(&evidence).unwrap();
    let back: Evidence = serde_json::from_str(&text).unwrap();
    assert_eq!(back.quote, evidence.quote);
    assert_eq!(back.event_log, evidence.event_log);
    assert!(text.contains(r#""format":"alphacompute-evidence/1""#));
}
