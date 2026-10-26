//! `alpha sign`: one release signature added to the artifact of a platform document, and
//! `--check`, which verifies one under the compiled-in key set and prints the pins a tenant puts
//! in its compose.

use std::time::SystemTime;

use alpha_attest::PlatformDocument;
use alpha_client::platform::{self, ReleaseKeys, SignedDocument};
use alpha_core::{ComposeHash, InitData};
use ed25519_dalek::SigningKey;
use serde::Serialize;
use serde_json::Value;

/// One more signature on the artifact; every signature already on it must be by a distinct key of
/// the set. Signing garbage is refused: the document must already be a platform document. Every
/// `kms_revisions` entry must be one of the supplied node Revisions, a dstack compose or a Kata
/// init-data; the KMS sees only a Kata node's digest, so its init-data must pass the document's
/// own `kata_policy` here, as a tenant's does at registration.
pub fn sign(
    mut artifact: SignedDocument,
    key: &SigningKey,
    keys: &ReleaseKeys,
    composes: &[String],
    init_data: &[String],
) -> Result<SignedDocument, String> {
    let doc = serde_json::from_value::<PlatformDocument>(artifact.document.clone())
        .map_err(|e| format!("document: {e}"))?;
    let mut supplied = Vec::new();
    for compose in composes {
        // An init-data is TOML, so it cannot pass as a compose and skip the policy check.
        alpha_core::parse(compose.as_bytes()).map_err(|e| format!("compose: {e}"))?;
        supplied.push(alpha_core::compose_hash(compose));
    }
    for toml in init_data {
        let init_data = InitData::parse(toml.clone()).map_err(|e| e.to_string())?;
        let digest = init_data.digest();
        let pinned = doc
            .kata_policy
            .as_ref()
            .ok_or("the document pins no kata_policy for an init-data")?;
        init_data
            .check_policy(pinned, &doc.kms_ca_pem)
            .map_err(|e| format!("init-data {digest}: {e}"))?;
        supplied.push(digest);
    }
    let listed: Vec<ComposeHash> = doc.kms_revisions.iter().map(|r| r.compose_hash).collect();
    if let Some(extra) = supplied.iter().find(|d| !listed.contains(d)) {
        return Err(format!("{extra} is not in kms_revisions"));
    }
    if let Some(missing) = listed.iter().find(|d| !supplied.contains(d)) {
        return Err(format!(
            "kms_revisions {missing}: no compose or init-data supplied"
        ));
    }
    artifact.add_signature(key).map_err(|e| e.to_string())?;
    platform::count_signatures(&artifact, keys).map_err(|e| e.to_string())?;
    Ok(artifact)
}

/// A platform document as a new artifact nobody has signed yet, anything else as
/// `{document, signatures}`. The document is tried first: it allows unknown fields, so a field
/// named `signatures` does not make it an artifact.
pub fn artifact(input: Value) -> Result<SignedDocument, String> {
    match serde_json::from_value::<PlatformDocument>(input.clone()) {
        Ok(_) => Ok(SignedDocument {
            document: input,
            signatures: Vec::new(),
        }),
        Err(e) if input.get("document").is_none() => Err(format!("document: {e}")),
        Err(_) => serde_json::from_value(input).map_err(|e| format!("artifact: {e}")),
    }
}

/// What a signature would change, one line per changed value: `- /path: old` and `+ /path: new`
/// against the published `previous` artifact, which must verify and carry a lower version; every
/// value is new without one.
pub fn diff(
    previous: Option<&SignedDocument>,
    document: &Value,
    keys: &ReleaseKeys,
    now: SystemTime,
) -> Result<String, String> {
    let empty = Value::Object(Default::default());
    let old = match previous {
        Some(previous) => {
            let old =
                platform::verify(previous, keys, now).map_err(|e| format!("previous: {e}"))?;
            let version = document.get("version").and_then(Value::as_u64);
            if version.is_none_or(|v| v <= old.version) {
                return Err(format!(
                    "document: version must be above the previous {}",
                    old.version
                ));
            }
            &previous.document
        }
        None => &empty,
    };
    let mut lines = Vec::new();
    changes("", Some(old), Some(document), &mut lines);
    Ok(lines.join("\n"))
}

/// `None` is an absent value, so adding or removing a `null` still shows. Keys are written as JSON
/// pointer segments; keys and values come from whoever wrote the document, so both go through
/// `printable` before they reach the next signer's terminal.
fn changes(path: &str, old: Option<&Value>, new: Option<&Value>, out: &mut Vec<String>) {
    match (old, new) {
        (Some(Value::Object(a)), Some(Value::Object(b))) => {
            for k in a.keys().chain(b.keys().filter(|k| !a.contains_key(*k))) {
                let segment = k.replace('~', "~0").replace('/', "~1");
                let path = format!("{path}/{}", printable(&segment));
                changes(&path, a.get(k), b.get(k), out);
            }
        }
        (Some(Value::Array(a)), Some(Value::Array(b))) => {
            for i in 0..a.len().max(b.len()) {
                changes(&format!("{path}/{i}"), a.get(i), b.get(i), out);
            }
        }
        _ if old == new => {}
        _ => {
            if let Some(old) = old {
                out.push(format!("- {path}: {}", printable(&old.to_string())));
            }
            if let Some(new) = new {
                out.push(format!("+ {path}: {}", printable(&new.to_string())));
            }
        }
    }
}

/// Control characters (C0, DEL, C1) and bidirectional formatting characters as `\u{…}`: JSON
/// leaves C1 and the bidi controls as they are, and a terminal acts on them.
fn printable(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            c if c.is_control() => c.escape_unicode().to_string(),
            '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' => {
                c.escape_unicode().to_string()
            }
            c => c.to_string(),
        })
        .collect()
}

/// `ALPHACOMPUTE_KMS_CA_SPKI_SHA256` and `ALPHACOMPUTE_KMS_REVISIONS`, from a verified artifact.
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct Summary {
    pub version: u64,
    pub kms_ca_spki_sha256: Option<String>,
    pub kms_revisions: Vec<ComposeHash>,
}

pub fn check(
    artifact: &SignedDocument,
    keys: &ReleaseKeys,
    now: SystemTime,
) -> Result<Summary, String> {
    let document = platform::verify(artifact, keys, now).map_err(|e| e.to_string())?;
    Ok(Summary {
        version: document.version,
        kms_ca_spki_sha256: ca_spki_sha256(&document.kms_ca_pem)?,
        kms_revisions: document
            .kms_revisions
            .iter()
            .map(|r| r.compose_hash)
            .collect(),
    })
}

/// `None` for the day-0 document that has no CA yet.
pub fn ca_spki_sha256(kms_ca_pem: &str) -> Result<Option<String>, String> {
    if kms_ca_pem.trim().is_empty() {
        return Ok(None);
    }
    let der = alpha_client::tls::cert_from_pem(kms_ca_pem).map_err(|e| e.to_string())?;
    let spki = alpha_client::tls::spki_of(&der).map_err(|e| e.to_string())?;
    Ok(Some(alpha_channel::sha256_label(&spki)))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn sign_then_check_prints_the_pins() {
        let key = SigningKey::from_bytes(&[8u8; 32]);
        let hash = alpha_core::compose_hash("{}");
        let document = json!({
            "version": 4, "issued_at": "2026-09-14T00:00:00Z",
            "policy": { "tcb_statuses": ["UpToDate"], "tolerated_advisories": [] },
            "reference_values": [], "kms_ca_pem": "",
            "kms_revisions": [{ "compose_hash": hash, "build": "b", "source_url": "u" }]
        });
        let compose = ["{}".to_owned()];
        assert!(artifact(json!({"version": 1})).is_err());
        let garbage = SignedDocument {
            document: json!({"version": 1}),
            signatures: Vec::new(),
        };
        assert!(sign(garbage, &key, &key.verifying_key().into(), &compose, &[]).is_err());
        let artifact = sign(
            artifact(document).unwrap(),
            &key,
            &key.verifying_key().into(),
            &compose,
            &[],
        )
        .unwrap();
        let summary = check(&artifact, &key.verifying_key().into(), SystemTime::now()).unwrap();
        assert_eq!(
            summary,
            Summary {
                version: 4,
                kms_ca_spki_sha256: None,
                kms_revisions: vec![hash]
            }
        );
        let other = SigningKey::from_bytes(&[9u8; 32]);
        assert!(check(&artifact, &other.verifying_key().into(), SystemTime::now()).is_err());
        assert!(ca_spki_sha256("not a pem").is_err());
    }

    #[test]
    fn sign_refuses_a_document_whose_signer_breaks_a_rule() {
        let key = SigningKey::from_bytes(&[8u8; 32]);
        let mut document = json!({
            "version": 4, "issued_at": "2026-09-14T00:00:00Z",
            "policy": { "tcb_statuses": ["UpToDate"], "tolerated_advisories": [] },
            "reference_values": [], "kms_ca_pem": "",
            "kms_revisions": [{
                "compose_hash": alpha_core::compose_hash("{}"), "build": "b", "source_url": "u"
            }],
            "signer": {
                "origins": ["https://sign.example"],
                "rp_id": "sign.example",
                "bundle_sha256": format!("sha256:{}", "0".repeat(64)),
                "api_origin": "https://api.example"
            }
        });
        let compose = ["{}".to_owned()];
        assert!(
            sign(
                artifact(document.clone()).unwrap(),
                &key,
                &key.verifying_key().into(),
                &compose,
                &[]
            )
            .is_ok()
        );
        document["signer"]["origins"][0] = json!("https://sign.example/path");
        let err = artifact(document).unwrap_err();
        assert!(err.starts_with("document:"), "{err}");
    }

    #[test]
    fn sign_checks_a_kata_node_init_data_against_the_document() {
        let key = SigningKey::from_bytes(&[8u8; 32]);
        let k3 = include_str!("../../../testdata/attest/b300-kata-4.0.0/k3-app.toml");
        let mut document: Value = serde_json::from_str(include_str!(
            "../../../testdata/attest/b300-kata-4.0.0/platform-document.json"
        ))
        .unwrap();
        document["kms_revisions"] = json!([{
            "compose_hash": alpha_core::compose_hash(k3), "build": "b", "source_url": "u"
        }]);
        let init_data = [k3.to_owned()];
        assert!(
            sign(
                artifact(document.clone()).unwrap(),
                &key,
                &key.verifying_key().into(),
                &[],
                &init_data
            )
            .is_ok()
        );

        let err = sign(
            artifact(document.clone()).unwrap(),
            &key,
            &key.verifying_key().into(),
            &[],
            &[],
        )
        .unwrap_err();
        assert!(err.contains("no compose or init-data"), "{err}");
        let err = sign(
            artifact(document.clone()).unwrap(),
            &key,
            &key.verifying_key().into(),
            &init_data,
            &[],
        )
        .unwrap_err();
        assert!(err.starts_with("compose:"), "{err}");

        document["kata_policy"]["rules_sha256"] = json!(format!("sha256:{}", "0".repeat(64)));
        let err = sign(
            artifact(document).unwrap(),
            &key,
            &key.verifying_key().into(),
            &[],
            &init_data,
        )
        .unwrap_err();
        assert!(err.contains("not the pinned rules"), "{err}");
    }

    #[test]
    fn signers_add_to_one_artifact_after_seeing_the_diff() {
        let [a, b, c] = [1u8, 2, 3].map(|n| SigningKey::from_bytes(&[n; 32]));
        let keys = ReleaseKeys::new(
            vec![a.verifying_key(), b.verifying_key(), c.verifying_key()],
            2,
        )
        .unwrap();
        let hash = alpha_core::compose_hash("{}");
        let compose = ["{}".to_owned()];
        let v1 = json!({
            "version": 1, "issued_at": "2026-09-14T00:00:00Z",
            "policy": { "tcb_statuses": ["UpToDate"], "tolerated_advisories": [] },
            "reference_values": [], "kms_ca_pem": "",
            "kms_revisions": [{ "compose_hash": hash, "build": "b", "source_url": "u" }]
        });
        let half = sign(artifact(v1.clone()).unwrap(), &a, &keys, &compose, &[]).unwrap();
        assert!(check(&half, &keys, SystemTime::now()).is_err());
        assert!(sign(half.clone(), &a, &keys, &compose, &[]).is_err());
        let stranger = SigningKey::from_bytes(&[4u8; 32]);
        assert!(sign(half.clone(), &stranger, &keys, &compose, &[]).is_err());
        let published = sign(half, &c, &keys, &compose, &[]).unwrap();
        assert_eq!(
            check(&published, &keys, SystemTime::now()).unwrap().version,
            1
        );

        let mut v2 = v1.clone();
        v2["version"] = json!(2);
        v2["policy"]["tolerated_advisories"] = json!(["INTEL-SA-00837"]);
        let shown = diff(Some(&published), &v2, &keys, SystemTime::now()).unwrap();
        assert_eq!(
            shown,
            "- /version: 1\n+ /version: 2\n+ /policy/tolerated_advisories/0: \"INTEL-SA-00837\""
        );
        let err = diff(Some(&published), &v1, &keys, SystemTime::now()).unwrap_err();
        assert!(err.contains("above the previous 1"), "{err}");
        assert!(
            diff(None, &v1, &keys, SystemTime::now())
                .unwrap()
                .contains("+ /version: 1")
        );

        let mut v3 = v1;
        v3["version"] = json!(3);
        v3["hidden\n+ /x"] = json!(null);
        v3["policy"]["note"] = json!("\u{9b}2J\u{202e}");
        let shown = diff(Some(&published), &v3, &keys, SystemTime::now()).unwrap();
        assert!(shown.contains("+ /hidden\\u{a}+ ~1x: null"), "{shown}");
        assert!(
            shown.contains("+ /policy/note: \"\\u{9b}2J\\u{202e}\""),
            "{shown}"
        );

        let mut fields = v2.clone();
        fields["signatures"] = json!([]);
        assert_eq!(artifact(fields.clone()).unwrap().document, fields);
    }
}
