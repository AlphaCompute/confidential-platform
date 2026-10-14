//! The release-signed platform document as its artifact URL serves it, and its verification:
//! at least the threshold of signatures by distinct keys of the compiled-in release key set, and
//! `issued_at` not in the future. Version monotonicity is the caller's, against whatever it
//! remembers.

use std::time::SystemTime;

use alpha_core::{CatalogKey, KataPolicy, KmsRevision, Signer, context, signing_digest};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use chrono::DateTime;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{Error, unix_seconds};

/// `{ document, signatures: [{ key, algorithm: "ed25519", signature }] }`, every signature over
/// the same digest of `document`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedDocument {
    pub document: Value,
    pub signatures: Vec<ReleaseSignature>,
}

/// `key` is the signer's raw Ed25519 public key, base64url.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseSignature {
    pub key: String,
    pub algorithm: String,
    pub signature: String,
}

/// The fields a channel client reads. Unknown fields are allowed so a document that grows a
/// field still verifies in a page built before it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlatformView {
    pub version: u64,
    pub issued_at: String,
    pub kms_ca_pem: String,
    pub kms_revisions: Vec<KmsRevision>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<Signer>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catalog_key: Option<CatalogKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kata_policy: Option<KataPolicy>,
}

/// Distinct keys and how many of them must sign. The threshold is compiled in beside the keys,
/// never read from a document: a document cannot lower the bar that admits it.
#[derive(Clone, Debug)]
pub struct ReleaseKeys {
    keys: Vec<VerifyingKey>,
    threshold: usize,
}

impl ReleaseKeys {
    pub fn new(keys: Vec<VerifyingKey>, threshold: usize) -> Result<Self, Error> {
        let malformed = |m: String| Err(Error::Malformed(format!("release key set: {m}")));
        if threshold == 0 || threshold > keys.len() {
            return malformed(format!("threshold {threshold} of {} keys", keys.len()));
        }
        if keys.iter().any(VerifyingKey::is_weak) {
            return malformed("a weak key".into());
        }
        let mut distinct: Vec<[u8; 32]> = keys.iter().map(VerifyingKey::to_bytes).collect();
        distinct.sort_unstable();
        distinct.dedup();
        if distinct.len() != keys.len() {
            return malformed("a key listed twice".into());
        }
        Ok(Self { keys, threshold })
    }
}

/// A set of one, threshold one.
impl From<VerifyingKey> for ReleaseKeys {
    fn from(key: VerifyingKey) -> Self {
        Self {
            keys: vec![key],
            threshold: 1,
        }
    }
}

// A build holds one set only, so a production verifier cannot accept a dev-signed document.
// build.rs holds the production threshold too, to refuse a set that could never meet it.
#[cfg(feature = "dev")]
const RELEASE_KEYS: (&str, usize) = (include_str!("../release-keys/dev.pub"), 1);
#[cfg(not(feature = "dev"))]
const RELEASE_KEYS: (&str, usize) = (include_str!("../release-keys/prod.pub"), 2);

/// The release key set compiled into this build, one hex public key per line, which `alpha-kms`,
/// `alpha` and the page share; replaced at the ceremony, never in CI.
pub fn release_keys() -> Result<ReleaseKeys, Error> {
    let (text, threshold) = RELEASE_KEYS;
    let keys = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(|l| {
            alpha_core::hex_bytes::<32>(l)
                .and_then(|b| VerifyingKey::from_bytes(&b).ok())
                .ok_or_else(|| Error::Malformed("a compiled-in release key is not Ed25519".into()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    ReleaseKeys::new(keys, threshold)
}

pub fn sign(document: Value, key: &SigningKey) -> Result<SignedDocument, Error> {
    let mut signed = SignedDocument {
        document,
        signatures: Vec::new(),
    };
    signed.add_signature(key)?;
    Ok(signed)
}

impl SignedDocument {
    /// One more signature over the same document; a key signs once.
    pub fn add_signature(&mut self, key: &SigningKey) -> Result<(), Error> {
        let public = BASE64_URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes());
        if self.signatures.iter().any(|s| s.key == public) {
            return Err(refuse("this key has already signed it"));
        }
        let digest = signing_digest(context::PLATFORM, &self.document).map_err(canonicalize)?;
        self.signatures.push(ReleaseSignature {
            key: public,
            algorithm: "ed25519".into(),
            signature: BASE64_URL_SAFE_NO_PAD.encode(key.sign(&digest).to_bytes()),
        });
        Ok(())
    }
}

fn canonicalize(e: serde_json::Error) -> Error {
    Error::PlatformSignature(format!("platform document does not canonicalize: {e}"))
}

fn refuse(m: &str) -> Error {
    Error::PlatformSignature(format!("platform document: {m}"))
}

/// Every signature must be by a distinct key of the set and verify: a stranger's or a broken one
/// refuses the artifact rather than being skipped. Returns how many keys signed.
pub fn count_signatures(signed: &SignedDocument, keys: &ReleaseKeys) -> Result<usize, Error> {
    let digest = signing_digest(context::PLATFORM, &signed.document).map_err(canonicalize)?;
    let mut seen: Vec<&VerifyingKey> = Vec::new();
    for s in &signed.signatures {
        if s.algorithm != "ed25519" {
            return Err(refuse(&format!("algorithm {:?}", s.algorithm)));
        }
        let key = BASE64_URL_SAFE_NO_PAD
            .decode(&s.key)
            .ok()
            .and_then(|b| keys.keys.iter().find(|k| k.as_bytes().as_slice() == b))
            .ok_or_else(|| refuse("a signature by a key outside the release key set"))?;
        if seen.contains(&key) {
            return Err(refuse("two signatures by one release key"));
        }
        let signature = BASE64_URL_SAFE_NO_PAD
            .decode(&s.signature)
            .ok()
            .and_then(|b| Signature::from_slice(&b).ok())
            .ok_or_else(|| refuse("signature is not base64url Ed25519"))?;
        key.verify_strict(&digest, &signature)
            .map_err(|_| refuse("release signature does not verify"))?;
        seen.push(key);
    }
    Ok(seen.len())
}

pub fn verify(
    signed: &SignedDocument,
    keys: &ReleaseKeys,
    now: SystemTime,
) -> Result<PlatformView, Error> {
    let signed_by = count_signatures(signed, keys)?;
    if signed_by < keys.threshold {
        return Err(refuse(&format!(
            "{signed_by} release signatures, {} needed",
            keys.threshold
        )));
    }
    let view: PlatformView = serde_json::from_value(signed.document.clone())
        .map_err(|e| refuse(&format!("document: {e}")))?;
    let issued_at = DateTime::parse_from_rfc3339(&view.issued_at)
        .map_err(|e| refuse(&format!("issued_at: {e}")))?;
    if issued_at.timestamp() > unix_seconds(now)? {
        return Err(refuse("issued_at is in the future"));
    }
    Ok(view)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use serde_json::json;

    use super::*;

    fn document(version: u64, issued_at: &str) -> Value {
        json!({
            "version": version, "issued_at": issued_at,
            "policy": { "tcb_statuses": ["UpToDate"], "tolerated_advisories": [] },
            "reference_values": [], "kms_ca_pem": "", "kms_revisions": []
        })
    }

    #[wasm_bindgen_test::wasm_bindgen_test(unsupported = test)]
    fn verify_checks_signature_key_and_issued_at() {
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let signed = sign(document(3, "2026-09-14T00:00:00Z"), &key).unwrap();
        assert_eq!(
            verify(&signed, &key.verifying_key().into(), now)
                .unwrap()
                .version,
            3
        );
        let other = SigningKey::from_bytes(&[6u8; 32]);
        assert!(verify(&signed, &other.verifying_key().into(), now).is_err());
        let mut tampered = signed.clone();
        tampered.document["version"] = json!(4);
        assert!(verify(&tampered, &key.verifying_key().into(), now).is_err());
        let future = sign(document(3, "2100-01-01T00:00:00Z"), &key).unwrap();
        assert!(
            verify(&future, &key.verifying_key().into(), now)
                .unwrap_err()
                .to_string()
                .contains("future")
        );
        let mut alg = signed.clone();
        alg.signatures[0].algorithm = "ml-dsa".into();
        assert_eq!(
            verify(&alg, &key.verifying_key().into(), now)
                .unwrap_err()
                .code(),
            "platform_signature"
        );
    }

    #[wasm_bindgen_test::wasm_bindgen_test(unsupported = test)]
    fn verify_needs_the_threshold_of_distinct_keys_from_the_set() {
        let [a, b, c, stranger] = [1u8, 2, 3, 4].map(|n| SigningKey::from_bytes(&[n; 32]));
        let keys = ReleaseKeys::new(
            vec![a.verifying_key(), b.verifying_key(), c.verifying_key()],
            2,
        )
        .unwrap();
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let mut signed = sign(document(3, "2026-09-14T00:00:00Z"), &a).unwrap();
        let err = verify(&signed, &keys, now).unwrap_err();
        assert!(
            err.to_string().contains("1 release signatures, 2 needed"),
            "{err}"
        );
        assert!(signed.add_signature(&a).is_err());
        signed.add_signature(&c).unwrap();
        assert_eq!(verify(&signed, &keys, now).unwrap().version, 3);

        let mut extra = signed.clone();
        extra.add_signature(&stranger).unwrap();
        assert!(
            verify(&extra, &keys, now)
                .unwrap_err()
                .to_string()
                .contains("outside")
        );
        let mut twice = signed.clone();
        twice.signatures.push(signed.signatures[0].clone());
        assert!(
            verify(&twice, &keys, now)
                .unwrap_err()
                .to_string()
                .contains("two signatures")
        );
        let mut swapped = signed.clone();
        swapped.signatures[1].signature = signed.signatures[0].signature.clone();
        assert!(verify(&swapped, &keys, now).is_err());

        assert!(ReleaseKeys::new(vec![a.verifying_key()], 2).is_err());
        assert!(ReleaseKeys::new(vec![a.verifying_key()], 0).is_err());
        assert!(ReleaseKeys::new(vec![a.verifying_key(), a.verifying_key()], 1).is_err());
    }

    fn catalog_public_key() -> [u8; 32] {
        SigningKey::from_bytes(&[7u8; 32])
            .verifying_key()
            .to_bytes()
    }

    fn document_with_signer_and_catalog_key() -> Value {
        let mut d = document(3, "2026-09-14T00:00:00Z");
        d["kms_revisions"] = json!([{
            "compose_hash": alpha_core::compose_hash("{}"), "build": "b", "source_url": "u"
        }]);
        d["signer"] = json!({
            "origins": ["https://sign.example", "https://a.sign.example"],
            "rp_id": "sign.example",
            "bundle_sha256": format!("sha256:{}", "0".repeat(64)),
            "api_origin": "https://api.example"
        });
        d["catalog_key"] = json!({
            "algorithm": "ed25519",
            "public_key": BASE64_URL_SAFE_NO_PAD.encode(catalog_public_key())
        });
        d
    }

    #[wasm_bindgen_test::wasm_bindgen_test(unsupported = test)]
    fn a_document_with_signer_and_catalog_key_exposes_them_in_the_view() {
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let mut d = document_with_signer_and_catalog_key();
        let signed = sign(d.clone(), &key).unwrap();
        let view = verify(&signed, &key.verifying_key().into(), now).unwrap();
        let signer = view.signer.as_ref().unwrap();
        assert_eq!(
            signer.origins,
            ["https://sign.example", "https://a.sign.example"]
        );
        assert_eq!(signer.rp_id, "sign.example");
        assert_eq!(signer.api_origin, "https://api.example");
        let catalog_key = view.catalog_key.as_ref().unwrap();
        assert_eq!(catalog_key.algorithm, "ed25519");
        assert_eq!(
            catalog_key.public_key,
            BASE64_URL_SAFE_NO_PAD.encode(catalog_public_key())
        );
        assert_eq!(view.kms_revisions.len(), 1);
        assert_eq!(
            view.kms_revisions[0].compose_hash,
            alpha_core::compose_hash("{}")
        );
        let json = serde_json::to_value(&view).unwrap();
        for k in ["signer", "catalog_key", "kms_revisions"] {
            assert!(json.get(k).is_some(), "{k}");
        }

        d["signer"]["origins"][0] = json!("https://sign.example/");
        let bad = sign(d, &key).unwrap();
        assert_eq!(
            verify(&bad, &key.verifying_key().into(), now)
                .unwrap_err()
                .code(),
            "platform_signature"
        );
    }

    #[wasm_bindgen_test::wasm_bindgen_test(unsupported = test)]
    fn a_document_without_signer_or_catalog_key_has_neither_in_the_view() {
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let signed = sign(document(3, "2026-09-14T00:00:00Z"), &key).unwrap();
        let view = verify(&signed, &key.verifying_key().into(), now).unwrap();
        assert!(view.signer.is_none());
        assert!(view.catalog_key.is_none());
        let json = serde_json::to_value(&view).unwrap();
        assert!(json.get("kms_revisions").is_some());
        assert!(json.get("signer").is_none());
        assert!(json.get("catalog_key").is_none());
    }

    #[wasm_bindgen_test::wasm_bindgen_test(unsupported = test)]
    fn a_signer_or_catalog_key_breaking_a_rule_is_refused_as_platform_signature() {
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        for (section, field, bad) in [
            ("signer", "origins", json!([])),
            ("signer", "origins", json!(["https://sign.example/"])),
            ("signer", "origins", json!(["http://sign.example"])),
            ("signer", "origins", json!(["https://Sign.example"])),
            ("signer", "origins", json!(["https://sign.example:443"])),
            ("signer", "origins", json!(["https://sign.example:+8443"])),
            ("signer", "origins", json!(["https://evilsign.example"])),
            ("signer", "origins", json!(["https://u@sign.example"])),
            ("signer", "origins", json!(["https://sign.example?x"])),
            ("signer", "api_origin", json!("https://api.example/v1")),
            (
                "signer",
                "bundle_sha256",
                json!(format!("sha256:{}", "A".repeat(64))),
            ),
            ("catalog_key", "algorithm", json!("ml-dsa")),
            (
                "catalog_key",
                "public_key",
                json!(BASE64_URL_SAFE_NO_PAD.encode([7u8; 31])),
            ),
            (
                "catalog_key",
                "public_key",
                json!(base64::prelude::BASE64_URL_SAFE.encode(catalog_public_key())),
            ),
        ] {
            let mut d = document_with_signer_and_catalog_key();
            d[section][field] = bad.clone();
            let signed = sign(d, &key).unwrap();
            assert_eq!(
                verify(&signed, &key.verifying_key().into(), now)
                    .unwrap_err()
                    .code(),
                "platform_signature",
                "{section}.{field} {bad}"
            );
        }
    }

    #[wasm_bindgen_test::wasm_bindgen_test(unsupported = test)]
    fn the_compiled_in_release_key_set_parses() {
        release_keys().unwrap();
    }
}
