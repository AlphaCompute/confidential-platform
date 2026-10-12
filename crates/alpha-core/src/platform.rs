use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use crate::ComposeHash;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KmsRevision {
    pub compose_hash: ComposeHash,
    pub build: String,
    pub source_url: String,
    /// The evidence profile this build's nodes attest under. A document written before Kata has
    /// none, and every build in it is a prototype CVM's. During the migration (PRD-05) one
    /// document lists the prototype build and the Kata build side by side.
    #[serde(default, skip_serializing_if = "KmsRevisionKind::is_prototype")]
    pub kind: KmsRevisionKind,
}

/// What a KMS build's `compose_hash` is the hash of: a prototype CVM's measured compose
/// (`alphacompute-evidence/1`) or a Kata pod's Revision v2 rebuilt from its init-data
/// (`kata-tdx/1`). A node is admitted only under the profile its build is listed for.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KmsRevisionKind {
    #[default]
    PrototypeTdx,
    KataTdx,
}

impl KmsRevisionKind {
    pub fn is_prototype(&self) -> bool {
        *self == Self::PrototypeTdx
    }
}

/// Option B (PRD-02 deliverable 26): the Trustee pods alpha-kms feeds, and what they may do.
/// Absent, no Trustee pod gets anything from the KMS.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "TrusteeFields")]
pub struct Trustee {
    /// The Trustee pod builds: each the Revision v2 of a Trustee pod's init-data, which must also
    /// be registered at the KMS like any App's.
    pub revisions: Vec<TrusteeRevision>,
    /// The DNS name workload pods reach Trustee's KBS under; the KBS's TLS leaf names it.
    pub kbs_hostname: String,
    /// How long a Trustee pod may act on the policy and reference values it last fetched from
    /// the KMS, in seconds: at least a minute, at most an hour (the life of a leaf).
    pub max_state_age_secs: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrusteeRevision {
    pub compose_hash: ComposeHash,
    pub build: String,
    pub source_url: String,
}

/// The suffix a KBS name must end in until G0 settles which roots the guest trusts.
pub const NON_PUBLIC_SUFFIX: &str = ".internal";

/// The bounds of [`Trustee::max_state_age_secs`].
pub const TRUSTEE_STATE_AGE_SECS: std::ops::RangeInclusive<u32> = 60..=3600;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrusteeFields {
    revisions: Vec<TrusteeRevision>,
    kbs_hostname: String,
    max_state_age_secs: u32,
}

impl TryFrom<TrusteeFields> for Trustee {
    type Error = String;

    fn try_from(f: TrusteeFields) -> Result<Self, Self::Error> {
        if !is_host(&f.kbs_hostname) {
            return Err(format!(
                "trustee.kbs_hostname {:?} is not a lowercase host",
                f.kbs_hostname
            ));
        }
        // ponytail: G0 — the guest's KBS client (kbs_protocol at guest-components d4dce5ce) adds
        // the pinned certificate as a root without dropping its built-in roots, so a publicly
        // trusted certificate for the KBS's name may pass too. Until G0 confirms the guest image's
        // root set, the name must be one no public CA issues for.
        if !f.kbs_hostname.ends_with(NON_PUBLIC_SUFFIX) {
            return Err(format!(
                "trustee.kbs_hostname {:?} is not under {NON_PUBLIC_SUFFIX} (G0: the guest's TLS roots)",
                f.kbs_hostname
            ));
        }
        if !TRUSTEE_STATE_AGE_SECS.contains(&f.max_state_age_secs) {
            return Err(format!(
                "trustee.max_state_age_secs {} is not between 60 and 3600",
                f.max_state_age_secs
            ));
        }
        Ok(Self {
            revisions: f.revisions,
            kbs_hostname: f.kbs_hostname,
            max_state_age_secs: f.max_state_age_secs,
        })
    }
}

impl Trustee {
    pub fn lists(&self, revision: ComposeHash) -> bool {
        self.revisions.iter().any(|r| r.compose_hash == revision)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "SignerFields")]
pub struct Signer {
    pub origins: Vec<String>,
    pub rp_id: String,
    pub bundle_sha256: String,
    pub api_origin: String,
}

#[derive(Deserialize)]
struct SignerFields {
    origins: Vec<String>,
    rp_id: String,
    bundle_sha256: String,
    api_origin: String,
}

impl TryFrom<SignerFields> for Signer {
    type Error = String;

    fn try_from(f: SignerFields) -> Result<Self, Self::Error> {
        if !is_host(&f.rp_id) {
            return Err(format!(
                "signer.rp_id {:?} is not a lowercase host",
                f.rp_id
            ));
        }
        if f.origins.is_empty() {
            return Err("signer.origins is empty".into());
        }
        for origin in &f.origins {
            let on_rp_id = origin_host(origin)
                .and_then(|host| host.strip_suffix(f.rp_id.as_str()))
                .is_some_and(|rest| rest.is_empty() || rest.ends_with('.'));
            if !on_rp_id {
                return Err(format!(
                    "signer.origins {origin:?} is not an https origin on {:?}",
                    f.rp_id
                ));
            }
        }
        if origin_host(&f.api_origin).is_none() {
            return Err(format!(
                "signer.api_origin {:?} is not an https origin",
                f.api_origin
            ));
        }
        if f.bundle_sha256
            .strip_prefix("sha256:")
            .and_then(crate::hex_bytes::<32>)
            .is_none()
        {
            return Err(format!(
                "signer.bundle_sha256 {:?} is not sha256:<64 lowercase hex>",
                f.bundle_sha256
            ));
        }
        Ok(Self {
            origins: f.origins,
            rp_id: f.rp_id,
            bundle_sha256: f.bundle_sha256,
            api_origin: f.api_origin,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "CatalogKeyFields")]
pub struct CatalogKey {
    pub algorithm: String,
    pub public_key: String,
}

impl CatalogKey {
    pub fn verifying_key(&self) -> Option<ed25519_dalek::VerifyingKey> {
        if self.algorithm != "ed25519" {
            return None;
        }
        BASE64_URL_SAFE_NO_PAD
            .decode(&self.public_key)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .and_then(|b| ed25519_dalek::VerifyingKey::from_bytes(&b).ok())
            .filter(|k| !k.is_weak())
    }
}

impl From<&ed25519_dalek::VerifyingKey> for CatalogKey {
    fn from(key: &ed25519_dalek::VerifyingKey) -> Self {
        Self {
            algorithm: "ed25519".into(),
            public_key: BASE64_URL_SAFE_NO_PAD.encode(key.to_bytes()),
        }
    }
}

#[derive(Deserialize)]
struct CatalogKeyFields {
    algorithm: String,
    public_key: String,
}

impl TryFrom<CatalogKeyFields> for CatalogKey {
    type Error = String;

    fn try_from(f: CatalogKeyFields) -> Result<Self, Self::Error> {
        if f.algorithm != "ed25519" {
            return Err(format!("catalog_key.algorithm {:?}", f.algorithm));
        }
        let key = Self {
            algorithm: f.algorithm,
            public_key: f.public_key,
        };
        if key.verifying_key().is_none() {
            return Err(format!(
                "catalog_key.public_key {:?} is not an Ed25519 public key in base64url",
                key.public_key
            ));
        }
        Ok(key)
    }
}

/// The host of a serialized `https` origin. A non-canonical origin is refused rather than
/// normalized, because the passkey check later compares origins byte for byte.
fn origin_host(origin: &str) -> Option<&str> {
    let rest = origin.strip_prefix("https://")?;
    let host = match rest.split_once(':') {
        None => rest,
        Some((host, port)) => {
            // `u16` parsing takes `+443` and `0443`, and a browser serializes neither of them,
            // nor the default port.
            if port.starts_with('0')
                || !port.bytes().all(|b| b.is_ascii_digit())
                || !matches!(port.parse::<u16>(), Ok(p) if p != 443)
            {
                return None;
            }
            host
        }
    };
    is_host(host).then_some(host)
}

fn is_host(host: &str) -> bool {
    host.len() <= 253
        && host.split('.').all(|label| {
            let bytes = label.as_bytes();
            !bytes.is_empty()
                && bytes.len() <= 63
                && bytes.first() != Some(&b'-')
                && bytes.last() != Some(&b'-')
                && bytes
                    .iter()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
        })
        && host
            .rsplit('.')
            .next()
            .is_some_and(|tld| tld.bytes().any(|b| b.is_ascii_lowercase()))
}

#[cfg(test)]
mod tests {
    use base64::prelude::{BASE64_STANDARD_NO_PAD, BASE64_URL_SAFE};
    use ed25519_dalek::SigningKey;
    use serde_json::{Value, json};

    use super::*;

    fn signer_on(rp_id: &str, field: &str, value: Value) -> Result<Signer, serde_json::Error> {
        let mut s = json!({
            "origins": [format!("https://{rp_id}")],
            "rp_id": rp_id,
            "bundle_sha256": format!("sha256:{}", "0".repeat(64)),
            "api_origin": "https://api.example"
        });
        s[field] = value;
        serde_json::from_value(s)
    }

    fn signer(field: &str, value: Value) -> Result<Signer, serde_json::Error> {
        signer_on("sign.example", field, value)
    }

    fn public_key() -> [u8; 32] {
        SigningKey::from_bytes(&[7u8; 32])
            .verifying_key()
            .to_bytes()
    }

    fn catalog_key(algorithm: &str, public_key: &str) -> Result<CatalogKey, serde_json::Error> {
        serde_json::from_value(json!({ "algorithm": algorithm, "public_key": public_key }))
    }

    #[test]
    fn trustee_names_a_host_and_a_state_age_within_a_leaf() {
        let trustee = |host: &str, age: u32| {
            serde_json::from_value::<Trustee>(json!({
                "revisions": [{ "compose_hash": format!("sha256:{}", "1".repeat(64)),
                                "build": "trustee v0.21.0", "source_url": "https://example" }],
                "kbs_hostname": host,
                "max_state_age_secs": age,
            }))
        };
        let ok = trustee("kbs.trustee.internal", 300).unwrap();
        assert!(ok.lists(format!("sha256:{}", "1".repeat(64)).parse().unwrap()));
        assert!(!ok.lists(format!("sha256:{}", "2".repeat(64)).parse().unwrap()));
        assert!(trustee("kbs.trustee.internal", 60).is_ok());
        assert!(trustee("kbs.trustee.internal", 3600).is_ok());
        for (host, age) in [
            ("KBS.internal", 300),
            ("https://kbs.internal", 300),
            ("kbs.internal:8443", 300),
            ("kbs.example", 300),
            ("kbs.internal.example", 300),
            ("kbs.internal", 59),
            ("kbs.internal", 3601),
        ] {
            assert!(trustee(host, age).is_err(), "{host} {age}");
        }
        let mut extra = serde_json::to_value(&ok).unwrap();
        extra["policy"] = json!("allow");
        assert!(serde_json::from_value::<Trustee>(extra).is_err());
    }

    #[test]
    fn origin_is_a_serialized_https_origin() {
        for ok in [
            "https://api.example",
            "https://api.example:1",
            "https://api.example:65535",
            "https://api.example:8443",
            "https://localhost",
        ] {
            assert!(signer("api_origin", json!(ok)).is_ok(), "{ok:?}");
        }
        for bad in [
            "http://api.example",
            "https://API.example",
            "https://api.example/",
            "https://api.example/v1",
            "https://api.example?x",
            "https://api.example#x",
            "https://u@api.example",
            "https://api.example:",
            "https://api.example:0",
            "https://api.example:443",
            "https://api.example:+443",
            "https://api.example:0443",
            "https://api.example:65536",
            "https://api.example:99999999999999999999",
            "https://127.0.0.1",
            "https://[::1]",
            "https://api.example.",
            "https://-a.example",
            "https://a..example",
            "https://",
            "",
        ] {
            assert!(signer("api_origin", json!(bad)).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn signer_origins_sit_on_rp_id_at_a_label_boundary() {
        for ok in [
            "https://sign.example",
            "https://a.sign.example",
            "https://a.b.sign.example:8443",
        ] {
            assert!(signer("origins", json!([ok])).is_ok(), "{ok:?}");
        }
        for bad in [
            "https://evilsign.example",
            "https://sign.example.evil",
            "https://example",
            "https://other.example",
        ] {
            assert!(signer("origins", json!([bad])).is_err(), "{bad:?}");
        }
        for ok in ["https://localhost:8443", "https://localhost"] {
            assert!(
                signer_on("localhost", "origins", json!([ok])).is_ok(),
                "{ok:?}"
            );
        }
        assert!(signer_on("localhost", "origins", json!(["http://localhost:8443"])).is_err());
        for bad in [
            "",
            "Sign.example",
            "sign.example.",
            "127.0.0.1",
            "https://sign.example",
        ] {
            assert!(signer("rp_id", json!(bad)).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn signer_refuses_empty_origins_and_bad_bundle_hashes() {
        assert!(signer("origins", json!([])).is_err());
        assert!(signer("origins", json!(["https://sign.example"])).is_ok());
        for bad in [
            format!("sha256:{}", "0".repeat(63)),
            format!("sha256:{}", "0".repeat(65)),
            format!("sha256:{}", "A".repeat(64)),
            format!("sha256:{}", "g".repeat(64)),
            "0".repeat(64),
        ] {
            assert!(signer("bundle_sha256", json!(bad)).is_err(), "{bad:?}");
        }
        let good = format!("sha256:{}", "0".repeat(64));
        assert!(signer("bundle_sha256", json!(good)).is_ok());
    }

    #[test]
    fn signer_keeps_origin_order_and_duplicates_and_tolerates_unknown_fields() {
        let b = "https://b.sign.example";
        let a = "https://a.sign.example";
        assert_eq!(
            signer("origins", json!([b, a, b])).unwrap().origins,
            [b, a, b]
        );
        assert!(signer("later", json!(1)).is_ok());
        let key = json!({
            "algorithm": "ed25519",
            "public_key": BASE64_URL_SAFE_NO_PAD.encode(public_key()),
            "later": 1
        });
        assert!(serde_json::from_value::<CatalogKey>(key).is_ok());
    }

    #[test]
    fn catalog_key_is_an_ed25519_public_key_in_base64url() {
        let good = BASE64_URL_SAFE_NO_PAD.encode(public_key());
        assert_eq!(catalog_key("ed25519", &good).unwrap().public_key, good);
        let standard = BASE64_STANDARD_NO_PAD.encode(public_key());
        assert!(standard.contains('+') || standard.contains('/'));
        for (algorithm, public_key) in [
            ("ml-dsa", good.clone()),
            ("Ed25519", good.clone()),
            (
                "ed25519",
                BASE64_URL_SAFE_NO_PAD.encode(&public_key()[..31]),
            ),
            (
                "ed25519",
                BASE64_URL_SAFE_NO_PAD.encode([&public_key()[..], &[0]].concat()),
            ),
            ("ed25519", BASE64_URL_SAFE.encode(public_key())),
            ("ed25519", standard),
            ("ed25519", BASE64_URL_SAFE_NO_PAD.encode([0u8; 32])),
            ("ed25519", BASE64_URL_SAFE_NO_PAD.encode([7u8; 32])),
        ] {
            assert!(
                catalog_key(algorithm, &public_key).is_err(),
                "{algorithm:?} {public_key:?}"
            );
        }
    }

    #[test]
    fn a_kms_revision_without_kind_is_a_prototype_build_and_a_kata_build_says_so() {
        let hash = crate::compose_hash("{}");
        let old = json!({ "compose_hash": hash, "build": "kms v1", "source_url": "u" });
        let revision: KmsRevision = serde_json::from_value(old.clone()).unwrap();
        assert_eq!(revision.kind, KmsRevisionKind::PrototypeTdx);
        assert_eq!(serde_json::to_value(&revision).unwrap(), old);

        let mut kata = old;
        kata["kind"] = json!("kata-tdx");
        let revision: KmsRevision = serde_json::from_value(kata.clone()).unwrap();
        assert_eq!(revision.kind, KmsRevisionKind::KataTdx);
        assert_eq!(serde_json::to_value(&revision).unwrap(), kata);

        kata["kind"] = json!("kata-snp");
        assert!(serde_json::from_value::<KmsRevision>(kata).is_err());
    }
}
