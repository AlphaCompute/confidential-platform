//! The resources a pod's Confidential Data Hub asks Trustee's KBS for, and the grant that opts an
//! App's resources in.
//!
//! The contract with the init-data generator (`docs/encrypted-storage.md`, branch
//! `prd02/15-cdh-storage`) is `kbs:///<repository>/<type>/<tag>`: the repository is the App id
//! in its lower-case canonical form, the type one of [`ResourceType`], the tag a Secret name or a
//! key purpose (`.` where a purpose would have `:`). The KBS hands the three path segments of
//! `GET /kbs/v0/resource/<repository>/<type>/<tag>` to its policy and its backend as they are.
//!
//! What backs each type at the KMS is decided here, not by the pod:
//!
//! | Type | Backed by |
//! |---|---|
//! | `secret/<name>` | the App's Secret `<name>`, as `GET /v1/secrets/<name>` releases it |
//! | `key/<purpose>` | the App's derived key for `<purpose>`, as `POST /v1/keys/derive` returns it, 32 raw bytes |
//! | `image-key/<name>` | the App's Secret `image-key.<name>`: a 32-byte key-encryption key the tenant chose, since the tenant encrypts the image with it |
//! | `sealed-secret-key/<name>` | the App's Secret `sealed-secret-key.<name>`: a P-256 public JWK, the key a sealed secret's signature verifies under |
//!
//! The three Secret-backed types never name one Secret: `secret/` refuses the other two prefixes.

use alpha_core::{AppId, is_key_purpose, is_secret_name};
use serde::{Deserialize, Serialize};

/// The prefix of a KBS resource URI; the empty authority means "the configured KBS".
pub const URI_PREFIX: &str = "kbs:///";

/// A grant entry's tag that covers every tag of its type.
pub const ANY_TAG: &str = "*";

/// Key purposes the release path never derives, whatever a grant says: the platform's own
/// derivations live under them (a Trustee pod's token-signing key is its App's `trustee.as-token`).
pub const RESERVED_PURPOSE_PREFIXES: [&str; 2] = ["trustee.", "kms."];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResourceType {
    /// A tenant Secret, by name: a sealed secret's value, a credential.
    Secret,
    /// The App's derived key for a purpose: a volume's key (`volume.<name>`).
    Key,
    /// The key-encryption key an encrypted image's layer keys are wrapped under.
    ImageKey,
    /// The public key a sealed secret's signature verifies under.
    SealedSecretKey,
}

impl ResourceType {
    pub const ALL: [Self; 4] = [
        Self::Secret,
        Self::Key,
        Self::ImageKey,
        Self::SealedSecretKey,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::Secret => "secret",
            Self::Key => "key",
            Self::ImageKey => "image-key",
            Self::SealedSecretKey => "sealed-secret-key",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|t| t.name() == name)
    }

    /// The prefix of the Secret names this type is backed by; `None` for derived keys and for
    /// `secret`, whose tag is the Secret's name itself.
    fn secret_prefix(self) -> Option<&'static str> {
        match self {
            Self::ImageKey => Some("image-key."),
            Self::SealedSecretKey => Some("sealed-secret-key."),
            Self::Secret | Self::Key => None,
        }
    }

    /// Whether `tag` names a resource of this type; never `*`.
    pub fn tag_ok(self, tag: &str) -> bool {
        match self {
            Self::Key => is_key_purpose(tag) && !is_reserved_purpose(tag),
            Self::Secret => {
                is_secret_name(tag)
                    && !Self::ALL
                        .iter()
                        .filter_map(|t| t.secret_prefix())
                        .any(|p| tag.starts_with(p))
            }
            Self::ImageKey | Self::SealedSecretKey => self
                .secret_name(tag)
                .is_some_and(|name| is_secret_name(tag) && is_secret_name(&name)),
        }
    }

    /// The App Secret a resource of this type and tag is; `None` for a derived key.
    pub fn secret_name(self, tag: &str) -> Option<String> {
        match self {
            Self::Key => None,
            Self::Secret => Some(tag.to_owned()),
            Self::ImageKey | Self::SealedSecretKey => {
                self.secret_prefix().map(|p| format!("{p}{tag}"))
            }
        }
    }
}

pub fn is_reserved_purpose(purpose: &str) -> bool {
    RESERVED_PURPOSE_PREFIXES
        .iter()
        .any(|p| purpose.starts_with(p))
}

/// One resource of the contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resource {
    pub app: AppId,
    pub kind: ResourceType,
    pub tag: String,
}

impl Resource {
    pub fn new(app: AppId, kind: ResourceType, tag: &str) -> Result<Self, String> {
        if !kind.tag_ok(tag) {
            return Err(format!("{} {tag:?} is not a valid name", kind.name()));
        }
        Ok(Self {
            app,
            kind,
            tag: tag.to_owned(),
        })
    }

    /// The KBS path segments `[<App id>, <type>, <tag>]`, exactly as the contract writes them.
    pub fn from_segments(segments: &[&str]) -> Result<Self, String> {
        let [app, kind, tag] = segments else {
            return Err(format!(
                "{} path segments, not <App id>/<type>/<tag>",
                segments.len()
            ));
        };
        let app = app
            .parse::<AppId>()
            .ok()
            .filter(|a| a.to_string() == *app)
            .ok_or_else(|| format!("{app:?} is not an App id in canonical form"))?;
        let kind = ResourceType::from_name(kind).ok_or_else(|| {
            format!("type {kind:?} is not secret, key, image-key or sealed-secret-key")
        })?;
        Self::new(app, kind, tag)
    }

    /// Exactly `kbs:///<App id>/<type>/<tag>`.
    pub fn parse(uri: &str) -> Result<Self, String> {
        let rest = uri
            .strip_prefix(URI_PREFIX)
            .ok_or_else(|| format!("{uri:?} is not kbs:///<App id>/<type>/<tag>"))?;
        Self::from_segments(&rest.split('/').collect::<Vec<_>>())
    }

    pub fn uri(&self) -> String {
        format!("{URI_PREFIX}{}", self.path())
    }

    /// `<App id>/<type>/<tag>`, as the KBS's resource backend is asked for it.
    pub fn path(&self) -> String {
        format!("{}/{}/{}", self.app, self.kind.name(), self.tag)
    }
}

/// One entry of a tenant's grant: a type, and one tag or [`ANY_TAG`].
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantEntry {
    #[serde(rename = "type")]
    pub kind: ResourceType,
    pub tag: String,
}

impl GrantEntry {
    pub fn check(&self) -> Result<(), String> {
        if self.tag == ANY_TAG || self.kind.tag_ok(&self.tag) {
            return Ok(());
        }
        Err(format!(
            "grant: {} {:?} is not a valid name or {ANY_TAG}",
            self.kind.name(),
            self.tag
        ))
    }

    pub fn covers(&self, resource: &Resource) -> bool {
        self.kind == resource.kind && (self.tag == ANY_TAG || self.tag == resource.tag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const APP: &str = "01994b3e-5c8a-7d3e-9a1b-2c3d4e5f6a7b";

    #[test]
    fn the_contract_is_exactly_app_type_tag() {
        let r = Resource::parse(&format!("kbs:///{APP}/secret/db-password")).unwrap();
        assert_eq!(r.app.to_string(), APP);
        assert_eq!(r.kind, ResourceType::Secret);
        assert_eq!(r.uri(), format!("kbs:///{APP}/secret/db-password"));
        assert_eq!(r.path(), format!("{APP}/secret/db-password"));
        for (kind, tag) in [
            ("key", "volume.data"),
            ("image-key", "base"),
            ("sealed-secret-key", "signing"),
        ] {
            let r = Resource::parse(&format!("kbs:///{APP}/{kind}/{tag}")).unwrap();
            assert_eq!(r.kind.name(), kind);
            assert_eq!(r.tag, tag);
        }
        for bad in [
            format!("kbs://kbs.example/{APP}/secret/x"),
            format!("kbs:///{}/secret/x", APP.to_uppercase()),
            format!("kbs:///{}/secret/x", APP.replace('-', "")),
            "kbs:///default/secret/x".into(),
            format!("kbs:///{APP}/token/x"),
            format!("kbs:///{APP}/secret"),
            format!("kbs:///{APP}/secret/x/y"),
            format!("kbs:///{APP}/secret/"),
            format!("kbs:///{APP}/key/volume:data"),
            format!("kbs:///{APP}/key/Volume"),
            format!("kbs:///{APP}/secret/a?b"),
        ] {
            assert!(Resource::parse(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_secret_backed_types_never_name_one_secret() {
        assert_eq!(
            ResourceType::Secret.secret_name("db").as_deref(),
            Some("db")
        );
        assert_eq!(
            ResourceType::ImageKey.secret_name("base").as_deref(),
            Some("image-key.base")
        );
        assert_eq!(
            ResourceType::SealedSecretKey.secret_name("s").as_deref(),
            Some("sealed-secret-key.s")
        );
        assert_eq!(ResourceType::Key.secret_name("volume.data"), None);
        assert!(!ResourceType::Secret.tag_ok("image-key.base"));
        assert!(!ResourceType::Secret.tag_ok("sealed-secret-key.s"));
        // A name that fits on its own but not behind its prefix.
        let long = "a".repeat(95);
        assert!(ResourceType::Secret.tag_ok(&long));
        assert!(!ResourceType::ImageKey.tag_ok(&long));
    }

    #[test]
    fn the_platform_purposes_are_never_released() {
        for purpose in ["trustee.as-token", "kms.anything"] {
            assert!(!ResourceType::Key.tag_ok(purpose), "{purpose}");
            assert!(
                Resource::parse(&format!("kbs:///{APP}/key/{purpose}")).is_err(),
                "{purpose}"
            );
        }
        assert!(ResourceType::Key.tag_ok("volume.trustee"));
    }

    #[test]
    fn a_grant_entry_covers_one_tag_or_every_tag_of_its_type() {
        let r = Resource::parse(&format!("kbs:///{APP}/secret/db")).unwrap();
        let entry = |kind: &str, tag: &str| -> GrantEntry {
            serde_json::from_value(serde_json::json!({ "type": kind, "tag": tag })).unwrap()
        };
        assert!(entry("secret", "db").covers(&r));
        assert!(entry("secret", "*").covers(&r));
        assert!(!entry("secret", "other").covers(&r));
        assert!(!entry("key", "*").covers(&r));
        assert!(entry("key", "*").check().is_ok());
        assert!(entry("key", "kms.x").check().is_err());
        assert!(entry("secret", "image-key.x").check().is_err());
        assert!(entry("secret", "db*").check().is_err());
        assert!(
            serde_json::from_value::<GrantEntry>(
                serde_json::json!({ "type": "token", "tag": "*" })
            )
            .is_err()
        );
        assert!(
            serde_json::from_value::<GrantEntry>(
                serde_json::json!({ "type": "key", "tag": "*", "extra": 1 })
            )
            .is_err()
        );
    }
}
