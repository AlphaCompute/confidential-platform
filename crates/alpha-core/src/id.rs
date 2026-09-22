use std::fmt;
use std::str::FromStr;

use uuid::Uuid;

macro_rules! id {
    ($name:ident) => {
        #[derive(
            Clone,
            Copy,
            Debug,
            PartialEq,
            Eq,
            Hash,
            PartialOrd,
            Ord,
            serde::Serialize,
            serde::Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            pub fn mint() -> Self {
                Self(Uuid::now_v7())
            }

            pub fn as_bytes(&self) -> &[u8; 16] {
                self.0.as_bytes()
            }
        }

        impl From<Uuid> for $name {
            fn from(uuid: Uuid) -> Self {
                Self(uuid)
            }
        }

        impl From<$name> for Uuid {
            fn from(id: $name) -> Uuid {
                id.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.as_hyphenated().fmt(f)
            }
        }

        impl FromStr for $name {
            type Err = uuid::Error;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Uuid::parse_str(s).map(Self)
            }
        }
    };
}

id!(OrgId);
id!(PrincipalId);
id!(AppId);
id!(KeyId);
id!(SecretId);
id!(RequestId);

impl OrgId {
    /// UUIDv8, first 128 bits of SHA-256(domain || canonical Ed25519 SPKI),
    /// with RFC 9562 version/variant bits set (122 fingerprint bits retained).
    /// The full SPKI remains the immutable root binding in the KMS.
    pub fn from_root_spki(spki: &[u8]) -> Self {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest([b"alphacompute/trust-org/v1\0".as_slice(), spki].concat());
        let mut bytes = [0u8; 16];
        for (out, input) in bytes.iter_mut().zip(digest.iter()) {
            *out = *input;
        }
        Self(uuid::Builder::from_custom_bytes(bytes).into_uuid())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mint_is_v7_and_round_trips() {
        let id = AppId::mint();
        assert_eq!(id.0.get_version_num(), 7);
        assert_eq!(id.to_string().parse::<AppId>().unwrap(), id);
        assert_eq!(serde_json::to_string(&id).unwrap(), format!("\"{id}\""));
    }
}
