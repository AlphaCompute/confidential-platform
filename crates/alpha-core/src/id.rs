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
