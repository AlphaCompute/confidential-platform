//! A Kata pod's init-data: the TOML a tenant signs as a Revision v2. Kata's shim hashes these
//! exact bytes into `MRCONFIGID`, not the base64-of-gzip annotation that carries them to the
//! host, so the host may re-encode the annotation without changing the Revision.

use serde::Deserialize;

use crate::{ComposeHash, compose_hash};

#[derive(Debug)]
pub struct InitData(String);

#[derive(Debug, thiserror::Error)]
pub enum InitDataError {
    #[error("init-data is not TOML: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("init-data algorithm {0:?} is not \"sha256\"")]
    Algorithm(String),
    #[error("init-data version {0:?} is not \"0.1.0\"")]
    Version(String),
}

#[derive(Deserialize)]
struct Header {
    algorithm: String,
    version: String,
}

impl InitData {
    pub fn parse(toml: String) -> Result<Self, InitDataError> {
        let header: Header = toml::from_str(&toml)?;
        // sha256 alone makes the Revision digest the first half of MRCONFIGID. Kata's shim
        // dies on any other spelling (`SHA256`), and its agent refuses any other version.
        if header.algorithm != "sha256" {
            return Err(InitDataError::Algorithm(header.algorithm));
        }
        if header.version != "0.1.0" {
            return Err(InitDataError::Version(header.version));
        }
        Ok(Self(toml))
    }

    pub fn digest(&self) -> ComposeHash {
        compose_hash(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T1: &str = include_str!("../../../testdata/attest/b300-kata-4.0.0/t1-sha256.toml");

    #[test]
    fn digest_is_sha256_of_the_signed_bytes() {
        let init_data = InitData::parse(T1.into()).unwrap();
        assert_eq!(
            init_data.digest().to_string(),
            "sha256:3e0edd232abd1af04a8d8db5ad17f6bd9a75a9643abcb25806b71bbe31d7020a"
        );
        let same_meaning = InitData::parse(T1.replace("\"note\"", "note")).unwrap();
        assert_ne!(same_meaning.digest(), init_data.digest());
    }

    #[test]
    fn refuses_what_kata_would_not_boot() {
        let cases = [
            (T1.replace("\"sha256\"", "\"SHA256\""), "algorithm"),
            (T1.replace("\"sha256\"", "\"sha384\""), "algorithm"),
            (T1.replace("\"0.1.0\"", "\"0.2.0\""), "version"),
            (T1.replace("algorithm = \"sha256\"\n", ""), "TOML"),
            (format!("algorithm = \"sha256\"\n{T1}"), "TOML"),
            ("not toml".into(), "TOML"),
        ];
        for (toml, fragment) in cases {
            let err = InitData::parse(toml.clone()).unwrap_err().to_string();
            assert!(err.contains(fragment), "{toml:?}: {err}");
        }
    }
}
