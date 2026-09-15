//! HPKE (RFC 9180, `mode_base`) with the X-Wing KEM, HKDF-SHA256 and AES-256-GCM, for the two
//! bodies that cross a custodian's boundary: unseal shares and the bootstrap request and reply.

#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )
)]

use std::fmt;

use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use hpke::aead::AesGcm256;
use hpke::kdf::HkdfSha256;
use hpke::kem::XWing;
use hpke::{Deserializable, Kem, OpModeR, OpModeS, Serializable};
use serde::{Deserialize, Serialize};
use serde_json::json;
use zeroize::{Zeroize, Zeroizing};

pub const INFO_UNSEAL_SHARE: &[u8] = b"alphacompute/unseal-share/v1";
pub const INFO_NODE_BOOTSTRAP: &[u8] = b"alphacompute/node-bootstrap/v1";
pub const KEM_NAME: &str = "x-wing";
pub const PUBLIC_KEY_LEN: usize = 1216;

type SecretKey = <XWing as Kem>::PrivateKey;

/// X-Wing decapsulation key; the 32-byte seed is the only secret.
#[derive(Clone)]
pub struct PrivateKey(SecretKey);

impl PrivateKey {
    pub fn generate() -> Result<Self, Error> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).map_err(|_| Error::Rng)?;
        let key = Self::from_seed(seed);
        seed.zeroize();
        key
    }

    pub fn from_seed(seed: [u8; 32]) -> Result<Self, Error> {
        SecretKey::from_bytes(&seed)
            .map(Self)
            .map_err(|_| Error::Seed)
    }

    pub fn public(&self) -> PublicKey {
        PublicKey(XWing::sk_to_pk(&self.0).to_bytes().0)
    }

    pub fn seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.to_bytes().0)
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateKey(..)")
    }
}

/// X-Wing encapsulation key: the 1216 bytes of draft-connolly-cfrg-xwing-kem, base64url on the wire.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey([u8; PUBLIC_KEY_LEN]);

impl PublicKey {
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.0
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", BASE64_URL_SAFE_NO_PAD.encode(self.0))
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Error> {
        let bytes: [u8; PUBLIC_KEY_LEN] = bytes.try_into().map_err(|_| Error::PublicKey)?;
        <XWing as Kem>::PublicKey::from_bytes(&bytes).map_err(|_| Error::PublicKey)?;
        Ok(Self(bytes))
    }
}

impl Serialize for PublicKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&BASE64_URL_SAFE_NO_PAD.encode(self.0))
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        let bytes = BASE64_URL_SAFE_NO_PAD
            .decode(text)
            .map_err(serde::de::Error::custom)?;
        Self::try_from(bytes.as_slice()).map_err(serde::de::Error::custom)
    }
}

/// `{ "kem": "x-wing", "enc": "<base64url>", "ct": "<base64url>" }`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sealed {
    pub kem: String,
    pub enc: String,
    pub ct: String,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("not an X-Wing public key")]
    PublicKey,
    #[error("unsupported kem {0:?}")]
    Kem(String),
    #[error("enc or ct is not base64url or has the wrong length")]
    Encoding,
    #[error("ciphertext does not open under this key, info and aad")]
    Open,
    #[error("the system RNG failed")]
    Rng,
    #[error("not an X-Wing seed")]
    Seed,
    #[error("aad does not canonicalize: {0}")]
    Aad(#[from] serde_json::Error),
    #[error("sealing failed: {0}")]
    Seal(hpke::HpkeError),
}

/// The aad binds a body to the node whose evidence carried the X-Wing key.
pub fn aad(kms_node_spki_sha256: &[u8; 32]) -> Result<Vec<u8>, Error> {
    Ok(alpha_core::jcs(&json!({
        "kms_node_spki_sha256": format!("sha256:{}", hex::encode(kms_node_spki_sha256)),
    }))?)
}

pub fn seal(
    recipient: &PublicKey,
    info: &[u8],
    kms_node_spki_sha256: &[u8; 32],
    plaintext: &[u8],
) -> Result<Sealed, Error> {
    let pk = <XWing as Kem>::PublicKey::from_bytes(&recipient.0).map_err(|_| Error::PublicKey)?;
    let (enc, ct) = hpke::single_shot_seal::<AesGcm256, HkdfSha256, XWing>(
        &OpModeS::Base,
        &pk,
        info,
        plaintext,
        &aad(kms_node_spki_sha256)?,
    )
    .map_err(Error::Seal)?;
    Ok(Sealed {
        kem: KEM_NAME.into(),
        enc: BASE64_URL_SAFE_NO_PAD.encode(enc.to_bytes()),
        ct: BASE64_URL_SAFE_NO_PAD.encode(ct),
    })
}

pub fn open(
    key: &PrivateKey,
    info: &[u8],
    kms_node_spki_sha256: &[u8; 32],
    sealed: &Sealed,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    if sealed.kem != KEM_NAME {
        return Err(Error::Kem(sealed.kem.clone()));
    }
    let enc = BASE64_URL_SAFE_NO_PAD
        .decode(&sealed.enc)
        .ok()
        .and_then(|b| <XWing as Kem>::EncappedKey::from_bytes(&b).ok())
        .ok_or(Error::Encoding)?;
    let ct = BASE64_URL_SAFE_NO_PAD
        .decode(&sealed.ct)
        .map_err(|_| Error::Encoding)?;
    hpke::single_shot_open::<AesGcm256, HkdfSha256, XWing>(
        &OpModeR::Base,
        &key.0,
        &enc,
        info,
        &ct,
        &aad(kms_node_spki_sha256)?,
    )
    .map(Zeroizing::new)
    .map_err(|_| Error::Open)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_binding() {
        let key = PrivateKey::generate().unwrap();
        let node = [7u8; 32];
        let sealed = seal(&key.public(), INFO_UNSEAL_SHARE, &node, b"share").unwrap();
        assert_eq!(sealed.kem, "x-wing");
        assert_eq!(
            open(&key, INFO_UNSEAL_SHARE, &node, &sealed)
                .unwrap()
                .as_slice(),
            b"share"
        );
        assert!(matches!(
            open(&key, INFO_NODE_BOOTSTRAP, &node, &sealed),
            Err(Error::Open)
        ));
        assert!(matches!(
            open(&key, INFO_UNSEAL_SHARE, &[8u8; 32], &sealed),
            Err(Error::Open)
        ));
        assert!(matches!(
            open(
                &PrivateKey::generate().unwrap(),
                INFO_UNSEAL_SHARE,
                &node,
                &sealed
            ),
            Err(Error::Open)
        ));
        let mut wrong_kem = sealed.clone();
        wrong_kem.kem = "x25519".into();
        assert!(matches!(
            open(&key, INFO_UNSEAL_SHARE, &node, &wrong_kem),
            Err(Error::Kem(_))
        ));
    }

    #[test]
    fn public_key_round_trips_through_json() {
        let key = PrivateKey::generate().unwrap();
        assert_eq!(
            PrivateKey::from_seed(*key.seed()).unwrap().public(),
            key.public()
        );
        let json = serde_json::to_string(&key.public()).unwrap();
        assert_eq!(
            serde_json::from_str::<PublicKey>(&json).unwrap(),
            key.public()
        );
        assert!(PublicKey::try_from(&[0u8; 10][..]).is_err());
    }

    #[test]
    fn aad_is_jcs() {
        assert_eq!(
            aad(&[0xab; 32]).unwrap(),
            format!(r#"{{"kms_node_spki_sha256":"sha256:{}"}}"#, "ab".repeat(32)).as_bytes()
        );
    }
}
