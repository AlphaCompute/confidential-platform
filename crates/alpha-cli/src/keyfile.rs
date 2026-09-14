//! One file format for the admin (Ed25519) and custodian (X-Wing) keys: the 32-byte seed
//! under scrypt + AES-256-GCM, the KDF and AEAD named in the file, the algorithm as AEAD aad.

use std::fs;
use std::path::Path;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::EncodePublicKey;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::random;

pub const FORMAT: &str = "alphacompute-key/1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Algorithm {
    Ed25519,
    XWing,
}

impl Algorithm {
    fn name(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
            Self::XWing => "x-wing",
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyFile {
    format: String,
    algorithm: Algorithm,
    kdf: Kdf,
    aead: String,
    nonce: String,
    ciphertext: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Kdf {
    name: String,
    log_n: u8,
    r: u32,
    p: u32,
    salt: String,
}

#[allow(clippy::large_enum_variant)]
pub enum Key {
    Ed25519(SigningKey),
    XWing(alpha_crypto::PrivateKey),
}

impl Key {
    pub fn from_seed(algorithm: Algorithm, seed: &[u8; 32]) -> Self {
        match algorithm {
            Algorithm::Ed25519 => Self::Ed25519(SigningKey::from_bytes(seed)),
            Algorithm::XWing => Self::XWing(alpha_crypto::PrivateKey::from_seed(*seed)),
        }
    }

    /// What registration takes: the SPKI DER of an admin key, the 1216 bytes of a custodian's.
    pub fn public_key_text(&self) -> String {
        match self {
            Self::Ed25519(key) => BASE64_URL_SAFE_NO_PAD.encode(
                key.verifying_key()
                    .to_public_key_der()
                    .expect("ed25519 spki")
                    .as_bytes(),
            ),
            Self::XWing(key) => BASE64_URL_SAFE_NO_PAD.encode(key.public().as_bytes()),
        }
    }

    pub fn ed25519(self) -> Result<SigningKey, String> {
        match self {
            Self::Ed25519(key) => Ok(key),
            Self::XWing(_) => Err("key file holds an X-Wing key, not an Ed25519 admin key".into()),
        }
    }

    pub fn xwing(self) -> Result<alpha_crypto::PrivateKey, String> {
        match self {
            Self::XWing(key) => Ok(key),
            Self::Ed25519(_) => {
                Err("key file holds an Ed25519 key, not an X-Wing custodian key".into())
            }
        }
    }
}

fn derive(passphrase: &[u8], kdf: &Kdf) -> Result<Zeroizing<[u8; 32]>, String> {
    if kdf.name != "scrypt" {
        return Err(format!("key file: unsupported kdf {:?}", kdf.name));
    }
    let salt = BASE64_URL_SAFE_NO_PAD
        .decode(&kdf.salt)
        .map_err(|_| "key file: salt is not base64url")?;
    let params = scrypt::Params::new(kdf.log_n, kdf.r, kdf.p)
        .map_err(|e| format!("key file: scrypt parameters: {e}"))?;
    let mut out = Zeroizing::new([0u8; 32]);
    scrypt::scrypt(passphrase, &salt, &params, out.as_mut())
        .map_err(|e| format!("key file: scrypt: {e}"))?;
    Ok(out)
}

pub fn generate(algorithm: Algorithm, path: &Path, passphrase: &[u8]) -> Result<Key, String> {
    let seed = Zeroizing::new(random::<32>());
    let kdf = Kdf {
        name: "scrypt".into(),
        log_n: 15,
        r: 8,
        p: 1,
        salt: BASE64_URL_SAFE_NO_PAD.encode(random::<16>()),
    };
    let key = derive(passphrase, &kdf)?;
    let nonce = random::<12>();
    let ciphertext = Aes256Gcm::new((&*key).into())
        .encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: seed.as_slice(),
                aad: algorithm.name().as_bytes(),
            },
        )
        .expect("AES-GCM encryption cannot fail");
    let file = KeyFile {
        format: FORMAT.into(),
        algorithm,
        kdf,
        aead: "aes-256-gcm".into(),
        nonce: BASE64_URL_SAFE_NO_PAD.encode(nonce),
        ciphertext: BASE64_URL_SAFE_NO_PAD.encode(ciphertext),
    };
    let text = serde_json::to_string_pretty(&file).expect("serializes") + "\n";
    fs::write(path, text).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(Key::from_seed(algorithm, &seed))
}

pub fn read(path: &Path, passphrase: &[u8]) -> Result<Key, String> {
    let text = fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let file: KeyFile =
        serde_json::from_slice(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    if file.format != FORMAT {
        return Err(format!("key file: unsupported format {:?}", file.format));
    }
    if file.aead != "aes-256-gcm" {
        return Err(format!("key file: unsupported aead {:?}", file.aead));
    }
    let key = derive(passphrase, &file.kdf)?;
    let decode = |field: &str, text: &str| {
        BASE64_URL_SAFE_NO_PAD
            .decode(text)
            .map_err(|_| format!("key file: {field} is not base64url"))
    };
    let nonce = decode("nonce", &file.nonce)?;
    let ciphertext = decode("ciphertext", &file.ciphertext)?;
    let nonce: [u8; 12] = nonce
        .try_into()
        .map_err(|_| "key file: nonce is not 12 bytes")?;
    let seed = Aes256Gcm::new((&*key).into())
        .decrypt(
            &Nonce::from(nonce),
            Payload {
                msg: &ciphertext,
                aad: file.algorithm.name().as_bytes(),
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| "key file: wrong passphrase or corrupted file")?;
    let seed: Zeroizing<[u8; 32]> = Zeroizing::new(
        <[u8; 32]>::try_from(seed.as_slice()).map_err(|_| "key file: seed is not 32 bytes")?,
    );
    Ok(Key::from_seed(file.algorithm, &seed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_passphrase_binding() {
        let dir = std::env::temp_dir().join(format!("alpha-keyfile-{}", uuid()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("admin.key");
        let generated = generate(Algorithm::Ed25519, &path, b"correct horse").unwrap();
        let loaded = read(&path, b"correct horse").unwrap();
        assert_eq!(generated.public_key_text(), loaded.public_key_text());
        assert!(loaded.xwing().is_err());
        assert!(
            read(&path, b"wrong")
                .err()
                .unwrap()
                .contains("wrong passphrase")
        );
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains("\"kdf\"") && text.contains("\"scrypt\""));
        assert!(text.contains("\"aead\": \"aes-256-gcm\""));

        let custodian = dir.join("c.key");
        let generated = generate(Algorithm::XWing, &custodian, b"pw").unwrap();
        let loaded = read(&custodian, b"pw").unwrap();
        assert_eq!(generated.public_key_text(), loaded.public_key_text());
        assert_eq!(
            BASE64_URL_SAFE_NO_PAD
                .decode(loaded.public_key_text())
                .unwrap()
                .len(),
            alpha_crypto::PUBLIC_KEY_LEN
        );
        // The algorithm is aad: relabelling the file does not turn one key into the other.
        let mut swapped: serde_json::Value = serde_json::from_str(&text).unwrap();
        swapped["algorithm"] = serde_json::json!("x-wing");
        fs::write(&path, swapped.to_string()).unwrap();
        assert!(read(&path, b"correct horse").is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    fn uuid() -> String {
        alpha_core::KeyId::mint().to_string()
    }
}
