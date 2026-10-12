//! The KBS resource response: a JWE in flattened JSON serialization, `ECDH-ES+A256KW` over P-256
//! and `A256GCM`, the one shape the pinned guest components' default TEE key decrypts
//! (`attestation-agent/kbs_protocol/src/keypair.rs` `decrypt_response`, and Trustee 258ea4ac
//! `kbs/src/jwe.rs` `ecdh_es_a256kw_p256` on the serving side).

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use aes_kw::KwAes256;
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use p256::elliptic_curve::sec1::ToSec1Point;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::ApiError;

pub const ALG: &str = "ECDH-ES+A256KW";
pub const ENC: &str = "A256GCM";
pub const CRV: &str = "P-256";

/// The protected header. Its fields are in the order the client re-serializes them to rebuild
/// the AAD (`alg`, `enc`, then `epk` with its members sorted), so the bytes it authenticates are
/// the bytes sent, whether or not its JSON map keeps insertion order.
#[derive(Serialize)]
struct Protected<'a> {
    alg: &'a str,
    enc: &'a str,
    epk: Epk<'a>,
}

#[derive(Serialize)]
struct Epk<'a> {
    crv: &'a str,
    kty: &'a str,
    x: String,
    y: String,
}

/// RFC 7518 §4.6.2's Concat KDF with SHA-256 for one output block: `AlgorithmID` is `alg`,
/// `PartyUInfo` and `PartyVInfo` are `apu` and `apv`, each length-prefixed, and `keydatalen`
/// is `bits`. The KBS protocol uses empty `apu` and `apv`.
pub fn concat_kdf(z: &[u8], alg: &str, apu: &[u8], apv: &[u8], bits: u32) -> Zeroizing<[u8; 32]> {
    let prefixed = |bytes: &[u8]| {
        let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX).to_be_bytes();
        [len.as_slice(), bytes].concat()
    };
    let digest = Sha256::new()
        .chain_update(1u32.to_be_bytes())
        .chain_update(z)
        .chain_update(prefixed(alg.as_bytes()))
        .chain_update(prefixed(apu))
        .chain_update(prefixed(apv))
        .chain_update(bits.to_be_bytes())
        .finalize();
    Zeroizing::new(digest.into())
}

/// `plaintext` sealed to `tee_key`, under a fresh ephemeral key, content key and IV.
pub fn seal(tee_key: &p256::PublicKey, plaintext: &[u8]) -> Result<Value, ApiError> {
    let ephemeral = p256::SecretKey::from_slice(&*Zeroizing::new(crate::random::<32>()?))
        .map_err(|_| ApiError::internal("ephemeral key"))?;
    let cek = Zeroizing::new(crate::random::<32>()?);
    seal_with(
        tee_key,
        &ephemeral,
        &cek,
        &crate::random::<12>()?,
        plaintext,
    )
}

/// [`seal`] with its random inputs given, for the known-answer tests.
pub fn seal_with(
    tee_key: &p256::PublicKey,
    ephemeral: &p256::SecretKey,
    cek: &[u8; 32],
    iv: &[u8; 12],
    plaintext: &[u8],
) -> Result<Value, ApiError> {
    let z = p256::ecdh::diffie_hellman(ephemeral.to_nonzero_scalar(), tee_key.as_affine());
    let kek = concat_kdf(z.raw_secret_bytes().as_slice(), ALG, &[], &[], 256);
    let mut encrypted_key = [0u8; 40];
    KwAes256::new_from_slice(kek.as_slice())
        .map_err(|_| ApiError::internal("key wrap key"))?
        .wrap_key(cek, &mut encrypted_key)
        .map_err(|e| ApiError::internal(format!("key wrap: {e}")))?;

    let point = ephemeral.public_key().to_sec1_point(false);
    let (Some(x), Some(y)) = (point.x(), point.y()) else {
        return Err(ApiError::internal(
            "ephemeral key has no affine coordinates",
        ));
    };
    let protected = serde_json::to_vec(&Protected {
        alg: ALG,
        enc: ENC,
        epk: Epk {
            crv: CRV,
            kty: "EC",
            x: BASE64_URL_SAFE_NO_PAD.encode(x),
            y: BASE64_URL_SAFE_NO_PAD.encode(y),
        },
    })
    .map_err(|e| ApiError::internal(format!("jwe header: {e}")))?;
    let protected = BASE64_URL_SAFE_NO_PAD.encode(protected);

    let sealed = Aes256Gcm::new_from_slice(cek)
        .map_err(|_| ApiError::internal("content key"))?
        .encrypt(
            &Nonce::from(*iv),
            Payload {
                msg: plaintext,
                aad: protected.as_bytes(),
            },
        )
        .map_err(|_| ApiError::internal("aes-gcm seal"))?;
    let tag_at = sealed
        .len()
        .checked_sub(16)
        .ok_or_else(|| ApiError::internal("aes-gcm output"))?;
    let (ciphertext, tag) = sealed.split_at(tag_at);
    Ok(json!({
        "protected": protected,
        "encrypted_key": BASE64_URL_SAFE_NO_PAD.encode(encrypted_key),
        "iv": BASE64_URL_SAFE_NO_PAD.encode(iv),
        "ciphertext": BASE64_URL_SAFE_NO_PAD.encode(ciphertext),
        "tag": BASE64_URL_SAFE_NO_PAD.encode(tag),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7518 Appendix C: ECDH-ES key agreement for `A128GCM` between Alice and Bob.
    #[test]
    fn concat_kdf_matches_rfc7518_appendix_c() {
        let z = [
            158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132, 38, 156, 251, 49,
            110, 163, 218, 128, 106, 72, 246, 218, 167, 121, 140, 254, 144, 196,
        ];
        let key = concat_kdf(&z, "A128GCM", b"Alice", b"Bob", 128);
        assert_eq!(
            BASE64_URL_SAFE_NO_PAD.encode(&key[..16]),
            "VqqN6vgjbSBcIijNcacQGg"
        );
    }

    /// RFC 3394 §4.6: 256 bits of key data wrapped with a 256-bit KEK, through the crate the
    /// guest decrypts with.
    #[test]
    fn key_wrap_matches_rfc3394() {
        let kek = hex::decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
            .unwrap();
        let data = hex::decode("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F")
            .unwrap();
        let mut out = [0u8; 40];
        KwAes256::new_from_slice(&kek)
            .unwrap()
            .wrap_key(&data, &mut out)
            .unwrap();
        assert_eq!(
            hex::encode_upper(out),
            "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21"
        );
    }

    /// The upstream AAD vector (kbs-types 0.18.0 `protected_header_generate_aad`): the AAD is
    /// the ASCII of the base64url protected header.
    #[test]
    fn aad_is_the_base64url_protected_header() {
        assert_eq!(
            BASE64_URL_SAFE_NO_PAD.encode(br#"{"alg":"fakealg","enc":"fakeenc"}"#),
            "eyJhbGciOiJmYWtlYWxnIiwiZW5jIjoiZmFrZWVuYyJ9"
        );
    }
}
