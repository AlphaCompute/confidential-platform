//! The attestation token `POST /kbs/v0/attest` returns: a JWT, HS256 under a key derived from
//! `tenant_kek_root`, so every serving node verifies a token any of them issued and nothing
//! outside a KMS TD can mint one. The guest only reads its `exp` (`kbs_protocol` `Token::new`);
//! the KMS reads the rest when the token comes back on a resource request.

use alpha_attest::Revision;
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use super::TeeKey;
use crate::error::ApiError;
use crate::keys::Key32;

pub const ISSUER: &str = "alphacompute-kms/kbs";

/// `{"alg":"HS256","typ":"JWT"}`; a token with any other header is refused.
const HEADER: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claims {
    pub iss: String,
    pub iat: u64,
    pub exp: u64,
    /// The Revision the pod attested as; checked again, as it is now, on every resource request.
    pub revision: Revision,
    /// The key the quote bound; every resource is sealed to it.
    #[serde(rename = "tee-pubkey")]
    pub tee_pubkey: TeeKey,
    /// The appraisal's `evidence_sha256`, to find its `kbs.attest` audit row.
    pub evidence_sha256: String,
}

pub fn token_key(tenant_kek_root: &[u8; 32]) -> Result<Key32, ApiError> {
    let mut out = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(b"alphacompute-kms/kbs-token/v1"), tenant_kek_root)
        .expand(&[], out.as_mut())
        .map_err(|e| ApiError::internal(format!("hkdf: {e}")))?;
    Ok(out)
}

fn mac(key: &[u8; 32], signed: &str) -> Result<Hmac<Sha256>, ApiError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|e| ApiError::internal(format!("hmac: {e}")))?;
    mac.update(signed.as_bytes());
    Ok(mac)
}

pub fn issue(key: &[u8; 32], claims: &Claims) -> Result<String, ApiError> {
    let claims =
        serde_json::to_vec(claims).map_err(|e| ApiError::internal(format!("token claims: {e}")))?;
    let signed = format!("{HEADER}.{}", BASE64_URL_SAFE_NO_PAD.encode(claims));
    let tag = mac(key, &signed)?.finalize().into_bytes();
    Ok(format!("{signed}.{}", BASE64_URL_SAFE_NO_PAD.encode(tag)))
}

fn invalid(message: &str) -> ApiError {
    ApiError::new("token_invalid", message)
}

/// The claims of a token this KMS issued that has not expired at `now` (seconds).
pub fn verify(key: &[u8; 32], token: &str, now: u64) -> Result<Claims, ApiError> {
    let (signed, tag) = token
        .rsplit_once('.')
        .ok_or_else(|| invalid("token is not a JWT"))?;
    let (header, claims) = signed
        .split_once('.')
        .ok_or_else(|| invalid("token is not a JWT"))?;
    if header != HEADER {
        return Err(invalid("token header is not this KMS's"));
    }
    let tag = BASE64_URL_SAFE_NO_PAD
        .decode(tag)
        .map_err(|_| invalid("token signature is not base64url"))?;
    mac(key, signed)?
        .verify_slice(&tag)
        .map_err(|_| invalid("token signature does not verify"))?;
    let claims: Claims = BASE64_URL_SAFE_NO_PAD
        .decode(claims)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .ok_or_else(|| invalid("token claims"))?;
    if claims.iss != ISSUER {
        return Err(invalid("token issuer"));
    }
    if now >= claims.exp {
        return Err(invalid("token has expired"));
    }
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use alpha_core::{AppId, OrgId};

    use super::*;

    fn claims() -> Claims {
        Claims {
            iss: ISSUER.into(),
            iat: 1_800_000_000,
            exp: 1_800_003_600,
            revision: Revision {
                compose_hash: alpha_core::compose_hash("revision"),
                app_id: AppId::mint(),
                org_id: OrgId::mint(),
            },
            tee_pubkey: TeeKey {
                kty: "EC".into(),
                crv: "P-256".into(),
                alg: "ECDH-ES+A256KW".into(),
                x: "x".into(),
                y: "y".into(),
            },
            evidence_sha256: format!("sha256:{}", "ab".repeat(32)),
        }
    }

    #[test]
    fn header_is_hs256_jwt() {
        assert_eq!(
            BASE64_URL_SAFE_NO_PAD.decode(HEADER).unwrap(),
            br#"{"alg":"HS256","typ":"JWT"}"#
        );
    }

    #[test]
    fn a_token_verifies_under_its_key_until_it_expires() {
        let key = token_key(&[1; 32]).unwrap();
        let claims = claims();
        let token = issue(&key, &claims).unwrap();
        assert_eq!(verify(&key, &token, 1_800_000_001).unwrap(), claims);
        let code = |r: Result<Claims, ApiError>| r.unwrap_err().code;
        assert_eq!(code(verify(&key, &token, 1_800_003_600)), "token_invalid");
        // Another deployment's root.
        let other = token_key(&[2; 32]).unwrap();
        assert_eq!(code(verify(&other, &token, 1_800_000_001)), "token_invalid");

        // Claims edited after signing: another pod's key or Revision, a later expiry.
        let (signed, tag) = token.rsplit_once('.').unwrap();
        let (header, _) = signed.split_once('.').unwrap();
        let mut edited = claims.clone();
        edited.tee_pubkey.x = "attacker".into();
        edited.exp = u64::MAX;
        let forged = format!(
            "{header}.{}.{tag}",
            BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&edited).unwrap())
        );
        assert_eq!(code(verify(&key, &forged, 1_800_000_001)), "token_invalid");

        // `alg: none` with no signature, and any other header.
        let none = format!(
            "{}.{}.",
            BASE64_URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#),
            signed.split_once('.').unwrap().1
        );
        assert_eq!(code(verify(&key, &none, 1_800_000_001)), "token_invalid");
        assert_eq!(
            code(verify(&key, "garbage", 1_800_000_001)),
            "token_invalid"
        );
    }
}
