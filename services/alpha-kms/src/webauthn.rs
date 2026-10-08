//! A passkey's signature is a WebAuthn assertion whose challenge is the signing digest, made by a
//! P-256 key on an origin and rp_id the current platform document's `signer` names. Every refusal
//! is `signature_invalid` and names its rule; nothing here counts signatures or compares the
//! client data with a template.

use alpha_core::Signer;
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::error::ApiError;
use crate::keys::SignatureObject;

pub const ALGORITHM: &str = "webauthn-es256";

const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;

pub fn verify(
    spki: &[u8],
    digest: &[u8; 32],
    signature: &SignatureObject,
    signer: Option<&Signer>,
) -> Result<(), ApiError> {
    let refuse = |m: &str| ApiError::signature_invalid(format!("{ALGORITHM}: {m}"));
    let decode = |field: Option<&str>| field.and_then(|s| BASE64_URL_SAFE_NO_PAD.decode(s).ok());

    let signer = signer.ok_or_else(|| refuse("the platform document names no signer"))?;
    let key = VerifyingKey::from_public_key_der(spki)
        .map_err(|_| refuse("the key is not a P-256 SPKI"))?;

    let client_data_json = decode(signature.client_data_json.as_deref())
        .ok_or_else(|| refuse("client_data_json is not base64url"))?;
    let Ok(Value::Object(client)) = alpha_core::parse(&client_data_json) else {
        return Err(refuse(
            "client_data_json is not a JSON object without repeated keys",
        ));
    };
    if client.get("type").and_then(Value::as_str) != Some("webauthn.get") {
        return Err(refuse("type is not webauthn.get"));
    }
    if client.get("challenge").and_then(Value::as_str)
        != Some(BASE64_URL_SAFE_NO_PAD.encode(digest).as_str())
    {
        return Err(refuse("challenge is not the signing digest"));
    }
    let origin = client.get("origin").and_then(Value::as_str);
    if !signer.origins.iter().any(|o| Some(o.as_str()) == origin) {
        return Err(refuse("origin is not in signer.origins"));
    }
    if !matches!(client.get("crossOrigin"), None | Some(Value::Bool(false))) {
        return Err(refuse("crossOrigin is not false"));
    }
    if client.contains_key("topOrigin") {
        return Err(refuse("topOrigin is present"));
    }

    let authenticator_data = decode(signature.authenticator_data.as_deref())
        .ok_or_else(|| refuse("authenticator_data is not base64url"))?;
    let Some((rp_id_hash, [flags, ..])) = authenticator_data
        .split_first_chunk::<32>()
        .and_then(|(hash, rest)| Some((hash, rest.split_first_chunk::<5>()?.0)))
    else {
        return Err(refuse("authenticator_data is shorter than 37 bytes"));
    };
    if rp_id_hash.as_slice() != Sha256::digest(signer.rp_id.as_bytes()).as_slice() {
        return Err(refuse("rpIdHash is not SHA-256 of signer.rp_id"));
    }
    if flags & FLAG_UP == 0 {
        return Err(refuse("user presence (UP) is not set"));
    }
    if flags & FLAG_UV == 0 {
        return Err(refuse("user verification (UV) is not set"));
    }

    let der =
        decode(Some(&signature.signature)).ok_or_else(|| refuse("signature is not base64url"))?;
    let der = Signature::from_der(&der).map_err(|_| refuse("signature is not DER"))?;
    let signed = [
        authenticator_data.as_slice(),
        Sha256::digest(&client_data_json).as_slice(),
    ]
    .concat();
    // The verifier does not refuse high-S, and authenticators emit it (the captured device does).
    key.verify(&signed, &der)
        .map_err(|_| refuse("signature does not verify"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alpha_core::signing_digest;

    fn vector() -> Value {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../testdata/webauthn/mac-icloud-keychain.json"
        );
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    fn vector_signer(v: &Value) -> Signer {
        let origin = v["origin"].as_str().unwrap().to_owned();
        Signer {
            origins: vec![origin.clone()],
            rp_id: v["rp_id"].as_str().unwrap().to_owned(),
            bundle_sha256: format!("sha256:{}", "0".repeat(64)),
            api_origin: origin,
        }
    }

    fn object(assertion: &Value) -> SignatureObject {
        let field = |name: &str| assertion[name].as_str().unwrap().to_owned();
        SignatureObject {
            key_id: None,
            algorithm: ALGORITHM.into(),
            signature: field("signature"),
            authenticator_data: Some(field("authenticator_data")),
            client_data_json: Some(field("client_data_json")),
        }
    }

    fn spki(v: &Value) -> Vec<u8> {
        BASE64_URL_SAFE_NO_PAD
            .decode(v["credential"]["spki"].as_str().unwrap())
            .unwrap()
    }

    fn digest(assertion: &Value) -> [u8; 32] {
        signing_digest(
            assertion["context"].as_str().unwrap(),
            &assertion["payload"],
        )
        .unwrap()
    }

    #[test]
    fn both_device_assertions_verify_over_their_recomputed_digests() {
        let v = vector();
        let signer = vector_signer(&v);
        let assertions = v["assertions"].as_array().unwrap();
        assert_eq!(assertions.len(), 2);
        for a in assertions {
            let digest = digest(a);
            assert_eq!(
                BASE64_URL_SAFE_NO_PAD.encode(digest),
                a["digest"].as_str().unwrap()
            );
            verify(&spki(&v), &digest, &object(a), Some(&signer)).unwrap();
        }
    }
}
