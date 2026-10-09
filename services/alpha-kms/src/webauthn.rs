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
pub(crate) mod tests {
    use super::*;
    use alpha_core::signing_digest;
    use serde_json::json;

    pub(crate) fn vector() -> Value {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../testdata/webauthn/mac-icloud-keychain.json"
        );
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    pub(crate) fn vector_signer(v: &Value) -> Signer {
        let origin = v["origin"].as_str().unwrap().to_owned();
        Signer {
            origins: vec![origin.clone()],
            rp_id: v["rp_id"].as_str().unwrap().to_owned(),
            bundle_sha256: format!("sha256:{}", "0".repeat(64)),
            api_origin: origin,
        }
    }

    pub(crate) fn object(assertion: &Value) -> SignatureObject {
        let field = |name: &str| assertion[name].as_str().unwrap().to_owned();
        SignatureObject {
            key_id: None,
            algorithm: ALGORITHM.into(),
            signature: field("signature"),
            authenticator_data: Some(field("authenticator_data")),
            client_data_json: Some(field("client_data_json")),
        }
    }

    pub(crate) fn spki(v: &Value) -> Vec<u8> {
        BASE64_URL_SAFE_NO_PAD
            .decode(v["credential"]["spki"].as_str().unwrap())
            .unwrap()
    }

    pub(crate) fn digest(assertion: &Value) -> [u8; 32] {
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

    fn refused(result: Result<(), ApiError>, fragment: &str) {
        let e = result.expect_err(fragment);
        assert_eq!(e.code, "signature_invalid", "{}", e.message);
        assert!(
            e.message.contains(fragment),
            "{:?} lacks {fragment:?}",
            e.message
        );
    }

    fn b64(bytes: &[u8]) -> String {
        BASE64_URL_SAFE_NO_PAD.encode(bytes)
    }

    #[test]
    fn the_device_vector_carries_high_s_an_unknown_key_and_both_flags() {
        let v = vector();
        let (a0, a1) = (&v["assertions"][0], &v["assertions"][1]);
        let der = |a: &Value| {
            Signature::from_der(
                &BASE64_URL_SAFE_NO_PAD
                    .decode(a["signature"].as_str().unwrap())
                    .unwrap(),
            )
            .unwrap()
        };
        let client = |a: &Value| {
            serde_json::from_slice::<Value>(
                &BASE64_URL_SAFE_NO_PAD
                    .decode(a["client_data_json"].as_str().unwrap())
                    .unwrap(),
            )
            .unwrap()
        };
        assert_ne!(der(a0).normalize_s(), der(a0), "assertion 0 is high-S");
        assert_eq!(der(a1).normalize_s(), der(a1), "assertion 1 is low-S");
        assert!(client(a0).get("other_keys_can_be_added_here").is_some());
        assert_eq!(client(a1)["crossOrigin"], json!(false));
        for a in [a0, a1] {
            let data = BASE64_URL_SAFE_NO_PAD
                .decode(a["authenticator_data"].as_str().unwrap())
                .unwrap();
            assert_eq!(data.len(), 37);
            assert_eq!(data[32], 0x1d);
            assert_eq!(&data[33..], &[0, 0, 0, 0]);
        }
    }

    #[test]
    fn each_mutation_of_a_device_assertion_is_refused_by_its_rule() {
        let v = vector();
        let (a0, a1) = (&v["assertions"][0], &v["assertions"][1]);
        let (key, signer) = (spki(&v), vector_signer(&v));

        let elsewhere = Signer {
            origins: vec!["https://localhost:9443".into()],
            ..signer.clone()
        };
        refused(
            verify(&key, &digest(a0), &object(a0), Some(&elsewhere)),
            "signer.origins",
        );
        refused(
            verify(&key, &digest(a1), &object(a0), Some(&signer)),
            "challenge",
        );
        let other_rp = Signer {
            rp_id: "example.localhost".into(),
            ..signer.clone()
        };
        refused(
            verify(&key, &digest(a0), &object(a0), Some(&other_rp)),
            "rpIdHash",
        );

        let mut flipped = object(a0);
        let mut der = BASE64_URL_SAFE_NO_PAD.decode(&flipped.signature).unwrap();
        *der.last_mut().unwrap() ^= 0x01;
        flipped.signature = b64(&der);
        refused(
            verify(&key, &digest(a0), &flipped, Some(&signer)),
            "does not verify",
        );

        let mut short = object(a0);
        let data = BASE64_URL_SAFE_NO_PAD
            .decode(short.authenticator_data.as_deref().unwrap())
            .unwrap();
        short.authenticator_data = Some(b64(&data[..36]));
        refused(verify(&key, &digest(a0), &short, Some(&signer)), "37 bytes");
    }

    /// A passkey that signs whatever bytes a test gives it, so a mutation reaches its own rule
    /// instead of failing at the signature.
    mod software {
        use super::*;
        use p256::ecdsa::SigningKey;
        use p256::ecdsa::signature::Signer as _;
        use p256::pkcs8::EncodePublicKey;
        use serde_json::Map;

        pub const ORIGIN: &str = "https://localhost:8443";

        pub fn key() -> SigningKey {
            SigningKey::from_bytes((&[5u8; 32]).into()).unwrap()
        }

        pub fn spki() -> Vec<u8> {
            key()
                .verifying_key()
                .to_public_key_der()
                .unwrap()
                .as_bytes()
                .to_vec()
        }

        pub fn signer() -> Signer {
            Signer {
                origins: vec![ORIGIN.into()],
                rp_id: "localhost".into(),
                bundle_sha256: format!("sha256:{}", "0".repeat(64)),
                api_origin: ORIGIN.into(),
            }
        }

        pub fn client(digest: &[u8; 32]) -> Map<String, Value> {
            json!({
                "type": "webauthn.get", "challenge": b64(digest), "origin": ORIGIN,
                "crossOrigin": false,
            })
            .as_object()
            .unwrap()
            .clone()
        }

        pub fn authenticator_data(flags: u8, sign_count: u32, extensions: &[u8]) -> Vec<u8> {
            [
                Sha256::digest(b"localhost").as_slice(),
                &[flags],
                &sign_count.to_be_bytes(),
                extensions,
            ]
            .concat()
        }

        pub fn sign(client_data_json: &[u8], authenticator_data: &[u8]) -> Signature {
            key().sign(&[authenticator_data, &Sha256::digest(client_data_json)].concat())
        }

        pub fn object(
            client_data_json: &[u8],
            authenticator_data: &[u8],
            signature: &Signature,
        ) -> SignatureObject {
            SignatureObject {
                key_id: None,
                algorithm: ALGORITHM.into(),
                signature: b64(signature.to_der().as_bytes()),
                authenticator_data: Some(b64(authenticator_data)),
                client_data_json: Some(b64(client_data_json)),
            }
        }

        /// The default assertion over `digest` with the client data edited, signed as it ends up.
        pub fn assertion(
            digest: &[u8; 32],
            flags: u8,
            edit: impl FnOnce(&mut Map<String, Value>),
        ) -> SignatureObject {
            let mut map = client(digest);
            edit(&mut map);
            let cdj = serde_json::to_vec(&map).unwrap();
            let ad = authenticator_data(flags, 0, &[]);
            object(&cdj, &ad, &sign(&cdj, &ad))
        }
    }

    const DIGEST: [u8; 32] = [0xab; 32];

    #[test]
    fn each_mutation_of_a_software_assertion_is_refused_by_its_rule() {
        let (key, signer) = (software::spki(), software::signer());
        let check = |object: &SignatureObject| verify(&key, &DIGEST, object, Some(&signer));
        check(&software::assertion(&DIGEST, 0x05, |_| {})).unwrap();

        for (field, value) in [
            ("crossOrigin", json!(true)),
            ("crossOrigin", Value::Null),
            ("crossOrigin", json!("false")),
            ("topOrigin", json!(software::ORIGIN)),
            // Present though null: a check by `as_str` would let it through.
            ("topOrigin", Value::Null),
            ("type", json!("webauthn.create")),
        ] {
            refused(
                check(&software::assertion(&DIGEST, 0x05, |m| {
                    m.insert(field.into(), value);
                })),
                field,
            );
        }
        refused(
            check(&software::assertion(&DIGEST, 0x04, |_| {})),
            "user presence",
        );
        refused(
            check(&software::assertion(&DIGEST, 0x01, |_| {})),
            "user verification",
        );

        let ad = software::authenticator_data(0x05, 0, &[]);
        let challenge = b64(&DIGEST);
        let repeated = format!(
            r#"{{"type":"webauthn.get","type":"webauthn.get","challenge":"{challenge}","origin":"{}"}}"#,
            software::ORIGIN
        );
        for cdj in [b"[]".as_slice(), repeated.as_bytes()] {
            refused(
                check(&software::object(cdj, &ad, &software::sign(cdj, &ad))),
                "JSON object",
            );
        }

        let cdj = serde_json::to_vec(&software::client(&DIGEST)).unwrap();
        let sig = software::sign(&cdj, &ad);
        let mut raw = software::object(&cdj, &ad, &sig);
        raw.signature = b64(&sig.to_bytes());
        refused(check(&raw), "not DER");

        // A length that is a multiple of three has no padding to add.
        let mut client = software::client(&DIGEST);
        client.insert("pad".into(), json!("x"));
        let cdj = serde_json::to_vec(&client).unwrap();
        let good = software::object(&cdj, &ad, &software::sign(&cdj, &ad));
        check(&good).unwrap();
        let padded = |bytes: &[u8]| {
            let s = base64::prelude::BASE64_URL_SAFE.encode(bytes);
            assert!(
                s.ends_with('='),
                "{} bytes encode without padding",
                bytes.len()
            );
            s
        };
        let decoded = |s: &str| BASE64_URL_SAFE_NO_PAD.decode(s).unwrap();
        let mut a = good.clone();
        a.client_data_json = Some(padded(&cdj));
        let mut b = good.clone();
        b.authenticator_data = Some(padded(&ad));
        let mut c = good.clone();
        c.signature = padded(&decoded(&good.signature));
        for (object, fragment) in [
            (a, "client_data_json is not base64url"),
            (b, "authenticator_data is not base64url"),
            (c, "signature is not base64url"),
        ] {
            refused(check(&object), fragment);
        }

        refused(verify(&key, &DIGEST, &good, None), "no signer");
        let ed25519 = {
            use ed25519_dalek::pkcs8::EncodePublicKey;
            ed25519_dalek::SigningKey::from_bytes(&[3u8; 32])
                .verifying_key()
                .to_public_key_der()
                .unwrap()
        };
        refused(
            verify(ed25519.as_bytes(), &DIGEST, &good, Some(&signer)),
            "P-256",
        );
    }

    #[test]
    fn any_sign_count_no_cross_origin_an_unknown_key_extensions_and_high_s_verify() {
        let (key, signer) = (software::spki(), software::signer());
        let check = |object: &SignatureObject| verify(&key, &DIGEST, object, Some(&signer));
        let cdj = serde_json::to_vec(&software::client(&DIGEST)).unwrap();

        let counted = software::authenticator_data(0x05, 42, &[]);
        check(&software::object(
            &cdj,
            &counted,
            &software::sign(&cdj, &counted),
        ))
        .unwrap();
        check(&software::assertion(&DIGEST, 0x05, |m| {
            m.remove("crossOrigin");
        }))
        .unwrap();
        check(&software::assertion(&DIGEST, 0x05, |m| {
            m.insert("somethingNew".into(), json!({"nested": [1, 2]}));
        }))
        .unwrap();
        let extended = software::authenticator_data(0x85, 0, &[0xa1, 0x01, 0x02]);
        check(&software::object(
            &cdj,
            &extended,
            &software::sign(&cdj, &extended),
        ))
        .unwrap();

        let ad = software::authenticator_data(0x05, 0, &[]);
        let sig = software::sign(&cdj, &ad);
        let (r, s) = sig.split_scalars();
        let high = if sig.normalize_s() == sig {
            Signature::from_scalars(r, -s).unwrap()
        } else {
            sig
        };
        assert_ne!(high.normalize_s(), high);
        check(&software::object(&cdj, &ad, &high)).unwrap();
    }
}
