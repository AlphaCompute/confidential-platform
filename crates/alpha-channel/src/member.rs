//! Documents a member signs with a P-256 key the page holds in WebCrypto and cannot export: the
//! connector requests, the writes, and the per-chat grant bound to one worker's Instance key. The
//! page gets each document's bytes and digest from `signable`, so both ends canonicalise with one
//! implementation. A signature is ECDSA P-256 `r‖s` over `SHA-256(context ‖ 0x00 ‖ JCS)`, which is
//! what WebCrypto's `sign({name: "ECDSA", hash: "SHA-256"}, key, digest)` produces.
//!
//! WebCrypto emits high-S signatures about half the time, so they are accepted as they are; that
//! makes a signature malleable, which is why replay is keyed on a document's nonce, never on its
//! signature bytes.

use std::time::SystemTime;

use alpha_core::{context, signing_digest};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use chrono::DateTime;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{Error, random, rfc3339, unix_seconds};

pub const SIGNATURE_ALGORITHM: &str = "ecdsa-p256";

/// How far a request's `issued_at` may be from the verifier's clock, either way.
pub const FRESHNESS_SECONDS: u64 = 60;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberSignature {
    pub algorithm: String,
    pub signature: String,
}

/// The key that signed: its SPKI DER and that SPKI's SHA-256.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    pub spki: Vec<u8>,
    pub key_sha256: [u8; 32],
}

/// Under `alphacompute/connector-request/v1`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase", deny_unknown_fields)]
pub enum ConnectorRequest {
    Connect {
        v: u8,
        provider: String,
        nonce: String,
        issued_at: String,
    },
    Finish {
        v: u8,
        state: String,
        code: String,
        nonce: String,
        issued_at: String,
    },
    List {
        v: u8,
        nonce: String,
        issued_at: String,
    },
    Disconnect {
        v: u8,
        connection_id: Uuid,
        nonce: String,
        issued_at: String,
    },
}

/// Under `alphacompute/connector-write/v1`: one request the member sends to a provider.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriteDocument {
    pub v: u8,
    pub connection_id: Uuid,
    pub method: String,
    pub url: String,
    /// `sha256:<hex>` of the body sent beside the document.
    pub body_sha256: String,
    pub nonce: String,
    pub issued_at: String,
}

/// Under `alphacompute/connector-grant/v1`: lets the Instance whose leaf SPKI hashes to `aud` read
/// through `connections` until `exp`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub v: u8,
    /// `sha256:<hex>` of the worker leaf's SPKI.
    pub aud: String,
    pub connections: Vec<Uuid>,
    pub exp: String,
    pub nonce: String,
    pub issued_at: String,
}

fn invalid(m: &str) -> Error {
    Error::SignatureInvalid(m.into())
}

fn verifying_key(spki: &[u8]) -> Result<VerifyingKey, Error> {
    VerifyingKey::from_public_key_der(spki)
        .map_err(|_| Error::Malformed("the member key is not a P-256 SPKI".into()))
}

fn check(key: &VerifyingKey, digest: &[u8; 32], signature: &Signature) -> Result<(), Error> {
    key.verify(digest, signature)
        .map_err(|_| invalid("the signature does not verify under the member key"))
}

/// Checks `signature` over `document` under `context` by the key `member_key_b64` (base64url SPKI
/// DER). Freshness is the caller's, with `check_fresh`.
pub fn verify_request(
    context: &str,
    document: &Value,
    member_key_b64: &str,
    signature: &MemberSignature,
) -> Result<Member, Error> {
    if signature.algorithm != SIGNATURE_ALGORITHM {
        return Err(invalid("algorithm is not ecdsa-p256"));
    }
    let spki = BASE64_URL_SAFE_NO_PAD
        .decode(member_key_b64)
        .map_err(|_| Error::Malformed("member_key is not base64url".into()))?;
    let key = verifying_key(&spki)?;
    let signature = BASE64_URL_SAFE_NO_PAD
        .decode(&signature.signature)
        .ok()
        .and_then(|b| Signature::from_slice(&b).ok())
        .ok_or_else(|| invalid("signature is not base64url r‖s"))?;
    let digest = signing_digest(context, document)
        .map_err(|e| Error::Malformed(format!("document: {e}")))?;
    check(&key, &digest, &signature)?;
    Ok(Member {
        key_sha256: Sha256::digest(&spki).into(),
        spki,
    })
}

/// A grant as received: the JCS bytes that were signed, and the signature.
#[derive(Clone, Debug)]
pub struct SignedGrant {
    document: Vec<u8>,
    signature: Signature,
}

/// `base64url(JCS) "." base64url(r‖s)`.
pub fn parse_grant(wire: &str) -> Result<SignedGrant, Error> {
    let malformed = || Error::Malformed("the grant is not base64url(JCS).base64url(r‖s)".into());
    let (document, signature) = wire.split_once('.').ok_or_else(malformed)?;
    Ok(SignedGrant {
        document: BASE64_URL_SAFE_NO_PAD
            .decode(document)
            .map_err(|_| malformed())?,
        signature: BASE64_URL_SAFE_NO_PAD
            .decode(signature)
            .ok()
            .and_then(|b| Signature::from_slice(&b).ok())
            .ok_or_else(malformed)?,
    })
}

impl SignedGrant {
    /// Verifies the bytes exactly as received under `spki`, and only then reads them.
    /// `exp` and `aud` are the caller's to compare.
    pub fn verify(&self, spki: &[u8]) -> Result<Grant, Error> {
        let key = verifying_key(spki)?;
        let digest: [u8; 32] = Sha256::new()
            .chain_update(context::CONNECTOR_GRANT)
            .chain_update([0u8])
            .chain_update(&self.document)
            .finalize()
            .into();
        check(&key, &digest, &self.signature)?;
        serde_json::from_slice(&self.document).map_err(|e| Error::Malformed(format!("grant: {e}")))
    }
}

/// Refuses an `issued_at` more than a minute away from `now`, the verifier's clock.
pub fn check_fresh(issued_at: &str, now: SystemTime) -> Result<(), Error> {
    let issued_at = DateTime::parse_from_rfc3339(issued_at)
        .map_err(|_| Error::Malformed("issued_at is not RFC 3339".into()))?;
    if issued_at.timestamp().abs_diff(unix_seconds(now)?) > FRESHNESS_SECONDS {
        return Err(Error::RequestStale);
    }
    Ok(())
}

/// The document to sign under one of the member contexts, `fields` plus `v`, a fresh 32-byte
/// `nonce` and `issued_at` from `now`, as JCS text and its signing digest.
pub fn signable(
    context: &str,
    fields: Value,
    now: SystemTime,
) -> Result<(String, [u8; 32]), Error> {
    if ![
        context::CONNECTOR_REQUEST,
        context::CONNECTOR_GRANT,
        context::CONNECTOR_WRITE,
    ]
    .contains(&context)
    {
        return Err(Error::Malformed(format!(
            "{context} is not a member context"
        )));
    }
    let Value::Object(mut document) = fields else {
        return Err(Error::Malformed("fields are not a JSON object".into()));
    };
    for (name, value) in [
        ("v", Value::from(1)),
        (
            "nonce",
            BASE64_URL_SAFE_NO_PAD.encode(random::<32>()?).into(),
        ),
        ("issued_at", rfc3339(now)?.into()),
    ] {
        if document.insert(name.into(), value).is_some() {
            return Err(Error::Malformed(format!("{name} is filled here")));
        }
    }
    let document = Value::Object(document);
    let text = alpha_core::jcs(&document)
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
        .ok_or_else(|| Error::Malformed("the document does not canonicalize".into()))?;
    let digest = signing_digest(context, &document)
        .map_err(|e| Error::Malformed(format!("document: {e}")))?;
    Ok((text, digest))
}
