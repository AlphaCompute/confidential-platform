//! A KMS receipt: the node's signature over a Control route's name, the hash of the request as
//! the KMS received it and the response, checked against a pinned CA at its own `issued_at`, so a
//! stored receipt stays verifiable after the node's one-hour leaf expires.

use std::time::SystemTime;

use alpha_core::{ComposeHash, context, jcs, signing_digest};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use chrono::DateTime;
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{SigningKey, VerifyingKey};
use p256::pkcs8::DecodePublicKey;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::cert::{parse_kms_sans, pem_to_der, spki_of, uri_sans, verify_leaf};
use crate::{
    ECDSA_P256, Error, NamedSignature, from_unix_seconds, p256_signature, rfc3339, sha256_label,
};

/// `{document, signature, certificate_chain}`; the chain is the node's leaf only, because every
/// verifier pins its own KMS CA.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub document: Value,
    pub signature: NamedSignature,
    pub certificate_chain: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    route: String,
    request_sha256: String,
    response: Map<String, Value>,
    issued_at: String,
}

/// What the caller sent and expects back. Every key in `response` must be in the signed response
/// with an equal value; an empty map checks the route and the request only.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Expected {
    pub route: String,
    pub request_sha256: String,
    pub response: Map<String, Value>,
}

fn canonical(value: &Value) -> Result<Vec<u8>, Error> {
    jcs(value).map_err(|e| Error::Malformed(format!("canonical JSON: {e}")))
}

pub fn request_sha256(body: &Value) -> Result<String, Error> {
    Ok(sha256_label(&canonical(body)?))
}

pub fn issue(
    key: &SigningKey,
    leaf_pem: String,
    route: &str,
    request: &Value,
    response: Value,
    issued_at: SystemTime,
) -> Result<Receipt, Error> {
    let document = json!({
        "route": route,
        "request_sha256": request_sha256(request)?,
        "response": response,
        "issued_at": rfc3339(issued_at)?,
    });
    let digest = signing_digest(context::KMS_RECEIPT, &document)
        .map_err(|e| Error::Malformed(format!("receipt document: {e}")))?;
    let signature: p256::ecdsa::Signature = key
        .try_sign(&digest)
        .map_err(|_| Error::Malformed("signing failed".into()))?;
    Ok(Receipt {
        document,
        signature: NamedSignature {
            algorithm: ECDSA_P256.into(),
            signature: BASE64_URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        },
        certificate_chain: vec![leaf_pem],
    })
}

/// Returns the response the KMS signed; callers use it instead of the reply's top-level fields,
/// which no signature covers. Takes the receipt's bytes because a typed `Receipt` has already
/// collapsed a repeated key to its last value, which other verifiers refuse.
pub fn verify(
    receipt_json: &[u8],
    kms_ca_pem: &str,
    kms_revisions: &[ComposeHash],
    expected: &Expected,
) -> Result<Value, Error> {
    let receipt: Receipt = alpha_core::parse(receipt_json)
        .and_then(serde_json::from_value)
        .map_err(|e| Error::Malformed(format!("receipt: {e}")))?;
    let foreign = |m: &str| Error::ForeignCertificate(m.into());
    let [leaf_pem] = receipt.certificate_chain.as_slice() else {
        return Err(foreign("a receipt carries exactly the node's leaf"));
    };
    let doc: Document = serde_json::from_value(receipt.document.clone())
        .map_err(|e| Error::Malformed(format!("receipt document: {e}")))?;
    let issued_at = DateTime::parse_from_rfc3339(&doc.issued_at)
        .ok()
        .and_then(|t| from_unix_seconds(t.timestamp()))
        .ok_or_else(|| Error::Malformed("issued_at is not RFC 3339 after 1970".into()))?;

    let ca = pem_to_der(kms_ca_pem)?;
    let leaf = pem_to_der(leaf_pem).map_err(|_| foreign("the leaf is not a certificate"))?;
    verify_leaf(&leaf, &ca, issued_at)?;

    let revision = parse_kms_sans(&uri_sans(&leaf)?)?;
    if !kms_revisions.contains(&revision) {
        return Err(Error::UnknownRevision(revision));
    }

    let refuse = |m: &str| Error::SignatureInvalid(m.into());
    if receipt.signature.algorithm != ECDSA_P256 {
        return Err(refuse("algorithm is not ecdsa-p256"));
    }
    let key = VerifyingKey::from_public_key_der(&spki_of(&leaf)?)
        .map_err(|_| refuse("the leaf key is not P-256"))?;
    let signature = p256_signature(&receipt.signature.signature)
        .ok_or_else(|| refuse("signature is not base64url r‖s"))?;
    let digest = signing_digest(context::KMS_RECEIPT, &receipt.document)
        .map_err(|e| Error::Malformed(format!("receipt document: {e}")))?;
    key.verify(&digest, &signature)
        .map_err(|_| refuse("the receipt does not verify under the leaf key"))?;

    if doc.route != expected.route {
        return Err(Error::ReceiptMismatch(format!(
            "the receipt is for route {}",
            doc.route
        )));
    }
    if doc.request_sha256 != expected.request_sha256 {
        return Err(Error::ReceiptMismatch(
            "the receipt is for another request".into(),
        ));
    }
    for (k, v) in &expected.response {
        let actual = doc
            .response
            .get(k)
            .ok_or_else(|| Error::ReceiptMismatch(format!("the signed response has no {k}")))?;
        // serde_json's Value equality tells 1 from 1.0; canonical JSON and the Go verifier do not.
        if canonical(actual)? != canonical(v)? {
            return Err(Error::ReceiptMismatch(format!(
                "the signed response's {k} differs"
            )));
        }
    }
    Ok(Value::Object(doc.response))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[wasm_bindgen_test::wasm_bindgen_test(unsupported = test)]
    fn request_sha256_is_the_sha256_of_the_canonical_body() {
        assert_eq!(
            request_sha256(&json!({"b": 1, "a": "x"})).unwrap(),
            sha256_label(br#"{"a":"x","b":1}"#)
        );
    }
}
