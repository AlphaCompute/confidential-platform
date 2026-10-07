//! A Secret's value sealed on the page to one KMS node: the `sealed` member of a put-Secret body.
//! The plaintext begins with the digest the put's signature covers, so a relay holding a key of
//! its own cannot carry the value into a put it signs itself; the path in the frame's AAD binds it
//! to its name.

use std::time::SystemTime;

use alpha_core::{ComposeHash, context, signing_digest};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::Error;
use crate::frame::{RequestFrame, open_detached};
use crate::handshake::{Initiator, ServerHello};

/// `{ "ticket": "<base64url>", "frame": RequestFrame }`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sealed {
    pub ticket: String,
    pub frame: RequestFrame,
}

fn path(name: &str) -> String {
    format!("/v1/secrets/{name}")
}

fn digest(payload: &Value) -> Result<[u8; 32], Error> {
    signing_digest(context::SECRET, payload).map_err(|e| Error::Malformed(format!("payload: {e}")))
}

/// Finishes the handshake with a KMS node and seals `digest(payload) ‖ value` for
/// `PUT /v1/secrets/<payload.name>`.
pub fn seal(
    initiator: Initiator,
    hello: &ServerHello,
    kms_ca_pem: &str,
    kms_revisions: &[ComposeHash],
    payload: &Value,
    value: &[u8],
    now: SystemTime,
) -> Result<Sealed, Error> {
    let name = payload
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| alpha_core::is_key_purpose(name))
        .ok_or_else(|| Error::Malformed("the payload's name is not a secret name".into()))?;
    let digest = digest(payload)?;
    let (mut channel, ticket) = initiator.finish_kms(hello, kms_ca_pem, kms_revisions, now)?;
    let mut plaintext = Zeroizing::new(Vec::with_capacity(value.len().saturating_add(32)));
    plaintext.extend_from_slice(&digest);
    plaintext.extend_from_slice(value);
    let frame = channel.seal_request("PUT", &path(name), &plaintext)?;
    Ok(Sealed { ticket, frame })
}

/// The value a frame carries for the put of `payload` under `name`, the decoded path parameter.
pub fn open(
    channel: &[u8; 16],
    c2s: &[u8; 32],
    frame: &RequestFrame,
    name: &str,
    payload: &Value,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let plaintext = open_detached(channel, c2s, frame, "PUT", &path(name))?;
    let (prefix, value) = plaintext
        .split_first_chunk::<32>()
        .ok_or_else(|| Error::Malformed("the sealed value is shorter than its digest".into()))?;
    if *prefix != digest(payload)? {
        return Err(Error::Malformed(
            "the value was sealed for another document".into(),
        ));
    }
    Ok(Zeroizing::new(value.to_vec()))
}
