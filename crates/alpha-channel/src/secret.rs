//! A Secret's value sealed on the page to one KMS node: the `sealed` member of a put-Secret body.
//! The plaintext is `digest(payload) ‖ org_id ‖ value`. The digest is the one the put's signature
//! covers, so the value cannot travel in a put with any other payload. The payload names no
//! organization, so anyone holding a key can sign that same payload; the organization id is what
//! stops a relay with a key of its own from re-signing it into its organization, because the KMS
//! stores the value only when the key that signed the put belongs to that organization. The path
//! in the frame's AAD binds the value to its name.

use std::time::SystemTime;

use alpha_core::{ComposeHash, OrgId, context, signing_digest};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
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

/// Finishes the handshake with a KMS node and seals `digest(payload) ‖ org_id ‖ value` for
/// `PUT /v1/secrets/<payload.name>`, signed by a key of `org_id`.
#[allow(clippy::too_many_arguments)]
pub fn seal(
    initiator: Initiator,
    hello: &ServerHello,
    kms_ca_pem: &str,
    kms_revisions: &[ComposeHash],
    payload: &Value,
    org_id: OrgId,
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
    let mut plaintext = Zeroizing::new(Vec::with_capacity(value.len().saturating_add(48)));
    plaintext.extend_from_slice(&digest);
    plaintext.extend_from_slice(org_id.as_bytes());
    plaintext.extend_from_slice(value);
    let frame = channel.seal_request("PUT", &path(name), &plaintext)?;
    Ok(Sealed { ticket, frame })
}

/// The organization a frame was sealed for and the value it carries, for the put of `payload`
/// under `name`, the decoded path parameter. The caller stores the value only for a put signed by
/// a key of that organization.
pub fn open(
    channel: &[u8; 16],
    c2s: &[u8; 32],
    frame: &RequestFrame,
    name: &str,
    payload: &Value,
) -> Result<(OrgId, Zeroizing<Vec<u8>>), Error> {
    let plaintext = open_detached(
        &BASE64_URL_SAFE_NO_PAD.encode(channel),
        c2s,
        frame,
        "PUT",
        &path(name),
    )?;
    let short =
        || Error::Malformed("the sealed value is shorter than its digest and organization".into());
    let (prefix, rest) = plaintext.split_first_chunk::<32>().ok_or_else(short)?;
    if *prefix != digest(payload)? {
        return Err(Error::Malformed(
            "the value was sealed for another document".into(),
        ));
    }
    let (org_id, value) = rest.split_first_chunk::<16>().ok_or_else(short)?;
    Ok((
        OrgId::from(uuid::Uuid::from_bytes(*org_id)),
        Zeroizing::new(value.to_vec()),
    ))
}
