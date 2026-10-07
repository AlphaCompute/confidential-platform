//! `POST /v1/channel` answers an inner-channel handshake with this node's leaf and returns a ticket
//! instead of keeping the channel, so whichever node takes the put opens it.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alpha_channel::handshake::{ClientHello, Responder, ServerHello};
use axum::Json;
use axum::extract::State;
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use zeroize::Zeroizing;

use crate::body::Body;
use crate::error::ApiError;
use crate::keys::{aead_open, aead_seal, ticket_key};
use crate::{Node, certs, later, random};

pub const TICKET_TTL: Duration = Duration::from_secs(600);

const TICKET_LABEL: &[u8] = b"alphacompute-kms/channel-ticket/v1";

/// `base64url(salt(16) ‖ nonce(12) ‖ AES-256-GCM(channel(16) ‖ c2s(32) ‖ expires_at(8, BE)))`.
pub fn seal_ticket(
    tenant_kek_root: &[u8; 32],
    channel: &[u8; 16],
    c2s: &[u8; 32],
    expires_at: SystemTime,
) -> Result<String, ApiError> {
    // Each derived key seals one ticket, so the random-nonce bound of AES-GCM never comes into
    // play on a route anyone can call.
    let salt = random::<16>()?;
    let expires_at = expires_at
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ApiError::internal("the ticket expires before 1970"))?
        .as_secs()
        .to_be_bytes();
    let plaintext = Zeroizing::new([channel.as_slice(), c2s, &expires_at].concat());
    let key = ticket_key(tenant_kek_root, &salt)?;
    let sealed = aead_seal(&key, TICKET_LABEL, &plaintext)?;
    Ok(BASE64_URL_SAFE_NO_PAD.encode([salt.as_slice(), &sealed].concat()))
}

/// The channel id and `c2s` a ticket carries, while it has not expired at `now`.
pub fn open_ticket(
    tenant_kek_root: &[u8; 32],
    ticket: &str,
    now: SystemTime,
) -> Result<([u8; 16], Zeroizing<[u8; 32]>), ApiError> {
    let bad = || ApiError::malformed("the ticket does not open");
    let bytes = BASE64_URL_SAFE_NO_PAD.decode(ticket).map_err(|_| bad())?;
    let (salt, sealed) = bytes.split_first_chunk::<16>().ok_or_else(bad)?;
    let key = ticket_key(tenant_kek_root, salt)?;
    let plaintext = aead_open(&key, TICKET_LABEL, sealed).ok_or_else(bad)?;
    let (channel, rest) = plaintext.split_first_chunk::<16>().ok_or_else(bad)?;
    let (c2s, rest) = rest.split_first_chunk::<32>().ok_or_else(bad)?;
    let expires_at: [u8; 8] = rest.try_into().map_err(|_| bad())?;
    let now = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    if now >= u64::from_be_bytes(expires_at) {
        return Err(ApiError::malformed(
            "the ticket has expired; open a new channel",
        ));
    }
    Ok((*channel, Zeroizing::new(*c2s)))
}

pub async fn handshake(
    State(node): State<Arc<Node>>,
    Body(hello, _): Body<ClientHello>,
) -> Result<Json<ServerHello>, ApiError> {
    let keys = node.intermediates()?;
    // Read per request: the leaf is reissued every five minutes.
    let leaf = certs::pem(&node.server_cert.leaf_der()?);
    let responder = Responder::kms(vec![leaf, keys.ca_pem()], &node.runtime_pkcs8)
        .map_err(|e| ApiError::internal(format!("this node's leaf: {e}")))?;
    let now = node.now();
    let (mut reply, channel, c2s) =
        responder
            .respond_detached(&hello, now)
            .map_err(|e| match e {
                alpha_channel::Error::Malformed(m) => ApiError::malformed(m),
                other => ApiError::internal(format!("handshake: {other}")),
            })?;
    reply.ticket = Some(seal_ticket(
        &keys.tenant_kek_root,
        &channel,
        &c2s,
        later(now, TICKET_TTL)?,
    )?);
    Ok(Json(reply))
}
