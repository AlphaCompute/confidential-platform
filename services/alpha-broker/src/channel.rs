//! The broker's end of the inner channel: `POST /channel` answers a page's handshake with this
//! Instance's leaf and compose, and every member route arrives as one request frame on such a
//! channel and answers with one sealed line. The tenant's backend relays both and reads neither.
//! A body that is not a frame, a frame for another route, a frame opened before and an unknown
//! channel are refused in plaintext before anything runs; everything after the frame opens,
//! refusals included, is sealed.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use alpha_channel::frame::{Channel, RequestFrame};
use alpha_channel::handshake::{ClientHello, Responder, ServerHello};
use alpha_client::runtime::RuntimeIdentity;
use axum::Json;
use axum::body::Bytes;
use axum::extract::{FromRequest, Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::{AppState, AuthedCorpus, Error};

const MAX_CHANNELS: usize = 1024;
const IDLE: Duration = Duration::from_secs(3600);

/// This process's open channels by id, with when each was last used. A restart forgets them and
/// the page opens a new one on `channel_unknown`.
#[derive(Default)]
pub struct Channels(parking_lot::Mutex<HashMap<String, (Channel, Instant)>>);

impl Channels {
    /// Drops idle channels, then the least recently used one if the table is still full.
    // ponytail: a channel whose request is still at the provider can be evicted by 1024 newer
    // handshakes, and its reply is then lost as `channel_unknown` although the request ran. The
    // upgrade is a response writer that leaves the table with the opened request.
    fn insert(&self, channel: Channel) {
        let mut table = self.0.lock();
        table.retain(|_, (_, used)| used.elapsed() < IDLE);
        if table.len() >= MAX_CHANNELS {
            let oldest = table
                .iter()
                .min_by_key(|(_, (_, used))| *used)
                .map(|(id, _)| id.clone());
            if let Some(oldest) = oldest {
                table.remove(&oldest);
            }
        }
        table.insert(channel.id().to_owned(), (channel, Instant::now()));
    }

    fn with<R>(&self, id: &str, f: impl FnOnce(&mut Channel) -> R) -> Option<R> {
        let mut table = self.0.lock();
        let (channel, used) = table.get_mut(id)?;
        if used.elapsed() >= IDLE {
            table.remove(id);
            return None;
        }
        *used = Instant::now();
        Some(f(channel))
    }
}

/// The runtime hands the chain over as one PEM text; the responder sends it as leaf and CA.
pub fn responder(identity: &RuntimeIdentity) -> Result<Responder, Error> {
    Responder::new(
        pem_blocks(&identity.certificate_chain),
        &identity.tls_private_key,
        identity.app_compose.clone(),
    )
    .map_err(|e| Error::internal(format!("channel responder: {e}")))
}

fn pem_blocks(chain: &str) -> Vec<String> {
    chain
        .split_inclusive("-----END CERTIFICATE-----")
        .map(str::trim)
        .filter(|block| !block.is_empty())
        .map(str::to_owned)
        .collect()
}

/// `POST /channel`: a `ClientHello` in, a `ServerHello` out.
pub async fn open(
    State(state): State<Arc<AppState>>,
    _: AuthedCorpus,
    body: Bytes,
) -> Result<Json<ServerHello>, Error> {
    let hello: ClientHello = crate::connect::parse_body(&body)?;
    let (reply, channel) = state
        .responder
        .read()
        .respond(&hello, SystemTime::now())
        .map_err(|e| match e {
            alpha_channel::Error::Malformed(m) => Error::Malformed(m),
            other => Error::internal(format!("handshake: {other}")),
        })?;
    state.channels.insert(channel);
    Ok(Json(reply))
}

/// A request frame opened on the method and path it arrived on.
pub struct Sealed {
    channel: String,
    seq: u64,
    pub plaintext: Zeroizing<Vec<u8>>,
}

impl FromRequest<Arc<AppState>> for Sealed {
    /// A body over the route's limit keeps its 413; everything else is this service's error.
    type Rejection = Response;

    async fn from_request(req: Request, state: &Arc<AppState>) -> Result<Self, Response> {
        let method = req.method().as_str().to_owned();
        let path = req.uri().path().to_owned();
        let body = Bytes::from_request(req, state)
            .await
            .map_err(IntoResponse::into_response)?;
        Sealed::open(state, &method, &path, &body).map_err(IntoResponse::into_response)
    }
}

impl Sealed {
    fn open(state: &AppState, method: &str, path: &str, body: &[u8]) -> Result<Self, Error> {
        let frame: RequestFrame = serde_json::from_slice(body).map_err(|_| Error::FrameInvalid)?;
        let plaintext = state
            .channels
            .with(&frame.channel, |c| c.open_request(&frame, method, path))
            .ok_or(Error::ChannelUnknown)?
            .map_err(|e| match e {
                alpha_channel::Error::Replayed(_) => Error::Replayed,
                _ => Error::FrameInvalid,
            })?;
        Ok(Sealed {
            channel: frame.channel,
            seq: frame.seq,
            plaintext,
        })
    }

    /// `result` as one end frame, a refusal in the same envelope as a plaintext one. The HTTP
    /// status mirrors it for the relay's logs; the page reads only the sealed body.
    pub fn reply(&self, state: &AppState, result: Result<Value, Error>) -> Response {
        let (status, body) = match result {
            Ok(body) => (StatusCode::OK, body),
            Err(e) => e.envelope(),
        };
        let sealed = serde_json::to_vec(&body)
            .map_err(|e| Error::internal(format!("reply: {e}")))
            .and_then(|bytes| {
                state
                    .channels
                    .with(&self.channel, |c| c.seal_response(self.seq, true, &bytes))
                    .ok_or(Error::ChannelUnknown)?
                    .map_err(|e| Error::internal(format!("seal: {e}")))
            });
        match sealed {
            Ok(line) => (status, format!("{line}\n")).into_response(),
            Err(e) => e.into_response(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_joined_chain_splits_into_its_blocks() {
        let block =
            |n: u8| format!("-----BEGIN CERTIFICATE-----\nAQ{n}\n-----END CERTIFICATE-----");
        let joined = format!("{}\n{}\n", block(1), block(2));
        assert_eq!(pem_blocks(&joined), [block(1), block(2)]);
        assert!(pem_blocks("").is_empty());
    }
}
