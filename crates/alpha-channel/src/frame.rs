//! Frames on an open channel. A request body is one AES-256-GCM box under `c2s` bound to the
//! channel, its sequence number, the method and the path, so a relay can neither replay it nor
//! move it to another route. A response is a run of lines under `s2c`, each bound to the request's
//! sequence number and its own index and flagged more or end, so a relay can neither reorder
//! nor cut it short unnoticed.

use std::collections::BTreeSet;
use std::fmt;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use serde_json::json;
use zeroize::Zeroizing;

use crate::Error;

/// After this many requests the client opens a new channel.
pub const MAX_REQUESTS: u64 = 65_536;

const MORE: u8 = 0x00;
const END: u8 = 0x01;

/// `{ "channel": "<base64url>", "seq": n, "ct": "<base64url>" }`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestFrame {
    pub channel: String,
    pub seq: u64,
    pub ct: String,
}

/// One end of a channel; the initiator seals requests and reads responses, the responder the
/// reverse.
pub struct Channel {
    id: String,
    c2s: Zeroizing<[u8; 32]>,
    s2c: Zeroizing<[u8; 32]>,
    next_seq: u64,
    used: BTreeSet<u64>,
}

impl fmt::Debug for Channel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Channel({})", self.id)
    }
}

fn seal(key: &[u8; 32], nonce: [u8; 12], aad: &[u8], msg: &[u8]) -> Result<Vec<u8>, Error> {
    Aes256Gcm::new(key.into())
        .encrypt(&Nonce::from(nonce), Payload { msg, aad })
        .map_err(|_| Error::Seal)
}

fn open(key: &[u8; 32], nonce: [u8; 12], aad: &[u8], msg: &[u8]) -> Result<Vec<u8>, Error> {
    Aes256Gcm::new(key.into())
        .decrypt(&Nonce::from(nonce), Payload { msg, aad })
        .map_err(|_| Error::Open)
}

fn nonce(seq: u64, index: u32) -> [u8; 12] {
    let mut out = [0u8; 12];
    let (head, tail) = out.split_at_mut(8);
    head.copy_from_slice(&seq.to_be_bytes());
    tail.copy_from_slice(&index.to_be_bytes());
    out
}

fn jcs(value: serde_json::Value) -> Result<Vec<u8>, Error> {
    alpha_core::jcs(&value).map_err(|e| Error::Malformed(format!("aad: {e}")))
}

impl Channel {
    pub(crate) fn new(id: &[u8; 16], c2s: Zeroizing<[u8; 32]>, s2c: Zeroizing<[u8; 32]>) -> Self {
        Self {
            id: BASE64_URL_SAFE_NO_PAD.encode(id),
            c2s,
            s2c,
            next_seq: 0,
            used: BTreeSet::new(),
        }
    }

    /// The channel id as it appears on the wire.
    pub fn id(&self) -> &str {
        &self.id
    }

    fn request_aad(&self, seq: u64, method: &str, path: &str) -> Result<Vec<u8>, Error> {
        jcs(json!({ "channel": self.id, "seq": seq, "method": method, "path": path }))
    }

    fn response_aad(&self, seq: u64, index: u32) -> Result<Vec<u8>, Error> {
        jcs(json!({ "channel": self.id, "seq": seq, "frame": index }))
    }

    pub fn seal_request(
        &mut self,
        method: &str,
        path: &str,
        plaintext: &[u8],
    ) -> Result<RequestFrame, Error> {
        let seq = self.next_seq;
        if seq >= MAX_REQUESTS {
            return Err(Error::Exhausted);
        }
        let ct = seal(
            &self.c2s,
            nonce(seq, 0),
            &self.request_aad(seq, method, path)?,
            plaintext,
        )?;
        self.next_seq = seq.checked_add(1).ok_or(Error::Exhausted)?;
        Ok(RequestFrame {
            channel: self.id.clone(),
            seq,
            ct: BASE64_URL_SAFE_NO_PAD.encode(ct),
        })
    }

    /// Opens a request as received on `method` and `path`, the responder's own view of the route.
    /// A sequence number is spent only once its frame opens.
    pub fn open_request(
        &mut self,
        frame: &RequestFrame,
        method: &str,
        path: &str,
    ) -> Result<(u64, Zeroizing<Vec<u8>>), Error> {
        if frame.channel != self.id {
            return Err(Error::Open);
        }
        if frame.seq >= MAX_REQUESTS {
            return Err(Error::Exhausted);
        }
        if self.used.contains(&frame.seq) {
            return Err(Error::Replayed(frame.seq));
        }
        let ct = BASE64_URL_SAFE_NO_PAD
            .decode(&frame.ct)
            .map_err(|_| Error::Open)?;
        let plaintext = open(
            &self.c2s,
            nonce(frame.seq, 0),
            &self.request_aad(frame.seq, method, path)?,
            &ct,
        )?;
        self.used.insert(frame.seq);
        Ok((frame.seq, Zeroizing::new(plaintext)))
    }

    /// One line of the response to request `seq`, without its trailing newline.
    pub fn seal_response(
        &self,
        seq: u64,
        index: u32,
        end: bool,
        plaintext: &[u8],
    ) -> Result<String, Error> {
        let mut framed = Zeroizing::new(Vec::with_capacity(plaintext.len().saturating_add(1)));
        framed.push(if end { END } else { MORE });
        framed.extend_from_slice(plaintext);
        let ct = seal(
            &self.s2c,
            nonce(seq, index),
            &self.response_aad(seq, index)?,
            &framed,
        )?;
        Ok(BASE64_URL_SAFE_NO_PAD.encode(ct))
    }

    pub fn response(&self, seq: u64) -> ResponseReader {
        ResponseReader {
            id: self.id.clone(),
            s2c: self.s2c.clone(),
            seq,
            index: 0,
            ended: false,
        }
    }
}

/// Reads the lines of one response in order.
pub struct ResponseReader {
    id: String,
    s2c: Zeroizing<[u8; 32]>,
    seq: u64,
    index: u32,
    ended: bool,
}

impl fmt::Debug for ResponseReader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ResponseReader({}, {})", self.id, self.seq)
    }
}

impl ResponseReader {
    /// The next frame's plaintext; `None` for a blank line, which carries nothing.
    pub fn open_line(&mut self, line: &str) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
        let line = line.trim();
        if line.is_empty() {
            return Ok(None);
        }
        if self.ended {
            return Err(Error::Open);
        }
        let ct = BASE64_URL_SAFE_NO_PAD
            .decode(line)
            .map_err(|_| Error::Open)?;
        let aad = jcs(json!({ "channel": self.id, "seq": self.seq, "frame": self.index }))?;
        let framed = Zeroizing::new(open(&self.s2c, nonce(self.seq, self.index), &aad, &ct)?);
        let (flag, body) = framed.split_first().ok_or(Error::Open)?;
        self.ended = match *flag {
            MORE => false,
            END => true,
            _ => return Err(Error::Open),
        };
        self.index = self.index.checked_add(1).ok_or(Error::Exhausted)?;
        Ok(Some(Zeroizing::new(body.to_vec())))
    }

    /// Call when the stream closes: a response that never sent its end frame was cut short.
    pub fn finish(&self) -> Result<(), Error> {
        if self.ended {
            Ok(())
        } else {
            Err(Error::Truncated)
        }
    }
}
