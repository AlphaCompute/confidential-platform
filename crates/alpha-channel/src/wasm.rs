//! The JavaScript surface. Every export returns an error instead of trapping, and its message
//! starts with the error's `code()`. Times come in as Unix milliseconds from the caller, because
//! the system clock traps in wasm. Everything is synchronous, so a page can seal a request inside
//! `pagehide`.

use std::time::{Duration, SystemTime};

use serde_json::json;
use wasm_bindgen::prelude::*;

use crate::{Error, compose, frame, handshake, member, platform, rfc3339, sha256_label};

fn js(e: Error) -> JsError {
    JsError::new(&format!("{}: {e}", e.code()))
}

fn at(now_ms: f64) -> Result<SystemTime, JsError> {
    Duration::try_from_secs_f64(now_ms / 1000.0)
        .ok()
        .and_then(|d| SystemTime::UNIX_EPOCH.checked_add(d))
        .ok_or_else(|| js(Error::Malformed(format!("now {now_ms} is not a time"))))
}

fn parse<T: serde::de::DeserializeOwned>(what: &str, text: &str) -> Result<T, JsError> {
    serde_json::from_str(text).map_err(|e| js(Error::Malformed(format!("{what}: {e}"))))
}

fn to_json(value: &impl serde::Serialize) -> Result<String, JsError> {
    serde_json::to_string(value).map_err(|e| js(Error::Malformed(e.to_string())))
}

/// `{version, issued_at, kms_ca_pem}` of a platform document that verifies under the release key
/// compiled into this package.
#[wasm_bindgen(js_name = verifyPlatform)]
pub fn verify_platform(signed_json: &str, now_ms: f64) -> Result<String, JsError> {
    let signed: platform::SignedDocument = parse("platform document", signed_json)?;
    let key = platform::release_key().map_err(js)?;
    to_json(&platform::verify(&signed, &key, at(now_ms)?).map_err(js)?)
}

/// `{name: {image, environment}}` for every service of an `app-compose.json`.
#[wasm_bindgen(js_name = composeServices)]
pub fn compose_services(compose: &str) -> Result<String, JsError> {
    to_json(&compose::services(compose).map_err(js)?)
}

#[wasm_bindgen]
pub struct Initiator {
    inner: Option<handshake::Initiator>,
    hello: String,
    verified: Option<String>,
}

#[wasm_bindgen]
impl Initiator {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<Initiator, JsError> {
        let (inner, hello) = handshake::Initiator::new().map_err(js)?;
        Ok(Self {
            inner: Some(inner),
            hello: to_json(&hello)?,
            verified: None,
        })
    }

    /// The ClientHello JSON to send.
    pub fn hello(&self) -> String {
        self.hello.clone()
    }

    /// `expected_json` is `{org_id, app_id, revisions: ["sha256:<hex>", …]}`; `kms_ca_pem` comes
    /// from `verifyPlatform`. An initiator finishes once.
    pub fn finish(
        &mut self,
        server_hello_json: &str,
        kms_ca_pem: &str,
        expected_json: &str,
        now_ms: f64,
    ) -> Result<Channel, JsError> {
        let hello: handshake::ServerHello = parse("server hello", server_hello_json)?;
        let expected: handshake::Expected = parse("expected", expected_json)?;
        let now = at(now_ms)?;
        let inner = self
            .inner
            .take()
            .ok_or_else(|| js(Error::Malformed("the initiator already finished".into())))?;
        let (channel, v) = inner
            .finish(&hello, kms_ca_pem, &expected, now)
            .map_err(js)?;
        self.verified = Some(to_json(&json!({
            "org_id": v.org_id,
            "app_id": v.app_id,
            "compose_hash": v.compose_hash,
            "aud": hex::encode(v.aud),
            "not_before": rfc3339(v.not_before).map_err(js)?,
            "not_after": rfc3339(v.not_after).map_err(js)?,
            "kms_ca_sha256": hex::encode(v.kms_ca_sha256),
            "compose": v.compose,
            "now": rfc3339(v.now).map_err(js)?,
        }))?);
        Ok(Channel {
            inner: channel,
            last_seq: None,
        })
    }

    /// What `finish` verified, as JSON; `aud` and `kms_ca_sha256` are hex, times RFC 3339.
    pub fn verified(&self) -> Result<String, JsError> {
        self.verified
            .clone()
            .ok_or_else(|| js(Error::Malformed("the initiator has not finished".into())))
    }
}

/// The initiator's end of an open channel.
#[wasm_bindgen]
pub struct Channel {
    inner: frame::Channel,
    last_seq: Option<u32>,
}

#[wasm_bindgen]
impl Channel {
    /// The request frame JSON for `body` on `method` and `path`.
    #[wasm_bindgen(js_name = sealRequest)]
    pub fn seal_request(
        &mut self,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> Result<String, JsError> {
        let frame = self.inner.seal_request(method, path, body).map_err(js)?;
        self.last_seq = Some(u32::try_from(frame.seq).map_err(|_| js(Error::Exhausted))?);
        to_json(&frame)
    }

    /// The sequence number of the last sealed request.
    #[wasm_bindgen(js_name = lastSeq)]
    pub fn last_seq(&self) -> Option<u32> {
        self.last_seq
    }

    pub fn response(&self, seq: u32) -> ResponseReader {
        ResponseReader {
            inner: self.inner.response(u64::from(seq)),
        }
    }
}

#[wasm_bindgen]
pub struct ResponseReader {
    inner: frame::ResponseReader,
}

#[wasm_bindgen]
impl ResponseReader {
    /// The next frame's body, or `undefined` for a blank line.
    #[wasm_bindgen(js_name = openLine)]
    pub fn open_line(&mut self, line: &str) -> Result<Option<Vec<u8>>, JsError> {
        Ok(self.inner.open_line(line).map_err(js)?.map(|b| b.to_vec()))
    }

    /// Call when the stream closes; refuses a response that never sent its end frame.
    pub fn finish(&self) -> Result<(), JsError> {
        self.inner.finish().map_err(js)
    }
}

/// An Instance's end, for a tenant's own server or a test fixture.
#[wasm_bindgen]
pub struct Responder {
    inner: handshake::Responder,
    channel: Option<frame::Channel>,
}

#[wasm_bindgen]
impl Responder {
    #[wasm_bindgen(constructor)]
    pub fn new(
        chain_pem: Vec<String>,
        pkcs8: &[u8],
        compose: String,
    ) -> Result<Responder, JsError> {
        Ok(Self {
            inner: handshake::Responder::new(chain_pem, pkcs8, compose).map_err(js)?,
            channel: None,
        })
    }

    /// The ServerHello JSON; its channel is then taken with `channel()`.
    pub fn respond(&mut self, client_hello_json: &str, now_ms: f64) -> Result<String, JsError> {
        let hello: handshake::ClientHello = parse("client hello", client_hello_json)?;
        let (reply, channel) = self.inner.respond(&hello, at(now_ms)?).map_err(js)?;
        self.channel = Some(channel);
        to_json(&reply)
    }

    pub fn channel(&mut self) -> Result<ServerChannel, JsError> {
        self.channel
            .take()
            .map(|inner| ServerChannel { inner })
            .ok_or_else(|| {
                js(Error::Malformed(
                    "no handshake to take a channel from".into(),
                ))
            })
    }
}

#[wasm_bindgen]
pub struct ServerChannel {
    inner: frame::Channel,
}

#[wasm_bindgen]
impl ServerChannel {
    /// The body of a request frame received on `method` and `path`.
    #[wasm_bindgen(js_name = openRequest)]
    pub fn open_request(
        &mut self,
        frame_json: &str,
        method: &str,
        path: &str,
    ) -> Result<Vec<u8>, JsError> {
        let frame: frame::RequestFrame = parse("request frame", frame_json)?;
        let (_, body) = self.inner.open_request(&frame, method, path).map_err(js)?;
        Ok(body.to_vec())
    }

    /// One line of the response to request `seq`.
    #[wasm_bindgen(js_name = sealResponse)]
    pub fn seal_response(
        &self,
        seq: u32,
        index: u32,
        end: bool,
        body: &[u8],
    ) -> Result<String, JsError> {
        self.inner
            .seal_response(u64::from(seq), index, end, body)
            .map_err(js)
    }
}

/// A member document and the digest the page signs with its WebCrypto key.
#[wasm_bindgen(getter_with_clone)]
pub struct Signable {
    /// The JCS text; send it as the signed document.
    pub document: String,
    pub digest: Vec<u8>,
}

/// `fields_json` plus `v`, a fresh `nonce` and `issued_at` from `now_ms`, under one of the member
/// contexts.
#[wasm_bindgen]
pub fn signable(context: &str, fields_json: &str, now_ms: f64) -> Result<Signable, JsError> {
    let fields = parse("fields", fields_json)?;
    let (document, digest) = member::signable(context, fields, at(now_ms)?).map_err(js)?;
    Ok(Signable {
        document,
        digest: digest.to_vec(),
    })
}

/// `sha256:<hex>` of a write's body.
#[wasm_bindgen(js_name = bodySha256)]
pub fn body_sha256(body: &[u8]) -> String {
    sha256_label(body)
}

/// The hex SHA-256 of the member key, once the signature and the freshness check out.
#[wasm_bindgen(js_name = verifyMemberRequest)]
pub fn verify_member_request(
    context: &str,
    document_json: &str,
    member_key_b64: &str,
    signature_json: &str,
    now_ms: f64,
) -> Result<String, JsError> {
    let document: serde_json::Value = parse("document", document_json)?;
    let signature: member::MemberSignature = parse("signature", signature_json)?;
    let signer =
        member::verify_request(context, &document, member_key_b64, &signature).map_err(js)?;
    let issued_at = document
        .get("issued_at")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| js(Error::Malformed("issued_at is missing".into())))?;
    member::check_fresh(issued_at, at(now_ms)?).map_err(js)?;
    Ok(hex::encode(signer.key_sha256))
}

/// The grant JSON, once `wire` verifies under the base64url SPKI `spki_b64`.
#[wasm_bindgen(js_name = verifyGrant)]
pub fn verify_grant(wire: &str, spki_b64: &str) -> Result<String, JsError> {
    use base64::Engine;
    let spki = base64::prelude::BASE64_URL_SAFE_NO_PAD
        .decode(spki_b64)
        .map_err(|_| js(Error::Malformed("spki is not base64url".into())))?;
    let grant = member::parse_grant(wire).map_err(js)?;
    to_json(&grant.verify(&spki).map_err(js)?)
}
