//! `POST /proxy`: an attested Instance presents a grant the member's key signed for its leaf, one
//! of the connections the grant names and a read on that connection's provider's read list.
//! `POST /write`: the tenant's backend relays, sealed on a channel, one export the member's key
//! signed for that request alone, on the provider's write list. The broker attaches the member's
//! access token and answers with the provider's status, content type and body. Neither route
//! reaches the other's list, nothing outside them reaches the provider, and no token leaves the
//! broker.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use reqwest::Url;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;
use zeroize::Zeroizing;

use alpha_channel::NamedSignature;
use alpha_channel::member::{MemberDocument, parse_grant};
use alpha_core::context;

use crate::channel::Sealed;
use crate::connect::{parse_body, spend, verify};
use crate::oauth::{self, Entry, Provider, RefreshError};
use crate::{AppState, AuthedCorpus, AuthedInstance, Error, store};

// ponytail: the provider's whole body is buffered, so a file larger than this cannot be read
// through the proxy. The upgrade is a ranged or streamed download.
pub const MAX_RESPONSE: usize = 16 << 20;

/// An 8 MiB file is base64 inside the member's plaintext, and that plaintext is base64 again
/// inside the sealed frame: about 14.3 MiB on the wire.
pub const WRITE_BODY_LIMIT: usize = 16 << 20;

/// A chat names at most as many connections as its worker keeps in one session.
const MAX_GRANT_CONNECTIONS: usize = 16;

/// An access token is used until this long before the provider says it expires.
const EXPIRY_MARGIN: Duration = Duration::from_secs(60);

// ponytail: a refresh reply without `expires_in` is trusted for an hour, so a token revoked or
// shorter-lived than that is noticed only when the provider answers 401, which drops it and
// retries once. The upgrade is each row naming its provider's documented lifetime.
const DEFAULT_LIFETIME: Duration = Duration::from_secs(3600);

/// A 16 MiB export can take longer than the client's default timeout.
const SEND_TIMEOUT: Duration = Duration::from_secs(100);

/// Access tokens by connection id, kept only in this process; expired ones are dropped whenever
/// a new one is stored.
pub type TokenCache = parking_lot::Mutex<HashMap<Uuid, (Zeroizing<String>, Instant)>>;

fn is_id(segment: &str) -> bool {
    (1..=256).contains(&segment.len())
        && segment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Judged on the parsed URL, whose `.` and `..` segments are already resolved, so the path
/// checked is the path sent. Method, host and path match one entry together.
pub fn allowed(entries: &'static [Entry], method: &str, url: &Url) -> Option<&'static Entry> {
    if url.scheme() != "https"
        || url.port().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    let host = url.host_str()?;
    let segments: Vec<&str> = url.path_segments()?.collect();
    entries.iter().find(|entry| {
        let template: Vec<&str> = entry.path.split('/').skip(1).collect();
        entry.method.as_str() == method
            && entry.host == host
            && template.len() == segments.len()
            && template
                .iter()
                .zip(&segments)
                .all(|(t, s)| if *t == "{id}" { is_id(s) } else { t == s })
    })
}

/// The caller's headers, each name on the provider's list and each value a valid header value.
fn check_headers(
    provider: &Provider,
    headers: Option<BTreeMap<String, String>>,
) -> Result<HeaderMap, Error> {
    let mut out = HeaderMap::new();
    for (name, value) in headers.unwrap_or_default() {
        if !provider
            .headers
            .iter()
            .any(|h| h.eq_ignore_ascii_case(&name))
        {
            return Err(Error::NotAllowed);
        }
        let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| Error::NotAllowed)?;
        let value = HeaderValue::from_str(&value)
            .map_err(|_| Error::Malformed(format!("header {name} has an invalid value")))?;
        out.insert(name, value);
    }
    Ok(out)
}

/// Besides `tools/call`, the handshake and the tool listing. Resources, prompts and completions
/// are refused: nothing has classified what they reach.
const MCP_METHODS: &[&str] = &[
    "initialize",
    "notifications/initialized",
    "ping",
    "tools/list",
];

/// An MCP request the broker forwards: one JSON-RPC object, never a batch, whose method is on
/// `MCP_METHODS` or is a `tools/call` of a tool named exactly on `tools`.
pub fn mcp_call_allowed(tools: &[&str], body: Option<&Value>) -> bool {
    let Some(Value::Object(request)) = body else {
        return false;
    };
    match request.get("method").and_then(Value::as_str) {
        Some("tools/call") => request
            .get("params")
            .and_then(|params| params.get("name"))
            .and_then(Value::as_str)
            .is_some_and(|name| tools.contains(&name)),
        Some(method) => MCP_METHODS.contains(&method),
        None => false,
    }
}

/// The live connection of the member, its provider, the entry of `list` the request matches,
/// the caller's headers and, for an MCP server, the tool called, checked in that order; a dead
/// connection is refused last.
#[allow(clippy::too_many_arguments)]
async fn target(
    state: &AppState,
    member: &[u8],
    id: Uuid,
    method: &str,
    url: &Url,
    headers: Option<BTreeMap<String, String>>,
    body: Option<&Value>,
    list: fn(&Provider) -> &'static [Entry],
) -> Result<(&'static Provider, &'static Entry, HeaderMap), Error> {
    let (provider, dead) = store::load_connection(&state.pool, id, member)
        .await?
        .ok_or(Error::NotFound)?;
    let provider = oauth::provider(&provider)
        .ok_or_else(|| Error::internal("a connection names an unknown provider"))?;
    let entry = allowed(list(provider), method, url).ok_or(Error::NotAllowed)?;
    let headers = check_headers(provider, headers)?;
    if provider
        .mcp_tools
        .is_some_and(|tools| !mcp_call_allowed(tools, body))
    {
        return Err(Error::NotAllowed);
    }
    if dead {
        return Err(Error::ReconnectRequired);
    }
    Ok((provider, entry, headers))
}

/// The member key that signed `wire` for the Instance whose leaf SPKI hashes to `aud`, when the
/// grant is live now and names `id` among connections that are all that key's.
async fn granted(state: &AppState, aud: &[u8; 32], wire: &str, id: Uuid) -> Result<Vec<u8>, Error> {
    let signed = parse_grant(wire).map_err(|e| Error::Malformed(e.to_string()))?;
    // The grant's connections can be read only once it verifies, so it is verified under the
    // requested connection's key, and every connection it names must then hold that same key.
    let Some((_, key)) = store::load_grant_keys(&state.pool, &[id])
        .await?
        .into_iter()
        .next()
    else {
        return Err(Error::NotFound);
    };
    let grant = signed.verify(&key).map_err(|e| match e {
        alpha_channel::Error::SignatureInvalid(_) => Error::GrantInvalid,
        other => Error::Malformed(other.to_string()),
    })?;
    if grant.connections.is_empty() || grant.connections.len() > MAX_GRANT_CONNECTIONS {
        return Err(Error::Malformed(format!(
            "a grant names 1 to {MAX_GRANT_CONNECTIONS} connections"
        )));
    }
    let listed = store::load_grant_keys(&state.pool, &grant.connections).await?;
    if !grant
        .connections
        .iter()
        .all(|c| listed.iter().any(|(live, _)| live == c))
    {
        return Err(Error::NotFound);
    }
    if listed.iter().any(|(_, other)| *other != key)
        || grant.aud != format!("sha256:{}", hex::encode(aud))
        || !grant.connections.contains(&id)
    {
        return Err(Error::GrantInvalid);
    }
    grant.check_window(SystemTime::now()).map_err(|e| match e {
        alpha_channel::Error::GrantExpired => Error::GrantExpired,
        other => Error::Malformed(other.to_string()),
    })?;
    Ok(key)
}

fn parse_url(url: &str) -> Result<Url, Error> {
    Url::parse(url).map_err(|_| Error::Malformed("url must be an absolute URL".into()))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProxyRequest {
    grant: String,
    connection_id: Uuid,
    method: String,
    url: String,
    body: Option<Value>,
    headers: Option<BTreeMap<String, String>>,
}

pub async fn proxy(
    State(state): State<Arc<AppState>>,
    instance: AuthedInstance,
    body: Bytes,
) -> Result<Relayed, Error> {
    let request: ProxyRequest = parse_body(&body)?;
    let url = parse_url(&request.url)?;
    let id = request.connection_id;
    let member = granted(&state, &instance.aud, &request.grant, id).await?;
    let (provider, entry, headers) = target(
        &state,
        &member,
        id,
        &request.method,
        &url,
        request.headers,
        request.body.as_ref(),
        |p| p.reads,
    )
    .await?;
    let payload = request
        .body
        .map(|b| serde_json::to_vec(&b))
        .transpose()
        .map_err(|e| Error::internal(format!("body: {e}")))?
        .map(|v| (HeaderValue::from_static("application/json"), Bytes::from(v)));
    forward(&state, id, provider, entry, url, headers, payload).await
}

/// The member's export as the page seals it: the signed document and the bytes it hashes.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedWrite {
    document: Value,
    member_key: String,
    signature: NamedSignature,
    content_type: String,
    body_base64: String,
    headers: Option<BTreeMap<String, String>>,
}

pub async fn write(
    State(state): State<Arc<AppState>>,
    _: AuthedCorpus,
    sealed: Sealed,
) -> Response {
    let result = async {
        let signed: SignedWrite = parse_body(&sealed.plaintext)?;
        let (member, document) = verify(
            context::CONNECTOR_WRITE,
            &signed.document,
            &signed.member_key,
            &signed.signature,
        )?;
        spend(&state, &document).await?;
        let MemberDocument::Write(write) = document else {
            return Err(Error::Malformed("the document is not a write".into()));
        };
        let content_type = HeaderValue::from_str(&signed.content_type)
            .map_err(|_| Error::Malformed("content_type is not a valid header value".into()))?;
        let bytes = BASE64_STANDARD
            .decode(&signed.body_base64)
            .map_err(|_| Error::Malformed("body_base64 must be standard base64".into()))?;
        if write.body_sha256 != alpha_channel::sha256_label(&bytes) {
            return Err(Error::Malformed(
                "body_sha256 is not the SHA-256 of the body".into(),
            ));
        }
        let url = parse_url(&write.url)?;
        let id = write.connection_id;
        let (provider, entry, headers) = target(
            &state,
            &member,
            id,
            &write.method,
            &url,
            signed.headers,
            None,
            |p| p.writes,
        )
        .await?;
        let payload = Some((content_type, Bytes::from(bytes)));
        let relayed = forward(&state, id, provider, entry, url, headers, payload).await?;
        Ok(json!({
            "status": relayed.status.as_u16(),
            "content_type": relayed.content_type.as_ref().and_then(|v| v.to_str().ok()),
            "body_base64": BASE64_STANDARD.encode(&relayed.body),
        }))
    }
    .await;
    sealed.reply(&state, result)
}

/// Sends the entry's method to `url` with the member's access token; a 401 on a cached token
/// drops it, refreshes once and retries once.
async fn forward(
    state: &AppState,
    id: Uuid,
    provider: &Provider,
    entry: &Entry,
    url: Url,
    headers: HeaderMap,
    payload: Option<(HeaderValue, Bytes)>,
) -> Result<Relayed, Error> {
    let mut retried = false;
    loop {
        let token = access_token(state, id, provider).await?;
        let outgoing = state
            .http
            .request(entry.method.clone(), url.clone())
            .headers(headers.clone());
        let mut outgoing = oauth::with_mcp_accept(outgoing, provider)
            .bearer_auth(token.as_str())
            .timeout(SEND_TIMEOUT);
        if let Some((content_type, bytes)) = &payload {
            outgoing = outgoing
                .header(header::CONTENT_TYPE, content_type.clone())
                .body(bytes.clone());
        }
        let response = outgoing.send().await.map_err(|_| Error::Upstream)?;
        if response.status() == StatusCode::UNAUTHORIZED && !retried {
            let mut cache = state.tokens.lock();
            if cache.get(&id).is_some_and(|(t, _)| *t == token) {
                cache.remove(&id);
            }
            retried = true;
            continue;
        }
        return relay(response).await;
    }
}

/// The provider's answer, read whole.
pub struct Relayed {
    status: StatusCode,
    content_type: Option<HeaderValue>,
    body: Vec<u8>,
}

impl IntoResponse for Relayed {
    fn into_response(self) -> Response {
        let mut reply = Response::new(Body::from(self.body));
        *reply.status_mut() = self.status;
        if let Some(content_type) = self.content_type {
            reply
                .headers_mut()
                .insert(header::CONTENT_TYPE, content_type);
        }
        reply
    }
}

async fn relay(mut response: reqwest::Response) -> Result<Relayed, Error> {
    let status = response.status();
    let content_type = response.headers().get(header::CONTENT_TYPE).cloned();
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| Error::Upstream)? {
        if body.len().saturating_add(chunk.len()) > MAX_RESPONSE {
            return Err(Error::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Relayed {
        status,
        content_type,
        body,
    })
}

fn cached(state: &AppState, id: Uuid) -> Option<Zeroizing<String>> {
    state
        .tokens
        .lock()
        .get(&id)
        .filter(|(_, until)| *until > Instant::now())
        .map(|(token, _)| token.clone())
}

/// The cached access token, or a new one from the sealed refresh token.
async fn access_token(
    state: &AppState,
    id: Uuid,
    provider: &Provider,
) -> Result<Zeroizing<String>, Error> {
    if let Some(token) = cached(state, id) {
        return Ok(token);
    }
    let mut tx = state.pool.begin().await?;
    let sealed = store::lock_token(&mut tx, id)
        .await?
        .ok_or(Error::NotFound)?;
    if let Some(token) = cached(state, id) {
        return Ok(token);
    }
    let key = state.secrets.read().connectors_key.clone();
    let (client_id, client_secret) = state.client(provider)?;
    let refresh_token = store::open(&key, id.as_bytes(), &sealed)
        .ok_or_else(|| Error::internal("a stored refresh token does not open"))?;
    let refresh_token = std::str::from_utf8(&refresh_token)
        .map_err(|_| Error::internal("a stored refresh token is not utf8"))?;

    let refreshed = match oauth::refresh(
        &state.http,
        provider,
        client_id,
        client_secret.as_deref().map(String::as_str),
        refresh_token,
    )
    .await
    {
        Ok(refreshed) => refreshed,
        Err(RefreshError::Dead) => {
            store::mark_dead(&mut tx, id).await?;
            tx.commit().await?;
            state.tokens.lock().remove(&id);
            return Err(Error::ReconnectRequired);
        }
        Err(RefreshError::Other(reason)) => {
            eprintln!("alpha-broker: refresh failed: {reason}");
            return Err(Error::Upstream);
        }
    };
    if let Some(rotated) = &refreshed.refresh_token {
        let sealed = store::seal(&key, id.as_bytes(), rotated.as_bytes())?;
        store::replace_refresh_token(&mut tx, id, &sealed).await?;
    }
    let until = refreshed
        .expires_in
        .map_or(DEFAULT_LIFETIME, Duration::from_secs)
        .checked_sub(EXPIRY_MARGIN)
        .and_then(|d| Instant::now().checked_add(d));
    // Cached before the row lock is released, so a call waiting on it finds the token.
    {
        let mut cache = state.tokens.lock();
        let now = Instant::now();
        cache.retain(|_, (_, until)| *until > now);
        if let Some(until) = until {
            cache.insert(id, (refreshed.access_token.clone(), until));
        }
    }
    if let Err(e) = tx.commit().await {
        state.tokens.lock().remove(&id);
        return Err(e.into());
    }
    Ok(refreshed.access_token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    use crate::oauth::{DROPBOX, GOOGLE, HUBSPOT, HUBSPOT_READ_TOOLS};

    fn mcp_call(name: Value) -> Value {
        json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": { "name": name } })
    }

    fn mcp_allowed(body: &Value) -> bool {
        mcp_call_allowed(HUBSPOT_READ_TOOLS, Some(body))
    }

    #[test]
    fn mcp_a_listed_tool_the_handshake_and_the_tool_listing_pass() {
        assert!(mcp_allowed(&mcp_call(json!("search_crm_objects"))));
        for method in [
            "tools/list",
            "initialize",
            "notifications/initialized",
            "ping",
        ] {
            assert!(
                mcp_allowed(&json!({ "jsonrpc": "2.0", "method": method })),
                "{method}"
            );
        }
    }

    #[test]
    fn mcp_an_unlisted_near_or_malformed_call_is_refused() {
        for name in [
            "manage_crm_objects",
            "search_crm_objects_v2",
            "search_crm_object",
            "Search_crm_objects",
            " search_crm_objects",
            "",
        ] {
            assert!(!mcp_allowed(&mcp_call(json!(name))), "{name:?}");
        }
        assert!(!mcp_allowed(&mcp_call(json!(7))));
        assert!(!mcp_allowed(
            &json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call" })
        ));
        assert!(!mcp_allowed(
            &json!({ "method": "tools/call", "params": { "arguments": {} } })
        ));
        assert!(!mcp_allowed(&json!([mcp_call(json!(
            "search_crm_objects"
        ))])));
        assert!(!mcp_allowed(&json!("tools/list")));
        for method in [
            json!("resources/read"),
            json!("resources/list"),
            json!("prompts/get"),
            json!("completion/complete"),
            json!("Tools/list"),
            json!(1),
        ] {
            assert!(
                !mcp_allowed(&json!({ "jsonrpc": "2.0", "id": 1, "method": method })),
                "{method}"
            );
        }
        assert!(!mcp_allowed(
            &json!({ "jsonrpc": "2.0", "id": 1, "result": {} })
        ));
        assert!(!mcp_call_allowed(HUBSPOT_READ_TOOLS, None));
    }

    #[test]
    fn mcp_hubspot_is_reached_with_or_without_a_trailing_slash() {
        for url in ["https://mcp.hubspot.com", "https://mcp.hubspot.com/"] {
            assert!(
                allowed(HUBSPOT.reads, "POST", &Url::parse(url).unwrap()).is_some(),
                "{url}"
            );
        }
        for url in ["https://mcp.hubspot.com/mcp", "https://mcp.hubspot.com//"] {
            assert!(allowed(HUBSPOT.reads, "POST", &Url::parse(url).unwrap()).is_none());
        }
        assert!(
            allowed(
                HUBSPOT.reads,
                "GET",
                &Url::parse("https://mcp.hubspot.com/").unwrap()
            )
            .is_none()
        );
    }

    fn google(method: &str, url: &str) -> bool {
        allowed(GOOGLE.reads, method, &Url::parse(url).unwrap()).is_some()
    }

    fn dropbox(method: &str, url: &str) -> bool {
        allowed(DROPBOX.reads, method, &Url::parse(url).unwrap()).is_some()
    }

    #[test]
    fn each_dropbox_read_is_allowed_as_a_post_on_its_own_host() {
        for url in [
            "https://api.dropboxapi.com/2/files/list_folder",
            "https://api.dropboxapi.com/2/files/list_folder/continue",
            "https://api.dropboxapi.com/2/files/get_metadata",
            "https://api.dropboxapi.com/2/files/search_v2",
            "https://api.dropboxapi.com/2/files/search/continue_v2",
            "https://api.dropboxapi.com/2/sharing/list_folders",
            "https://api.dropboxapi.com/2/sharing/list_folders/continue",
            "https://api.dropboxapi.com/2/users/get_current_account",
            "https://content.dropboxapi.com/2/files/download",
            "https://content.dropboxapi.com/2/files/export",
        ] {
            assert!(dropbox("POST", url), "{url}");
            assert!(!dropbox("GET", url), "{url}");
        }
    }

    #[test]
    fn anything_else_on_dropbox_is_refused() {
        for url in [
            "https://content.dropboxapi.com/2/files/list_folder",
            "https://api.dropboxapi.com/2/files/download",
            "https://notify.dropboxapi.com/2/files/list_folder/longpoll",
            "https://api.dropboxapi.com:8443/2/files/list_folder",
            "https://user@api.dropboxapi.com/2/files/list_folder",
            "http://api.dropboxapi.com/2/files/list_folder",
            "https://api.dropboxapi.com/2/files/list_folder#x",
            "https://api.dropboxapi.com/2/files/list_folder/../../files/delete_v2",
            "https://api.dropboxapi.com/2/files/list_folder/%2e%2e/delete_v2",
            "https://api.dropboxapi.com/2/files/delete_v2",
            "https://content.dropboxapi.com/2/files/upload",
            "https://api.dropboxapi.com/2/files/create_folder_v2",
            "https://www.googleapis.com/drive/v3/files",
        ] {
            assert!(!dropbox("POST", url), "{url}");
        }
    }

    #[test]
    fn each_read_is_allowed_with_a_valid_id() {
        for url in [
            "https://www.googleapis.com/drive/v3/drives?pageSize=100",
            "https://www.googleapis.com/drive/v3/files?q=trashed%3Dfalse",
            "https://www.googleapis.com/drive/v3/files/1AbC_d-9?alt=media",
            "https://www.googleapis.com/drive/v3/files/1AbC_d-9/export?mimeType=text/csv",
            "https://www.googleapis.com/gmail/v1/users/me/messages?q=from:x",
            "https://www.googleapis.com/gmail/v1/users/me/messages/18c2f0a1b",
            "https://www.googleapis.com/calendar/v3/calendars/primary/events",
            "https://www.googleapis.com:443/drive/v3/files",
        ] {
            assert!(google("GET", url), "{url}");
        }
        assert!(google(
            "GET",
            &format!(
                "https://www.googleapis.com/drive/v3/files/{}",
                "a".repeat(256)
            )
        ));
    }

    #[test]
    fn anything_else_is_refused() {
        for method in ["POST", "PUT", "PATCH", "DELETE", "get"] {
            assert!(
                !google(method, "https://www.googleapis.com/drive/v3/files"),
                "{method}"
            );
        }
        for url in [
            "https://www.googleapis.com/upload/drive/v3/files",
            "https://www.googleapis.com/drive/v3/files/abc/permissions",
            "https://docs.googleapis.com/v1/documents/x",
            "http://www.googleapis.com/drive/v3/files",
            "https://www.googleapis.com:8443/drive/v3/files",
            "https://user@www.googleapis.com/drive/v3/files",
            "https://user:pw@www.googleapis.com/drive/v3/files",
            "https://www.googleapis.com/drive/v3/files#x",
            "https://www.googleapis.com/drive/v3/files/../../upload/drive/v3/files",
            "https://www.googleapis.com/drive/v3/files/%2e%2e/x",
            "https://www.googleapis.com/drive/v3/files/a.b",
            "https://www.googleapis.com/drive/v3/files/a%2Fb",
            "https://www.googleapis.com/drive/v3/files/",
            "https://www.googleapis.com/drive/v3/files//export",
            "https://www.googleapis.com./drive/v3/files",
            "https://www.googleapis.com/calendar/v3/calendars/other/events",
            "https://www.googleapis.com/gmail/v1/users/other/messages",
            "https://api.dropboxapi.com/2/files/list_folder",
        ] {
            assert!(!google("GET", url), "{url}");
        }
        assert!(!google(
            "GET",
            &format!(
                "https://www.googleapis.com/drive/v3/files/{}",
                "a".repeat(257)
            )
        ));
    }
}
