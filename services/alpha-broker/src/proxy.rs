//! `POST /proxy`: an attested Instance names a member, one of that member's connections and a
//! read on the connection's provider's read list; the broker attaches the member's access token
//! and answers with the provider's status, content type and body. Nothing outside the list
//! reaches the provider, and no token leaves the broker.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use axum::response::Response;
use reqwest::Url;
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::connect::{parse_body, parse_member};
use crate::oauth::{self, Entry, Provider, RefreshError};
use crate::{AppState, AuthedInstance, Error, store};

// ponytail: the provider's whole body is buffered, so a file larger than this cannot be read
// through the proxy. The upgrade is a ranged or streamed download.
pub const MAX_RESPONSE: usize = 16 << 20;

/// An access token is used until this long before the provider says it expires.
const EXPIRY_MARGIN: Duration = Duration::from_secs(60);

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
    let headers = headers.unwrap_or_default();
    let listed = |name: &str| {
        provider
            .headers
            .contains(&name.to_ascii_lowercase().as_str())
    };
    if !headers.keys().all(|name| listed(name)) {
        return Err(Error::NotAllowed);
    }
    let mut out = HeaderMap::new();
    for (name, value) in headers {
        let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| Error::NotAllowed)?;
        let value = HeaderValue::from_str(&value)
            .map_err(|_| Error::Malformed(format!("header {name} has an invalid value")))?;
        out.insert(name, value);
    }
    Ok(out)
}

/// A live connection of the member, its provider and whether it is dead.
async fn load(
    state: &AppState,
    member: &str,
    connection_id: &str,
) -> Result<(Uuid, &'static Provider, bool), Error> {
    let member = parse_member(member)?;
    let id = Uuid::parse_str(connection_id)
        .map_err(|_| Error::Malformed("connection_id must be a UUID".into()))?;
    let (provider, dead) = store::load_connection(&state.pool, id, &member)
        .await?
        .ok_or(Error::NotFound)?;
    let provider = oauth::provider(&provider)
        .ok_or_else(|| Error::internal("a connection names an unknown provider"))?;
    Ok((id, provider, dead))
}

fn parse_url(url: &str) -> Result<Url, Error> {
    Url::parse(url).map_err(|_| Error::Malformed("url must be an absolute URL".into()))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProxyRequest {
    member: String,
    connection_id: String,
    method: String,
    url: String,
    body: Option<Value>,
    headers: Option<BTreeMap<String, String>>,
}

pub async fn proxy(
    State(state): State<Arc<AppState>>,
    _: AuthedInstance,
    body: Bytes,
) -> Result<Response, Error> {
    let request: ProxyRequest = parse_body(&body)?;
    let url = parse_url(&request.url)?;
    let (id, provider, dead) = load(&state, &request.member, &request.connection_id).await?;
    let entry = allowed(provider.reads, &request.method, &url).ok_or(Error::NotAllowed)?;
    let headers = check_headers(provider, request.headers)?;
    if dead {
        return Err(Error::ReconnectRequired);
    }
    forward(&state, id, provider, entry, url, headers, request.body).await
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
    body: Option<Value>,
) -> Result<Response, Error> {
    let mut retried = false;
    loop {
        let token = access_token(state, id, provider).await?;
        let mut outgoing = state
            .http
            .request(entry.method.clone(), url.clone())
            .headers(headers.clone())
            .bearer_auth(token.as_str())
            .timeout(SEND_TIMEOUT);
        if let Some(body) = &body {
            outgoing = outgoing.json(body);
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

async fn relay(mut response: reqwest::Response) -> Result<Response, Error> {
    let status = response.status();
    let content_type = response.headers().get(header::CONTENT_TYPE).cloned();
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| Error::Upstream)? {
        if body.len().saturating_add(chunk.len()) > MAX_RESPONSE {
            return Err(Error::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    let mut reply = Response::new(Body::from(body));
    *reply.status_mut() = status;
    if let Some(content_type) = content_type {
        reply
            .headers_mut()
            .insert(header::CONTENT_TYPE, content_type);
    }
    Ok(reply)
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
        &client_secret,
        refresh_token,
    )
    .await
    {
        Ok(refreshed) => refreshed,
        Err(RefreshError::InvalidGrant) => {
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
    tx.commit().await?;
    let until = Duration::from_secs(refreshed.expires_in)
        .checked_sub(EXPIRY_MARGIN)
        .and_then(|d| Instant::now().checked_add(d));
    let mut cache = state.tokens.lock();
    let now = Instant::now();
    cache.retain(|_, (_, until)| *until > now);
    if let Some(until) = until {
        cache.insert(id, (refreshed.access_token.clone(), until));
    }
    Ok(refreshed.access_token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::{DROPBOX, GOOGLE};

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
