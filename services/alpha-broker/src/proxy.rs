//! `POST /proxy`: an attested Instance names a member, one of that member's connections and a
//! read inside the provider's allowlist; the broker attaches the member's access token and
//! answers with the provider's status, content type and body. Nothing outside the allowlist
//! reaches the provider, and no token leaves the broker.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::Response;
use reqwest::Url;
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::connect::{parse_body, parse_member};
use crate::oauth::{self, Provider, RefreshError};
use crate::{AppState, AuthedInstance, Error, store};

/// Every read the agent may make through a Google connection, all `GET` on
/// `https://www.googleapis.com`, where a `{id}` segment matches one identifier. Nothing here
/// writes, uploads or reaches the Docs, Sheets or Slides APIs; those files are read through
/// Drive's export.
const GOOGLE_READS: &[&str] = &[
    "/drive/v3/drives",
    "/drive/v3/files",
    "/drive/v3/files/{id}",
    "/drive/v3/files/{id}/export",
    "/gmail/v1/users/me/messages",
    "/gmail/v1/users/me/messages/{id}",
    "/calendar/v3/calendars/primary/events",
];

// ponytail: the provider's whole body is buffered, so a Drive file larger than this cannot be
// read through the proxy. The upgrade is a ranged or streamed download.
pub const MAX_RESPONSE: usize = 16 << 20;

/// An access token is used until this long before the provider says it expires.
const EXPIRY_MARGIN: Duration = Duration::from_secs(60);

/// A 16 MiB export can take longer than the client's default timeout.
const SEND_TIMEOUT: Duration = Duration::from_secs(100);

/// Access tokens by connection id, kept only in this process.
pub type TokenCache = parking_lot::Mutex<HashMap<Uuid, (Zeroizing<String>, Instant)>>;

fn is_id(segment: &str) -> bool {
    (1..=256).contains(&segment.len())
        && segment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Judged on the parsed URL, whose `.` and `..` segments are already resolved, so the path
/// checked is the path sent.
pub fn allowed(provider: &Provider, method: &str, url: &Url) -> bool {
    if provider.name != "google"
        || method != "GET"
        || url.scheme() != "https"
        || url.host_str() != Some("www.googleapis.com")
        || url.port().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return false;
    }
    let Some(segments) = url.path_segments() else {
        return false;
    };
    let segments: Vec<&str> = segments.collect();
    GOOGLE_READS.iter().any(|template| {
        let template: Vec<&str> = template.split('/').skip(1).collect();
        template.len() == segments.len()
            && template
                .iter()
                .zip(&segments)
                .all(|(t, s)| if *t == "{id}" { is_id(s) } else { t == s })
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProxyRequest {
    member: String,
    connection_id: String,
    method: String,
    url: String,
    body: Option<Value>,
}

pub async fn proxy(
    State(state): State<Arc<AppState>>,
    _: AuthedInstance,
    body: Bytes,
) -> Result<Response, Error> {
    let request: ProxyRequest = parse_body(&body)?;
    let member = parse_member(&request.member)?;
    let id = Uuid::parse_str(&request.connection_id)
        .map_err(|_| Error::Malformed("connection_id must be a UUID".into()))?;
    let url = Url::parse(&request.url)
        .map_err(|_| Error::Malformed("url must be an absolute URL".into()))?;

    let (provider, dead) = store::load_connection(&state.pool, id, &member)
        .await?
        .ok_or(Error::NotFound)?;
    let provider = oauth::provider(&provider)
        .ok_or_else(|| Error::internal("a connection names an unknown provider"))?;
    if !allowed(provider, &request.method, &url) {
        return Err(Error::NotAllowed);
    }
    if dead {
        return Err(Error::ReconnectRequired);
    }
    let mut retried = false;
    loop {
        let token = access_token(&state, id, provider).await?;
        let mut outgoing = state
            .http
            .get(url.clone())
            .bearer_auth(token.as_str())
            .timeout(SEND_TIMEOUT);
        if let Some(body) = &request.body {
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
    let (key, client_secret) = {
        let secrets = state.secrets.read();
        (
            secrets.connectors_key.clone(),
            secrets.google_client_secret.clone(),
        )
    };
    let refresh_token = store::open(&key, id.as_bytes(), &sealed)
        .ok_or_else(|| Error::internal("a stored refresh token does not open"))?;
    let refresh_token = std::str::from_utf8(&refresh_token)
        .map_err(|_| Error::internal("a stored refresh token is not utf8"))?;

    let refreshed = match oauth::refresh(
        &state.http,
        provider,
        &state.config.google_client_id,
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
    if let Some(until) = until {
        state
            .tokens
            .lock()
            .insert(id, (refreshed.access_token.clone(), until));
    }
    Ok(refreshed.access_token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::GOOGLE;

    fn google(method: &str, url: &str) -> bool {
        allowed(&GOOGLE, method, &Url::parse(url).unwrap())
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
