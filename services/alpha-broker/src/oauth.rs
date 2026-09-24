//! Every provider as one row of a fixed table: its OAuth endpoints and scopes, the reads and
//! writes the broker forwards, and the request headers a caller may set. PKCE, and the four
//! calls the broker makes: authorization URL, code exchange, account lookup, revoke. Failures
//! carry a short reason for the log, never the provider's body.

use std::time::Duration;

use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use reqwest::Method;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::Error;

/// One request the broker forwards: the method, the exact host, and a path in which a `{id}`
/// segment matches one identifier.
pub struct Entry {
    pub method: Method,
    pub host: &'static str,
    pub path: &'static str,
}

/// How a disconnect ends the grant at the provider.
pub enum Revoke {
    /// A form post of the refresh token.
    Form(&'static str),
    /// A `POST` carrying a fresh access token as bearer; the provider ends the refresh token
    /// behind it too.
    Bearer(&'static str),
}

/// How the broker proves it is the tenant's client at the token endpoint.
pub enum ClientAuth {
    /// `client_id` and `client_secret` in the form.
    Form,
    /// A public client: only `client_id`; the PKCE verifier stands in for a secret.
    Public,
}

pub struct Provider {
    pub name: &'static str,
    pub authorization: &'static str,
    pub token: &'static str,
    pub client_auth: ClientAuth,
    pub scopes: &'static [&'static str],
    /// The authorization parameter carrying the scopes, and what joins them.
    pub scope_param: (&'static str, &'static str),
    /// The object of the exchange reply holding the tokens, when not its root.
    pub tokens_at: Option<&'static str>,
    /// The refresh reply's `error` codes that mean the member must reconnect.
    pub dead: &'static [&'static str],
    pub extra_authorize: &'static [(&'static str, &'static str)],
    /// The account lookup, sent with the bearer and no body.
    pub identity: (Method, &'static str),
    pub revoke: Revoke,
    pub reads: &'static [Entry],
    pub writes: &'static [Entry],
    /// Names of the request headers a caller may set.
    pub headers: &'static [&'static str],
}

const fn get(host: &'static str, path: &'static str) -> Entry {
    Entry {
        method: Method::GET,
        host,
        path,
    }
}

const fn post(host: &'static str, path: &'static str) -> Entry {
    Entry {
        method: Method::POST,
        host,
        path,
    }
}

/// `openid` and `email` grant no data; they let `account` read the account's subject and the
/// address the member sees in the Sources menu. `drive.file` reaches only files this client
/// created, which is what an export writes. Nothing read reaches the Docs, Sheets or Slides
/// APIs; those files are read through Drive's export.
pub const GOOGLE: Provider = Provider {
    name: "google",
    authorization: "https://accounts.google.com/o/oauth2/v2/auth",
    token: "https://oauth2.googleapis.com/token",
    client_auth: ClientAuth::Form,
    scopes: &[
        "https://www.googleapis.com/auth/drive.readonly",
        "https://www.googleapis.com/auth/gmail.readonly",
        "https://www.googleapis.com/auth/calendar.readonly",
        "https://www.googleapis.com/auth/drive.file",
        "openid",
        "email",
    ],
    scope_param: ("scope", " "),
    tokens_at: None,
    dead: &["invalid_grant"],
    extra_authorize: &[("access_type", "offline"), ("prompt", "consent")],
    identity: (
        Method::GET,
        "https://openidconnect.googleapis.com/v1/userinfo",
    ),
    revoke: Revoke::Form("https://oauth2.googleapis.com/revoke"),
    reads: &[
        get("www.googleapis.com", "/drive/v3/drives"),
        get("www.googleapis.com", "/drive/v3/files"),
        get("www.googleapis.com", "/drive/v3/files/{id}"),
        get("www.googleapis.com", "/drive/v3/files/{id}/export"),
        get("www.googleapis.com", "/gmail/v1/users/me/messages"),
        get("www.googleapis.com", "/gmail/v1/users/me/messages/{id}"),
        get(
            "www.googleapis.com",
            "/calendar/v3/calendars/primary/events",
        ),
    ],
    writes: &[
        post("www.googleapis.com", "/upload/drive/v3/files"),
        post("www.googleapis.com", "/drive/v3/files"),
    ],
    headers: &[],
};

/// `account_info.read` names the account (the lookup must carry no content type: Dropbox refuses
/// a JSON `null` there); `sharing.read` lists the shared folders a member
/// reads through. `dropbox-api-path-root` reaches a team space, and `dropbox-api-arg` carries
/// the arguments of a content-host call.
pub const DROPBOX: Provider = Provider {
    name: "dropbox",
    authorization: "https://www.dropbox.com/oauth2/authorize",
    token: "https://api.dropboxapi.com/oauth2/token",
    client_auth: ClientAuth::Form,
    scopes: &[
        "account_info.read",
        "files.metadata.read",
        "files.content.read",
        "files.content.write",
        "sharing.read",
    ],
    scope_param: ("scope", " "),
    tokens_at: None,
    dead: &["invalid_grant"],
    extra_authorize: &[("token_access_type", "offline")],
    identity: (
        Method::POST,
        "https://api.dropboxapi.com/2/users/get_current_account",
    ),
    revoke: Revoke::Bearer("https://api.dropboxapi.com/2/auth/token/revoke"),
    reads: &[
        post("api.dropboxapi.com", "/2/files/list_folder"),
        post("api.dropboxapi.com", "/2/files/list_folder/continue"),
        post("api.dropboxapi.com", "/2/files/get_metadata"),
        post("api.dropboxapi.com", "/2/files/search_v2"),
        post("api.dropboxapi.com", "/2/files/search/continue_v2"),
        post("api.dropboxapi.com", "/2/sharing/list_folders"),
        post("api.dropboxapi.com", "/2/sharing/list_folders/continue"),
        post("api.dropboxapi.com", "/2/users/get_current_account"),
        post("content.dropboxapi.com", "/2/files/download"),
        post("content.dropboxapi.com", "/2/files/export"),
    ],
    writes: &[
        post("content.dropboxapi.com", "/2/files/upload"),
        post("api.dropboxapi.com", "/2/files/create_folder_v2"),
    ],
    headers: &["dropbox-api-arg", "dropbox-api-path-root"],
};

/// A user token, never a bot's: the connection reads as the member, in every channel and direct
/// message the member sees. A public client, so no Slack secret exists to leak. Every Slack
/// failure is HTTP 200 with `ok: false`; the exchange's user token sits under `authed_user`.
pub const SLACK: Provider = Provider {
    name: "slack",
    authorization: "https://slack.com/oauth/v2/authorize",
    token: "https://slack.com/api/oauth.v2.access",
    client_auth: ClientAuth::Public,
    scopes: &[
        "channels:read",
        "channels:history",
        "groups:read",
        "groups:history",
        "im:read",
        "im:history",
        "mpim:read",
        "mpim:history",
        "users:read",
    ],
    scope_param: ("user_scope", ","),
    tokens_at: Some("authed_user"),
    dead: &["invalid_refresh_token"],
    extra_authorize: &[],
    identity: (Method::POST, "https://slack.com/api/auth.test"),
    revoke: Revoke::Bearer("https://slack.com/api/auth.revoke"),
    reads: &[
        get("slack.com", "/api/conversations.list"),
        get("slack.com", "/api/conversations.history"),
        get("slack.com", "/api/users.info"),
    ],
    writes: &[],
    headers: &[],
};

pub const PROVIDERS: [&Provider; 3] = [&GOOGLE, &DROPBOX, &SLACK];

pub fn provider(name: &str) -> Option<&'static Provider> {
    PROVIDERS.into_iter().find(|p| p.name == name)
}

pub fn challenge(verifier: &str) -> String {
    BASE64_URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// A verifier of 32 random bytes, base64url without padding (43 characters), and its S256
/// challenge.
pub fn pkce() -> Result<(Zeroizing<String>, String), Error> {
    let verifier = Zeroizing::new(BASE64_URL_SAFE_NO_PAD.encode(crate::random::<32>()?));
    let challenge = challenge(&verifier);
    Ok((verifier, challenge))
}

pub fn authorization_url(
    provider: &Provider,
    client_id: &str,
    redirect_uri: &str,
    state: &str,
    challenge: &str,
) -> Result<String, Error> {
    let (scope_param, separator) = provider.scope_param;
    let scope = provider.scopes.join(separator);
    let params = [
        ("client_id", client_id),
        ("redirect_uri", redirect_uri),
        ("response_type", "code"),
        (scope_param, scope.as_str()),
        ("state", state),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256"),
    ];
    reqwest::Url::parse_with_params(
        provider.authorization,
        params
            .into_iter()
            .chain(provider.extra_authorize.iter().copied()),
    )
    .map(String::from)
    .map_err(|e| Error::internal(format!("authorization url: {e}")))
}
pub struct Tokens {
    pub access_token: Zeroizing<String>,
    pub refresh_token: Zeroizing<String>,
    pub scope: String,
}

#[derive(Deserialize)]
struct TokenReply {
    access_token: String,
    refresh_token: Option<String>,
    #[serde(default)]
    scope: String,
}

/// A form post to `url` carrying `form` and the row's client authentication; `None` when the
/// row needs a secret and none was given.
fn token_request<'a>(
    http: &reqwest::Client,
    provider: &Provider,
    url: &str,
    client_id: &'a str,
    client_secret: Option<&'a str>,
    mut form: Vec<(&'a str, &'a str)>,
) -> Option<reqwest::RequestBuilder> {
    form.push(("client_id", client_id));
    match provider.client_auth {
        ClientAuth::Form => form.push(("client_secret", client_secret?)),
        ClientAuth::Public => {}
    }
    Some(http.post(url).form(&form))
}

pub async fn exchange(
    http: &reqwest::Client,
    provider: &Provider,
    client_id: &str,
    client_secret: Option<&str>,
    redirect_uri: &str,
    code: &str,
    verifier: &str,
) -> Result<Tokens, &'static str> {
    let form = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("code_verifier", verifier),
        ("redirect_uri", redirect_uri),
    ];
    let response = token_request(
        http,
        provider,
        provider.token,
        client_id,
        client_secret,
        form,
    )
    .ok_or("no_client_secret")?
    .send()
    .await
    .map_err(|_| "token_unreachable")?;
    if !response.status().is_success() {
        return Err("token_refused");
    }
    let mut reply: Value = response.json().await.map_err(|_| "token_malformed")?;
    if let Some(key) = provider.tokens_at {
        reply = reply.get_mut(key).map(Value::take).unwrap_or_default();
    }
    let reply: TokenReply = serde_json::from_value(reply).map_err(|_| "token_malformed")?;
    let refresh_token = reply.refresh_token.ok_or("no_refresh_token")?;
    Ok(Tokens {
        access_token: Zeroizing::new(reply.access_token),
        refresh_token: Zeroizing::new(refresh_token),
        scope: reply.scope,
    })
}

pub struct Refreshed {
    pub access_token: Zeroizing<String>,
    pub expires_in: Option<u64>,
    /// Present only when the provider rotated the refresh token.
    pub refresh_token: Option<Zeroizing<String>>,
}

pub enum RefreshError {
    /// The provider will never accept this refresh token again; the member must reconnect.
    Dead,
    Other(&'static str),
}

/// The provider's `error` is checked against the row's dead codes whatever the HTTP status:
/// some providers answer every failure with 200.
pub async fn refresh(
    http: &reqwest::Client,
    provider: &Provider,
    client_id: &str,
    client_secret: Option<&str>,
    refresh_token: &str,
) -> Result<Refreshed, RefreshError> {
    #[derive(Deserialize)]
    struct Reply {
        access_token: Option<String>,
        expires_in: Option<u64>,
        refresh_token: Option<String>,
        error: Option<Value>,
    }
    let form = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
    ];
    let response = token_request(
        http,
        provider,
        provider.token,
        client_id,
        client_secret,
        form,
    )
    .ok_or(RefreshError::Other("no_client_secret"))?
    .send()
    .await
    .map_err(|_| RefreshError::Other("token_unreachable"))?;
    let success = response.status().is_success();
    let reply: Reply = response
        .json()
        .await
        .map_err(|_| RefreshError::Other("token_malformed"))?;
    let dead = reply
        .error
        .as_ref()
        .and_then(Value::as_str)
        .is_some_and(|e| provider.dead.contains(&e));
    match (success, reply.access_token) {
        _ if dead => Err(RefreshError::Dead),
        (true, Some(access_token)) => Ok(Refreshed {
            access_token: Zeroizing::new(access_token),
            expires_in: reply.expires_in,
            refresh_token: reply.refresh_token.map(Zeroizing::new),
        }),
        _ => Err(RefreshError::Other("token_refused")),
    }
}

/// The provider's stable subject identifies the account; the email is only what the member
/// sees, and it can be renamed or given to another account.
pub struct Account {
    pub subject: String,
    pub email: String,
}

/// The account lookup's reply: a subject and an email, or Slack's user within its team, whose
/// subject is `<team_id>:<user_id>` since one member can be in several workspaces.
#[derive(Deserialize)]
#[serde(untagged)]
enum AccountReply {
    Email {
        #[serde(alias = "account_id", alias = "id")]
        sub: String,
        email: String,
    },
    Team {
        team_id: String,
        user_id: String,
        user: String,
        team: String,
    },
}

pub async fn account(
    http: &reqwest::Client,
    provider: &Provider,
    access_token: &str,
) -> Result<Account, &'static str> {
    let (method, url) = &provider.identity;
    let response = http
        .request(method.clone(), *url)
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|_| "account_unreachable")?;
    if !response.status().is_success() {
        return Err("account_refused");
    }
    Ok(
        match response.json().await.map_err(|_| "account_malformed")? {
            AccountReply::Email { sub, email } => Account {
                subject: sub,
                email,
            },
            AccountReply::Team {
                team_id,
                user_id,
                user,
                team,
            } => Account {
                subject: format!("{team_id}:{user_id}"),
                email: format!("{user} @ {team}"),
            },
        },
    )
}

/// Best effort: the caller revokes locally whatever the provider answers.
pub async fn revoke(
    http: &reqwest::Client,
    provider: &Provider,
    client_id: &str,
    client_secret: Option<&str>,
    refresh_token: &str,
) {
    let attempt = async {
        match provider.revoke {
            Revoke::Form(url) => {
                let _ = http
                    .post(url)
                    .form(&[("token", refresh_token)])
                    .send()
                    .await;
            }
            Revoke::Bearer(url) => {
                if let Ok(fresh) =
                    refresh(http, provider, client_id, client_secret, refresh_token).await
                {
                    let _ = http
                        .post(url)
                        .bearer_auth(fresh.access_token.as_str())
                        .send()
                        .await;
                }
            }
        }
    };
    let _ = tokio::time::timeout(Duration::from_secs(5), attempt).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_challenge_of_rfc7636_appendix_b_matches() {
        assert_eq!(
            challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn a_minted_verifier_is_43_base64url_characters_and_fresh() {
        let (a, challenge_a) = pkce().unwrap();
        let (b, _) = pkce().unwrap();
        assert_eq!(a.len(), 43);
        assert!(
            a.bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        );
        assert_eq!(challenge_a, challenge(&a));
        assert_ne!(*a, *b);
    }
}
