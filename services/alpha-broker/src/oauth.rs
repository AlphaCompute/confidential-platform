//! Every provider as one row of a fixed table: its OAuth endpoints and scopes, the reads and
//! writes the broker forwards, and the request headers a caller may set. PKCE, and the four
//! calls the broker makes: authorization URL, code exchange, account lookup, revoke. Failures
//! carry a short reason for the log, never the provider's body.

use std::time::Duration;

use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use reqwest::Method;
use reqwest::header::ACCEPT;
use serde::Deserialize;
use serde_json::{Value, json};
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
    /// A form post of a fresh access token and the client id, as a public client revokes. The
    /// refresh that minted it rotates the refresh token, and the broker keeps neither.
    AccessForm(&'static str),
    // ponytail: the provider offers no revoke, so the grant stays valid there until the member
    // removes the app in the provider's settings or it expires; the broker's row is revoked and
    // its token never used again. No upgrade exists until the provider adds a revoke.
    Local,
}

/// How the broker proves it is the tenant's client at the token endpoint.
pub enum ClientAuth {
    /// `client_id` and `client_secret` in the form.
    Form,
    /// `client_id` and `client_secret` only in HTTP Basic, never in the form.
    Basic,
    /// A public client: only `client_id`; the PKCE verifier stands in for a secret.
    Public,
}

pub struct Provider {
    pub name: &'static str,
    pub authorization: &'static str,
    pub token: &'static str,
    pub refresh: &'static str,
    pub client_auth: ClientAuth,
    pub scopes: &'static [&'static str],
    /// The authorization parameter carrying the scopes, and what joins them.
    pub scope_param: (&'static str, &'static str),
    /// The object of the exchange reply holding the tokens, when not its root.
    pub tokens_at: Option<&'static str>,
    /// The refresh reply's `error` codes that mean the member must reconnect.
    pub dead: &'static [&'static str],
    pub extra_authorize: &'static [(&'static str, &'static str)],
    pub identity: Identity,
    pub revoke: Revoke,
    pub reads: &'static [Entry],
    pub writes: &'static [Entry],
    /// Names of the request headers a caller may set.
    pub headers: &'static [&'static str],
    /// For an MCP server: the only tools a `tools/call` may name.
    pub mcp_tools: Option<&'static [&'static str]>,
}

/// How the broker names the account behind a fresh access token.
pub enum Identity {
    /// A request with the bearer and no body, whose JSON reply names the account.
    Bearer(Method, &'static str),
    /// A `tools/call` on the provider's MCP server whose text content is a JSON object: the
    /// subject joins the values at the `subject` pointers with `:`, and the name is the first
    /// value found at a `name` pointer.
    Mcp {
        url: &'static str,
        tool: &'static str,
        arguments: &'static [(&'static str, &'static str)],
        subject: &'static [&'static str],
        name: &'static [&'static str],
    },
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
    refresh: "https://oauth2.googleapis.com/token",
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
    identity: Identity::Bearer(
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
    mcp_tools: None,
};

/// `account_info.read` names the account (the lookup must carry no content type: Dropbox refuses
/// a JSON `null` there); `sharing.read` lists the shared folders a member
/// reads through. `dropbox-api-path-root` reaches a team space, and `dropbox-api-arg` carries
/// the arguments of a content-host call.
pub const DROPBOX: Provider = Provider {
    name: "dropbox",
    authorization: "https://www.dropbox.com/oauth2/authorize",
    token: "https://api.dropboxapi.com/oauth2/token",
    refresh: "https://api.dropboxapi.com/oauth2/token",
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
    identity: Identity::Bearer(
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
    mcp_tools: None,
};

/// A user token, never a bot's: the connection reads as the member, in every channel and direct
/// message the member sees. Slack refuses a refresh without the client secret even when the
/// code was exchanged with PKCE, so the secret goes on both. Every Slack failure is HTTP 200
/// with `ok: false`; the exchange's user token sits under `authed_user`.
pub const SLACK: Provider = Provider {
    name: "slack",
    authorization: "https://slack.com/oauth/v2/authorize",
    token: "https://slack.com/api/oauth.v2.access",
    refresh: "https://slack.com/api/oauth.v2.access",
    client_auth: ClientAuth::Form,
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
    identity: Identity::Bearer(Method::POST, "https://slack.com/api/auth.test"),
    revoke: Revoke::Bearer("https://slack.com/api/auth.revoke"),
    reads: &[
        get("slack.com", "/api/conversations.list"),
        get("slack.com", "/api/conversations.history"),
        get("slack.com", "/api/users.info"),
    ],
    writes: &[],
    headers: &[],
    mcp_tools: None,
};

/// `current_user:read` names the account; `file_metadata:read` and `folders:read` reach the team
/// folders a member browses before opening a file. Nothing reached writes.
pub const FIGMA: Provider = Provider {
    name: "figma",
    authorization: "https://www.figma.com/oauth",
    token: "https://api.figma.com/v1/oauth/token",
    refresh: "https://api.figma.com/v1/oauth/refresh",
    client_auth: ClientAuth::Basic,
    scopes: &[
        "current_user:read",
        "file_content:read",
        "file_metadata:read",
        "file_comments:read",
        "folders:read",
    ],
    scope_param: ("scope", " "),
    tokens_at: None,
    dead: &["invalid_grant"],
    extra_authorize: &[],
    identity: Identity::Bearer(Method::GET, "https://api.figma.com/v1/me"),
    revoke: Revoke::Local,
    reads: &[
        get("api.figma.com", "/v1/me"),
        get("api.figma.com", "/v2/teams/{id}/folders"),
        get("api.figma.com", "/v2/folders/{id}/folders"),
        get("api.figma.com", "/v2/folders/{id}/files"),
        get("api.figma.com", "/v1/files/{id}"),
        get("api.figma.com", "/v1/files/{id}/nodes"),
        get("api.figma.com", "/v1/images/{id}"),
        get("api.figma.com", "/v1/files/{id}/comments"),
    ],
    writes: &[],
    headers: &[],
    mcp_tools: None,
};

/// A tool HubSpot renames or adds is refused until this list changes.
pub const HUBSPOT_READ_TOOLS: &[&str] = &[
    "get_campaign_attribution_reports",
    "get_aeo_metrics",
    "get_conversation_channel_metadata",
    "search_intent_signals",
    "discover_hubspot_schema",
    "get_content_analytics_report",
    "get_properties",
    "get_crm_objects",
    "search_conversations",
    "get_user_details",
    "search_crm_objects",
    "get_marketing_email_analytics",
    "search_owners",
    "query_crm_data",
    "read_campaign_data",
    "get_organization_details",
    "search_properties",
    "tool_guidance",
];

/// HubSpot's MCP server offers no scope choice (the member picks a preset at consent), and its
/// scopes include writes, so the tool list is the only fence. Its introspection names no
/// account, so `get_user_details` does: the hub (`accountId`) and the user within it.
pub const HUBSPOT: Provider = Provider {
    name: "hubspot",
    authorization: "https://mcp.hubspot.com/oauth/authorize/user",
    token: "https://mcp.hubspot.com/oauth/v3/token",
    refresh: "https://mcp.hubspot.com/oauth/v3/token",
    client_auth: ClientAuth::Form,
    scopes: &[],
    scope_param: ("scope", " "),
    tokens_at: None,
    dead: &["invalid_grant"],
    extra_authorize: &[],
    identity: Identity::Mcp {
        url: "https://mcp.hubspot.com/",
        tool: "get_user_details",
        arguments: &[],
        subject: &["/accountId", "/userId"],
        name: &["/userInformation/email"],
    },
    revoke: Revoke::Local,
    reads: &[post("mcp.hubspot.com", "/")],
    writes: &[],
    headers: &[],
    mcp_tools: Some(HUBSPOT_READ_TOOLS),
};

/// A tool Notion renames or adds is refused until this list changes. `notion-ai-search` stays
/// off: it reaches the member's other apps connected to Notion. So do the custom-agent tools,
/// which start or read an agent acting in the workspace.
pub const NOTION_READ_TOOLS: &[&str] = &[
    "notion-search",
    "notion-get-tool-access",
    "notion-fetch",
    "notion-download-attachment",
    "notion-get-comments",
    "notion-get-async-task",
    "notion-get-teams",
    "notion-get-users",
    "notion-query-data-sources",
    "notion-query-multiple-data-sources",
    "notion-query-meeting-notes",
    "notion-list-private-pages",
    "notion-list-shared-pages",
    "notion-list-favorite-pages",
    "notion-list-recent-pages",
];

/// Notion's hosted MCP server, not its REST API: the REST OAuth has no PKCE, so whoever held
/// the client secret could redeem a member's code. Here Corpus is a public client registered
/// once per redirect URI, and no secret exists. Every reply is server-sent events.
pub const NOTION: Provider = Provider {
    name: "notion",
    authorization: "https://mcp.notion.com/authorize",
    token: "https://mcp.notion.com/token",
    refresh: "https://mcp.notion.com/token",
    client_auth: ClientAuth::Public,
    scopes: &["default"],
    scope_param: ("scope", " "),
    tokens_at: None,
    dead: &["invalid_grant", "invalid_token"],
    extra_authorize: &[],
    identity: Identity::Mcp {
        url: "https://mcp.notion.com/mcp",
        tool: "notion-fetch",
        arguments: &[("id", "self")],
        subject: &["/self/workspace/id", "/self/user/id"],
        name: &["/self/user/email", "/self/user/name"],
    },
    revoke: Revoke::AccessForm("https://mcp.notion.com/token"),
    reads: &[post("mcp.notion.com", "/mcp")],
    writes: &[],
    headers: &[],
    mcp_tools: Some(NOTION_READ_TOOLS),
};

pub const PROVIDERS: [&Provider; 6] = [&GOOGLE, &DROPBOX, &SLACK, &FIGMA, &HUBSPOT, &NOTION];

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
            .filter(|(_, value)| !value.is_empty())
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
    let request = http.post(url);
    let request = match provider.client_auth {
        ClientAuth::Basic => request.basic_auth(client_id, Some(client_secret?)),
        ClientAuth::Form => {
            form.extend([("client_id", client_id), ("client_secret", client_secret?)]);
            request
        }
        ClientAuth::Public => {
            form.push(("client_id", client_id));
            request
        }
    };
    Some(request.form(&form))
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
        provider.refresh,
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
#[derive(Deserialize)]
pub struct Account {
    #[serde(rename = "sub", alias = "account_id", alias = "id")]
    pub subject: String,
    pub email: String,
}

/// The account lookup's reply: a subject and an email, or Slack's user within its team, whose
/// subject is `<team_id>:<user_id>` since one member can be in several workspaces.
#[derive(Deserialize)]
#[serde(untagged)]
enum AccountReply {
    Email(Account),
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
    let request = match &provider.identity {
        Identity::Bearer(method, url) => http.request(method.clone(), *url),
        Identity::Mcp {
            url,
            tool,
            arguments,
            ..
        } => {
            let arguments: serde_json::Map<String, Value> = arguments
                .iter()
                .map(|(k, v)| ((*k).to_owned(), Value::from(*v)))
                .collect();
            let call = json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": { "name": tool, "arguments": arguments },
            });
            with_mcp_accept(http.post(*url), provider).json(&call)
        }
    };
    let response = request
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|_| "account_unreachable")?;
    if !response.status().is_success() {
        return Err("account_refused");
    }
    let Identity::Mcp { subject, name, .. } = &provider.identity else {
        return Ok(
            match response.json().await.map_err(|_| "account_malformed")? {
                AccountReply::Email(account) => account,
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
        );
    };
    let text = response.text().await.map_err(|_| "account_unreachable")?;
    let content = tool_content(&text).ok_or("account_malformed")?;
    let at = |pointer: &str| match content.pointer(pointer)? {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    };
    let subject = subject
        .iter()
        .map(|p| at(p))
        .collect::<Option<Vec<_>>>()
        .ok_or("account_malformed")?
        .join(":");
    let email = name.iter().find_map(|p| at(p)).ok_or("account_malformed")?;
    Ok(Account { subject, email })
}

/// An MCP server needs both content types in `Accept`; the broker sets it, never the caller.
pub fn with_mcp_accept(
    request: reqwest::RequestBuilder,
    provider: &Provider,
) -> reqwest::RequestBuilder {
    if provider.mcp_tools.is_some() {
        request.header(ACCEPT, "application/json, text/event-stream")
    } else {
        request
    }
}

/// The JSON object in the text content of a successful `tools/call` reply, which an MCP server
/// sends either as JSON or as server-sent events.
fn tool_content(reply: &str) -> Option<Value> {
    let result = std::iter::once(reply)
        .chain(reply.lines().filter_map(|l| l.strip_prefix("data:")))
        .filter_map(|r| serde_json::from_str::<Value>(r.trim()).ok())
        .find_map(|mut r| r.get_mut("result").map(Value::take))?;
    if result.get("isError") == Some(&Value::Bool(true)) {
        return None;
    }
    let text = result
        .get("content")?
        .as_array()?
        .iter()
        .find(|c| c.get("type").and_then(Value::as_str) == Some("text"))?
        .get("text")?
        .as_str()?;
    serde_json::from_str(text).ok()
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
            Revoke::Bearer(url) | Revoke::AccessForm(url) => {
                if let Ok(fresh) =
                    refresh(http, provider, client_id, client_secret, refresh_token).await
                {
                    let access = fresh.access_token.as_str();
                    let request = match provider.revoke {
                        Revoke::AccessForm(_) => http.post(url).form(&[
                            ("token", access),
                            ("token_type_hint", "access_token"),
                            ("client_id", client_id),
                        ]),
                        _ => http.post(url).bearer_auth(access),
                    };
                    let _ = request.send().await;
                }
            }
            Revoke::Local => {}
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
