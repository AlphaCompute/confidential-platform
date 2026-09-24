//! Every provider as one row of a fixed table: its OAuth endpoints and scopes, the reads and
//! writes the broker forwards, and the request headers a caller may set. PKCE, and the four
//! calls the broker makes: authorization URL, code exchange, account lookup, revoke. Failures
//! carry a short reason for the log, never the provider's body.

use std::time::Duration;

use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use reqwest::Method;
use serde::Deserialize;
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

/// How the account behind a fresh access token is named.
pub enum Identity {
    /// OpenID userinfo: `GET` with the bearer, the account in `sub` and `email`.
    UserInfo(&'static str),
    /// `POST` with the bearer and no body or content type, the account in `account_id` and
    /// `email`. Dropbox refuses a JSON `null` body here.
    CurrentAccount(&'static str),
}

/// How a disconnect ends the grant at the provider.
pub enum Revoke {
    /// A form post of the refresh token.
    Form(&'static str),
    /// A `POST` carrying a fresh access token as bearer; the provider ends the refresh token
    /// behind it too.
    Bearer(&'static str),
}

pub struct Provider {
    pub name: &'static str,
    pub authorization: &'static str,
    pub token: &'static str,
    pub scopes: &'static [&'static str],
    pub extra_authorize: &'static [(&'static str, &'static str)],
    pub identity: Identity,
    pub revoke: Revoke,
    pub reads: &'static [Entry],
    pub writes: &'static [Entry],
    /// Lowercase names of the request headers a caller may set.
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
    scopes: &[
        "https://www.googleapis.com/auth/drive.readonly",
        "https://www.googleapis.com/auth/gmail.readonly",
        "https://www.googleapis.com/auth/calendar.readonly",
        "https://www.googleapis.com/auth/drive.file",
        "openid",
        "email",
    ],
    extra_authorize: &[("access_type", "offline"), ("prompt", "consent")],
    identity: Identity::UserInfo("https://openidconnect.googleapis.com/v1/userinfo"),
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

/// `account_info.read` names the account; `sharing.read` lists the shared folders a member
/// reads through. `dropbox-api-path-root` reaches a team space, and `dropbox-api-arg` carries
/// the arguments of a content-host call.
pub const DROPBOX: Provider = Provider {
    name: "dropbox",
    authorization: "https://www.dropbox.com/oauth2/authorize",
    token: "https://api.dropboxapi.com/oauth2/token",
    scopes: &[
        "account_info.read",
        "files.metadata.read",
        "files.content.read",
        "files.content.write",
        "sharing.read",
    ],
    extra_authorize: &[("token_access_type", "offline")],
    identity: Identity::CurrentAccount("https://api.dropboxapi.com/2/users/get_current_account"),
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

pub const PROVIDERS: [&Provider; 2] = [&GOOGLE, &DROPBOX];

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
    let scope = provider.scopes.join(" ");
    let params = [
        ("client_id", client_id),
        ("redirect_uri", redirect_uri),
        ("response_type", "code"),
        ("scope", scope.as_str()),
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

pub async fn exchange(
    http: &reqwest::Client,
    provider: &Provider,
    client_id: &str,
    client_secret: &str,
    redirect_uri: &str,
    code: &str,
    verifier: &str,
) -> Result<Tokens, &'static str> {
    let response = http
        .post(provider.token)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("code_verifier", verifier),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("redirect_uri", redirect_uri),
        ])
        .send()
        .await
        .map_err(|_| "token_unreachable")?;
    if !response.status().is_success() {
        return Err("token_refused");
    }
    let reply: TokenReply = response.json().await.map_err(|_| "token_malformed")?;
    let refresh_token = reply.refresh_token.ok_or("no_refresh_token")?;
    Ok(Tokens {
        access_token: Zeroizing::new(reply.access_token),
        refresh_token: Zeroizing::new(refresh_token),
        scope: reply.scope,
    })
}

pub struct Refreshed {
    pub access_token: Zeroizing<String>,
    pub expires_in: u64,
    /// Present only when the provider rotated the refresh token.
    pub refresh_token: Option<Zeroizing<String>>,
}

pub enum RefreshError {
    /// The provider will never accept this refresh token again; the member must reconnect.
    InvalidGrant,
    Other(&'static str),
}

pub async fn refresh(
    http: &reqwest::Client,
    provider: &Provider,
    client_id: &str,
    client_secret: &str,
    refresh_token: &str,
) -> Result<Refreshed, RefreshError> {
    #[derive(Deserialize)]
    struct Reply {
        access_token: Option<String>,
        expires_in: Option<u64>,
        refresh_token: Option<String>,
        error: Option<String>,
    }
    let response = http
        .post(provider.token)
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", client_id),
            ("client_secret", client_secret),
        ])
        .send()
        .await
        .map_err(|_| RefreshError::Other("token_unreachable"))?;
    let success = response.status().is_success();
    let reply: Reply = response
        .json()
        .await
        .map_err(|_| RefreshError::Other("token_malformed"))?;
    match (success, reply.access_token) {
        (true, Some(access_token)) => Ok(Refreshed {
            access_token: Zeroizing::new(access_token),
            expires_in: reply.expires_in.unwrap_or_default(),
            refresh_token: reply.refresh_token.map(Zeroizing::new),
        }),
        _ if reply.error.as_deref() == Some("invalid_grant") => Err(RefreshError::InvalidGrant),
        _ => Err(RefreshError::Other("token_refused")),
    }
}

/// The provider's stable subject identifies the account; the name is only what the member
/// sees (an email), and it can be renamed or given to another account.
pub struct Account {
    pub subject: String,
    pub name: String,
}

pub async fn account(
    http: &reqwest::Client,
    provider: &Provider,
    access_token: &str,
) -> Result<Account, &'static str> {
    #[derive(Deserialize)]
    struct Reply {
        #[serde(alias = "sub", alias = "account_id")]
        subject: String,
        email: String,
    }
    let request = match provider.identity {
        Identity::UserInfo(url) => http.get(url),
        Identity::CurrentAccount(url) => http.post(url),
    };
    let response = request
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|_| "account_unreachable")?;
    if !response.status().is_success() {
        return Err("account_refused");
    }
    let reply: Reply = response.json().await.map_err(|_| "account_malformed")?;
    Ok(Account {
        subject: reply.subject,
        name: reply.email,
    })
}

/// Best effort: the caller revokes locally whatever the provider answers.
pub async fn revoke(
    http: &reqwest::Client,
    provider: &Provider,
    client_id: &str,
    client_secret: &str,
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

    #[test]
    fn names_are_unique_and_header_names_lowercase() {
        for (i, a) in PROVIDERS.iter().enumerate() {
            assert!(PROVIDERS[i + 1..].iter().all(|b| b.name != a.name));
            assert!(a.headers.iter().all(|h| *h == h.to_ascii_lowercase()));
        }
    }
}
