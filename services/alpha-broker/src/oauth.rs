//! A provider's OAuth endpoints and scopes as constants, PKCE, and the four calls the broker
//! makes: authorization URL, code exchange, account lookup, revoke. Failures carry a short
//! reason for the log, never the provider's body.

use std::time::Duration;

use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::Error;

pub struct Provider {
    pub name: &'static str,
    pub authorization: &'static str,
    pub token: &'static str,
    pub account: &'static str,
    pub revoke: &'static str,
    pub scopes: &'static [&'static str],
}

/// `openid` and `email` grant no data; they let `account` read the address the member sees in
/// the Sources menu.
pub const GOOGLE: Provider = Provider {
    name: "google",
    authorization: "https://accounts.google.com/o/oauth2/v2/auth",
    token: "https://oauth2.googleapis.com/token",
    account: "https://openidconnect.googleapis.com/v1/userinfo",
    revoke: "https://oauth2.googleapis.com/revoke",
    scopes: &[
        "https://www.googleapis.com/auth/drive.readonly",
        "https://www.googleapis.com/auth/gmail.readonly",
        "https://www.googleapis.com/auth/calendar.readonly",
        "https://www.googleapis.com/auth/drive.file",
        "openid",
        "email",
    ],
};

pub fn provider(name: &str) -> Option<&'static Provider> {
    (name == GOOGLE.name).then_some(&GOOGLE)
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
    reqwest::Url::parse_with_params(
        provider.authorization,
        [
            ("client_id", client_id),
            ("redirect_uri", redirect_uri),
            ("response_type", "code"),
            ("scope", scope.as_str()),
            ("state", state),
            ("code_challenge", challenge),
            ("code_challenge_method", "S256"),
            ("access_type", "offline"),
            ("prompt", "consent"),
        ],
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

pub async fn account(
    http: &reqwest::Client,
    provider: &Provider,
    access_token: &str,
) -> Result<String, &'static str> {
    #[derive(Deserialize)]
    struct Account {
        email: String,
    }
    let response = http
        .get(provider.account)
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|_| "account_unreachable")?;
    if !response.status().is_success() {
        return Err("account_refused");
    }
    let account: Account = response.json().await.map_err(|_| "account_malformed")?;
    Ok(account.email)
}

/// Best effort: the caller revokes locally whatever the provider answers.
pub async fn revoke(http: &reqwest::Client, provider: &Provider, token: &str) {
    let _ = http
        .post(provider.revoke)
        .form(&[("token", token)])
        .timeout(Duration::from_secs(5))
        .send()
        .await;
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
