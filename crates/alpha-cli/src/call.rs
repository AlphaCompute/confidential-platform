//! `alpha call <route>`: one signed Control body, the path derived from the payload.

use std::time::SystemTime;

use alpha_client::{Client, PutSecretBody, sign};
use alpha_core::{ComposeHash, KeyId, context};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};

use crate::{rfc3339, sha256_prefixed};

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Route {
    RegisterRevision,
    RevokeRevision,
    PutSecret,
    RegisterKey,
    RevokeKey,
}

impl Route {
    pub fn context(self) -> &'static str {
        match self {
            Self::RegisterRevision => context::REVISION,
            Self::RevokeRevision | Self::RevokeKey => context::CONTROL,
            Self::PutSecret => context::SECRET,
            Self::RegisterKey => context::PRINCIPAL_KEY,
        }
    }
}

fn field<'a>(payload: &'a Value, name: &str) -> Result<&'a str, String> {
    payload[name]
        .as_str()
        .ok_or_else(|| format!("payload has no {name}"))
}

/// Fills `issued_at` (and, for a secret, `content_sha256`) when the payload lacks them, signs
/// under the route's context (or `ctx`) and sends. The reply is printed as received.
pub async fn run(
    client: &Client,
    route: Route,
    ctx: Option<&str>,
    signer: (KeyId, &SigningKey),
    mut payload: Value,
    value: Option<&[u8]>,
    now: SystemTime,
) -> Result<Value, String> {
    if !payload.is_object() {
        return Err("payload is not a JSON object".into());
    }
    if route != Route::RegisterRevision && payload.get("issued_at").is_none() {
        payload["issued_at"] = json!(rfc3339(now));
    }
    if route == Route::PutSecret && payload.get("content_sha256").is_none() {
        let value = value.ok_or("put-secret needs --value")?;
        payload["content_sha256"] = json!(sha256_prefixed(value));
    }
    if route != Route::PutSecret && value.is_some() {
        return Err("--value is only for put-secret".into());
    }
    let signed = sign(ctx.unwrap_or(route.context()), payload, signer.0, signer.1);
    let api = |e: alpha_client::Error| e.to_string();
    let reply = match route {
        Route::RegisterRevision => json!(client.register_revision(&signed).await.map_err(api)?),
        Route::RevokeRevision => {
            let hash: ComposeHash = field(&signed.payload, "compose_hash")?
                .parse()
                .map_err(|e| format!("compose_hash: {e}"))?;
            json!(client.revoke_revision(hash, &signed).await.map_err(api)?)
        }
        Route::PutSecret => {
            let name = field(&signed.payload, "name")?.to_owned();
            let body = PutSecretBody {
                payload: signed.payload,
                signature: signed.signature,
                value: BASE64_URL_SAFE_NO_PAD.encode(value.ok_or("put-secret needs --value")?),
            };
            json!(client.put_secret(&name, &body).await.map_err(api)?)
        }
        Route::RegisterKey => json!(client.register_key(&signed).await.map_err(api)?),
        Route::RevokeKey => {
            let id: KeyId = field(&signed.payload, "key_id")?
                .parse()
                .map_err(|e| format!("key_id: {e}"))?;
            json!(client.revoke_key(id, &signed).await.map_err(api)?)
        }
    };
    Ok(reply)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_parse_and_name_their_context() {
        use clap::ValueEnum;
        let parse = |s| Route::from_str(s, false);
        assert_eq!(parse("put-secret").unwrap().context(), context::SECRET);
        assert_eq!(parse("revoke-key").unwrap().context(), context::CONTROL);
        assert!(parse("secrets").is_err());
    }
}
