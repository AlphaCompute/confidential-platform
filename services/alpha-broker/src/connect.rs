//! The member's routes: start a connect, finish it with the provider's code, list the
//! connections, disconnect one. Each arrives sealed on a channel and carries a document signed by
//! the member's key; the member is that key and nothing else. The connect bearer only admits the
//! tenant's relay.

use std::sync::Arc;
use std::time::SystemTime;

use alpha_channel::NamedSignature;
use alpha_channel::member::{ConnectorRequest, MemberDocument, verify_request};
use alpha_core::context;
use axum::extract::{Path, State};
use axum::response::Response;
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::channel::Sealed;
use crate::{AppState, AuthedCorpus, Error, oauth, store};

pub(crate) fn parse_body<T: DeserializeOwned>(body: &[u8]) -> Result<T, Error> {
    serde_json::from_slice(body).map_err(|e| Error::Malformed(format!("body: {e}")))
}

fn exchange_failed(reason: &'static str) -> Error {
    eprintln!("alpha-broker: exchange_failed: {reason}");
    Error::ExchangeFailed
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedRequest {
    document: Value,
    member_key: String,
    signature: NamedSignature,
}

/// The key that signed a request: its SPKI and the SHA-256 rows are keyed by.
pub struct Member {
    pub sha256: [u8; 32],
    pub spki: Vec<u8>,
}

/// The signature under `context`, the document's shape and its freshness; the key that signed
/// and the document.
pub(crate) fn verify(
    context: &str,
    document: &Value,
    member_key: &str,
    signature: &NamedSignature,
) -> Result<(Member, MemberDocument), Error> {
    let (spki, document) =
        verify_request(context, document, member_key, signature, SystemTime::now()).map_err(
            |e| match e {
                alpha_channel::Error::SignatureInvalid(m) => Error::SignatureInvalid(m),
                alpha_channel::Error::RequestStale => Error::RequestStale,
                other => Error::Malformed(other.to_string()),
            },
        )?;
    let sha256 = Sha256::digest(&spki).into();
    Ok((Member { sha256, spki }, document))
}

fn verified(plaintext: &[u8]) -> Result<(Member, MemberDocument), Error> {
    let signed: SignedRequest = parse_body(plaintext)?;
    verify(
        context::CONNECTOR_REQUEST,
        &signed.document,
        &signed.member_key,
        &signed.signature,
    )
}

/// Records the document's nonce, refusing one seen before, before the request acts.
pub(crate) async fn spend(state: &AppState, document: &MemberDocument) -> Result<(), Error> {
    let nonce = BASE64_URL_SAFE_NO_PAD
        .decode(document.nonce().as_str())
        .map_err(|_| Error::Malformed("nonce is not base64url".into()))?;
    store::purge_expired(&state.pool).await?;
    if store::use_nonce(&state.pool, &nonce).await? {
        Ok(())
    } else {
        Err(Error::NonceReplayed)
    }
}

fn wrong_op(route: &str) -> Error {
    Error::Malformed(format!("the document is not a {route} request"))
}

pub async fn start(
    State(state): State<Arc<AppState>>,
    _: AuthedCorpus,
    Path(provider): Path<String>,
    sealed: Sealed,
) -> Response {
    let result = async {
        let (member, document) = verified(&sealed.plaintext)?;
        let MemberDocument::Request(ConnectorRequest::Connect {
            provider: named, ..
        }) = &document
        else {
            return Err(wrong_op("connect"));
        };
        if *named != provider {
            return Err(Error::Malformed(
                "the document names another provider than the route".into(),
            ));
        }
        let provider = oauth::provider(&provider).ok_or(Error::NotFound)?;
        spend(&state, &document).await?;

        let connect_state = BASE64_URL_SAFE_NO_PAD.encode(crate::random::<32>()?);
        let (verifier, challenge) = oauth::pkce()?;
        let key = state.secrets.read().connectors_key.clone();
        let enc = store::seal(&key, connect_state.as_bytes(), verifier.as_bytes())?;
        store::insert_pending(&state.pool, &connect_state, &member, provider.name, &enc).await?;

        let url = oauth::authorization_url(
            provider,
            state.config.client_id(provider)?,
            &state.config.redirect_uri(provider),
            &connect_state,
            &challenge,
        )?;
        Ok(json!({ "url": url }))
    }
    .await;
    sealed.reply(&state, result)
}

/// Only the key that started a connect can finish it; any other consumes the state.
pub async fn finish(
    State(state): State<Arc<AppState>>,
    _: AuthedCorpus,
    sealed: Sealed,
) -> Response {
    let result = async {
        let (member, document) = verified(&sealed.plaintext)?;
        let MemberDocument::Request(ConnectorRequest::Finish {
            state: connect_state,
            code,
            ..
        }) = &document
        else {
            return Err(wrong_op("finish"));
        };
        spend(&state, &document).await?;
        let pending = store::take_pending(&state.pool, connect_state)
            .await?
            .filter(|p| p.live && p.member == member.sha256)
            .ok_or(Error::StateInvalid)?;
        let provider = oauth::provider(&pending.provider)
            .ok_or_else(|| Error::internal("a pending connect names an unknown provider"))?;

        let key = state.secrets.read().connectors_key.clone();
        let (client_id, client_secret) = state.client(provider)?;
        let verifier = store::open(&key, connect_state.as_bytes(), &pending.enc_pkce_verifier)
            .ok_or_else(|| Error::internal("a pending verifier does not open"))?;
        let verifier = std::str::from_utf8(&verifier)
            .map_err(|_| Error::internal("a pending verifier is not utf8"))?;

        let tokens = oauth::exchange(
            &state.http,
            provider,
            client_id,
            client_secret.as_deref().map(String::as_str),
            &state.config.redirect_uri(provider),
            code,
            verifier,
        )
        .await
        .map_err(exchange_failed)?;
        let account = oauth::account(&state.http, provider, &tokens.access_token)
            .await
            .map_err(exchange_failed)?;

        let id = store::save_connection(
            &state.pool,
            &key,
            &member,
            provider.name,
            &account,
            &tokens.refresh_token,
            &tokens.scope,
        )
        .await?;
        Ok(json!({ "id": id, "provider": provider.name, "account": account.email }))
    }
    .await;
    sealed.reply(&state, result)
}

pub async fn list(State(state): State<Arc<AppState>>, _: AuthedCorpus, sealed: Sealed) -> Response {
    let result = async {
        let (member, document) = verified(&sealed.plaintext)?;
        let MemberDocument::Request(ConnectorRequest::List { .. }) = &document else {
            return Err(wrong_op("list"));
        };
        spend(&state, &document).await?;
        let connections = store::list_connections(&state.pool, &member.sha256).await?;
        Ok(json!({ "connections": connections }))
    }
    .await;
    sealed.reply(&state, result)
}

/// Local revocation always happens; the provider's revoke is best effort.
pub async fn disconnect(
    State(state): State<Arc<AppState>>,
    _: AuthedCorpus,
    Path(id): Path<String>,
    sealed: Sealed,
) -> Response {
    let result = async {
        let (member, document) = verified(&sealed.plaintext)?;
        let MemberDocument::Request(ConnectorRequest::Disconnect { connection_id, .. }) = &document
        else {
            return Err(wrong_op("disconnect"));
        };
        let id = Uuid::parse_str(&id).map_err(|_| Error::NotFound)?;
        if *connection_id != id {
            return Err(Error::Malformed(
                "the document names another connection than the route".into(),
            ));
        }
        spend(&state, &document).await?;
        let (provider, enc, shared) = store::revoke_connection(&state.pool, id, &member.sha256)
            .await?
            .ok_or(Error::NotFound)?;
        state.tokens.lock().remove(&id);
        if shared {
            return Ok(json!({}));
        }
        let key = state.secrets.read().connectors_key.clone();
        let token = store::open(&key, id.as_bytes(), &enc);
        let token = token.as_deref().and_then(|t| std::str::from_utf8(t).ok());
        if let (Some(provider), Some(token)) = (oauth::provider(&provider), token)
            && let Ok((client_id, client_secret)) = state.client(provider)
        {
            let client_secret = client_secret.as_deref().map(String::as_str);
            oauth::revoke(&state.http, provider, client_id, client_secret, token).await;
        }
        Ok(json!({}))
    }
    .await;
    sealed.reply(&state, result)
}
