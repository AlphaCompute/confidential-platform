//! The routes the tenant's backend calls with its connect bearer: start a connect, finish it
//! with the provider's code, list a member's connections, disconnect one.

use std::sync::Arc;

use axum::Json;
use axum::body::Bytes;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{AppState, AuthedCorpus, Error, oauth, store};

/// The member reference is the lowercase hex SHA-256 of the tenant's user id.
fn parse_member(hex_member: &str) -> Result<[u8; 32], Error> {
    let malformed = || Error::Malformed("member must be 64 lowercase hex characters".into());
    if !hex_member
        .bytes()
        .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(malformed());
    }
    hex::decode(hex_member)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(malformed)
}

fn parse_body<T: DeserializeOwned>(body: &Bytes) -> Result<T, Error> {
    serde_json::from_slice(body).map_err(|e| Error::Malformed(format!("body: {e}")))
}

#[derive(Deserialize)]
pub struct MemberQuery {
    member: String,
}

fn query_member(query: Result<Query<MemberQuery>, QueryRejection>) -> Result<[u8; 32], Error> {
    let Query(query) = query.map_err(|_| Error::Malformed("member is required".into()))?;
    parse_member(&query.member)
}

fn exchange_failed(reason: &'static str) -> Error {
    eprintln!("alpha-broker: exchange_failed: {reason}");
    Error::ExchangeFailed
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StartBody {
    member: String,
}

pub async fn start(
    State(state): State<Arc<AppState>>,
    _: AuthedCorpus,
    Path(provider): Path<String>,
    body: Bytes,
) -> Result<Json<Value>, Error> {
    let provider = oauth::provider(&provider).ok_or(Error::NotFound)?;
    let body: StartBody = parse_body(&body)?;
    let member = parse_member(&body.member)?;
    store::purge_expired(&state.pool).await?;

    let connect_state = BASE64_URL_SAFE_NO_PAD.encode(crate::random::<32>()?);
    let (verifier, challenge) = oauth::pkce()?;
    let key = state.secrets.read().connectors_key.clone();
    let sealed = store::seal(&key, connect_state.as_bytes(), verifier.as_bytes())?;
    store::insert_pending(&state.pool, &connect_state, &member, provider.name, &sealed).await?;

    let url = oauth::authorization_url(
        provider,
        &state.config.google_client_id,
        &state.config.google_redirect_uri,
        &connect_state,
        &challenge,
    )?;
    Ok(Json(json!({ "url": url })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FinishBody {
    member: String,
    code: String,
    state: String,
}

pub async fn finish(
    State(state): State<Arc<AppState>>,
    _: AuthedCorpus,
    body: Bytes,
) -> Result<Json<Value>, Error> {
    let body: FinishBody = parse_body(&body)?;
    let member = parse_member(&body.member)?;
    let pending = store::take_pending(&state.pool, &body.state)
        .await?
        .filter(|p| p.live && p.member == member)
        .ok_or(Error::StateInvalid)?;
    let provider = oauth::provider(&pending.provider)
        .ok_or_else(|| Error::internal("a pending connect names an unknown provider"))?;

    let (key, client_secret) = {
        let secrets = state.secrets.read();
        (
            secrets.connectors_key.clone(),
            secrets.google_client_secret.clone(),
        )
    };
    let verifier = store::open(&key, body.state.as_bytes(), &pending.enc_pkce_verifier)
        .ok_or_else(|| Error::internal("a pending verifier does not open"))?;
    let verifier = std::str::from_utf8(&verifier)
        .map_err(|_| Error::internal("a pending verifier is not utf8"))?;

    let tokens = oauth::exchange(
        &state.http,
        provider,
        &state.config.google_client_id,
        &client_secret,
        &state.config.google_redirect_uri,
        &body.code,
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
    Ok(Json(
        json!({ "id": id, "provider": provider.name, "account": account }),
    ))
}

pub async fn list(
    State(state): State<Arc<AppState>>,
    _: AuthedCorpus,
    query: Result<Query<MemberQuery>, QueryRejection>,
) -> Result<Json<Value>, Error> {
    let member = query_member(query)?;
    let connections = store::list_connections(&state.pool, &member).await?;
    Ok(Json(json!({ "connections": connections })))
}

/// Local revocation always happens; the provider's revoke is best effort.
pub async fn disconnect(
    State(state): State<Arc<AppState>>,
    _: AuthedCorpus,
    Path(id): Path<String>,
    query: Result<Query<MemberQuery>, QueryRejection>,
) -> Result<StatusCode, Error> {
    let member = query_member(query)?;
    let id = Uuid::parse_str(&id).map_err(|_| Error::NotFound)?;
    let (provider, sealed) = store::revoke_connection(&state.pool, id, &member)
        .await?
        .ok_or(Error::NotFound)?;
    let key = state.secrets.read().connectors_key.clone();
    let token = store::open(&key, id.as_bytes(), &sealed);
    let token = token.as_deref().and_then(|t| std::str::from_utf8(t).ok());
    if let (Some(provider), Some(token)) = (oauth::provider(&provider), token) {
        oauth::revoke(&state.http, provider, token).await;
    }
    Ok(StatusCode::NO_CONTENT)
}
