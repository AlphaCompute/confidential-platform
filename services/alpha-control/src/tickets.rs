//! Tickets: what the signer page reads and acts on. A ticket is a bearer and authorises nothing
//! the KMS checks: an `approve` ticket carries bodies a roster key signed, and a `claim` ticket
//! roots an Organization only together with its owner's sign-in.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use alpha_core::ComposeHash;
use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use data_encoding::BASE64URL_NOPAD;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::{AppState, Caller, Error, audit, random};

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Opens a ticket and answers it and its 8-character code.
pub async fn open(
    tx: &mut Transaction<'_, Postgres>,
    kind: &str,
    org_id: Uuid,
    compose_hash: Option<&ComposeHash>,
    predecessor: Option<&ComposeHash>,
    principal_id: Option<Uuid>,
    lifetime: &str,
) -> Result<(String, String), Error> {
    let ticket = BASE64URL_NOPAD.encode(&random::<32>()?);
    // 256 is a multiple of 32, so every character is uniform.
    let code: String = random::<8>()?
        .iter()
        .filter_map(|b| CROCKFORD.get(usize::from(b & 31)).map(|c| char::from(*c)))
        .collect();
    sqlx::query(
        "insert into tickets \
           (ticket, code, kind, org_id, compose_hash, predecessor, principal_id, expires_at) \
         values ($1, $2, $3, $4, $5, $6, $7, now() + $8::interval)",
    )
    .bind(&ticket)
    .bind(&code)
    .bind(kind)
    .bind(org_id)
    .bind(compose_hash.map(|h| h.as_bytes().to_vec()))
    .bind(predecessor.map(|h| h.as_bytes().to_vec()))
    .bind(principal_id)
    .bind(lifetime)
    .execute(&mut **tx)
    .await?;
    Ok((ticket, code))
}

/// `POST /v1/orgs/{org}/tickets`: a `claim` ticket, sent to the owner out of band.
pub async fn claim(
    State(state): State<Arc<AppState>>,
    caller: Caller,
    Path(org_id): Path<Uuid>,
) -> Result<(StatusCode, Json<Value>), Error> {
    if !matches!(caller, Caller::Operator) && caller.org("org:admin")? != org_id {
        return Err(Error::Forbidden);
    }
    let mut tx = state.pool.begin().await?;
    let rooted: bool = sqlx::query_scalar(
        "select rooted_at is not null from organizations where id = $1 and disabled_at is null",
    )
    .bind(org_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(Error::NotFound)?;
    // A rooted Organization adds a key for a new holder; an unrooted one learns its owner at the
    // sign-in.
    let holder = rooted.then(Uuid::now_v7);
    let (ticket, code) = open(&mut tx, "claim", org_id, None, None, holder, "72 hours").await?;
    // The code redeems the ticket, so the audit row names only the Organization.
    let object = org_id.to_string();
    audit(&mut tx, &caller, org_id, "ticket.claim", &object, json!({})).await?;
    tx.commit().await?;
    let url = format!("{}/claim#{ticket}", state.signer_url);
    Ok((
        StatusCode::CREATED,
        Json(json!({ "ticket": ticket, "code": code, "url": url })),
    ))
}

#[derive(sqlx::FromRow)]
struct Row {
    kind: String,
    state: String,
    expires_at: String,
    server_time: String,
    org_id: Uuid,
    org_name: String,
    owner_email: String,
    rooted: bool,
    principal_id: Option<Uuid>,
    credentials: Value,
    compose_hash: Option<Vec<u8>>,
    app_id: Option<Uuid>,
    slug: Option<String>,
    title: Option<String>,
    template_sha256: Option<String>,
    secrets: Value,
    predecessor: Option<Vec<u8>>,
    predecessor_revision: Option<String>,
}

fn hash(bytes: Option<Vec<u8>>) -> Option<ComposeHash> {
    bytes
        .and_then(|h| <[u8; 32]>::try_from(h).ok())
        .map(ComposeHash::from)
}

/// `GET /v1/tickets/{ticket}`, in the shapes the signer page reads.
pub async fn read(
    State(state): State<Arc<AppState>>,
    Path(ticket): Path<String>,
) -> Result<Json<Value>, Error> {
    let row: Row = sqlx::query_as(
        "select t.kind, \
           case when t.state = 'open' and t.expires_at <= now() then 'expired' else t.state end \
             as state, \
           to_char(t.expires_at at time zone 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') as expires_at, \
           to_char(now() at time zone 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') as server_time, \
           t.org_id, o.name as org_name, o.owner_email, o.rooted_at is not null as rooted, \
           t.principal_id, r.compose_hash, r.app_id, a.slug, \
           (select coalesce(jsonb_agg(jsonb_build_object( \
              'credential_id', c.credential_id, 'key_id', c.key_id) order by c.created_at), '[]') \
            from credentials c where c.org_id = t.org_id) as credentials, \
           r.catalog ->> 'title' as title, r.catalog ->> 'template_sha256' as template_sha256, \
           (select coalesce(jsonb_agg(jsonb_build_object('name', s.name, 'set', true) \
              order by s.name), '[]') from app_secrets s where s.app_id = r.app_id) as secrets, \
           p.compose_hash as predecessor, p.init_data as predecessor_revision \
         from tickets t join organizations o on o.id = t.org_id \
         left join revisions r on r.compose_hash = t.compose_hash \
         left join revisions p on p.compose_hash = t.predecessor \
         left join apps a on a.id = r.app_id \
         where t.ticket = $1",
    )
    .bind(&ticket)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(Error::TicketNotFound)?;
    // ponytail: only passkeys the relay carried are listed, because the KMS lists none; a key an
    // Organization adds with the CLI is missing until the KMS can answer a credential lookup.
    let mut read = json!({
        "kind": row.kind, "state": row.state, "expires_at": row.expires_at,
        "server_time": row.server_time, "org_id": row.org_id, "org_name": row.org_name,
        "credentials": row.credentials,
    });
    let extra = match row.kind.as_str() {
        "claim" if row.rooted => json!({ "rooted": true, "principal_id": row.principal_id }),
        "claim" => json!({ "rooted": false, "owner_email": row.owner_email }),
        kind => {
            let compose_hash = hash(row.compose_hash)
                .ok_or_else(|| Error::internal("ticket without a Revision"))?;
            if kind == "revoke" {
                json!({ "app_id": row.app_id, "title": row.title, "revisions": [compose_hash] })
            } else {
                let predecessor = hash(row.predecessor)
                    .map(|p| json!({ "compose_hash": p, "revision": row.predecessor_revision }));
                json!({
                    "app_id": row.app_id, "slug": row.slug, "compose_hash": compose_hash,
                    "title": row.title, "catalog_template_sha256": row.template_sha256,
                    "secrets": row.secrets, "predecessor": predecessor,
                })
            }
        }
    };
    if let (Some(read), Value::Object(extra)) = (read.as_object_mut(), extra) {
        read.extend(extra);
    }
    Ok(Json(read))
}

/// `GET /v1/tickets/by-code/{code}`: the ticket behind a code typed on the page.
pub async fn by_code(
    State(state): State<Arc<AppState>>,
    Path(code): Path<String>,
) -> Result<Json<Value>, Error> {
    if !state.code_lookups.allow() {
        return Err(Error::RateLimited);
    }
    let (kind, ticket): (String, String) =
        sqlx::query_as("select kind, ticket from tickets where code = $1")
            .bind(&code)
            .fetch_optional(&state.pool)
            .await?
            .ok_or(Error::TicketNotFound)?;
    Ok(Json(json!({ "kind": kind, "ticket": ticket })))
}

#[derive(sqlx::FromRow)]
pub(crate) struct Ticket {
    pub kind: String,
    pub org_id: Uuid,
    /// The state-changing relay ops it already drove.
    pub used: Vec<String>,
    pub session_sha256: Option<Vec<u8>>,
    pub owner: Option<Uuid>,
    pub rooted: bool,
    /// The holder whose key a claim ticket adds.
    pub principal_id: Option<Uuid>,
    pub disabled: bool,
    pub compose_hash: Option<Vec<u8>>,
    pub predecessor: Option<Vec<u8>>,
    pub app_id: Option<Uuid>,
    state: String,
    expired: bool,
}

/// The open ticket, locked for the transaction with its Organization, so steps that change the
/// Organization (sign-in, root, disable) run one after another.
pub(crate) async fn usable(
    tx: &mut Transaction<'_, Postgres>,
    ticket: &str,
) -> Result<Ticket, Error> {
    let found: Ticket = sqlx::query_as(
        "select t.kind, t.org_id, t.used, t.session_sha256, o.owner_principal_id as owner, \
           o.rooted_at is not null as rooted, t.principal_id, \
           o.disabled_at is not null as disabled, t.compose_hash, t.predecessor, r.app_id, \
           t.state, t.expires_at <= clock_timestamp() as expired \
         from tickets t join organizations o on o.id = t.org_id \
         left join revisions r on r.compose_hash = t.compose_hash \
         where t.ticket = $1 for update of t for no key update of o",
    )
    .bind(ticket)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(Error::TicketNotFound)?;
    match (found.state.as_str(), found.expired) {
        ("open", false) => Ok(found),
        ("open", true) => Err(Error::TicketExpired),
        _ => Err(Error::TicketClosed),
    }
}

pub async fn decline(
    State(state): State<Arc<AppState>>,
    Path(ticket): Path<String>,
) -> Result<Json<Value>, Error> {
    let mut tx = state.pool.begin().await?;
    let Ticket { kind, org_id, .. } = usable(&mut tx, &ticket).await?;
    let declined = sqlx::query(
        "update tickets set state = 'declined' where ticket = $1 and expires_at > clock_timestamp()",
    )
    .bind(&ticket)
    .execute(&mut *tx)
    .await?;
    if declined.rows_affected() == 0 {
        return Err(Error::TicketExpired);
    }
    sqlx::query(
        "insert into audit_log (actor, org_id, action, details) \
         values ('ticket', $1, 'ticket.decline', $2)",
    )
    .bind(org_id)
    .bind(json!({ "kind": kind }))
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(json!({ "state": "declined" })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionRequest {
    code: String,
    code_verifier: String,
    redirect_uri: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

#[derive(Deserialize)]
struct Claims {
    iss: String,
    aud: Audience,
    exp: u64,
    sub: String,
    email: Option<String>,
    #[serde(default)]
    email_verified: bool,
}

/// Redeems the code at the token endpoint. The ID token comes straight from the provider over
/// TLS, so its issuer is checked by that connection and its signature is not (OIDC Core
/// 3.1.3.7, item 6).
async fn redeem(state: &AppState, request: &SessionRequest) -> Result<Claims, Error> {
    let oidc = &state.oidc;
    let http = alpha_client::http()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| Error::internal(format!("http client: {e}")))?;
    let reply = http
        .post(&oidc.token_endpoint)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", request.code.as_str()),
            ("redirect_uri", request.redirect_uri.as_str()),
            ("client_id", oidc.client_id.as_str()),
            ("code_verifier", request.code_verifier.as_str()),
        ])
        .send()
        .await
        .map_err(|e| Error::Unavailable(format!("token endpoint: {e}")))?;
    if reply.status().is_client_error() {
        return Err(Error::SessionRefused);
    }
    if !reply.status().is_success() {
        return Err(Error::Unavailable(format!(
            "token endpoint answered {}",
            reply.status()
        )));
    }
    #[derive(Deserialize)]
    struct Tokens {
        id_token: String,
    }
    let body = alpha_client::read_capped(reply, 64 << 10)
        .await
        .map_err(|e| Error::Unavailable(format!("token endpoint reply: {e}")))?;
    let tokens: Tokens = serde_json::from_slice(&body)
        .map_err(|e| Error::Unavailable(format!("token endpoint reply: {e}")))?;
    let claims: Claims = tokens
        .id_token
        .split('.')
        .nth(1)
        .and_then(|payload| BASE64URL_NOPAD.decode(payload.as_bytes()).ok())
        .and_then(|payload| serde_json::from_slice(&payload).ok())
        .ok_or_else(|| Error::Unavailable("the ID token does not parse".into()))?;
    // No other audience is trusted, so the client must be the only one.
    let audience = match &claims.aud {
        Audience::One(aud) => aud == &oidc.client_id,
        Audience::Many(auds) => auds.as_slice() == [oidc.client_id.as_str()],
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::internal("clock before 1970"))?
        .as_secs();
    if claims.iss != oidc.issuer || !audience || claims.exp <= now || !claims.email_verified {
        return Err(Error::SessionRefused);
    }
    Ok(claims)
}

/// `POST /v1/tickets/{ticket}/session`: binds the owner's sign-in to an unrooted Organization's
/// `claim` ticket. A later sign-in replaces its session.
pub async fn session(
    State(state): State<Arc<AppState>>,
    Path(ticket): Path<String>,
    body: Result<Json<SessionRequest>, JsonRejection>,
) -> Result<Json<Value>, Error> {
    let Json(request) = body?;
    // Checked before the code is spent, and again under the lock below.
    let found = usable(&mut state.pool.begin().await?, &ticket).await?;
    if found.kind != "claim" || found.rooted || found.disabled {
        return Err(Error::SessionRefused);
    }
    let claims = redeem(&state, &request).await?;

    let mut tx = state.pool.begin().await?;
    let org_id = usable(&mut tx, &ticket).await?.org_id;
    let (owner_email, owner, rooted): (String, Option<Uuid>, bool) = sqlx::query_as(
        "select owner_email, owner_principal_id, rooted_at is not null from organizations \
         where id = $1 and disabled_at is null for no key update",
    )
    .bind(org_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(Error::SessionRefused)?;
    if rooted {
        return Err(Error::SessionRefused);
    }
    let principal_id: Uuid = sqlx::query_scalar(
        "insert into principals (id, issuer, subject) values ($1, $2, $3) \
         on conflict (issuer, subject) do update set issuer = excluded.issuer returning id",
    )
    .bind(Uuid::now_v7())
    .bind(&claims.iss)
    .bind(&claims.sub)
    .fetch_one(&mut *tx)
    .await?;
    // The first sign-in whose verified address is the owner's becomes the owner for good.
    let is_owner = match owner {
        Some(owner) => owner == principal_id,
        None => claims
            .email
            .as_deref()
            .is_some_and(|email| email.eq_ignore_ascii_case(&owner_email)),
    };
    if !is_owner {
        return Err(Error::SessionRefused);
    }
    let secret = BASE64URL_NOPAD.encode(&random::<32>()?);
    sqlx::query("update organizations set owner_principal_id = $1 where id = $2")
        .bind(principal_id)
        .bind(org_id)
        .execute(&mut *tx)
        .await?;
    // The Organization's lock may have been held past the ticket's expiry.
    let bound = sqlx::query(
        "update tickets set session_sha256 = $1 where ticket = $2 and expires_at > clock_timestamp()",
    )
    .bind(Sha256::digest(secret.as_bytes()).as_slice())
    .bind(&ticket)
    .execute(&mut *tx)
    .await?;
    if bound.rows_affected() == 0 {
        return Err(Error::TicketExpired);
    }
    sqlx::query(
        "insert into audit_log (actor, org_id, action) \
         values ($1, $2, 'ticket.session')",
    )
    .bind(format!("principal:{principal_id}"))
    .bind(org_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(
        json!({ "session": secret, "principal_id": principal_id }),
    ))
}
