//! `POST /v1/orgs`: an Organization is created unrooted. Its id carries no authority until the
//! owner claims it at the KMS with their own session and passkey, so the creator never roots it,
//! and the response never carries a claim link.

use std::sync::Arc;

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::{AppState, Caller, Error, SCOPES, audit, mint_token};

const TEXT_MAX: usize = 256;
const LINKS_MAX: usize = 16;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Link {
    pub issuer: String,
    pub external_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeployKeyRequest {
    pub scopes: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewOrg {
    pub name: String,
    pub owner_email: String,
    #[serde(default)]
    pub links: Vec<Link>,
    pub deploy_key: Option<DeployKeyRequest>,
}

fn text(field: &str, value: &str) -> Result<(), Error> {
    if value.is_empty() || value.len() > TEXT_MAX || value.chars().any(char::is_control) {
        return Err(Error::Malformed(format!(
            "{field} must be 1 to {TEXT_MAX} bytes without control characters"
        )));
    }
    Ok(())
}

fn email(value: &str) -> Result<(), Error> {
    text("owner_email", value)?;
    match value.split_once('@') {
        Some((local, domain))
            if !local.is_empty()
                && !domain.is_empty()
                && !domain.contains('@')
                && !value.contains(char::is_whitespace) =>
        {
            Ok(())
        }
        _ => Err(Error::Malformed("owner_email is not an address".into())),
    }
}

/// An onboarding key cannot hand out another onboarding key.
fn deploy_scopes(scopes: &[String]) -> Result<(), Error> {
    if scopes.is_empty()
        || scopes
            .iter()
            .any(|s| s == "onboard" || !SCOPES.contains(&s.as_str()))
    {
        return Err(Error::Malformed(
            "deploy_key.scopes must be some of apps:read, apps:write, deploy, org:admin".into(),
        ));
    }
    Ok(())
}

const LINK_TAKEN: Error = Error::Conflict("a link names another Organization or repeats");

pub async fn create(
    State(state): State<Arc<AppState>>,
    caller: Caller,
    body: Result<Json<NewOrg>, JsonRejection>,
) -> Result<(StatusCode, Json<Value>), Error> {
    if !matches!(caller, Caller::Operator) && !caller.has("onboard") {
        return Err(Error::Forbidden);
    }
    let Json(new) = body?;
    text("name", &new.name)?;
    email(&new.owner_email)?;
    // Each link is one insert while the transaction holds a pool connection.
    if new.links.len() > LINKS_MAX {
        return Err(Error::Malformed(format!("at most {LINKS_MAX} links")));
    }
    for link in &new.links {
        text("links.issuer", &link.issuer)?;
        text("links.external_id", &link.external_id)?;
    }
    // A partner's onboarding key links only under the issuer its row names.
    if let Caller::Key(key) = &caller
        && new
            .links
            .iter()
            .any(|l| key.issuer.as_deref() != Some(l.issuer.as_str()))
    {
        return Err(Error::Forbidden);
    }
    if let Some(key) = &new.deploy_key {
        deploy_scopes(&key.scopes)?;
    }

    let mut tx = state.pool.begin().await?;
    let (status, action, org_id) = match retried(&mut tx, &caller, &new).await? {
        Some(org_id) => (StatusCode::OK, "org.retry", org_id),
        None => (
            StatusCode::CREATED,
            "org.create",
            insert(&mut tx, &caller, &new).await?,
        ),
    };
    let mut created = json!({ "org_id": org_id });
    let mut details = json!({ "links": new.links });
    if let Some(request) = new.deploy_key {
        // The token is shown once, so a retry that lost it gets a new key and the lost one dies.
        sqlx::query(
            "update api_keys set revoked_at = now() \
             where org_id = $1 and label = 'deploy' and revoked_at is null",
        )
        .bind(org_id)
        .execute(&mut *tx)
        .await?;
        let (token, hash) = mint_token()?;
        let id = Uuid::now_v7();
        sqlx::query(
            "insert into api_keys (id, org_id, token_sha256, scopes, label) \
             values ($1, $2, $3, $4, 'deploy')",
        )
        .bind(id)
        .bind(org_id)
        .bind(hash.as_slice())
        .bind(&request.scopes)
        .execute(&mut *tx)
        .await?;
        details =
            json!({ "links": new.links, "deploy_key": { "id": id, "scopes": request.scopes } });
        created = json!({ "org_id": org_id, "deploy_key": { "id": id, "token": token, "scopes": request.scopes } });
    }
    audit(
        &mut tx,
        &caller,
        org_id,
        action,
        &org_id.to_string(),
        details,
    )
    .await?;
    tx.commit().await?;
    Ok((status, Json(created)))
}

/// The Organization that an earlier create by the same caller made from the same name, owner and
/// links within the hour, so a storefront that timed out can retry. Without links nothing tells a
/// retry from a second Organization.
async fn retried(
    tx: &mut Transaction<'_, Postgres>,
    caller: &Caller,
    new: &NewOrg,
) -> Result<Option<Uuid>, Error> {
    let Some(first) = new.links.first() else {
        return Ok(None);
    };
    // A used link that matches no retry falls through to the insert, which refuses it.
    let linked: Option<Uuid> = sqlx::query_scalar(
        "select o.id from org_links l join organizations o on o.id = l.org_id \
         where l.issuer = $1 and l.external_id = $2 and o.name = $3 and o.owner_email = $4 \
           and o.created_by = $5 and o.disabled_at is null \
           and o.created_at > now() - interval '1 hour'",
    )
    .bind(&first.issuer)
    .bind(&first.external_id)
    .bind(&new.name)
    .bind(&new.owner_email)
    .bind(caller.actor())
    .fetch_optional(&mut **tx)
    .await?;
    let Some(org_id) = linked else {
        return Ok(None);
    };
    let mut stored: Vec<(String, String)> =
        sqlx::query_as("select issuer, external_id from org_links where org_id = $1")
            .bind(org_id)
            .fetch_all(&mut **tx)
            .await?;
    let mut asked: Vec<(String, String)> = new
        .links
        .iter()
        .map(|l| (l.issuer.clone(), l.external_id.clone()))
        .collect();
    stored.sort_unstable();
    asked.sort_unstable();
    if stored != asked {
        return Err(LINK_TAKEN);
    }
    Ok(Some(org_id))
}

async fn insert(
    tx: &mut Transaction<'_, Postgres>,
    caller: &Caller,
    new: &NewOrg,
) -> Result<Uuid, Error> {
    let org_id = Uuid::now_v7();
    sqlx::query(
        "insert into organizations (id, name, owner_email, created_by) values ($1, $2, $3, $4)",
    )
    .bind(org_id)
    .bind(&new.name)
    .bind(&new.owner_email)
    .bind(caller.actor())
    .execute(&mut **tx)
    .await?;
    for link in &new.links {
        let inserted = sqlx::query(
            "insert into org_links (issuer, external_id, org_id) values ($1, $2, $3) \
             on conflict do nothing",
        )
        .bind(&link.issuer)
        .bind(&link.external_id)
        .bind(org_id)
        .execute(&mut **tx)
        .await?;
        if inserted.rows_affected() == 0 {
            return Err(LINK_TAKEN);
        }
    }
    Ok(org_id)
}

/// Operator only: every key of the Organization stops working at once. Its id stays claimed.
pub async fn disable(
    State(state): State<Arc<AppState>>,
    caller: Caller,
    Path(org_id): Path<Uuid>,
) -> Result<StatusCode, Error> {
    if !matches!(caller, Caller::Operator) {
        return Err(Error::Forbidden);
    }
    let mut tx = state.pool.begin().await?;
    let disabled = sqlx::query(
        "update organizations set disabled_at = coalesce(disabled_at, now()) where id = $1",
    )
    .bind(org_id)
    .execute(&mut *tx)
    .await?;
    if disabled.rows_affected() == 0 {
        return Err(Error::NotFound);
    }
    let object = org_id.to_string();
    audit(&mut tx, &caller, org_id, "org.disable", &object, json!({})).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// The operator, or a key with `org:admin` in the same Organization.
pub async fn revoke_key(
    State(state): State<Arc<AppState>>,
    caller: Caller,
    Path((org_id, key_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, Error> {
    if !matches!(caller, Caller::Operator) && caller.org("org:admin")? != org_id {
        return Err(Error::Forbidden);
    }
    let mut tx = state.pool.begin().await?;
    let revoked = sqlx::query(
        "update api_keys set revoked_at = coalesce(revoked_at, now()) \
         where id = $1 and org_id = $2",
    )
    .bind(key_id)
    .bind(org_id)
    .execute(&mut *tx)
    .await?;
    if revoked.rows_affected() == 0 {
        return Err(Error::NotFound);
    }
    let object = key_id.to_string();
    audit(&mut tx, &caller, org_id, "key.revoke", &object, json!({})).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
