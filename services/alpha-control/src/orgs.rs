//! `POST /v1/orgs`: an Organization is created unrooted. Its id carries no authority until the
//! owner claims it at the KMS with their own session and passkey, so the creator never roots it,
//! and the response never carries a claim link.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
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

    let org_id = Uuid::now_v7();
    let mut tx = state.pool.begin().await?;
    sqlx::query("insert into organizations (id, name, owner_email) values ($1, $2, $3)")
        .bind(org_id)
        .bind(&new.name)
        .bind(&new.owner_email)
        .execute(&mut *tx)
        .await?;
    for link in &new.links {
        let inserted = sqlx::query(
            "insert into org_links (issuer, external_id, org_id) values ($1, $2, $3) \
             on conflict do nothing",
        )
        .bind(&link.issuer)
        .bind(&link.external_id)
        .bind(org_id)
        .execute(&mut *tx)
        .await?;
        if inserted.rows_affected() == 0 {
            return Err(Error::Conflict(
                "a link names another Organization or repeats",
            ));
        }
    }
    let mut created = json!({ "org_id": org_id });
    let mut details = json!({ "links": new.links });
    if let Some(request) = new.deploy_key {
        let (token, hash) = mint_token()?;
        let id = Uuid::now_v7();
        sqlx::query(
            "insert into api_keys (id, org_id, token_sha256, scopes) values ($1, $2, $3, $4)",
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
        "org.create",
        &org_id.to_string(),
        details,
    )
    .await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(created)))
}
