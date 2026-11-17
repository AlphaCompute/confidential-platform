//! `POST /v1/orgs`: an Organization is created unrooted. Its id carries no authority until the
//! owner claims it at the KMS with their own session and passkey, so the creator never roots it,
//! and the response never carries a claim link.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::{AppState, Caller, Error, SCOPES, audit, mint_token};

const TEXT_MAX: usize = 256;

#[derive(Deserialize)]
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

#[derive(Serialize)]
pub struct DeployKey {
    pub id: Uuid,
    pub token: String,
    pub scopes: Vec<String>,
}

#[derive(Serialize)]
pub struct Created {
    pub org_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deploy_key: Option<DeployKey>,
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
    if value.contains(char::is_whitespace) || !value.trim_start_matches('@').contains('@') {
        return Err(Error::Malformed("owner_email is not an address".into()));
    }
    Ok(())
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
) -> Result<(StatusCode, Json<Created>), Error> {
    if !matches!(caller, Caller::Operator) && !caller.has("onboard") {
        return Err(Error::Forbidden);
    }
    let Json(new) = body?;
    text("name", &new.name)?;
    email(&new.owner_email)?;
    for link in &new.links {
        text("links.issuer", &link.issuer)?;
        text("links.external_id", &link.external_id)?;
    }
    if let Some(key) = &new.deploy_key {
        deploy_scopes(&key.scopes)?;
    }

    let org_id = Uuid::now_v7();
    let actor = caller.actor();
    let mut tx = state.pool.begin().await?;
    sqlx::query(
        "insert into organizations (id, name, owner_email, created_by) values ($1, $2, $3, $4)",
    )
    .bind(org_id)
    .bind(&new.name)
    .bind(&new.owner_email)
    .bind(&actor)
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
            return Err(Error::Conflict("a link names another Organization"));
        }
    }
    let deploy_key = match new.deploy_key {
        Some(request) => {
            let (token, hash) = mint_token()?;
            let id = Uuid::now_v7();
            sqlx::query(
                "insert into api_keys (id, org_id, token_sha256, scopes, label, created_by) \
                 values ($1, $2, $3, $4, 'deploy', $5)",
            )
            .bind(id)
            .bind(org_id)
            .bind(hash.as_slice())
            .bind(&request.scopes)
            .bind(&actor)
            .execute(&mut *tx)
            .await?;
            Some(DeployKey {
                id,
                token,
                scopes: request.scopes,
            })
        }
        None => None,
    };
    let links: Vec<_> = new
        .links
        .iter()
        .map(|l| json!({ "issuer": l.issuer, "external_id": l.external_id }))
        .collect();
    let details = json!({
        "links": links,
        "deploy_key": deploy_key.as_ref().map(|k| json!({ "id": k.id, "scopes": k.scopes })),
    });
    audit(
        &mut tx,
        &caller,
        Some(org_id),
        "org.create",
        &org_id.to_string(),
        details,
    )
    .await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(Created { org_id, deploy_key })))
}
