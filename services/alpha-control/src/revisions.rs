//! Revisions made from a release-signed catalog entry. The control plane never picks an image:
//! the entry's signature fixes every byte but the App id and the public name. A Revision stays
//! `awaiting_approval` until a roster key of the Organization registers it at the KMS, which
//! repeats its own checks.

use std::sync::Arc;

use alpha_core::catalog::{self, CatalogFile};
use alpha_core::{ComposeHash, InitData};
use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{AppState, Caller, Error, audit, platform, stale, tickets};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewRevision {
    pub catalog: CatalogFile,
}

pub async fn create(
    State(state): State<Arc<AppState>>,
    caller: Caller,
    Path(slug): Path<String>,
    body: Result<Json<NewRevision>, JsonRejection>,
) -> Result<(StatusCode, Json<Value>), Error> {
    let org_id = caller.org("apps:write")?;
    let Json(new) = body?;
    let app_id: Uuid = sqlx::query_scalar("select id from apps where org_id = $1 and slug = $2")
        .bind(org_id)
        .bind(&slug)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(Error::NotFound)?;
    let (version, document) = platform(&state).await?;
    let (Some(catalog_key), Some(kata_policy)) = (document.catalog_key, document.kata_policy)
    else {
        return Err(Error::Unavailable(
            "the platform document names no catalog_key or kata_policy".into(),
        ));
    };
    let kms_ca_pem = document.kms_ca_pem;
    let rendered = catalog::render(&new.catalog, &catalog_key, app_id.into(), &slug)
        .map_err(|e| Error::Malformed(format!("catalog {}: {e}", e.code())))?;
    InitData::parse(rendered.init_data.clone())
        .and_then(|init_data| init_data.check_policy(&kata_policy, &kms_ca_pem))
        .map_err(|e| Error::Malformed(format!("init-data: {e}")))?;

    let entry = &new.catalog.entry;
    let catalog = json!({
        "catalog_id": entry.catalog_id, "version": entry.version, "title": entry.title,
        "template_sha256": entry.template_sha256,
    });
    let shape = json!(entry.resources);
    let mut tx = state.pool.begin().await?;
    // Held until commit, so a newer document accepted meanwhile cannot leave this Revision checked
    // under the key it replaced.
    let accepted: i64 =
        sqlx::query_scalar("select version from platform_version where one = 1 for share")
            .fetch_one(&mut *tx)
            .await?;
    if version < accepted {
        return Err(stale(version, accepted));
    }
    let inserted = sqlx::query(
        "insert into revisions (compose_hash, app_id, init_data, pod, shape, catalog) \
         values ($1, $2, $3, $4, $5, $6) on conflict (compose_hash) do nothing",
    )
    .bind(rendered.revision.as_bytes().as_slice())
    .bind(app_id)
    .bind(&rendered.init_data)
    .bind(&rendered.pod)
    .bind(&shape)
    .bind(&catalog)
    .execute(&mut *tx)
    .await?;
    let status = if inserted.rows_affected() == 0 {
        // The digest covers the init-data only; another entry with the same template but another
        // pod or shape is not this Revision.
        let same: bool = sqlx::query_scalar(
            "select pod = $2 and shape = $3 and catalog = $4 from revisions where compose_hash = $1",
        )
        .bind(rendered.revision.as_bytes().as_slice())
        .bind(&rendered.pod)
        .bind(&shape)
        .bind(&catalog)
        .fetch_one(&mut *tx)
        .await?;
        if !same {
            return Err(Error::Conflict(
                "the Revision is stored from another catalog entry",
            ));
        }
        StatusCode::OK
    } else {
        audit(
            &mut tx,
            &caller,
            org_id,
            "revision.create",
            &rendered.revision.to_string(),
            catalog,
        )
        .await?;
        StatusCode::CREATED
    };
    // The approval also revokes the App's newest registered Revision unless its signer keeps it.
    let predecessor: Option<Vec<u8>> = sqlx::query_scalar(
        "select compose_hash from revisions where app_id = $1 and compose_hash <> $2 \
           and registered_at is not null and revoked_at is null \
         order by registered_at desc limit 1",
    )
    .bind(app_id)
    .bind(rendered.revision.as_bytes().as_slice())
    .fetch_optional(&mut *tx)
    .await?;
    let predecessor = predecessor
        .and_then(|h| <[u8; 32]>::try_from(h).ok())
        .map(ComposeHash::from);
    let (ticket, code) = tickets::open(
        &mut tx,
        "approve",
        org_id,
        Some(&rendered.revision),
        predecessor.as_ref(),
        None,
        "30 minutes",
    )
    .await?;
    let object = rendered.revision.to_string();
    audit(
        &mut tx,
        &caller,
        org_id,
        "ticket.approve",
        &object,
        json!({}),
    )
    .await?;
    tx.commit().await?;
    let approval_url = format!("{}/approve#{ticket}", state.signer_url);
    Ok((
        status,
        Json(json!({
            "compose_hash": rendered.revision, "ticket": ticket, "code": code,
            "approval_url": approval_url,
        })),
    ))
}

pub async fn get(
    State(state): State<Arc<AppState>>,
    caller: Caller,
    Path((slug, hash)): Path<(String, String)>,
) -> Result<Json<Value>, Error> {
    let org_id = caller.org("apps:read")?;
    let hash: ComposeHash = hash.parse().map_err(|_| Error::NotFound)?;
    let (state, init_data, pod, shape, catalog): (String, String, String, Value, Value) =
        sqlx::query_as(
            "select case when r.revoked_at is not null then 'revoked' \
           when r.registered_at is not null then 'registered' else 'awaiting_approval' end, \
           r.init_data, r.pod, r.shape, r.catalog from revisions r \
         join apps a on a.id = r.app_id \
         where r.compose_hash = $1 and a.org_id = $2 and a.slug = $3",
        )
        .bind(hash.as_bytes().as_slice())
        .bind(org_id)
        .bind(&slug)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(Error::NotFound)?;
    Ok(Json(json!({
        "compose_hash": hash,
        "state": state,
        "init_data": init_data,
        "pod": pod,
        "shape": shape,
        "catalog": catalog,
    })))
}

/// `POST /v1/apps/{slug}/revisions/{hash}/revoke`: opens a `revoke` ticket. Only a roster key can
/// revoke, so the ticket carries the request to the signer page.
pub async fn revoke(
    State(state): State<Arc<AppState>>,
    caller: Caller,
    Path((slug, hash)): Path<(String, String)>,
) -> Result<(StatusCode, Json<Value>), Error> {
    let org_id = caller.org("apps:write")?;
    let hash: ComposeHash = hash.parse().map_err(|_| Error::NotFound)?;
    let mut tx = state.pool.begin().await?;
    let registered: bool = sqlx::query_scalar(
        "select r.registered_at is not null and r.revoked_at is null from revisions r \
         join apps a on a.id = r.app_id \
         where r.compose_hash = $1 and a.org_id = $2 and a.slug = $3",
    )
    .bind(hash.as_bytes().as_slice())
    .bind(org_id)
    .bind(&slug)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(Error::NotFound)?;
    if !registered {
        return Err(Error::Conflict(
            "the Revision is not registered, or already revoked",
        ));
    }
    let (ticket, code) =
        tickets::open(&mut tx, "revoke", org_id, Some(&hash), None, None, "7 days").await?;
    let object = hash.to_string();
    audit(
        &mut tx,
        &caller,
        org_id,
        "ticket.revoke",
        &object,
        json!({}),
    )
    .await?;
    tx.commit().await?;
    let url = format!("{}/revoke#{ticket}", state.signer_url);
    Ok((
        StatusCode::CREATED,
        Json(json!({ "ticket": ticket, "code": code, "url": url })),
    ))
}
