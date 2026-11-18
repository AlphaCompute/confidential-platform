//! Revisions made from a release-signed catalog entry. The control plane never picks an image:
//! the entry's signature fixes every byte but the App id and the public name. A Revision stays
//! `awaiting_approval` until a roster key of the Organization registers it at the KMS, which
//! repeats its own checks.

use std::sync::Arc;
use std::time::SystemTime;

use alpha_core::catalog::{self, CatalogFile};
use alpha_core::{CatalogKey, ComposeHash, InitData, KataPolicy};
use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{AppState, Caller, Error, audit};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewRevision {
    pub catalog: CatalogFile,
}

/// The version, catalog key, agent policy and KMS CA of the current platform document. Each call
/// fetches it, and a version below one already accepted is refused, so a stale copy cannot bring
/// back a rotated key.
async fn platform(state: &AppState) -> Result<(i64, CatalogKey, KataPolicy, String), Error> {
    // The URL may carry a read credential, so neither the caller nor the log sees the error text.
    let unavailable = |e: alpha_client::Error| {
        alpha_client::warn!("platform_document_unavailable", error = e.kind());
        Error::Unavailable("the platform document is unavailable".into())
    };
    let signed = alpha_client::platform::fetch_signed(&state.platform_document_url)
        .await
        .map_err(unavailable)?;
    let document = alpha_client::platform::verify(&signed, &state.release_keys, SystemTime::now())
        .map_err(unavailable)?;
    let version = i64::try_from(document.version)
        .map_err(|_| Error::Unavailable("platform document version overflows".into()))?;
    // Read first, so a create under the current version takes no row lock.
    let stored: Option<i64> =
        sqlx::query_scalar("select version from platform_version where one = 1")
            .fetch_optional(&state.pool)
            .await?;
    let accepted = match stored {
        Some(stored) if stored >= version => stored,
        _ => {
            sqlx::query_scalar(
                "insert into platform_version (one, version) values (1, $1) on conflict (one) \
                 do update set version = greatest(platform_version.version, excluded.version) \
                 returning version",
            )
            .bind(version)
            .fetch_one(&state.pool)
            .await?
        }
    };
    if version < accepted {
        return Err(stale(version, accepted));
    }
    match (document.catalog_key, document.kata_policy) {
        (Some(key), Some(policy)) => Ok((version, key, policy, document.kms_ca_pem)),
        _ => Err(Error::Unavailable(
            "the platform document names no catalog_key or kata_policy".into(),
        )),
    }
}

fn stale(version: i64, accepted: i64) -> Error {
    Error::Unavailable(format!(
        "platform document version {version} is below the accepted {accepted}"
    ))
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
    let (version, catalog_key, kata_policy, kms_ca_pem) = platform(&state).await?;
    let rendered = catalog::render(&new.catalog, &catalog_key, app_id.into(), &slug)
        .map_err(|e| Error::Malformed(format!("catalog {}: {e}", e.code())))?;
    InitData::parse(rendered.init_data.clone())
        .and_then(|init_data| init_data.check_policy(&kata_policy, &kms_ca_pem))
        .map_err(|e| Error::Malformed(format!("init-data: {e}")))?;

    let entry = &new.catalog.entry;
    let catalog =
        json!({ "catalog_id": entry.catalog_id, "version": entry.version, "title": entry.title });
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
    tx.commit().await?;
    Ok((status, Json(json!({ "compose_hash": rendered.revision }))))
}

pub async fn get(
    State(state): State<Arc<AppState>>,
    caller: Caller,
    Path((slug, hash)): Path<(String, String)>,
) -> Result<Json<Value>, Error> {
    let org_id = caller.org("apps:read")?;
    let hash: ComposeHash = hash.parse().map_err(|_| Error::NotFound)?;
    let (init_data, pod, shape, catalog): (String, String, Value, Value) = sqlx::query_as(
        "select r.init_data, r.pod, r.shape, r.catalog from revisions r \
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
        "init_data": init_data,
        "pod": pod,
        "shape": shape,
        "catalog": catalog,
    })))
}
