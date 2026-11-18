//! `PUT /v1/apps/{slug}`: find or create an App. A slug is global and never reused, so an
//! answer about a slug another Organization holds says only that it is taken.

use std::sync::Arc;

use alpha_core::{APP_ZONE, is_slug};
use axum::Json;
use axum::extract::{Path, State};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{AppState, Caller, Error, audit};

pub async fn put(
    State(state): State<Arc<AppState>>,
    caller: Caller,
    Path(slug): Path<String>,
) -> Result<Json<Value>, Error> {
    let org_id = caller.org("apps:write")?;
    if !is_slug(&slug) {
        return Err(Error::Malformed(
            "the slug must match ^[a-z][a-z0-9-]{1,46}[a-z0-9]$, hold no `--` and not be reserved"
                .into(),
        ));
    }
    let mut tx = state.pool.begin().await?;
    let created: Option<Uuid> = sqlx::query_scalar(
        "insert into apps (id, org_id, slug) values ($1, $2, $3) \
         on conflict (slug) do nothing returning id",
    )
    .bind(Uuid::now_v7())
    .bind(org_id)
    .bind(&slug)
    .fetch_optional(&mut *tx)
    .await?;
    let app_id = match created {
        Some(app_id) => {
            audit(
                &mut tx,
                &caller,
                org_id,
                "app.create",
                &app_id.to_string(),
                json!({ "slug": slug }),
            )
            .await?;
            app_id
        }
        None => sqlx::query_scalar("select id from apps where slug = $1 and org_id = $2")
            .bind(&slug)
            .bind(org_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(Error::Conflict("the slug is taken"))?,
    };
    tx.commit().await?;
    let endpoint = format!("https://{slug}.{APP_ZONE}");
    Ok(Json(
        json!({ "app_id": app_id, "slug": slug, "endpoint": endpoint }),
    ))
}
