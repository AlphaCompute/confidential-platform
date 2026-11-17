//! `PUT /v1/apps/{slug}`: find or create an App. A slug is global and never reused, so an
//! answer about a slug another Organization holds says only that it is taken.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use serde::Serialize;
use serde_json::json;
use uuid::Uuid;

use crate::{AppState, Caller, Error, audit};

const APP_DOMAIN: &str = "app.alphacompute.cc";
const RESERVED: [&str; 13] = [
    "api",
    "sign",
    "verify",
    "kms",
    "registry",
    "inference",
    "app",
    "apps",
    "www",
    "mail",
    "docs",
    "status",
    "admin",
];

/// `^[a-z][a-z0-9-]{1,46}[a-z0-9]$` without `--`, which Instance names use as their separator,
/// and outside the names the platform keeps for itself.
pub fn valid_slug(slug: &str) -> bool {
    let bytes = slug.as_bytes();
    (3..=48).contains(&bytes.len())
        && bytes.first().is_some_and(u8::is_ascii_lowercase)
        && bytes.last().is_some_and(|b| *b != b'-')
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
        && !slug.contains("--")
        && !RESERVED.contains(&slug)
}

#[derive(Serialize)]
pub struct App {
    pub app_id: Uuid,
    pub slug: String,
    pub endpoint: String,
}

pub async fn put(
    State(state): State<Arc<AppState>>,
    caller: Caller,
    Path(slug): Path<String>,
) -> Result<Json<App>, Error> {
    let org_id = caller.org("apps:write")?;
    if !valid_slug(&slug) {
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
    Ok(Json(App {
        app_id,
        endpoint: format!("https://{slug}.{APP_DOMAIN}"),
        slug,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_slug_follows_the_dns_label_rules_and_skips_reserved_names() {
        let longest = format!("a{}", "b".repeat(47));
        for ok in ["abc", "rafay-01h2x3", "a-1", longest.as_str()] {
            assert!(valid_slug(ok), "{ok}");
        }
        let too_long = format!("a{}", "b".repeat(48));
        for bad in [
            "ab",
            too_long.as_str(),
            "1ab",
            "-ab",
            "ab-",
            "a--b",
            "Abc",
            "a_b",
            "a.b",
            "api",
            "sign",
            "admin",
        ] {
            assert!(!valid_slug(bad), "{bad}");
        }
    }
}
