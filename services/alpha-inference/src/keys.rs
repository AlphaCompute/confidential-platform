//! Tenant API keys: `sk-alpha-<id>_<secret>`, with `<id>` the key's UUIDv7 and `<secret>` 32
//! random bytes, both in lowercase hex. A row holds only an HMAC under the App's `api-keys` key,
//! over the row's id, its organization and the secret: the database is untrusted storage, so a
//! reader learns no key and a writer can neither add a key nor move one to another organization.

use chrono::{DateTime, Utc};
use hmac::{Hmac, KeyInit, Mac};
use serde::Serialize;
use sha2::Sha256;
use sqlx::PgPool;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::Error;

pub const KEY_PURPOSE: &str = "api-keys";
const PREFIX: &str = "sk-alpha-";
const MAC_CONTEXT: &[u8] = b"alphacompute/inference/api-key/v1";
const NAME_MAX: usize = 128;

pub async fn migrate(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    sqlx::migrate!("./migrations").run(pool).await
}

fn mac(k: &[u8; 32], id: Uuid, org_id: Uuid, secret: &[u8; 32]) -> Result<Hmac<Sha256>, Error> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(k).map_err(|e| Error::internal(format!("hmac: {e}")))?;
    mac.update(MAC_CONTEXT);
    mac.update(id.as_bytes());
    mac.update(org_id.as_bytes());
    mac.update(secret);
    Ok(mac)
}

fn parse(token: &str) -> Option<(Uuid, Zeroizing<[u8; 32]>)> {
    let (id, secret) = token.strip_prefix(PREFIX)?.split_once('_')?;
    if id.len() != 32 {
        return None;
    }
    let id = Uuid::try_parse(id).ok()?;
    let mut bytes = Zeroizing::new([0u8; 32]);
    hex::decode_to_slice(secret, bytes.as_mut_slice()).ok()?;
    Some((id, bytes))
}

#[derive(Debug, Serialize)]
pub struct Created {
    pub id: Uuid,
    pub key: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct Listed {
    pub id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

pub async fn create(
    pool: &PgPool,
    k: &[u8; 32],
    org_id: Uuid,
    name: &str,
) -> Result<Created, Error> {
    if name.is_empty() || name.len() > NAME_MAX {
        return Err(Error::BadRequest(format!(
            "name must be 1 to {NAME_MAX} bytes"
        )));
    }
    let id = Uuid::now_v7();
    let mut secret = Zeroizing::new([0u8; 32]);
    getrandom::fill(secret.as_mut_slice()).map_err(|e| Error::internal(format!("rng: {e}")))?;
    let tag = mac(k, id, org_id, &secret)?.finalize().into_bytes();
    let created_at: DateTime<Utc> = sqlx::query_scalar(
        "insert into api_keys (id, org_id, name, mac) values ($1, $2, $3, $4) returning created_at",
    )
    .bind(id)
    .bind(org_id)
    .bind(name)
    .bind(tag.as_slice())
    .fetch_one(pool)
    .await?;
    Ok(Created {
        id,
        key: format!("{PREFIX}{}_{}", id.simple(), hex::encode(secret.as_slice())),
        name: name.to_owned(),
        created_at,
    })
}

pub async fn list(pool: &PgPool, org_id: Uuid) -> Result<Vec<Listed>, Error> {
    Ok(sqlx::query_as(
        "select id, name, created_at, revoked_at from api_keys where org_id = $1 order by id",
    )
    .bind(org_id)
    .fetch_all(pool)
    .await?)
}

/// True when the key exists, revoked now or before.
pub async fn revoke(pool: &PgPool, id: Uuid) -> Result<bool, Error> {
    let done =
        sqlx::query("update api_keys set revoked_at = coalesce(revoked_at, now()) where id = $1")
            .bind(id)
            .execute(pool)
            .await?;
    Ok(done.rows_affected() > 0)
}

/// The organization of a live key, or `None` for anything else: a malformed token, an unknown
/// or revoked id, or a row whose MAC does not match.
// ponytail: `revoked_at` is outside the MAC, so a database writer can revive a revoked key (but
// never create one, which needs the `api-keys` key). Upgrade: a monotonic revocation counter in a
// KMS Secret.
pub async fn authenticate(pool: &PgPool, k: &[u8; 32], token: &str) -> Result<Option<Uuid>, Error> {
    let Some((id, secret)) = parse(token) else {
        return Ok(None);
    };
    let row: Option<(Uuid, Vec<u8>)> =
        sqlx::query_as("select org_id, mac from api_keys where id = $1 and revoked_at is null")
            .bind(id)
            .fetch_optional(pool)
            .await?;
    let Some((org_id, tag)) = row else {
        return Ok(None);
    };
    Ok(mac(k, id, org_id, &secret)?
        .verify_slice(&tag)
        .is_ok()
        .then_some(org_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_takes_only_the_exact_shape() {
        let id = Uuid::now_v7();
        let good = format!("{PREFIX}{}_{}", id.simple(), "ab".repeat(32));
        let (parsed, secret) = parse(&good).unwrap();
        assert_eq!(parsed, id);
        assert_eq!(*secret, [0xab; 32]);
        for bad in [
            format!("{PREFIX}{}_{}", id.hyphenated(), "ab".repeat(32)),
            format!("{PREFIX}{}_{}", id.simple(), "ab".repeat(31)),
            format!("{PREFIX}{}{}", id.simple(), "ab".repeat(32)),
            format!("sk-other-{}_{}", id.simple(), "ab".repeat(32)),
            "right-bearer".to_owned(),
        ] {
            assert!(parse(&bad).is_none(), "{bad}");
        }
    }
}
