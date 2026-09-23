//! Sealing under the connectors key, and every query on `pending_connects` and `connections`.
//! Queries are checked at run time by the db tests; the broker's migrations live in their own
//! database and never meet the KMS's.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{Error, oauth};

/// `nonce(12) ‖ AES-256-GCM(key, plaintext, aad)`.
pub fn seal(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    let nonce = crate::random::<12>()?;
    let ct = Aes256Gcm::new(key.into())
        .encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::internal("aead: encryption failed"))?;
    Ok([nonce.as_slice(), &ct].concat())
}

pub fn open(key: &[u8; 32], aad: &[u8], blob: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let (nonce, ct) = blob.split_at_checked(12)?;
    Aes256Gcm::new(key.into())
        .decrypt(&Nonce::try_from(nonce).ok()?, Payload { msg: ct, aad })
        .ok()
        .map(Zeroizing::new)
}

pub async fn migrate(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    sqlx::migrate!("./migrations").run(pool).await
}

pub async fn purge_expired(pool: &PgPool) -> Result<(), Error> {
    sqlx::query("delete from pending_connects where exp < now()")
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn insert_pending(
    pool: &PgPool,
    state: &str,
    member: &[u8; 32],
    provider: &str,
    enc_pkce_verifier: &[u8],
) -> Result<(), Error> {
    sqlx::query(
        "insert into pending_connects (state, member_key_sha256, provider, enc_pkce_verifier, exp)
         values ($1, $2, $3, $4, now() + interval '10 minutes')",
    )
    .bind(state)
    .bind(member.as_slice())
    .bind(provider)
    .bind(enc_pkce_verifier)
    .execute(pool)
    .await?;
    Ok(())
}

#[derive(sqlx::FromRow)]
pub struct Pending {
    pub member: Vec<u8>,
    pub provider: String,
    pub enc_pkce_verifier: Vec<u8>,
    pub live: bool,
}

/// Consumes the state whatever it turns out to be, so a state is never used twice.
pub async fn take_pending(pool: &PgPool, state: &str) -> Result<Option<Pending>, Error> {
    Ok(sqlx::query_as(
        "delete from pending_connects where state = $1
         returning member_key_sha256 as member, provider, enc_pkce_verifier, exp > now() as live",
    )
    .bind(state)
    .fetch_optional(pool)
    .await?)
}

/// A member connecting the same account again keeps the connection's id, so a chat that
/// already holds it keeps working; the token is re-sealed, the email refreshed and the dead
/// mark cleared.
pub async fn save_connection(
    pool: &PgPool,
    key: &[u8; 32],
    member: &[u8; 32],
    provider: &str,
    account: &oauth::Account,
    refresh_token: &str,
    scopes: &str,
) -> Result<Uuid, Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("select pg_advisory_xact_lock(hashtext($1))")
        .bind(format!(
            "{}/{provider}/{}",
            hex::encode(member),
            account.subject
        ))
        .execute(&mut *tx)
        .await?;
    let existing: Option<Uuid> = sqlx::query_scalar(
        "select id from connections
         where member_key_sha256 = $1 and provider = $2 and subject = $3 and revoked_at is null
         for update",
    )
    .bind(member.as_slice())
    .bind(provider)
    .bind(&account.subject)
    .fetch_optional(&mut *tx)
    .await?;
    let (id, new) = existing.map_or((Uuid::now_v7(), true), |id| (id, false));
    let sealed = seal(key, id.as_bytes(), refresh_token.as_bytes())?;
    let statement = if new {
        "insert into connections (id, member_key_sha256, provider, subject, account, enc_refresh_token, scopes)
         values ($1, $2, $3, $4, $5, $6, $7)"
    } else {
        "update connections set account = $5, enc_refresh_token = $6, scopes = $7, dead_at = null
         where id = $1"
    };
    sqlx::query(statement)
        .bind(id)
        .bind(member.as_slice())
        .bind(provider)
        .bind(&account.subject)
        .bind(&account.email)
        .bind(sealed)
        .bind(scopes)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(id)
}

#[derive(Serialize, sqlx::FromRow)]
pub struct Connection {
    pub id: Uuid,
    pub provider: String,
    pub account: String,
    pub dead: bool,
}

pub async fn list_connections(pool: &PgPool, member: &[u8; 32]) -> Result<Vec<Connection>, Error> {
    Ok(sqlx::query_as(
        "select id, provider, account, dead_at is not null as dead from connections
         where member_key_sha256 = $1 and revoked_at is null
         order by created_at, id",
    )
    .bind(member.as_slice())
    .fetch_all(pool)
    .await?)
}

/// Revokes a live connection of `member` and hands back its provider and the sealed token it
/// held, so the caller can revoke at the provider too.
pub async fn revoke_connection(
    pool: &PgPool,
    id: Uuid,
    member: &[u8; 32],
) -> Result<Option<(String, Vec<u8>)>, Error> {
    Ok(sqlx::query_as(
        "with prior as (
           select id, provider, enc_refresh_token from connections
           where id = $1 and member_key_sha256 = $2 and revoked_at is null
           for update
         )
         update connections c set revoked_at = now(), enc_refresh_token = null
         from prior where c.id = prior.id
         returning prior.provider, prior.enc_refresh_token",
    )
    .bind(id)
    .bind(member.as_slice())
    .fetch_optional(pool)
    .await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_refuses_another_key_another_aad_and_a_short_blob() {
        let blob = seal(&[1; 32], b"aad", b"token").unwrap();
        assert_eq!(open(&[1; 32], b"aad", &blob).unwrap().as_slice(), b"token");
        assert!(open(&[2; 32], b"aad", &blob).is_none());
        assert!(open(&[1; 32], b"other", &blob).is_none());
        assert!(open(&[1; 32], b"aad", &blob[..11]).is_none());
    }

    #[test]
    fn two_seals_of_one_plaintext_differ() {
        assert_ne!(
            seal(&[1; 32], b"aad", b"token").unwrap(),
            seal(&[1; 32], b"aad", b"token").unwrap()
        );
    }
}
