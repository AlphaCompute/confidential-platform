//! The trust-zone Postgres as an untrusted store (D4, M2(b)). A row keeps in the clear only what a
//! query needs: random ids, the compose hash, timestamps and keyed HMAC blind indexes. The rest is
//! `sealed`, AES-256-GCM under a key derived from tenant-kek-root, bound to its table and primary
//! key. The keys exist only in a serving node's [`crate::Intermediates`], so a sealed node reads and
//! writes no tenant row, and every value the KMS decides on comes out of a sealed blob. The column
//! classification and its reasons are in `docs/metadata-encryption.md`.

use alpha_core::ComposeHash;
use chrono::{DateTime, Utc};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;
use sqlx::{PgConnection, PgExecutor, PgPool};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::ApiError;
use crate::instance::RevisionRow;
use crate::keys::{Key32, KeyRow, aead_open, aead_seal};

const SALT: &[u8] = b"alphacompute-kms/metadata/v1";
const ROW_AAD: &[u8] = b"alphacompute-kms/row/v1";
/// Serializes the passes of [`seal_plaintext`] across nodes.
const SEAL_LOCK: i64 = 0x616c_7068_6173_6c64;

/// The keys over the database's contents, derived from tenant-kek-root rather than wrapped beside
/// it: they exist exactly when the intermediates do (after unseal, join or bootstrap), and neither
/// the join protocol nor an existing database needs a new intermediate.
pub struct MetadataKeys {
    row: Key32,
    index: Key32,
    audit: Key32,
}

/// A blind index: the column it stands for goes into the HMAC, so equal values in two columns
/// never match.
#[derive(Clone, Copy, Debug)]
pub enum Index {
    KeyOrg,
    KeyPublicKey,
    RevisionApp,
    RevisionOrg,
    /// `org_id ‖ name`: a Secret's name is only unique within its organization.
    SecretName,
}

impl Index {
    fn column(self) -> &'static str {
        match self {
            Self::KeyOrg => "principal_keys.org_id",
            Self::KeyPublicKey => "principal_keys.public_key",
            Self::RevisionApp => "revisions.app_id",
            Self::RevisionOrg => "revisions.org_id",
            Self::SecretName => "secrets.org_id,name",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Table {
    PrincipalKeys,
    Revisions,
    Secrets,
}

impl Table {
    pub fn name(self) -> &'static str {
        match self {
            Self::PrincipalKeys => "principal_keys",
            Self::Revisions => "revisions",
            Self::Secrets => "secrets",
        }
    }
}

fn hkdf(ikm: &[u8; 32], info: &[u8]) -> Result<Key32, ApiError> {
    let mut out = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(SALT), ikm)
        .expand(info, out.as_mut())
        .map_err(|e| ApiError::internal(format!("hkdf: {e}")))?;
    Ok(out)
}

impl MetadataKeys {
    pub fn derive(tenant_kek_root: &[u8; 32]) -> Result<Self, ApiError> {
        Ok(Self {
            row: hkdf(tenant_kek_root, b"row")?,
            index: hkdf(tenant_kek_root, b"index")?,
            audit: hkdf(tenant_kek_root, b"audit")?,
        })
    }

    /// HMAC-SHA256 over `column ‖ 0x00 ‖ value`: equality, never the value. A blind index rather
    /// than deterministic encryption, because no query ever needs the value back.
    pub fn index(&self, index: Index, value: &[u8]) -> Result<Vec<u8>, ApiError> {
        let mut mac = Hmac::<Sha256>::new_from_slice(self.index.as_slice())
            .map_err(|e| ApiError::internal(format!("hmac: {e}")))?;
        mac.update(index.column().as_bytes());
        mac.update(&[0]);
        mac.update(value);
        Ok(mac.finalize().into_bytes().to_vec())
    }

    pub fn seal<T: Serialize>(
        &self,
        table: Table,
        pk: &[u8],
        fields: &T,
    ) -> Result<Vec<u8>, ApiError> {
        let json = Zeroizing::new(
            serde_json::to_vec(fields)
                .map_err(|e| ApiError::internal(format!("{}: {e}", table.name())))?,
        );
        aead_seal(&self.row, &row_aad(table, pk), &json)
    }

    /// A blob that does not open under this key, or under this row's table and key, is a row
    /// written or moved by someone without the key: refused, never read around.
    pub fn open<T: DeserializeOwned>(
        &self,
        table: Table,
        pk: &[u8],
        sealed: &[u8],
    ) -> Result<T, ApiError> {
        let tampered = || {
            ApiError::internal(format!(
                "a {} row does not open under the metadata key",
                table.name()
            ))
        };
        let json = aead_open(&self.row, &row_aad(table, pk), sealed).ok_or_else(tampered)?;
        serde_json::from_slice(&json).map_err(|_| tampered())
    }

    pub(crate) fn audit_key(&self) -> &[u8; 32] {
        &self.audit
    }
}

fn row_aad(table: Table, pk: &[u8]) -> Vec<u8> {
    [ROW_AAD, &[0], table.name().as_bytes(), &[0], pk].concat()
}

fn unsealed(table: Table) -> ApiError {
    ApiError::internal(format!(
        "a {} row is not sealed; it is read only once sealed",
        table.name()
    ))
}

pub(crate) mod b64 {
    use base64::Engine;
    use base64::prelude::BASE64_URL_SAFE_NO_PAD;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&BASE64_URL_SAFE_NO_PAD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        BASE64_URL_SAFE_NO_PAD
            .decode(String::deserialize(d)?)
            .map_err(serde::de::Error::custom)
    }

    pub mod option {
        use super::*;

        pub fn serialize<S: Serializer>(bytes: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
            match bytes {
                Some(bytes) => super::serialize(bytes, s),
                None => s.serialize_none(),
            }
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
            Option::<String>::deserialize(d)?
                .map(|s| {
                    BASE64_URL_SAFE_NO_PAD
                        .decode(s)
                        .map_err(serde::de::Error::custom)
                })
                .transpose()
        }
    }
}

/// A `principal_keys` row's sealed fields; its `id` and `anchor_check` stay in the clear.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyRecord {
    pub org_id: Uuid,
    pub principal_id: Uuid,
    #[serde(with = "b64")]
    pub public_key: Vec<u8>,
    pub document: Value,
    pub registered_by_key: Option<Uuid>,
    pub signature: Value,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revocation_reason: Option<String>,
}

impl KeyRecord {
    fn row(self, id: Uuid, anchor_check: Option<Vec<u8>>) -> KeyRow {
        KeyRow {
            id,
            org_id: self.org_id,
            principal_id: self.principal_id,
            public_key: self.public_key,
            document: self.document,
            signature: self.signature,
            registered_by_key: self.registered_by_key,
            anchor_check,
            revoked_at: self.revoked_at,
            revocation_reason: self.revocation_reason,
        }
    }
}

impl KeyRow {
    fn record(&self) -> KeyRecord {
        KeyRecord {
            org_id: self.org_id,
            principal_id: self.principal_id,
            public_key: self.public_key.clone(),
            document: self.document.clone(),
            registered_by_key: self.registered_by_key,
            signature: self.signature.clone(),
            revoked_at: self.revoked_at,
            revocation_reason: self.revocation_reason.clone(),
        }
    }
}

/// A `secrets` row's sealed fields; its `id` and the value's own ciphertext stay as they were.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecretRecord {
    pub org_id: Uuid,
    pub name: String,
    pub app_ids: Vec<Uuid>,
    #[serde(with = "b64")]
    pub content_sha256: Vec<u8>,
    pub document: Value,
    pub signed_by_key: Uuid,
    pub signature: Value,
    pub issued_at: DateTime<Utc>,
}

pub struct SecretRow {
    pub id: Uuid,
    pub ciphertext: Vec<u8>,
    pub record: SecretRecord,
}

/// The transaction's `now()`, which a column's `default now()` would have stored.
pub async fn now(conn: &mut PgConnection) -> Result<DateTime<Utc>, ApiError> {
    Ok(sqlx::query_scalar!(r#"select now() as "now!""#)
        .fetch_one(conn)
        .await?)
}

pub async fn load_key(
    exec: impl PgExecutor<'_>,
    keys: &MetadataKeys,
    id: Uuid,
) -> Result<Option<KeyRow>, ApiError> {
    let Some(row) = sqlx::query!(
        "select anchor_check, sealed from principal_keys where id = $1",
        id
    )
    .fetch_optional(exec)
    .await?
    else {
        return Ok(None);
    };
    let sealed = row.sealed.ok_or_else(|| unsealed(Table::PrincipalKeys))?;
    let record: KeyRecord = keys.open(Table::PrincipalKeys, id.as_bytes(), &sealed)?;
    Ok(Some(record.row(id, row.anchor_check)))
}

/// The organization's root key, its record and when it was registered.
pub async fn root_key(
    exec: impl PgExecutor<'_>,
    keys: &MetadataKeys,
    org: Uuid,
) -> Result<Option<(Uuid, KeyRecord, DateTime<Utc>)>, ApiError> {
    let Some(row) = sqlx::query!(
        "select id, sealed, created_at from principal_keys
         where org_index = $1 and anchor_check is not null",
        keys.index(Index::KeyOrg, org.as_bytes())?
    )
    .fetch_optional(exec)
    .await?
    else {
        return Ok(None);
    };
    let sealed = row.sealed.ok_or_else(|| unsealed(Table::PrincipalKeys))?;
    let record = keys.open(Table::PrincipalKeys, row.id.as_bytes(), &sealed)?;
    Ok(Some((row.id, record, row.created_at)))
}

/// `None` when the public key (or, for a root key, the organization) is already registered.
pub async fn insert_key(
    conn: &mut PgConnection,
    keys: &MetadataKeys,
    id: Uuid,
    anchor_check: Option<&[u8]>,
    record: &KeyRecord,
) -> Result<Option<DateTime<Utc>>, ApiError> {
    let inserted = sqlx::query_scalar!(
        "insert into principal_keys (id, org_index, public_key_index, anchor_check, sealed)
         values ($1, $2, $3, $4, $5) returning created_at",
        id,
        keys.index(Index::KeyOrg, record.org_id.as_bytes())?,
        keys.index(Index::KeyPublicKey, &record.public_key)?,
        anchor_check,
        keys.seal(Table::PrincipalKeys, id.as_bytes(), record)?,
    )
    .fetch_one(conn)
    .await;
    match inserted {
        Ok(t) => Ok(Some(t)),
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Locks the row for the rest of the transaction, then loads it.
pub async fn lock_key(
    conn: &mut PgConnection,
    keys: &MetadataKeys,
    id: Uuid,
) -> Result<Option<KeyRow>, ApiError> {
    sqlx::query!("select id from principal_keys where id = $1 for update", id)
        .fetch_optional(&mut *conn)
        .await?;
    load_key(conn, keys, id).await
}

/// Reseals `row` revoked now for `reason`; the caller holds its lock.
pub async fn revoke_key(
    conn: &mut PgConnection,
    keys: &MetadataKeys,
    row: &KeyRow,
    reason: &str,
) -> Result<DateTime<Utc>, ApiError> {
    let at = now(conn).await?;
    let mut record = row.record();
    record.revoked_at = Some(at);
    record.revocation_reason = Some(reason.to_owned());
    sqlx::query!(
        "update principal_keys set sealed = $2 where id = $1",
        row.id,
        keys.seal(Table::PrincipalKeys, row.id.as_bytes(), &record)?,
    )
    .execute(conn)
    .await?;
    Ok(at)
}

pub async fn load_revision(
    exec: impl PgExecutor<'_>,
    keys: &MetadataKeys,
    compose_hash: ComposeHash,
) -> Result<Option<RevisionRow>, ApiError> {
    let pk = compose_hash.as_bytes().as_slice();
    let Some(sealed) =
        sqlx::query_scalar!("select sealed from revisions where compose_hash = $1", pk)
            .fetch_optional(exec)
            .await?
    else {
        return Ok(None);
    };
    let sealed = sealed.ok_or_else(|| unsealed(Table::Revisions))?;
    keys.open(Table::Revisions, pk, &sealed).map(Some)
}

pub async fn lock_revision(
    conn: &mut PgConnection,
    keys: &MetadataKeys,
    compose_hash: ComposeHash,
) -> Result<Option<RevisionRow>, ApiError> {
    sqlx::query!(
        "select compose_hash from revisions where compose_hash = $1 for update",
        compose_hash.as_bytes().as_slice()
    )
    .fetch_optional(&mut *conn)
    .await?;
    load_revision(conn, keys, compose_hash).await
}

pub async fn insert_revision(
    exec: impl PgExecutor<'_>,
    keys: &MetadataKeys,
    compose_hash: ComposeHash,
    row: &RevisionRow,
) -> Result<(), ApiError> {
    let pk = compose_hash.as_bytes().as_slice();
    sqlx::query!(
        "insert into revisions (compose_hash, app_index, org_index, sealed, created_at)
         values ($1, $2, $3, $4, $5)",
        pk,
        keys.index(Index::RevisionApp, row.app_id.as_bytes())?,
        keys.index(Index::RevisionOrg, row.org_id.as_bytes())?,
        keys.seal(Table::Revisions, pk, row)?,
        row.created_at,
    )
    .execute(exec)
    .await?;
    Ok(())
}

/// Reseals `row` revoked now; the caller holds its lock.
pub async fn revoke_revision(
    conn: &mut PgConnection,
    keys: &MetadataKeys,
    compose_hash: ComposeHash,
    row: &RevisionRow,
) -> Result<DateTime<Utc>, ApiError> {
    let at = now(conn).await?;
    let pk = compose_hash.as_bytes().as_slice();
    let revoked = RevisionRow {
        revoked_at: Some(at),
        ..row.clone()
    };
    sqlx::query!(
        "update revisions set sealed = $2 where compose_hash = $1",
        pk,
        keys.seal(Table::Revisions, pk, &revoked)?,
    )
    .execute(conn)
    .await?;
    Ok(at)
}

/// Whether any of `apps` has a Revision of another organization.
pub async fn apps_of_another_org(
    exec: impl PgExecutor<'_>,
    keys: &MetadataKeys,
    apps: &[Uuid],
    org: Uuid,
) -> Result<bool, ApiError> {
    let indexes = apps
        .iter()
        .map(|a| keys.index(Index::RevisionApp, a.as_bytes()))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(sqlx::query_scalar!(
        "select exists(select 1 from revisions where app_index = any($1) and org_index <> $2)",
        &indexes,
        keys.index(Index::RevisionOrg, org.as_bytes())?,
    )
    .fetch_one(exec)
    .await?
    .unwrap_or(false))
}

fn secret_index(keys: &MetadataKeys, org: Uuid, name: &str) -> Result<Vec<u8>, ApiError> {
    keys.index(
        Index::SecretName,
        &[org.as_bytes().as_slice(), name.as_bytes()].concat(),
    )
}

pub async fn load_secret(
    exec: impl PgExecutor<'_>,
    keys: &MetadataKeys,
    org: Uuid,
    name: &str,
) -> Result<Option<SecretRow>, ApiError> {
    let Some(row) = sqlx::query!(
        "select id, ciphertext, sealed from secrets where name_index = $1",
        secret_index(keys, org, name)?
    )
    .fetch_optional(exec)
    .await?
    else {
        return Ok(None);
    };
    let sealed = row.sealed.ok_or_else(|| unsealed(Table::Secrets))?;
    let record: SecretRecord = keys.open(Table::Secrets, row.id.as_bytes(), &sealed)?;
    if record.org_id != org || record.name != name {
        return Err(ApiError::internal(
            "a secrets row is filed under another name",
        ));
    }
    Ok(Some(SecretRow {
        id: row.id,
        ciphertext: row.ciphertext,
        record,
    }))
}

/// Inserts the Secret, or replaces the one of its organization and name (which must have `id`).
pub async fn upsert_secret(
    exec: impl PgExecutor<'_>,
    keys: &MetadataKeys,
    id: Uuid,
    ciphertext: &[u8],
    record: &SecretRecord,
) -> Result<(), ApiError> {
    sqlx::query!(
        "insert into secrets (id, name_index, ciphertext, sealed) values ($1, $2, $3, $4)
         on conflict (name_index) do update set ciphertext = $3, sealed = $4",
        id,
        secret_index(keys, record.org_id, &record.name)?,
        ciphertext,
        keys.seal(Table::Secrets, id.as_bytes(), record)?,
    )
    .execute(exec)
    .await?;
    Ok(())
}

/// What one [`seal_plaintext`] pass sealed.
#[derive(Debug, Default, PartialEq, Eq, Serialize)]
pub struct Sealed {
    pub principal_keys: u64,
    pub revisions: u64,
    pub secrets: u64,
    pub audit_rows: u64,
}

impl Sealed {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// Seals every row an earlier release (or an older node still running one) wrote in the clear,
/// clearing its plaintext columns, and moves its plaintext audit rows into the chain. A serving
/// node runs it before it serves and on every platform tick; reads refuse a row not yet sealed.
pub async fn seal_plaintext(pool: &PgPool, keys: &MetadataKeys) -> Result<Sealed, ApiError> {
    let mut tx = pool.begin().await?;
    sqlx::query!("select pg_advisory_xact_lock($1)", SEAL_LOCK)
        .execute(&mut *tx)
        .await?;
    let mut sealed = Sealed::default();

    let rows = sqlx::query!(
        r#"select id, org_id as "org_id!", principal_id as "principal_id!",
                  public_key as "public_key!", document as "document!", registered_by_key,
                  signature as "signature!", revoked_at, revocation_reason::text as revocation_reason
           from principal_keys where sealed is null for update"#
    )
    .fetch_all(&mut *tx)
    .await?;
    for r in rows {
        let record = KeyRecord {
            org_id: r.org_id,
            principal_id: r.principal_id,
            public_key: r.public_key,
            document: r.document,
            registered_by_key: r.registered_by_key,
            signature: r.signature,
            revoked_at: r.revoked_at,
            revocation_reason: r.revocation_reason,
        };
        sqlx::query!(
            "update principal_keys set org_index = $2, public_key_index = $3, sealed = $4,
               org_id = null, principal_id = null, public_key = null, document = null,
               registered_by_key = null, signature = null, revoked_at = null, revocation_reason = null
             where id = $1",
            r.id,
            keys.index(Index::KeyOrg, record.org_id.as_bytes())?,
            keys.index(Index::KeyPublicKey, &record.public_key)?,
            keys.seal(Table::PrincipalKeys, r.id.as_bytes(), &record)?,
        )
        .execute(&mut *tx)
        .await?;
        sealed.principal_keys = sealed.principal_keys.saturating_add(1);
    }

    let rows = sqlx::query!(
        r#"select compose_hash, app_id as "app_id!", org_id as "org_id!", compose as "compose!",
                  created_by_key as "created_by_key!", signature as "signature!", created_at, revoked_at
           from revisions where sealed is null for update"#
    )
    .fetch_all(&mut *tx)
    .await?;
    for r in rows {
        let row = RevisionRow {
            app_id: r.app_id,
            org_id: r.org_id,
            compose: Some(r.compose),
            init_data: None,
            created_by_key: r.created_by_key,
            signature: r.signature,
            created_at: r.created_at,
            revoked_at: r.revoked_at,
        };
        sqlx::query!(
            "update revisions set app_index = $2, org_index = $3, sealed = $4,
               app_id = null, org_id = null, compose = null, created_by_key = null,
               signature = null, revoked_at = null
             where compose_hash = $1",
            r.compose_hash,
            keys.index(Index::RevisionApp, row.app_id.as_bytes())?,
            keys.index(Index::RevisionOrg, row.org_id.as_bytes())?,
            keys.seal(Table::Revisions, &r.compose_hash, &row)?,
        )
        .execute(&mut *tx)
        .await?;
        sealed.revisions = sealed.revisions.saturating_add(1);
    }

    let rows = sqlx::query!(
        r#"select id, org_id as "org_id!", name as "name!", app_ids as "app_ids!",
                  content_sha256 as "content_sha256!", document as "document!",
                  signed_by_key as "signed_by_key!", signature as "signature!", issued_at as "issued_at!"
           from secrets where sealed is null for update"#
    )
    .fetch_all(&mut *tx)
    .await?;
    for r in rows {
        let record = SecretRecord {
            org_id: r.org_id,
            name: r.name,
            app_ids: r.app_ids,
            content_sha256: r.content_sha256,
            document: r.document,
            signed_by_key: r.signed_by_key,
            signature: r.signature,
            issued_at: r.issued_at,
        };
        sqlx::query!(
            "update secrets set name_index = $2, sealed = $3,
               org_id = null, name = null, app_ids = null, content_sha256 = null, document = null,
               signed_by_key = null, signature = null, issued_at = null
             where id = $1",
            r.id,
            secret_index(keys, record.org_id, &record.name)?,
            keys.seal(Table::Secrets, r.id.as_bytes(), &record)?,
        )
        .execute(&mut *tx)
        .await?;
        sealed.secrets = sealed.secrets.saturating_add(1);
    }
    tx.commit().await?;

    sealed.audit_rows = crate::audit::import_unlinked(pool, keys).await?;
    Ok(sealed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indexes_separate_columns_and_values() {
        let keys = MetadataKeys::derive(&[1; 32]).unwrap();
        let org = Uuid::now_v7();
        let a = keys.index(Index::KeyOrg, org.as_bytes()).unwrap();
        assert_eq!(a, keys.index(Index::KeyOrg, org.as_bytes()).unwrap());
        assert_ne!(a, keys.index(Index::RevisionOrg, org.as_bytes()).unwrap());
        assert_ne!(
            a,
            keys.index(Index::KeyOrg, Uuid::now_v7().as_bytes())
                .unwrap()
        );
        let other = MetadataKeys::derive(&[2; 32]).unwrap();
        assert_ne!(a, other.index(Index::KeyOrg, org.as_bytes()).unwrap());
    }

    #[test]
    fn a_sealed_row_opens_only_in_its_own_table_and_row() {
        let keys = MetadataKeys::derive(&[1; 32]).unwrap();
        let blob = keys.seal(Table::Secrets, b"row-1", &"value").unwrap();
        assert_eq!(
            keys.open::<String>(Table::Secrets, b"row-1", &blob)
                .unwrap(),
            "value"
        );
        for (table, pk) in [
            (Table::Secrets, &b"row-2"[..]),
            (Table::Revisions, b"row-1"),
        ] {
            let e = keys.open::<String>(table, pk, &blob).unwrap_err();
            assert!(e.message.contains("does not open"), "{}", e.message);
        }
        let other = MetadataKeys::derive(&[2; 32]).unwrap();
        assert!(
            other
                .open::<String>(Table::Secrets, b"row-1", &blob)
                .is_err()
        );
    }
}
