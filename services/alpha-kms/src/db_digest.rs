//! `alpha-kms digest` (PRD-05 draft): the trust-zone Postgres move's check that nothing was lost
//! (PRD-05 §6, "zero lost Secrets or Revisions (row counts and hashes verified)", migration step 4:
//! write freeze, dump/restore into the encrypted Postgres pod, repoint).
//!
//! For every table of the KMS's schema it prints the row count and a SHA-256 over the rows' text,
//! in one read-only, repeatable-read snapshot with the session's output settings fixed, so the
//! same rows give the same digest on the old and the new server. Run it on the old database at the
//! start of the write freeze and on the new one after the restore; any difference stops the
//! repoint. It reads ciphertext (#95 seals the tenant columns), so the operator who runs it needs
//! no key and learns nothing a dump would not show.
//!
//! QUESTION(PRD-05 Q69): who runs it, with which credential, and what enforces the write freeze?
//! Proposed: the operator runs it as a read-only role on each server (the prototype CVM's
//! Postgres, then the Kata pod from inside the verifier pool) during the freeze, which is both KMS
//! nodes sealed or stopped; under D10's client-cert mode (#105) a read-only role needs its own
//! access path. The tool itself enforces nothing.
//!
//! `_sqlx_migrations` is reported by its versions only: its `installed_on` and `execution_time`
//! legitimately differ when the new database was migrated before a data-only restore.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};

pub const FORMAT: &str = "alphacompute-kms-db-digest/1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Digest {
    pub format: String,
    /// The applied migration versions, in order.
    pub migrations: Vec<i64>,
    /// Table name → its rows.
    pub tables: BTreeMap<String, TableDigest>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TableDigest {
    pub rows: i64,
    /// `sha256:<hex>` over the rows' text form, sorted, newline-separated.
    pub sha256: String,
}

/// A table name this will interpolate: what the KMS's migrations create, nothing to quote.
fn plain(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

pub async fn digest(pool: &PgPool) -> Result<Digest, String> {
    let db = |e: sqlx::Error| format!("database: {e}");
    let mut tx = pool.begin().await.map_err(db)?;
    for statement in [
        "set transaction isolation level repeatable read, read only",
        "set local timezone to 'UTC'",
        "set local bytea_output to 'hex'",
        "set local datestyle to 'ISO, YMD'",
        "set local intervalstyle to 'postgres'",
        "set local extra_float_digits to 3",
    ] {
        sqlx::query(statement).execute(&mut *tx).await.map_err(db)?;
    }
    let migrations: Vec<i64> =
        sqlx::query_scalar("select version from _sqlx_migrations order by version")
            .fetch_all(&mut *tx)
            .await
            .map_err(db)?;
    let names: Vec<String> = sqlx::query_scalar(
        "select table_name::text from information_schema.tables
          where table_schema = 'public' and table_type = 'BASE TABLE'
            and table_name <> '_sqlx_migrations'
          order by table_name",
    )
    .fetch_all(&mut *tx)
    .await
    .map_err(db)?;
    let mut tables = BTreeMap::new();
    for name in names {
        if !plain(&name) {
            return Err(format!(
                "table {name:?}: not a name the KMS's schema creates"
            ));
        }
        // TODO(draft): string_agg holds the whole table in one value on the server; the audit
        // log grows without bound, so a production run wants a cursor and an incremental hash.
        let row = sqlx::query(sqlx::AssertSqlSafe(format!(
            "select count(*)::bigint as rows,
                    encode(sha256(convert_to(coalesce(
                      string_agg(t::text, E'\\n' order by t::text), ''), 'UTF8')), 'hex') as sha256
               from public.{name} t"
        )))
        .fetch_one(&mut *tx)
        .await
        .map_err(db)?;
        tables.insert(
            name,
            TableDigest {
                rows: row.try_get("rows").map_err(db)?,
                sha256: format!("sha256:{}", row.try_get::<String, _>("sha256").map_err(db)?),
            },
        );
    }
    tx.rollback().await.map_err(db)?;
    Ok(Digest {
        format: FORMAT.into(),
        migrations,
        tables,
    })
}

/// Every way `after` differs from `before`; empty means the move kept every row.
pub fn compare(before: &Digest, after: &Digest) -> Vec<String> {
    let mut out = Vec::new();
    if before.format != after.format {
        out.push(format!("format {:?} vs {:?}", before.format, after.format));
    }
    if before.migrations != after.migrations {
        out.push(format!(
            "migrations {:?} vs {:?}",
            before.migrations, after.migrations
        ));
    }
    for (name, b) in &before.tables {
        match after.tables.get(name) {
            None => out.push(format!("{name}: missing after")),
            Some(a) if a.rows != b.rows => {
                out.push(format!("{name}: {} rows before, {} after", b.rows, a.rows));
            }
            Some(a) if a.sha256 != b.sha256 => {
                out.push(format!("{name}: same row count, different content"));
            }
            Some(_) => {}
        }
    }
    for name in after.tables.keys() {
        if !before.tables.contains_key(name) {
            out.push(format!("{name}: only after"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(rows: &[(&str, i64, &str)]) -> Digest {
        Digest {
            format: FORMAT.into(),
            migrations: vec![1, 2],
            tables: rows
                .iter()
                .map(|(n, r, h)| {
                    (
                        (*n).to_owned(),
                        TableDigest {
                            rows: *r,
                            sha256: (*h).to_owned(),
                        },
                    )
                })
                .collect(),
        }
    }

    #[test]
    fn compare_names_each_difference() {
        let before = digest(&[("secrets", 3, "a"), ("revisions", 2, "b")]);
        assert!(compare(&before, &before).is_empty());
        let after = digest(&[
            ("secrets", 2, "a"),
            ("revisions", 2, "c"),
            ("extra", 0, "d"),
        ]);
        let diff = compare(&before, &after);
        assert_eq!(
            diff,
            [
                "revisions: same row count, different content",
                "secrets: 3 rows before, 2 after",
                "extra: only after"
            ]
        );
        let mut later = before.clone();
        later.migrations.push(3);
        later.tables.remove("secrets");
        assert_eq!(compare(&before, &later).len(), 2);
    }

    #[test]
    fn only_plain_table_names_are_interpolated() {
        assert!(plain("audit_log"));
        assert!(!plain("audit log"));
        assert!(!plain("Secrets"));
        assert!(!plain("x\"; drop"));
        assert!(!plain(""));
    }
}
