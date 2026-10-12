//! `alpha-kms digest` (PRD-05 draft) against a real Postgres (`DATABASE_URL`; skipped without it):
//! a database copied row for row digests the same, and one lost or changed row is named.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use alpha_kms::db_digest::{compare, digest};
use common::*;

#[tokio::test]
async fn a_copy_digests_the_same_and_a_lost_row_is_named() {
    let Some(h) = harness().await else {
        return;
    };
    let before = digest(&h.pool).await.unwrap();
    assert!(before.tables.contains_key("revisions"));
    assert!(before.tables["intermediate_keys"].rows >= 2);
    assert!(!before.migrations.is_empty());
    assert_eq!(digest(&h.pool).await.unwrap(), before);

    // The copy: a second database with the same rows, inserted in another order.
    let Some(copy) = fresh_database().await else {
        return;
    };
    for table in ["intermediate_keys", "principal_keys", "platform_document"] {
        let rows: Vec<serde_json::Value> = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "select to_jsonb(t) from {table} t order by random()"
        )))
        .fetch_all(&h.pool)
        .await
        .unwrap();
        for row in rows {
            sqlx::query(sqlx::AssertSqlSafe(format!(
                "insert into {table} select * from jsonb_populate_record(null::{table}, $1)"
            )))
            .bind(row)
            .execute(&copy)
            .await
            .unwrap();
        }
    }
    let copied = digest(&copy).await.unwrap();
    for table in ["intermediate_keys", "principal_keys", "platform_document"] {
        assert_eq!(copied.tables[table], before.tables[table], "{table}");
    }

    // One row lost in the copy is named by its table.
    sqlx::query("delete from principal_keys where ctid = (select min(ctid) from principal_keys)")
        .execute(&copy)
        .await
        .unwrap();
    let lost = compare(&before, &digest(&copy).await.unwrap());
    assert!(
        lost.iter().any(|d| d.starts_with("principal_keys: ")),
        "{lost:?}"
    );
}
