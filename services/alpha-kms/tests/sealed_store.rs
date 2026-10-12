//! D4 / M2(b): the trust-zone Postgres as an untrusted store. Over a real database: what the raw
//! tables hold after every route has run, that the routes still find their rows, that rows an
//! earlier release wrote in the clear are sealed when a node unseals, and that the audit chain
//! catches a changed, moved, inserted or removed row.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use alpha_core::{AppId, context};
use alpha_crypto::INFO_UNSEAL_SHARE;
use alpha_kms::audit::{self, ChainError, Checkpoint, Form};
use alpha_kms::rfc3339;
use common::*;
use ed25519_dalek::pkcs8::EncodePublicKey;
use reqwest::StatusCode;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const NAME: &str = "sealed-store-name";
const VALUE: &[u8] = b"sealed-store-value";

/// Everything the tables hold, as text: every column of every row.
async fn dump(h: &Harness, table: &str) -> String {
    sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "select coalesce(string_agg(to_jsonb(t)::text, ' '), '') from {table} t"
    )))
    .fetch_one(&h.pool)
    .await
    .unwrap()
}

async fn count(h: &Harness, sql: &str) -> i64 {
    sqlx::query_scalar(sqlx::AssertSqlSafe(sql.to_owned()))
        .fetch_one(&h.pool)
        .await
        .unwrap()
}

/// No tenant value in any column of the four tables, and no plaintext column filled.
async fn assert_no_plaintext(h: &Harness, markers: &[String]) {
    for table in ["principal_keys", "revisions", "secrets", "audit_log"] {
        let text = dump(h, table).await;
        for marker in markers {
            assert!(!text.contains(marker.as_str()), "{table} holds {marker}");
        }
    }
    for (table, columns) in [
        (
            "principal_keys",
            "org_id, principal_id, public_key, document, registered_by_key, signature, revoked_at, revocation_reason",
        ),
        (
            "revisions",
            "app_id, org_id, compose, created_by_key, signature, revoked_at",
        ),
        (
            "secrets",
            "org_id, name, app_ids, content_sha256, document, signed_by_key, signature, issued_at",
        ),
    ] {
        let any = columns
            .split(", ")
            .map(|c| format!("{c} is not null"))
            .collect::<Vec<_>>()
            .join(" or ");
        let filled = count(
            h,
            &format!("select count(*) from {table} where sealed is null or {any}"),
        )
        .await;
        assert_eq!(filled, 0, "{table} has a plaintext row");
    }
    let tenant_rows = count(
        h,
        "select count(*) from audit_log where sealed is null and action <> 'audit.imported'
           and (actor_kind <> 'node' or org_id is not null or object is not null
                or evidence_sha256 is not null)",
    )
    .await;
    assert_eq!(
        tenant_rows, 0,
        "an audit row about a tenant is in the clear"
    );
}

fn uuid_forms(id: Uuid) -> [String; 2] {
    [id.to_string(), id.simple().to_string()]
}

/// The tenant values a run of every route leaves behind, in each form a column could show them.
fn markers(h: &Harness, app: AppId, admin_spki: &[u8]) -> Vec<String> {
    let mut markers = vec![
        NAME.to_owned(),
        String::from_utf8(VALUE.to_vec()).unwrap(),
        hex::encode(Sha256::digest(VALUE)),
        hex::encode(admin_spki),
        b64(admin_spki),
        "root key".to_owned(),
        "key 61".to_owned(),
    ];
    markers.extend(uuid_forms(h.org.into()));
    markers.extend(uuid_forms(app.into()));
    markers
}

#[tokio::test]
async fn the_database_holds_no_tenant_plaintext_and_every_route_still_finds_its_rows() {
    let Some(h) = harness().await else {
        return;
    };
    let admin = h.register_key(&h.root, 61).await;
    let spare = h.register_key(&h.root, 62).await;
    let app = AppId::mint();
    let hash = h.insert_capture_revision(app, &admin).await;
    let (status, reply) = h.put_secret(NAME, &[app], VALUE, h.now(), &admin).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let (payload, _) = canonical_compose();
    let (status, reply) = h
        .post(
            "/v1/revisions",
            h.signed(context::REVISION, payload.clone(), &admin),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let revoke = json!({ "key_id": spare.0, "reason": "retired", "issued_at": rfc3339(h.now()) });
    let (status, reply) = h
        .post(
            &format!("/v1/keys/{}/revoke", spare.0),
            h.signed(context::CONTROL, revoke, &h.root),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{reply}");

    let instance = h.instance_client().await;
    let secret_url = format!("{}/v1/secrets/{NAME}", h.url);
    let (status, reply) = send(instance.get(&secret_url)).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["value"], json!(b64(VALUE)));
    let (status, reply) = derive(&h, &instance, json!({ "purpose": "connectors" })).await;
    assert_eq!(status, StatusCode::OK, "{reply}");

    let admin_spki = admin.1.verifying_key().to_public_key_der().unwrap();
    let mut markers = markers(&h, app, admin_spki.as_bytes());
    markers.push(payload["app_id"].as_str().unwrap().to_owned());
    assert_no_plaintext(&h, &markers).await;

    // The queries behind each route run on blind indexes: a second put replaces the Secret, the
    // root claim is idempotent, another organization's App is refused, and a revocation sticks.
    let later = h.now() + std::time::Duration::from_secs(5);
    let (status, reply) = h.put_secret(NAME, &[app], b"newer", later, &admin).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(h.secrets_named(NAME).await, 1);
    let (status, reply) = send(instance.get(&secret_url)).await;
    assert_eq!(
        (status, reply["value"].clone()),
        (StatusCode::OK, json!(b64(b"newer")))
    );
    let (status, reply) = h
        .post("/v1/keys", root_key_registration(h.org, &h.root.1, h.now()))
        .await;
    assert_eq!(
        (status, reply["id"].clone()),
        (StatusCode::OK, json!(h.root.0))
    );
    let (status, reply) = h
        .post(
            "/v1/keys",
            root_key_registration(alpha_core::OrgId::mint(), &h.root.1, h.now()),
        )
        .await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::CONFLICT, "already_exists")
    );
    let other_admin = {
        let other = alpha_core::OrgId::mint();
        let key = ed25519_dalek::SigningKey::from_bytes(&[63u8; 32]);
        let (status, reply) = h
            .post("/v1/keys", root_key_registration(other, &key, h.now()))
            .await;
        assert_eq!(status, StatusCode::OK, "{reply}");
        (reply["id"].as_str().unwrap().parse().unwrap(), key)
    };
    let (status, reply) = h
        .put_secret("theirs", &[app], b"x", h.now(), &other_admin)
        .await;
    assert_eq!((status, code(&reply)), (StatusCode::NOT_FOUND, "not_found"));
    let revoke = json!({ "compose_hash": hash, "issued_at": rfc3339(h.now()) });
    let (status, reply) = h
        .post(
            &format!("/v1/revisions/{hash}/revoke"),
            h.signed(context::CONTROL, revoke, &admin),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let (status, reply) = h.attest(KEYED).await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::CONFLICT, "revision_revoked")
    );
    assert_no_plaintext(&h, &markers).await;
}

#[tokio::test]
async fn a_row_changed_without_the_key_or_moved_to_another_row_is_refused() {
    let Some(h) = harness().await else {
        return;
    };
    let admin = h.register_key(&h.root, 64).await;
    let app = AppId::mint();
    let hash = h.insert_capture_revision(app, &admin).await;
    let other = h
        .insert_revision(app, r#"{"other":true}"#.into(), &admin)
        .await;
    let (status, reply) = h.attest(KEYED).await;
    assert_eq!(status, StatusCode::OK, "{reply}");

    let flip = "update revisions set sealed = set_byte(sealed, 20, get_byte(sealed, 20) # 1)
                where compose_hash = $1";
    let flip = || {
        sqlx::query(flip)
            .bind(hash.as_bytes().as_slice())
            .execute(&h.pool)
    };
    flip().await.unwrap();
    let (status, reply) = h.attest(KEYED).await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::INTERNAL_SERVER_ERROR, "internal")
    );
    assert!(
        reply["error"]["message"]
            .as_str()
            .unwrap()
            .contains("does not open under the metadata key"),
        "{reply}"
    );
    flip().await.unwrap();
    let (status, reply) = h.attest(KEYED).await;
    assert_eq!(status, StatusCode::OK, "flipped back: {reply}");

    // The other Revision's blob under this Revision's key: authentic, but not this row's.
    sqlx::query(
        "update revisions set sealed = (select sealed from revisions where compose_hash = $2)
         where compose_hash = $1",
    )
    .bind(hash.as_bytes().as_slice())
    .bind(other.as_bytes().as_slice())
    .execute(&h.pool)
    .await
    .unwrap();
    let (status, reply) = h.attest(KEYED).await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::INTERNAL_SERVER_ERROR, "internal")
    );

    // A row in the clear, as an earlier release wrote it, is not read until a node seals it.
    sqlx::query(
        "update revisions set sealed = null, app_index = null, org_index = null,
           app_id = $2, org_id = $3, compose = '{}', created_by_key = $4, signature = '{}'
         where compose_hash = $1",
    )
    .bind(hash.as_bytes().as_slice())
    .bind(Uuid::from(app))
    .bind(Uuid::from(h.org))
    .bind(Uuid::from(admin.0))
    .execute(&h.pool)
    .await
    .unwrap();
    let (status, reply) = h.attest(KEYED).await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::INTERNAL_SERVER_ERROR, "internal")
    );
    assert!(
        reply["error"]["message"]
            .as_str()
            .unwrap()
            .contains("not sealed"),
        "{reply}"
    );
}

#[tokio::test]
async fn without_keys_a_node_writes_only_node_facts_in_the_clear() {
    let Some(h) = harness().await else {
        return;
    };
    let tenant = audit::Audit {
        actor_kind: "principal",
        actor: "someone",
        action: "secret.put",
        org_id: Some(h.org.into()),
        object: Some("secret:x".into()),
        outcome: "ok",
        details: json!({}),
        evidence_sha256: None,
    };
    let e = tenant.insert_now(&h.pool, None).await.unwrap_err();
    assert_eq!(e.code, "sealed");
    let fact = audit::node(
        "node.join.request",
        "ok",
        json!({ "endpoint": "https://a" }),
    );
    let seq = fact.insert_now(&h.pool, None).await.unwrap();
    let row = h
        .audit_rows()
        .await
        .into_iter()
        .find(|r| r.seq == seq)
        .unwrap();
    assert!(!row.sealed);
    assert_eq!(row.entry.details, json!({ "endpoint": "https://a" }));
}

/// Where [`audit::verify`] finds the chain broken, or `None`.
async fn broken_at(h: &Harness) -> Option<i64> {
    match audit::verify(&h.pool, &h.metadata(), Checkpoint::default(), |_| {}).await {
        Ok(_) => None,
        Err(ChainError::Broken { seq, .. }) => Some(seq),
        Err(e) => panic!("{e}"),
    }
}

async fn exec(h: &Harness, sql: &str, seqs: &[i64]) {
    let mut q = sqlx::query(sqlx::AssertSqlSafe(sql.to_owned()));
    for seq in seqs {
        q = q.bind(seq);
    }
    q.execute(&h.pool).await.unwrap();
}

#[tokio::test]
async fn the_audit_chain_catches_a_changed_moved_inserted_or_removed_row() {
    let Some(h) = harness().await else {
        return;
    };
    let admin = h.register_key(&h.root, 65).await;
    let app = AppId::mint();
    h.insert_capture_revision(app, &admin).await;
    for seconds in 0..3 {
        let at = h.now() + std::time::Duration::from_secs(seconds);
        let (status, reply) = h.put_secret("chained", &[app], b"v", at, &admin).await;
        assert_eq!(status, StatusCode::OK, "{reply}");
    }
    let (status, reply) = h.attest(KEYED).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(broken_at(&h).await, None);

    let rows = h.audit_rows().await;
    let plain = rows.iter().find(|r| !r.sealed).unwrap().seq;
    let sealed: Vec<i64> = rows.iter().filter(|r| r.sealed).map(|r| r.seq).collect();
    assert!(sealed.len() >= 5 && plain < sealed[0], "{rows:?}");
    let (a, b) = (sealed[1], sealed[3]);
    let after = |seq: i64| rows.iter().find(|r| r.seq > seq).unwrap().seq;

    let flip = "update audit_log set sealed = set_byte(sealed, 30, get_byte(sealed, 30) # 1)
                where seq = $1";
    exec(&h, flip, &[a]).await;
    assert_eq!(broken_at(&h).await, Some(a), "a sealed byte flipped");
    exec(&h, flip, &[a]).await;
    assert_eq!(broken_at(&h).await, None);

    let swap = "update audit_log x set sealed = y.sealed from audit_log y
                where (x.seq, y.seq) in (($1, $2), ($2, $1))";
    exec(&h, swap, &[a, b]).await;
    assert_eq!(broken_at(&h).await, Some(a), "two sealed rows swapped");
    exec(&h, swap, &[a, b]).await;

    let shift = "update audit_log set ts = ts + $2 * interval '1 microsecond' where seq = $1";
    exec(&h, shift, &[a, 1]).await;
    assert_eq!(broken_at(&h).await, Some(a), "a timestamp moved");
    exec(&h, shift, &[a, -1]).await;
    assert_eq!(broken_at(&h).await, None);

    // A plaintext node fact edited, then its link recomputed as anyone can: the next sealed row,
    // whose associated data is that link, no longer opens.
    let (ts, details, link): (chrono::DateTime<chrono::Utc>, Value, Vec<u8>) =
        sqlx::query_as("select ts, details, link from audit_log where seq = $1")
            .bind(plain)
            .fetch_one(&h.pool)
            .await
            .unwrap();
    let prev: Option<Vec<u8>> = sqlx::query_scalar(
        "select link from audit_log where seq < $1 and link is not null order by seq desc limit 1",
    )
    .bind(plain)
    .fetch_optional(&h.pool)
    .await
    .unwrap();
    let mut forged = rows.iter().find(|r| r.seq == plain).unwrap().entry.clone();
    forged.details = json!({ "version": 999, "previous": null });
    let forged_link = audit::link(
        &prev.unwrap_or(vec![0; 32]),
        ts,
        Form::Plain,
        &alpha_core::jcs(&serde_json::to_value(&forged).unwrap()).unwrap(),
    );
    sqlx::query("update audit_log set details = $2 where seq = $1")
        .bind(plain)
        .bind(&forged.details)
        .execute(&h.pool)
        .await
        .unwrap();
    assert_eq!(broken_at(&h).await, Some(plain), "a node fact edited");
    sqlx::query("update audit_log set link = $2 where seq = $1")
        .bind(plain)
        .bind(&forged_link)
        .execute(&h.pool)
        .await
        .unwrap();
    assert_eq!(
        broken_at(&h).await,
        Some(after(plain)),
        "its link recomputed"
    );
    sqlx::query("update audit_log set details = $2, link = $3 where seq = $1")
        .bind(plain)
        .bind(&details)
        .bind(&link)
        .execute(&h.pool)
        .await
        .unwrap();
    assert_eq!(broken_at(&h).await, None);

    // A row removed from the middle, then put back exactly.
    let saved = "create table saved_row as select * from audit_log where seq = $1";
    exec(&h, saved, &[a]).await;
    exec(&h, "delete from audit_log where seq = $1", &[a]).await;
    assert_eq!(broken_at(&h).await, Some(after(a)), "a row removed");
    exec(
        &h,
        "insert into audit_log overriding system value select * from saved_row",
        &[],
    )
    .await;
    exec(&h, "drop table saved_row", &[]).await;
    assert_eq!(broken_at(&h).await, None);

    // A sealed row replayed at the end does not open after its new predecessor.
    let head: i64 = count(&h, "select max(seq) from audit_log").await;
    exec(
        &h,
        "insert into audit_log (ts, sealed, link)
         select ts, sealed, link from audit_log where seq = $1",
        &[b],
    )
    .await;
    assert_eq!(broken_at(&h).await, Some(head + 1), "a sealed row replayed");
    exec(&h, "delete from audit_log where seq > $1", &[head]).await;
    assert_eq!(broken_at(&h).await, None);

    // A serving node walks the whole chain on its first maintenance pass, then what was appended
    // since, and says how far on /ready.
    h.node.maintain().await;
    let (_, ready) = send(client().get(format!("{}/ready", h.url))).await;
    assert_eq!(ready["audit_chain"], json!({ "verified_through": head }));
    exec(
        &h,
        "insert into audit_log (ts, sealed, link) select ts, sealed, link from audit_log where seq = $1",
        &[b],
    )
    .await;
    h.node.maintain().await;
    let (_, ready) = send(client().get(format!("{}/ready", h.url))).await;
    let broken = ready["audit_chain"]["broken"].as_str().unwrap();
    assert!(broken.contains(&format!("seq {}", head + 2)), "{broken}");
}

#[tokio::test]
async fn the_service_role_cannot_rewrite_the_chain_and_scrubs_only_an_imported_row() {
    let Some(h) = harness().await else {
        return;
    };
    let admin = h.register_key(&h.root, 66).await;
    let rows = h.audit_rows().await;
    let sealed = rows.iter().find(|r| r.sealed).unwrap().seq;

    let mut conn = h.pool.acquire().await.unwrap();
    sqlx::query("set role alpha_kms")
        .execute(&mut *conn)
        .await
        .unwrap();
    for sql in [
        "update audit_log set ts = ts where seq = $1",
        "delete from audit_log where seq = $1",
    ] {
        let e = sqlx::query(sql)
            .bind(sealed)
            .execute(&mut *conn)
            .await
            .unwrap_err();
        assert!(e.to_string().contains("permission denied"), "{e}");
    }
    let scrub = |legacy: i64, imported: i64| {
        sqlx::query_scalar::<_, Option<bool>>("select audit_log_scrub($1, $2)")
            .bind(legacy)
            .bind(imported)
    };
    assert_eq!(
        scrub(sealed, sealed + 1)
            .fetch_one(&mut *conn)
            .await
            .unwrap(),
        None,
        "a linked row is out of reach"
    );
    // A row as an earlier release writes it: no link, its content in the clear.
    let legacy: i64 = sqlx::query_scalar(
        "insert into audit_log (actor_kind, actor, action, org_id, object, outcome, details)
         values ('principal', $1, 'secret.put', $2, 'secret:legacy-name', 'ok', '{}') returning seq",
    )
    .bind(admin.0.to_string())
    .bind(Uuid::from(h.org))
    .fetch_one(&mut *conn)
    .await
    .unwrap();
    assert_eq!(
        scrub(legacy, sealed).fetch_one(&mut *conn).await.unwrap(),
        None,
        "only toward a later sealed row"
    );
    assert_eq!(
        scrub(legacy, legacy + 1)
            .fetch_one(&mut *conn)
            .await
            .unwrap(),
        None,
        "only toward a row that exists and is sealed"
    );
    drop(conn);

    let at = audit::verify(&h.pool, &h.metadata(), Checkpoint::default(), |_| {})
        .await
        .unwrap();
    assert_eq!(at.unlinked, [legacy], "reported, not taken for chained");
    h.node.maintain().await;
    let at = audit::verify(&h.pool, &h.metadata(), Checkpoint::default(), |_| {})
        .await
        .unwrap();
    assert!(at.unlinked.is_empty());
    let import = h
        .audit("audit.import")
        .await
        .into_iter()
        .find(|(_, _, d)| d["seq"] == json!(legacy))
        .unwrap();
    assert_eq!(import.2["row"]["object"], "secret:legacy-name");
    assert_eq!(import.2["row"]["org_id"], json!(h.org));
    let tombstone: (String, Option<Uuid>, Option<String>, Value) =
        sqlx::query_as("select action, org_id, object, details from audit_log where seq = $1")
            .bind(legacy)
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert_eq!(
        tombstone,
        (
            "audit.imported".into(),
            None,
            None,
            json!({ "imported_as": import.0 })
        )
    );
}

/// Rewrites every sealed row in the clear, as the previous release stored it.
async fn as_an_earlier_release_wrote_it(h: &Harness) {
    for (id, k) in h.keys().await {
        sqlx::query(
            "update principal_keys set sealed = null, org_index = null, public_key_index = null,
               org_id = $2, principal_id = $3, public_key = $4, document = $5,
               registered_by_key = $6, signature = $7, revoked_at = $8,
               revocation_reason = $9::principal_key_revocation
             where id = $1",
        )
        .bind(id)
        .bind(k.org_id)
        .bind(k.principal_id)
        .bind(&k.public_key)
        .bind(&k.document)
        .bind(k.registered_by_key)
        .bind(&k.signature)
        .bind(k.revoked_at)
        .bind(&k.revocation_reason)
        .execute(&h.pool)
        .await
        .unwrap();
    }
    for (hash, r) in h.revisions().await {
        sqlx::query(
            "update revisions set sealed = null, app_index = null, org_index = null,
               app_id = $2, org_id = $3, compose = $4, created_by_key = $5, signature = $6,
               revoked_at = $7
             where compose_hash = $1",
        )
        .bind(&hash)
        .bind(r.app_id)
        .bind(r.org_id)
        .bind(&r.compose)
        .bind(r.created_by_key)
        .bind(&r.signature)
        .bind(r.revoked_at)
        .execute(&h.pool)
        .await
        .unwrap();
    }
    for (id, s) in h.secrets().await {
        sqlx::query(
            "update secrets set sealed = null, name_index = null, org_id = $2, name = $3,
               app_ids = $4, content_sha256 = $5, document = $6, signed_by_key = $7,
               signature = $8, issued_at = $9
             where id = $1",
        )
        .bind(id)
        .bind(s.org_id)
        .bind(&s.name)
        .bind(&s.app_ids)
        .bind(&s.content_sha256)
        .bind(&s.document)
        .bind(s.signed_by_key)
        .bind(&s.signature)
        .bind(s.issued_at)
        .execute(&h.pool)
        .await
        .unwrap();
    }
    sqlx::query(
        "insert into audit_log (actor_kind, actor, action, org_id, object, outcome, details)
         values ('instance', 'ab', 'secret.get', $1, $2, 'ok', '{}')",
    )
    .bind(Uuid::from(h.org))
    .bind(format!("secret:{NAME}"))
    .execute(&h.pool)
    .await
    .unwrap();
}

#[tokio::test]
async fn rows_an_earlier_release_wrote_in_the_clear_are_sealed_when_a_node_unseals() {
    let Some(h) = harness().await else {
        return;
    };
    let admin = h.register_key(&h.root, 67).await;
    let app = AppId::mint();
    h.insert_capture_revision(app, &admin).await;
    let (status, reply) = h.put_secret(NAME, &[app], VALUE, h.now(), &admin).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let instance = h.instance_client().await;
    let secret_url = format!("{}/v1/secrets/{NAME}", h.url);
    assert_eq!(send(instance.get(&secret_url)).await.0, StatusCode::OK);

    as_an_earlier_release_wrote_it(&h).await;
    let (status, reply) = send(instance.get(&secret_url)).await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
        "a plaintext row is not read: {reply}"
    );

    // A node of this release unseals over the database: unseal → the database's keys → every
    // plaintext row sealed → serve.
    let (node2, url2, _shutdown2) = start_node(
        h.pool.clone(),
        &h.release.url,
        &h.release.key,
        h.node.clock.clone(),
    )
    .await;
    let aad: [u8; 32] = Sha256::digest(&node2.runtime_spki).into();
    for share in &h.shares[..2] {
        let sealed =
            alpha_crypto::seal(&node2.xwing_key.public(), INFO_UNSEAL_SHARE, &aad, share).unwrap();
        let (status, reply) = send(
            client()
                .post(format!("{url2}/v1/node/unseal"))
                .json(&json!({ "share_hpke": sealed })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{reply}");
    }
    assert!(!node2.is_sealed());

    let admin_spki = admin.1.verifying_key().to_public_key_der().unwrap();
    assert_no_plaintext(&h, &markers(&h, app, admin_spki.as_bytes())).await;
    let (status, reply) = send(instance.get(&secret_url)).await;
    assert_eq!(
        (status, reply["value"].clone()),
        (StatusCode::OK, json!(b64(VALUE)))
    );
    let imported = h.audit("audit.import").await;
    assert_eq!(imported.len(), 1);
    assert_eq!(
        imported[0].2["row"]["object"],
        json!(format!("secret:{NAME}"))
    );
    assert_eq!(h.audit("node.unseal").await.len(), 1);
}
