//! The audit log: append-only for the service role, and a chain. Every row a node of this release
//! appends carries `link = SHA-256(domain ‖ previous link ‖ ts ‖ form ‖ content)`. A serving node
//! seals the row's content with AES-256-GCM under the metadata audit key, its associated data the
//! previous link and `ts`, so each sealed row authenticates everything before it. A node without
//! keys (sealed, or joining) can only append node facts in the clear: no organization, no object,
//! details that name no tenant. Those are fixed in place by the next sealed row.
//!
//! [`verify`] walks the chain: a changed, inserted, reordered or removed row before the last sealed
//! one breaks it. What it cannot see is the tail cut back to an earlier row, or the whole database
//! rolled back; `docs/metadata-encryption.md` says what covers those.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, PgTransaction};
use uuid::Uuid;

use crate::error::ApiError;
use crate::keys::{aead_open, aead_seal};
use crate::store::{MetadataKeys, b64};

const DOMAIN: &[u8] = b"alphacompute-kms/audit/v1";
const GENESIS: [u8; 32] = [0; 32];
/// Serializes appends across nodes, so each row links to the one committed before it.
const CHAIN_LOCK: i64 = 0x616c_7068_6175_6474;
const PAGE: i64 = 1000;

/// One `audit_log` row; the caller decides the transaction, so a row lands with the action it records.
pub struct Audit<'a> {
    pub actor_kind: &'a str,
    pub actor: &'a str,
    pub action: &'a str,
    pub org_id: Option<Uuid>,
    pub object: Option<String>,
    pub outcome: &'a str,
    pub details: Value,
    pub evidence_sha256: Option<Vec<u8>>,
}

/// A row's content, sealed or (a node fact before unseal) in the clear.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    pub actor_kind: String,
    pub actor: String,
    pub action: String,
    pub org_id: Option<Uuid>,
    pub object: Option<String>,
    pub outcome: String,
    pub details: Value,
    #[serde(with = "b64::option")]
    pub evidence_sha256: Option<Vec<u8>>,
}

impl Entry {
    /// What a node may write before it holds keys: about itself, never about a tenant.
    fn is_node_fact(&self) -> bool {
        self.actor_kind == "node"
            && self.org_id.is_none()
            && self.object.is_none()
            && self.evidence_sha256.is_none()
    }

    fn canonical(&self) -> Result<Vec<u8>, ApiError> {
        let value =
            serde_json::to_value(self).map_err(|e| ApiError::internal(format!("audit: {e}")))?;
        alpha_core::jcs(&value).map_err(|e| ApiError::internal(format!("audit: {e}")))
    }
}

#[derive(Clone, Copy)]
#[repr(u8)]
pub enum Form {
    Plain = 0,
    Sealed = 1,
}

pub fn link(prev: &[u8], ts: DateTime<Utc>, form: Form, content: &[u8]) -> Vec<u8> {
    Sha256::new()
        .chain_update(DOMAIN)
        .chain_update(prev)
        .chain_update(ts.timestamp_micros().to_be_bytes())
        .chain_update([form as u8])
        .chain_update(content)
        .finalize()
        .to_vec()
}

fn sealed_aad(prev: &[u8], ts: DateTime<Utc>) -> Vec<u8> {
    [DOMAIN, prev, &ts.timestamp_micros().to_be_bytes()].concat()
}

impl Audit<'_> {
    fn entry(self) -> Entry {
        Entry {
            actor_kind: self.actor_kind.to_owned(),
            actor: self.actor.to_owned(),
            action: self.action.to_owned(),
            org_id: self.org_id,
            object: self.object,
            outcome: self.outcome.to_owned(),
            details: self.details,
            evidence_sha256: self.evidence_sha256,
        }
    }

    /// Appends the row in `tx`, holding the chain's lock until `tx` ends; its `seq`. Without
    /// `keys` only a node fact is written, in the clear; anything else is refused.
    pub async fn insert(
        self,
        tx: &mut PgTransaction<'_>,
        keys: Option<&MetadataKeys>,
    ) -> Result<i64, ApiError> {
        append(tx, keys, &self.entry()).await
    }

    /// [`Audit::insert`] in a transaction of its own.
    pub async fn insert_now(
        self,
        pool: &PgPool,
        keys: Option<&MetadataKeys>,
    ) -> Result<i64, ApiError> {
        let mut tx = pool.begin().await?;
        let seq = self.insert(&mut tx, keys).await?;
        tx.commit().await?;
        Ok(seq)
    }
}

async fn append(
    tx: &mut PgTransaction<'_>,
    keys: Option<&MetadataKeys>,
    entry: &Entry,
) -> Result<i64, ApiError> {
    sqlx::query!("select pg_advisory_xact_lock($1)", CHAIN_LOCK)
        .execute(&mut **tx)
        .await?;
    let head = sqlx::query!(
        r#"select now() as "ts!",
                  (select link from audit_log where link is not null order by seq desc limit 1) as prev"#
    )
    .fetch_one(&mut **tx)
    .await?;
    let prev = head.prev.unwrap_or_else(|| GENESIS.to_vec());
    let ts = head.ts;
    let seq = match keys {
        Some(keys) => {
            let content =
                serde_json::to_vec(entry).map_err(|e| ApiError::internal(format!("audit: {e}")))?;
            let sealed = aead_seal(keys.audit_key(), &sealed_aad(&prev, ts), &content)?;
            sqlx::query_scalar!(
                "insert into audit_log (ts, details, sealed, link) values ($1, null, $2, $3)
                 returning seq",
                ts,
                sealed,
                link(&prev, ts, Form::Sealed, &sealed),
            )
            .fetch_one(&mut **tx)
            .await?
        }
        None if entry.is_node_fact() => {
            sqlx::query_scalar!(
                "insert into audit_log (ts, actor_kind, actor, action, outcome, details, link)
                 values ($1, $2, $3, $4, $5, $6, $7) returning seq",
                ts,
                entry.actor_kind,
                entry.actor,
                entry.action,
                entry.outcome,
                entry.details,
                link(&prev, ts, Form::Plain, &entry.canonical()?),
            )
            .fetch_one(&mut **tx)
            .await?
        }
        None => {
            return Err(ApiError::new(
                "sealed",
                "no audit row about a tenant is written before unseal",
            ));
        }
    };
    Ok(seq)
}

pub fn node<'a>(action: &'a str, outcome: &'a str, details: Value) -> Audit<'a> {
    Audit {
        actor_kind: "node",
        actor: "node",
        action,
        org_id: None,
        object: None,
        outcome,
        details,
        evidence_sha256: None,
    }
}

/// A row as [`verify`] read it.
#[derive(Clone, Debug)]
pub struct Row {
    pub seq: i64,
    pub ts: DateTime<Utc>,
    /// Sealed by a serving node; otherwise a node fact written in the clear before unseal.
    pub sealed: bool,
    pub entry: Entry,
}

/// The chain as far as [`verify`] walked it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Checkpoint {
    /// The last row walked, and its link.
    pub seq: i64,
    #[serde(skip)]
    pub link: Vec<u8>,
    pub linked: u64,
    pub sealed: u64,
    /// Rows without a link (written by an earlier release) not yet moved into the chain.
    pub unlinked: Vec<i64>,
}

#[derive(Debug)]
pub enum ChainError {
    Broken { seq: i64, reason: String },
    Read(String),
}

impl std::fmt::Display for ChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Broken { seq, reason } => write!(f, "audit chain broken at seq {seq}: {reason}"),
            Self::Read(e) => write!(f, "audit chain: {e}"),
        }
    }
}

impl From<sqlx::Error> for ChainError {
    fn from(e: sqlx::Error) -> Self {
        Self::Read(format!("database: {e}"))
    }
}

/// Walks every row after `from` (the whole log from `Checkpoint::default()`), checking each link
/// and opening each sealed row, and hands each linked row to `each`.
pub async fn verify(
    pool: &PgPool,
    keys: &MetadataKeys,
    from: Checkpoint,
    mut each: impl FnMut(Row),
) -> Result<Checkpoint, ChainError> {
    let mut at = from;
    if at.link.is_empty() {
        at.link = GENESIS.to_vec();
    }
    loop {
        let rows = sqlx::query!(
            "select seq, ts, actor_kind, actor, action, org_id, object, outcome, details,
                    evidence_sha256, sealed, link
             from audit_log where seq > $1 order by seq limit $2",
            at.seq,
            PAGE
        )
        .fetch_all(pool)
        .await?;
        if rows.is_empty() {
            return Ok(at);
        }
        for r in rows {
            at.seq = r.seq;
            let broken = |reason: &str| ChainError::Broken {
                seq: r.seq,
                reason: reason.to_owned(),
            };
            let Some(stored) = r.link else {
                if r.action.as_deref() != Some("audit.imported") {
                    at.unlinked.push(r.seq);
                }
                continue;
            };
            let is_sealed = r.sealed.is_some();
            let (entry, expected) = match r.sealed {
                Some(sealed) => {
                    let content = aead_open(keys.audit_key(), &sealed_aad(&at.link, r.ts), &sealed)
                        .ok_or_else(|| {
                            broken("a sealed row does not open after its predecessor")
                        })?;
                    let entry: Entry = serde_json::from_slice(&content)
                        .map_err(|_| broken("a sealed row is not an audit entry"))?;
                    at.sealed = at.sealed.saturating_add(1);
                    (entry, link(&at.link, r.ts, Form::Sealed, &sealed))
                }
                None => {
                    let entry = Entry {
                        actor_kind: r.actor_kind.unwrap_or_default(),
                        actor: r.actor.unwrap_or_default(),
                        action: r.action.unwrap_or_default(),
                        org_id: r.org_id,
                        object: r.object,
                        outcome: r.outcome.unwrap_or_default(),
                        details: r.details.unwrap_or(Value::Null),
                        evidence_sha256: r.evidence_sha256,
                    };
                    if !entry.is_node_fact() {
                        return Err(broken("a row in the clear names more than the node"));
                    }
                    let expected = link(
                        &at.link,
                        r.ts,
                        Form::Plain,
                        &entry.canonical().map_err(|e| broken(&e.message))?,
                    );
                    (entry, expected)
                }
            };
            if stored != expected {
                return Err(broken("the link does not follow from the row before"));
            }
            at.link = stored;
            at.linked = at.linked.saturating_add(1);
            each(Row {
                seq: r.seq,
                ts: r.ts,
                sealed: is_sealed,
                entry,
            });
        }
    }
}

/// Moves each row an earlier release wrote without a link into the chain: a sealed `audit.import`
/// row carrying it, then `audit_log_scrub` replaces its content with a pointer to that row. A
/// `node.join.request` younger than the join window stays readable until a later pass.
pub async fn import_unlinked(pool: &PgPool, keys: &MetadataKeys) -> Result<u64, ApiError> {
    let mut imported = 0u64;
    loop {
        let rows = sqlx::query!(
            r#"select seq, ts, actor_kind as "actor_kind!", actor as "actor!", action as "action!",
                      org_id, object, outcome as "outcome!", details, evidence_sha256
               from audit_log
               where link is null and sealed is null and action <> 'audit.imported'
                 and (action <> 'node.join.request' or ts < now() - interval '10 minutes')
               order by seq limit $1"#,
            PAGE
        )
        .fetch_all(pool)
        .await?;
        if rows.is_empty() {
            return Ok(imported);
        }
        for r in rows {
            let original = Entry {
                actor_kind: r.actor_kind,
                actor: r.actor,
                action: r.action,
                org_id: r.org_id,
                object: r.object,
                outcome: r.outcome,
                details: r.details.unwrap_or(Value::Null),
                evidence_sha256: r.evidence_sha256,
            };
            let mut tx = pool.begin().await?;
            let seq = node(
                "audit.import",
                "ok",
                serde_json::json!({ "seq": r.seq, "ts": r.ts.to_rfc3339(), "row": original }),
            )
            .insert(&mut tx, Some(keys))
            .await?;
            let scrubbed = sqlx::query_scalar!("select audit_log_scrub($1, $2)", r.seq, seq)
                .fetch_one(&mut *tx)
                .await?;
            if scrubbed != Some(true) {
                return Err(ApiError::internal(format!(
                    "audit row {} was not scrubbed after its import",
                    r.seq
                )));
            }
            tx.commit().await?;
            imported = imported.saturating_add(1);
        }
    }
}
