//! The audit log: append-only for the service role, and a chain. Every row a node of this release
//! appends carries `link = SHA-256(domain ‖ previous link ‖ ts ‖ form ‖ content)`. A serving node
//! seals the row's content with AES-256-GCM under the metadata audit key, its associated data the
//! previous link and `ts`, so each sealed row authenticates everything before it. A node without
//! keys (sealed, or joining) can only append node facts in the clear: no organization, no object,
//! details that name no tenant. Those are fixed in place by the next sealed row.
//!
//! [`verify`] walks the chain: a changed, inserted, reordered or removed row before the last sealed
//! one breaks it. What it cannot see on its own is the tail cut back to an earlier row, or the
//! whole database restored from an older copy, whose chain is just as consistent. [`Watch`] covers
//! those: each node keeps, in memory, the highest head it has seen committed, learns heads from the
//! node it joins, from its peers and from custodians' share files, and refuses a database that does
//! not hold them. A node that finds the chain broken or rolled back halts: it releases nothing and
//! appends nothing until an operator restarts it. `docs/metadata-encryption.md` has the design and
//! what it still misses.

use alpha_client::AuditHead;
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{PgExecutor, PgPool, PgTransaction};
use uuid::Uuid;

use crate::error::ApiError;
use crate::keys::{aead_open, aead_seal};
use crate::store::{MetadataKeys, b64};

const DOMAIN: &[u8] = b"alphacompute-kms/audit/v1";
const GENESIS: [u8; 32] = [0; 32];
/// Serializes appends across nodes, so each row links to the one committed before it.
const CHAIN_LOCK: i64 = 0x616c_7068_6175_6474;
const PAGE: i64 = 1000;

/// A point of the chain: a linked row's `seq` and its `link`, which commits to every row before it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Head {
    pub seq: i64,
    pub link: Vec<u8>,
}

impl Head {
    pub fn to_wire(&self) -> AuditHead {
        AuditHead {
            seq: self.seq,
            link: BASE64_URL_SAFE_NO_PAD.encode(&self.link),
        }
    }

    pub fn from_wire(head: &AuditHead) -> Result<Self, ApiError> {
        let link = BASE64_URL_SAFE_NO_PAD
            .decode(&head.link)
            .ok()
            .filter(|l| l.len() == 32)
            .ok_or_else(|| ApiError::malformed("audit head: link is not 32 bytes of base64url"))?;
        if head.seq < 1 {
            return Err(ApiError::malformed("audit head: seq is not positive"));
        }
        Ok(Self {
            seq: head.seq,
            link,
        })
    }
}

/// Why a node halted. `/ready` names only this fixed reason; the detail goes to the log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Halt {
    /// [`verify`] found a row changed, inserted, reordered or removed.
    Broken,
    /// The database does not hold a head this node saw committed: restored from an older copy,
    /// its tail cut, or another copy than the one its peers or custodians saw.
    RolledBack,
}

impl Halt {
    pub fn reason(self) -> &'static str {
        match self {
            Self::Broken => "audit_chain_broken",
            Self::RolledBack => "audit_chain_rolled_back",
        }
    }

    pub fn error(self) -> ApiError {
        ApiError::new(
            "halted",
            format!(
                "{}: this node releases no key and writes no audit row until an operator restarts it",
                self.reason()
            ),
        )
    }
}

/// What this node knows of the chain outside the database it reads, in memory only: the highest
/// head it has seen committed, and whether it has halted.
///
/// The floor rises with this node's own appends once their transaction commits, with the head it
/// reads under the chain lock (committed by whoever held the lock before), with each walk of
/// [`verify`], and with heads from outside that the database turned out to hold: the serving node's
/// in the join reply, a peer's, a custodian's. Every append and every maintenance pass first checks
/// that the database still holds the floor's row with the floor's link; a linked row is never
/// updated or deleted by the service role, so a database without it was restored or replaced.
#[derive(Debug, Default)]
pub struct Watch(Mutex<WatchState>);

#[derive(Debug, Default)]
struct WatchState {
    floor: Option<Head>,
    halted: Option<Halt>,
}

impl Watch {
    pub fn halted(&self) -> Option<Halt> {
        self.0.lock().halted
    }

    /// `halted` while halted: the first thing every key-releasing path and every append checks.
    pub fn refuse_if_halted(&self) -> Result<(), ApiError> {
        self.halted().map_or(Ok(()), |halt| Err(halt.error()))
    }

    /// The first reason sticks. Nothing un-halts a node: an operator restarts it.
    pub fn halt(&self, halt: Halt, detail: &str) {
        let mut state = self.0.lock();
        if state.halted.is_none() {
            eprintln!("halted ({}): {detail}", halt.reason());
            state.halted = Some(halt);
        }
    }

    pub fn floor(&self) -> Option<Head> {
        self.0.lock().floor.clone()
    }

    /// Raises the floor to `head` if it is later. Only for a head known to be committed.
    fn raise(&self, head: Head) {
        let mut state = self.0.lock();
        if state.floor.as_ref().is_none_or(|f| f.seq < head.seq) {
            state.floor = Some(head);
        }
    }

    /// Halts, and returns the refusal, unless the database `exec` reads holds the floor.
    pub async fn check(&self, exec: impl PgExecutor<'_>) -> Result<(), ApiError> {
        self.refuse_if_halted()?;
        let Some(floor) = self.floor() else {
            return Ok(());
        };
        if holds(exec, &floor).await? {
            return Ok(());
        }
        self.halt(
            Halt::RolledBack,
            &format!(
                "the database does not hold audit row {} seen committed",
                floor.seq
            ),
        );
        Err(Halt::RolledBack.error())
    }

    /// A head from outside this node's own reads (the node it joined, a peer, a custodian): the
    /// floor rises to it if the database holds it, and the node halts if it does not.
    pub async fn observe(
        &self,
        exec: impl PgExecutor<'_>,
        head: Head,
        from: &str,
    ) -> Result<(), ApiError> {
        self.refuse_if_halted()?;
        if !holds(exec, &head).await? {
            self.halt(
                Halt::RolledBack,
                &format!(
                    "the database does not hold audit row {} that {from} saw committed",
                    head.seq
                ),
            );
            return Err(Halt::RolledBack.error());
        }
        self.raise(head);
        Ok(())
    }
}

/// Whether the row at `head.seq` carries `head.link`.
async fn holds(exec: impl PgExecutor<'_>, head: &Head) -> Result<bool, ApiError> {
    let link = sqlx::query_scalar!("select link from audit_log where seq = $1", head.seq)
        .fetch_optional(exec)
        .await?
        .flatten();
    Ok(link.as_deref() == Some(head.link.as_slice()))
}

/// A row appended in a transaction the caller has yet to commit. Once it has, [`Appended::committed`]
/// raises the node's floor to it, so a database that later loses it is refused.
#[must_use = "pass it to `committed` once the transaction commits"]
#[derive(Debug)]
pub struct Appended {
    pub seq: i64,
    link: Vec<u8>,
}

impl Appended {
    pub fn committed(self, watch: &Watch) {
        watch.raise(Head {
            seq: self.seq,
            link: self.link,
        });
    }
}

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

    /// Appends the row in `tx`, holding the chain's lock until `tx` ends. Without `keys` only a
    /// node fact is written, in the clear; anything else is refused. A halted node, or a database
    /// that no longer holds `watch`'s floor, gets no row (`halted`).
    pub async fn insert(
        self,
        tx: &mut PgTransaction<'_>,
        watch: &Watch,
        keys: Option<&MetadataKeys>,
    ) -> Result<Appended, ApiError> {
        append(tx, watch, keys, &self.entry()).await
    }

    /// [`Audit::insert`] in a transaction of its own; its `seq`.
    pub async fn insert_now(
        self,
        pool: &PgPool,
        watch: &Watch,
        keys: Option<&MetadataKeys>,
    ) -> Result<i64, ApiError> {
        let mut tx = pool.begin().await?;
        let appended = self.insert(&mut tx, watch, keys).await?;
        tx.commit().await?;
        let seq = appended.seq;
        appended.committed(watch);
        Ok(seq)
    }
}

async fn append(
    tx: &mut PgTransaction<'_>,
    watch: &Watch,
    keys: Option<&MetadataKeys>,
    entry: &Entry,
) -> Result<Appended, ApiError> {
    watch.refuse_if_halted()?;
    sqlx::query!("select pg_advisory_xact_lock($1)", CHAIN_LOCK)
        .execute(&mut **tx)
        .await?;
    watch.check(&mut **tx).await?;
    if let Some(keys) = keys {
        check_epoch(tx, watch, keys).await?;
    }
    let head = sqlx::query!(
        r#"select now() as "ts!", h.seq as "seq?", h.link as "link?"
           from (select 1) one
           left join (select seq, link from audit_log where link is not null
                      order by seq desc limit 1) h on true"#
    )
    .fetch_one(&mut **tx)
    .await?;
    // Read under the lock, so committed by whoever held it before.
    if let (Some(seq), Some(link)) = (head.seq, head.link.clone()) {
        watch.raise(Head { seq, link });
    }
    let prev = head.link.unwrap_or_else(|| GENESIS.to_vec());
    let ts = head.ts;
    let (seq, link) = match keys {
        Some(keys) => {
            let content =
                serde_json::to_vec(entry).map_err(|e| ApiError::internal(format!("audit: {e}")))?;
            let sealed = aead_seal(keys.audit_key()?, &sealed_aad(&prev, ts), &content)?;
            let link = link(&prev, ts, Form::Sealed, &sealed);
            let seq = sqlx::query_scalar!(
                "insert into audit_log (ts, details, sealed, link) values ($1, null, $2, $3)
                 returning seq",
                ts,
                sealed,
                link,
            )
            .fetch_one(&mut **tx)
            .await?;
            (seq, link)
        }
        None if entry.is_node_fact() => {
            let link = link(&prev, ts, Form::Plain, &entry.canonical()?);
            let seq = sqlx::query_scalar!(
                "insert into audit_log (ts, actor_kind, actor, action, outcome, details, link)
                 values ($1, $2, $3, $4, $5, $6, $7) returning seq",
                ts,
                entry.actor_kind,
                entry.actor,
                entry.action,
                entry.outcome,
                entry.details,
                link,
            )
            .fetch_one(&mut **tx)
            .await?;
            (seq, link)
        }
        None => {
            return Err(ApiError::new(
                "sealed",
                "no audit row about a tenant is written before unseal",
            ));
        }
    };
    Ok(Appended { seq, link })
}

/// Takes the chain lock in `tx` without appending: a custodian rotation holds it from its first
/// statement, so no node appends, and so commits a route's rows, under keys the rotation replaces.
pub async fn lock_chain(tx: &mut PgTransaction<'_>) -> Result<(), ApiError> {
    sqlx::query!("select pg_advisory_xact_lock($1)", CHAIN_LOCK)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Under the chain lock: the database's data key must be the one `keys` come from. Every route
/// that writes a sealed row appends its audit row in the same transaction, so a node whose keys a
/// rotation has replaced writes nothing under them (`sealed`, and it joins again on its next
/// maintenance pass). A database whose data key is older than the node's was restored: it halts.
async fn check_epoch(
    tx: &mut PgTransaction<'_>,
    watch: &Watch,
    keys: &MetadataKeys,
) -> Result<(), ApiError> {
    let epoch = crate::store::data_epoch(&mut **tx).await?;
    match epoch.cmp(&keys.epoch()) {
        std::cmp::Ordering::Equal => Ok(()),
        std::cmp::Ordering::Greater => Err(stale_keys()),
        std::cmp::Ordering::Less => {
            watch.halt(
                Halt::RolledBack,
                &format!(
                    "the database's data key is from epoch {epoch}, before this node's {}",
                    keys.epoch()
                ),
            );
            Err(Halt::RolledBack.error())
        }
    }
}

pub fn stale_keys() -> ApiError {
    ApiError::new(
        "sealed",
        "a custodian rotation has re-keyed the database since this node took its keys; it joins again",
    )
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
    /// The last row walked, and the link of the last linked row walked (at `link_seq`).
    pub seq: i64,
    #[serde(skip)]
    pub link: Vec<u8>,
    #[serde(skip)]
    pub link_seq: i64,
    /// The epoch of the audit key that opened the last sealed row: rows seal under one epoch's key
    /// after another, never back.
    #[serde(skip)]
    pub audit_epoch: usize,
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

impl Checkpoint {
    /// The last linked row walked, once there is one.
    pub fn head(&self) -> Option<Head> {
        (self.link_seq > 0).then(|| Head {
            seq: self.link_seq,
            link: self.link.clone(),
        })
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
                    let aad = sealed_aad(&at.link, r.ts);
                    let (epoch, content) = keys
                        .audit_keys()
                        .iter()
                        .enumerate()
                        .skip(at.audit_epoch)
                        .find_map(|(epoch, key)| aead_open(key, &aad, &sealed).map(|c| (epoch, c)))
                        .ok_or_else(|| {
                            broken("a sealed row does not open after its predecessor")
                        })?;
                    at.audit_epoch = epoch;
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
            at.link_seq = r.seq;
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
pub async fn import_unlinked(
    pool: &PgPool,
    watch: &Watch,
    keys: &MetadataKeys,
) -> Result<u64, ApiError> {
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
            let appended = node(
                "audit.import",
                "ok",
                serde_json::json!({ "seq": r.seq, "ts": r.ts.to_rfc3339(), "row": original }),
            )
            .insert(&mut tx, watch, Some(keys))
            .await?;
            let scrubbed =
                sqlx::query_scalar!("select audit_log_scrub($1, $2)", r.seq, appended.seq)
                    .fetch_one(&mut *tx)
                    .await?;
            if scrubbed != Some(true) {
                return Err(ApiError::internal(format!(
                    "audit row {} was not scrubbed after its import",
                    r.seq
                )));
            }
            tx.commit().await?;
            appended.committed(watch);
            imported = imported.saturating_add(1);
        }
    }
}
