//! M2(a): the trust-zone Postgres's data volume is LUKS2 under a key the KMS holds, so the host
//! sees no row counts, sizes or compose hashes either (`docs/db-volume-key.md`).
//!
//! The key is the `db-volume` intermediate, a random 256-bit key wrapped under the root KEK like
//! the others. It is in `intermediate_keys`, and its wrapped form is also in every custodian's
//! share file, because a node must open it before the database it unlocks is up. The order on a
//! cold start is **unseal → db key → database → serve**:
//!
//! 1. Custodians unseal a node while Postgres is down. Each share file carries the wrapped key, and
//!    the combined root opens it. The node enters [`Phase::Unsealed`]: it holds the root and the
//!    volume key and answers only the Node API.
//! 2. The Postgres pod's init container attests the node, then asks `POST /v1/node/db-key` with
//!    its own Kata evidence. The node appraises it (`kata-tdx/1`, its Revision v2 in the platform
//!    document's `db_revisions`) and answers with the key sealed to the pod's X-Wing key.
//! 3. The pod opens its volume and Postgres starts. The node, polling, unwraps every intermediate
//!    from the database under the root and serves. The root is dropped then, and the audit rows it
//!    held are appended.
//!
//! A node whose database is reachable unseals as before and serves the key from its
//! intermediates. A joining node receives it in the join reply. Genesis with the database closed
//! keeps the new intermediates in memory and writes them once the database answers.
//!
//! How the KMS authenticates to Postgres is not decided here (D10, `ponytail: D10` in `main.rs`).

use std::sync::Arc;
use std::time::Duration;

use alpha_attest::{AnyEvidence, VerifiedQuote, kata};
use alpha_client::{DbKeyReply, DbKeyRequest};
use alpha_crypto::INFO_DB_VOLUME_KEY;
use axum::Json;
use axum::extract::State;
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::audit::{self, Audit};
use crate::body::Body;
use crate::error::ApiError;
use crate::instance::{check_nonce, collateral, decode32};
use crate::keys::{aead_open, aead_seal};
use crate::{Intermediates, Node, Phase, node, random, rfc3339};

/// The `intermediate_keys` purpose, and the AES-GCM aad of its wrapping.
pub const DB_VOLUME: &str = "db-volume";
/// How often a node waiting for its database tries it.
const WAIT_EVERY: Duration = Duration::from_secs(1);

/// What the custodians' unseal requests carried beside their shares.
#[derive(Default)]
pub struct UnsealExtras {
    /// The volume key wrapped under the root KEK, from a share file.
    pub db_volume_wrapped: Option<Vec<u8>>,
    /// The highest platform document version a custodian verified the node against.
    pub document_version: u64,
}

/// A node unsealed while its database is closed.
pub struct Unsealed {
    pub root: Zeroizing<[u8; 32]>,
    pub db_volume: Zeroizing<[u8; 32]>,
    /// Nothing is appraised under a platform document older than the custodians verified, since
    /// without the database the node cannot check the version it fetched against the stored one.
    pub min_document_version: u64,
    genesis: Mutex<Option<Genesis>>,
}

/// One `intermediate_keys` row: purpose, wrapped key, public part.
pub type Row = (&'static str, Vec<u8>, Option<Vec<u8>>);

/// Genesis while the database is closed: the rows to write once it answers.
pub struct Genesis {
    pub rows: Vec<Row>,
    pub keys: Intermediates,
}

/// An audit row of a node waiting for its database: a node fact, written once it can be.
pub struct Held {
    pub action: String,
    outcome: String,
    details: Value,
}

impl Held {
    pub fn new(action: &str, outcome: &str, details: Value, at: DateTime<Utc>) -> Self {
        let details = match details {
            Value::Object(mut fields) => {
                fields.insert("held_at".into(), json!(rfc3339(at)));
                Value::Object(fields)
            }
            other => json!({ "details": other, "held_at": rfc3339(at) }),
        };
        Self {
            action: action.to_owned(),
            outcome: outcome.to_owned(),
            details,
        }
    }

    pub fn audit(&self) -> Audit<'_> {
        audit::node(&self.action, &self.outcome, self.details.clone())
    }
}

/// The database did not answer, as opposed to answering with an error.
pub fn unreachable(e: &sqlx::Error) -> bool {
    matches!(
        e,
        sqlx::Error::Io(_)
            | sqlx::Error::Tls(_)
            | sqlx::Error::PoolTimedOut
            | sqlx::Error::PoolClosed
    )
}

async fn reachable(node: &Node) -> Result<(), sqlx::Error> {
    sqlx::query("select 1")
        .execute(&node.pool)
        .await
        .map(|_| ())
}

/// Every intermediate unwrapped under `root`. A database from before M2(a) gets its volume key
/// here, wrapped under `root`, since only a holder of the root can add one.
pub async fn open_database(node: &Node, root: &[u8; 32]) -> Result<Intermediates, ApiError> {
    let keys = node::unwrap_intermediates(node, root).await?;
    if keys.db_volume.is_some() {
        return Ok(keys);
    }
    let key = Zeroizing::new(random::<32>()?);
    let wrapped = aead_seal(root, DB_VOLUME.as_bytes(), key.as_slice())?;
    sqlx::query!(
        "insert into intermediate_keys (purpose, wrapped) values ('db-volume', $1)
           on conflict (purpose) do nothing",
        wrapped,
    )
    .execute(&node.pool)
    .await?;
    // Another node may have added one first: what is stored is the key.
    let keys = node::unwrap_intermediates(node, root).await?;
    if keys.db_volume.is_none() {
        return Err(ApiError::internal("the db-volume key was not stored"));
    }
    Ok(keys)
}

/// Whether [`enter`] served or is waiting for the database.
pub enum Entered {
    Serving,
    Waiting,
}

/// After custodians combined `root`: serve if the database answers; if it does not, and a share
/// file carried the volume key, wait for it unsealed.
pub async fn enter(node: &Arc<Node>, root: Zeroizing<[u8; 32]>) -> Result<Entered, ApiError> {
    match reachable(node).await {
        Err(e) if unreachable(&e) => {
            let (wrapped, document_version) = {
                let extras = node.unseal_extras.lock();
                (extras.db_volume_wrapped.clone(), extras.document_version)
            };
            let wrapped = wrapped.ok_or_else(|| {
                ApiError::internal(format!(
                    "database: {e}; no share file carried the db-volume key to open it with"
                ))
            })?;
            let db_volume = open_key(&root, &wrapped)
                .ok_or_else(|| ApiError::malformed("the shares do not open the db-volume key"))?;
            wait(
                node,
                Unsealed {
                    root,
                    db_volume,
                    min_document_version: document_version,
                    genesis: Mutex::new(None),
                },
            );
            Ok(Entered::Waiting)
        }
        _ => {
            let keys = open_database(node, &root).await?;
            node.start_serving(keys).await?;
            Ok(Entered::Serving)
        }
    }
}

/// Genesis with the database closed: the new intermediates are held until it answers.
pub fn bootstrap_waiting(
    node: &Arc<Node>,
    root: Zeroizing<[u8; 32]>,
    db_volume: Zeroizing<[u8; 32]>,
    genesis: Genesis,
) {
    wait(
        node,
        Unsealed {
            root,
            db_volume,
            min_document_version: 0,
            genesis: Mutex::new(Some(genesis)),
        },
    );
}

/// Whether bootstrap may write genesis now or must wait for the database.
pub async fn database_closed(node: &Node) -> bool {
    matches!(reachable(node).await, Err(e) if unreachable(&e))
}

fn open_key(root: &[u8; 32], wrapped: &[u8]) -> Option<Zeroizing<[u8; 32]>> {
    let key = aead_open(root, DB_VOLUME.as_bytes(), wrapped)?;
    <[u8; 32]>::try_from(key.as_slice())
        .ok()
        .map(Zeroizing::new)
}

fn wait(node: &Arc<Node>, unsealed: Unsealed) {
    *node.phase.write() = Phase::Unsealed(Arc::new(unsealed));
    tokio::spawn(await_database(node.clone()));
}

/// Polls the database; once it answers, serves under the intermediates it holds (or writes
/// genesis). A database whose rows the root does not open sends the node back to sealed.
async fn await_database(node: Arc<Node>) {
    loop {
        tokio::time::sleep(WAIT_EVERY).await;
        let unsealed = match &*node.phase.read() {
            Phase::Unsealed(unsealed) => unsealed.clone(),
            _ => return,
        };
        if reachable(&node).await.is_err() {
            continue;
        }
        let genesis = unsealed.genesis.lock().take();
        let result = match genesis {
            None => match open_database(&node, &unsealed.root).await {
                Ok(keys) => node.start_serving(keys).await,
                Err(e) => Err(e),
            },
            Some(genesis) => match write_genesis(&node, &genesis).await {
                Ok(()) => node.start_serving(genesis.keys).await,
                Err(e) if transient(&e) => {
                    *unsealed.genesis.lock() = Some(genesis);
                    Err(e)
                }
                Err(e) => Err(e),
            },
        };
        match result {
            Ok(()) => {
                eprintln!("database open; serving");
                node.maintain().await;
                return;
            }
            Err(e) if transient(&e) => eprintln!("waiting for the database: {}", e.message),
            Err(e) => {
                eprintln!("the database does not open under this root: {}", e.message);
                *node.phase.write() = Phase::Sealed { shares: Vec::new() };
                *node.unseal_extras.lock() = UnsealExtras::default();
                let held: Vec<Held> = std::mem::take(&mut *node.held_audit.lock());
                for row in &held {
                    let _ = node.audit(row.audit()).await;
                }
                let _ = node
                    .audit(audit::node("node.unseal", e.outcome(), e.details()))
                    .await;
                return;
            }
        }
    }
}

/// A database error, not a refusal: the database went away again.
fn transient(e: &ApiError) -> bool {
    e.code == "internal" && e.message.starts_with("database:")
}

async fn write_genesis(node: &Node, genesis: &Genesis) -> Result<(), ApiError> {
    let mut tx = node.pool.begin().await?;
    let mut inserted = 0u64;
    for (purpose, wrapped, public_part) in &genesis.rows {
        inserted = inserted.saturating_add(
            sqlx::query!(
                "insert into intermediate_keys (purpose, wrapped, public_part)
                   values ($1::text::intermediate_purpose, $2, $3)
                   on conflict (purpose) do nothing",
                *purpose,
                wrapped,
                public_part.as_deref(),
            )
            .execute(&mut *tx)
            .await?
            .rows_affected(),
        );
    }
    if inserted != genesis.rows.len() as u64 {
        return Err(ApiError::new("already_exists", "database is not empty"));
    }
    audit::node(
        "node.bootstrap",
        "ok",
        json!({ "database": "opened after" }),
    )
    .insert(&mut tx, Some(&genesis.keys.metadata))
    .await?;
    tx.commit().await?;
    Ok(())
}

/// `POST /v1/node/db-key`: the volume key to the attested Postgres pod, DCAP included.
pub async fn db_key(
    State(node): State<Arc<Node>>,
    Body(request, _): Body<DbKeyRequest>,
) -> Result<Json<DbKeyReply>, ApiError> {
    release_audited(&node, &request, None).await.map(Json)
}

/// [`db_key`] over a quote the caller has verified: every step after DCAP, the audit row
/// included. No route reaches it; the KMS's tests run the Postgres pod through it over synthetic
/// quotes until B300 Kata captures exist (M1), as [`node::join_verified`] does for a node.
pub async fn db_key_verified(
    node: &Node,
    request: &DbKeyRequest,
    verified: VerifiedQuote,
) -> Result<DbKeyReply, ApiError> {
    release_audited(node, request, Some(verified)).await
}

async fn release_audited(
    node: &Node,
    request: &DbKeyRequest,
    verified: Option<VerifiedQuote>,
) -> Result<DbKeyReply, ApiError> {
    let xwing_sha256 = sha256_label(request.xwing_pubkey.as_bytes());
    match release(node, request, verified).await {
        Ok((reply, appraised)) => {
            let coco = appraised.coco.as_ref();
            let details = json!({
                "revision": appraised.compose_hash,
                "os_image": appraised.os_image,
                "tcb_status": appraised.tcb_status,
                "policy_sha256": coco.map(|c| c.policy_sha256),
                "xwing_sha256": xwing_sha256,
            });
            // Released only once its row is written, or held while the database is closed.
            node.audit_or_hold("db.key", "ok", details).await?;
            Ok(reply)
        }
        Err(e) => {
            let mut details = e.details();
            if let Value::Object(fields) = &mut details {
                fields.insert("xwing_sha256".into(), json!(xwing_sha256));
            }
            let _ = node.audit_or_hold("db.key", e.outcome(), details).await;
            Err(e)
        }
    }
}

fn sha256_label(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

async fn release(
    node: &Node,
    request: &DbKeyRequest,
    verified: Option<VerifiedQuote>,
) -> Result<(DbKeyReply, alpha_attest::Appraised), ApiError> {
    let key = node.db_volume_key()?;
    let nonce = decode32("nonce", &request.nonce)?;
    check_nonce(&node.nonce_key, &nonce, node.now())?;
    let doc = node
        .platform_document()
        .ok_or_else(|| ApiError::new("attestation_unknown", "no platform document"))?;
    if let Phase::Unsealed(unsealed) = &*node.phase.read()
        && doc.version < unsealed.min_document_version
    {
        return Err(ApiError::new(
            "attestation_unknown",
            format!(
                "platform document version {} is below the {} the custodians verified",
                doc.version, unsealed.min_document_version
            ),
        ));
    }
    let AnyEvidence::V2(evidence) = &request.evidence else {
        return Err(ApiError::malformed(
            "the database pod is a Kata pod: alphacompute-evidence/2 only",
        ));
    };
    let verified = match verified {
        Some(verified) => verified,
        None => {
            kata::check_cpu_kind(evidence)?;
            let collateral = collateral(node, &evidence.cpu.quote).await?;
            alpha_attest::verify_quote(&evidence.cpu.quote, &collateral, &doc.policy, node.now())?
        }
    };
    let xwing = request.xwing_pubkey.as_bytes();
    let appraised =
        alpha_attest::node::appraise_db_pod_verified(evidence, verified, &nonce, xwing, &doc)?;
    let aad: [u8; 32] = Sha256::digest(&node.runtime_spki).into();
    let key_hpke = alpha_crypto::seal(
        &request.xwing_pubkey,
        INFO_DB_VOLUME_KEY,
        &aad,
        key.as_slice(),
    )
    .map_err(|e| ApiError::internal(format!("seal db key: {e}")))?;
    Ok((DbKeyReply { key_hpke }, appraised))
}
