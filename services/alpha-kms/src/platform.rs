//! The platform document, the one release-signed input. Fetched on start and every five minutes, verified
//! here and nowhere else, kept in `platform_document` and in memory.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use alpha_attest::PlatformDocument;
use alpha_client::platform::ReleaseKeys;
use serde_json::json;

use crate::error::ApiError;
use crate::{Node, audit};

pub const RELOAD_EVERY: Duration = Duration::from_secs(300);

pub use alpha_client::platform::SignedDocument;

#[derive(Debug)]
pub struct Verified {
    pub document: PlatformDocument,
    pub signed: SignedDocument,
}

/// Signatures, `issued_at` not in the future, and a well-formed document.
pub fn verify(
    signed: SignedDocument,
    keys: &ReleaseKeys,
    now: SystemTime,
) -> Result<Verified, String> {
    let document = alpha_client::platform::verify(&signed, keys, now).map_err(|e| e.to_string())?;
    Ok(Verified { document, signed })
}

/// The stored row, re-verified: a swapped row must not become the reference values. A row stored
/// before signatures were a list has none; the URL then supplies the document, and `apply` still
/// holds it to the stored version.
pub async fn load_stored(node: &Node) -> Result<Option<Verified>, ApiError> {
    let row = sqlx::query!("select document, signatures from platform_document")
        .fetch_optional(&node.pool)
        .await?;
    let Some((document, Some(signatures))) = row.map(|r| (r.document, r.signatures)) else {
        return Ok(None);
    };
    let signed = SignedDocument {
        document,
        signatures: serde_json::from_value(signatures)
            .map_err(|e| ApiError::internal(format!("stored platform document: {e}")))?,
    };
    verify(signed, &node.release_keys, node.now())
        .map(Some)
        .map_err(|e| ApiError::internal(format!("stored platform document: {e}")))
}

/// Applies a verified document: the row moves only to a higher version (with a
/// `platform.reload` audit row), memory follows the row.
pub async fn apply(node: &Node, verified: Verified) -> Result<(), ApiError> {
    let version = i32::try_from(verified.document.version)
        .map_err(|_| ApiError::internal("platform document version overflows"))?;
    let mut tx = node.pool.begin().await?;
    let stored = sqlx::query_scalar!("select version from platform_document for update")
        .fetch_optional(&mut *tx)
        .await?;
    match stored {
        Some(stored) if stored > version => {
            return Err(ApiError::internal(format!(
                "platform document version {version} is below the stored {stored}"
            )));
        }
        Some(stored) if stored == version => {}
        _ => {
            let signatures = serde_json::to_value(&verified.signed.signatures)
                .map_err(|e| ApiError::internal(format!("platform document signatures: {e}")))?;
            sqlx::query!(
                "insert into platform_document (one, version, document, signatures) values (1, $1, $2, $3)
                 on conflict (one) do update
                 set version = $1, document = $2, signatures = $3, signature = null, verified_at = now()",
                version,
                verified.signed.document,
                signatures,
            )
            .execute(&mut *tx)
            .await?;
            audit::node(
                "platform.reload",
                "ok",
                json!({ "version": version, "previous": stored }),
            )
            .insert(&mut *tx)
            .await?;
        }
    }
    tx.commit().await?;
    remember(node, verified.document);
    Ok(())
}

fn remember(node: &Node, document: PlatformDocument) {
    let mut platform = node.platform.write();
    if platform
        .as_ref()
        .is_none_or(|d| d.version < document.version)
    {
        *platform = Some(Arc::new(document));
    }
}

pub async fn reload(node: &Node) -> Result<(), ApiError> {
    let signed: SignedDocument = reqwest::get(&node.config.platform_document_url)
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|e| ApiError::internal(format!("platform document fetch: {e}")))?
        .json()
        .await
        .map_err(|e| ApiError::internal(format!("platform document body: {e}")))?;
    let verified = verify(signed, &node.release_keys, node.now())
        .map_err(|e| ApiError::internal(format!("platform document: {e}")))?;
    if !node.has_database() {
        remember(node, verified.document);
        return Ok(());
    }
    apply(node, verified).await
}

/// Start: the stored row, then the URL; afterwards one tick every five minutes. A Kata node runs
/// it again once it has the database, so the stored version bounds what it fetched while sealed.
pub async fn start(node: &Node) {
    if node.has_database() {
        match load_stored(node).await {
            Ok(Some(stored)) => remember(node, stored.document),
            Ok(None) => {}
            Err(e) => eprintln!("{}", e.message),
        }
    }
    if let Err(e) = reload(node).await {
        eprintln!("platform document: {}", e.message);
    }
}

pub async fn run(node: Arc<Node>) {
    loop {
        tokio::time::sleep(RELOAD_EVERY).await;
        if let Err(e) = reload(&node).await {
            eprintln!("platform document: {}", e.message);
        }
        renew_leaf(&node);
    }
}

/// The node's own one-hour leaf is simply reissued on every tick.
fn renew_leaf(node: &Node) {
    if let Ok(keys) = node.intermediates()
        && let Err(e) = node.issue_own_leaf(&keys)
    {
        eprintln!("leaf renewal: {}", e.message);
    }
}
