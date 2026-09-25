//! The platform document, the one release-signed input. Fetched on start and every five minutes, verified
//! here and nowhere else, kept in `platform_document` and in memory.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use alpha_attest::PlatformDocument;
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use ed25519_dalek::VerifyingKey;
use serde_json::{Value, json};

use crate::error::ApiError;
use crate::{Node, audit};

pub const RELOAD_EVERY: Duration = Duration::from_secs(300);

pub use alpha_client::platform::{NamedSignature, SignedDocument};

#[derive(Debug)]
pub struct Verified {
    pub document: PlatformDocument,
    pub raw: Value,
    pub signature: Vec<u8>,
}

/// Signature, `issued_at` not in the future, and a well-formed document.
pub fn verify(
    signed: &SignedDocument,
    release_key: &VerifyingKey,
    now: SystemTime,
) -> Result<Verified, String> {
    let document =
        alpha_client::platform::verify(signed, release_key, now).map_err(|e| e.to_string())?;
    Ok(Verified {
        document,
        raw: signed.document.clone(),
        signature: BASE64_URL_SAFE_NO_PAD
            .decode(&signed.signature.signature)
            .map_err(|e| e.to_string())?,
    })
}

/// The stored row, re-verified: a swapped row must not become the reference values.
pub async fn load_stored(node: &Node) -> Result<Option<Verified>, ApiError> {
    let row = sqlx::query!("select document, signature from platform_document")
        .fetch_optional(&node.pool)
        .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let signed = SignedDocument {
        document: row.document,
        signature: NamedSignature {
            algorithm: "ed25519".into(),
            signature: BASE64_URL_SAFE_NO_PAD.encode(row.signature),
        },
    };
    verify(&signed, &node.release_key, node.now())
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
            sqlx::query!(
                "insert into platform_document (one, version, document, signature) values (1, $1, $2, $3)
                 on conflict (one) do update set version = $1, document = $2, signature = $3, verified_at = now()",
                version,
                verified.raw,
                verified.signature,
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
    let mut platform = node.platform.write();
    if platform
        .as_ref()
        .is_none_or(|d| d.version < verified.document.version)
    {
        *platform = Some(Arc::new(verified.document));
    }
    Ok(())
}

pub async fn reload(node: &Node) -> Result<(), ApiError> {
    let signed: SignedDocument = reqwest::get(&node.config.platform_document_url)
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|e| ApiError::internal(format!("platform document fetch: {e}")))?
        .json()
        .await
        .map_err(|e| ApiError::internal(format!("platform document body: {e}")))?;
    let verified = verify(&signed, &node.release_key, node.now())
        .map_err(|e| ApiError::internal(format!("platform document: {e}")))?;
    apply(node, verified).await
}

/// Start: the stored row, then the URL; afterwards one tick every five minutes.
pub async fn start(node: &Node) {
    match load_stored(node).await {
        Ok(Some(stored)) => *node.platform.write() = Some(Arc::new(stored.document)),
        Ok(None) => {}
        Err(e) => eprintln!("{}", e.message),
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
