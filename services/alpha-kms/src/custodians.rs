//! Custodian re-share with root rotation. Two current custodians approve a proposal that names
//! three new X-Wing keys and a nonce this node minted; each approval seals the proposal's digest
//! and the custodian's share to this node's attested X-Wing key. With two, the node rebuilds the
//! current root KEK, proves it by unwrapping every `intermediate_keys` row and finding the
//! tenant-kek-root (and data key) it serves, generates a new root and a new data key inside the
//! node, and in one transaction: re-wraps tenant-kek-root and the CA key under the new root,
//! re-encrypts every sealed row, blind index and Secret value under the new data key
//! ([`crate::data_key`], [`store::rekey`]), and records the rotation with the new shares sealed to
//! the new custodians and a signed receipt. Both roots are zeroized when the call returns.
//!
//! What changes at the commit: which shares open the database (before it only the old ones,
//! after it only the new ones, never neither), and which key everything the database holds is
//! sealed under. Two old shares and a copy of the database taken before the rotation therefore
//! open that copy's data and nothing written later. What does not change: tenant-kek-root, from
//! which every App's derived keys come (customers' volumes are encrypted under them), and the CA
//! key, which tenants pin through the platform document. Those two are the residual
//! (`docs/custodian-rotation.md`). A joined node holds the old data key after the commit: its
//! writes are refused under the chain lock, and its next maintenance pass makes it join again.

use std::sync::Arc;

use alpha_channel::sha256_label;
use alpha_client::{
    ROTATION_FORMAT, ROTATION_ROUTE, RotateReply, RotateRequest, Rotation, RotationProposal,
    sealed_sha256,
};
use alpha_crypto::{INFO_CUSTODIAN_APPROVAL, INFO_UNSEAL_SHARE, Sealed};
use axum::Json;
use axum::extract::State;
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use vsss_rs::Gf256;
use zeroize::Zeroizing;

use crate::audit;
use crate::body::Body;
use crate::data_key::{self, DataKey};
use crate::error::ApiError;
use crate::instance::{check_nonce, decode32};
use crate::keys::{aead_open, aead_seal};
use crate::{Intermediates, Node, Phase, control, random, store};

/// Approvals of one proposal, held in memory until the second arrives or another proposal
/// replaces them. Never written anywhere.
pub struct Pending {
    digest: [u8; 32],
    shares: Vec<Zeroizing<Vec<u8>>>,
}

fn malformed(e: impl std::fmt::Display) -> ApiError {
    ApiError::malformed(e.to_string())
}

pub async fn rotate(
    State(node): State<Arc<Node>>,
    Body(request, _): Body<RotateRequest>,
) -> Result<Json<RotateReply>, ApiError> {
    let result = approve(&node, &request).await;
    match &result {
        // The rotation's own row went in with its transaction.
        Ok(reply) if reply.rotated => {}
        Ok(reply) => {
            let details = json!({
                "proposal_sha256": request.proposal.digest().ok().map(|d| sha256_hex(&d)),
                "approvals": reply.approvals,
            });
            node.audit(audit::node("custodians.approve", "ok", details))
                .await?;
        }
        // As a refused Control call: the refusal is the answer even if its row cannot be written.
        Err(e) => {
            let _ = node
                .audit(audit::node("custodians.rotate", e.outcome(), e.details()))
                .await;
        }
    }
    result.map(Json)
}

/// The rotation as stored by the last commit, for new custodians whose reply never arrived.
/// Nothing in it opens without a new custodian's key; the receipt is what they check.
pub async fn last_rotation(State(node): State<Arc<Node>>) -> Result<Json<Value>, ApiError> {
    sqlx::query_scalar!(
        "select rotation from custodian_rotations order by created_at desc, id desc limit 1"
    )
    .fetch_optional(&node.pool)
    .await?
    .map(Json)
    .ok_or_else(|| ApiError::not_found("no rotation has been committed"))
}

fn sha256_hex(digest: &[u8; 32]) -> String {
    format!("sha256:{}", hex::encode(digest))
}

/// The proposal must be for this node, over a nonce it minted that has not expired, and name
/// three distinct custodians.
fn check_proposal(node: &Node, proposal: &RotationProposal) -> Result<[u8; 32], ApiError> {
    if proposal.format != ROTATION_FORMAT {
        return Err(ApiError::malformed(format!(
            "proposal: format is not {ROTATION_FORMAT}"
        )));
    }
    if proposal.kms_node_spki_sha256 != sha256_label(&node.runtime_spki) {
        return Err(ApiError::malformed(
            "proposal: kms_node_spki_sha256 names another node",
        ));
    }
    let nonce = decode32("proposal.nonce", &proposal.nonce)?;
    check_nonce(&node.nonce_key, &nonce, node.now())?;
    let [a, b, c] = &proposal.custodians;
    if a == b || a == c || b == c {
        return Err(ApiError::malformed(
            "proposal: the three custodians must be three keys",
        ));
    }
    proposal.digest().map_err(malformed)
}

/// Opens one approval and counts it; with two distinct shares of one proposal, rotates.
async fn approve(node: &Node, request: &RotateRequest) -> Result<RotateReply, ApiError> {
    let keys = node.intermediates()?;
    // The development root comes from the environment: rotating it would leave a node whose
    // every restart reads a root that opens nothing.
    #[cfg(feature = "dev-root")]
    if node.config.dev_root_kek.is_some() {
        return Err(ApiError::new(
            "policy_denied",
            "a node with a development root KEK does not rotate its custodians",
        ));
    }
    let digest = check_proposal(node, &request.proposal)?;
    let aad: [u8; 32] = Sha256::digest(&node.runtime_spki).into();
    let opened = alpha_crypto::open(
        &node.xwing_key,
        INFO_CUSTODIAN_APPROVAL,
        &aad,
        &request.approval_hpke,
    )
    .map_err(|e| ApiError::malformed(format!("approval_hpke: {e}")))?;
    let (approved, share) = opened
        .split_first_chunk::<32>()
        .ok_or_else(|| ApiError::malformed("approval_hpke: shorter than a digest"))?;
    if *approved != digest {
        return Err(ApiError::malformed(
            "approval_hpke: the approval is for another proposal",
        ));
    }
    let collected = {
        let mut pending = node.pending_rotation.lock();
        let current = match pending.take() {
            Some(p) if p.digest == digest => p,
            _ => Pending {
                digest,
                shares: Vec::new(),
            },
        };
        let mut current = current;
        if !current.shares.iter().any(|s| s.as_slice() == share) {
            current.shares.push(Zeroizing::new(share.to_vec()));
        }
        if current.shares.len() < 2 {
            let approvals = current.shares.len();
            *pending = Some(current);
            return Ok(RotateReply {
                rotated: false,
                approvals,
                rotation: None,
            });
        }
        current.shares
    };
    let shares: Vec<Vec<u8>> = collected.iter().map(|s| s.to_vec()).collect();
    let old_root = Gf256::combine_bytes(&shares)
        .ok()
        .map(Zeroizing::new)
        .and_then(|r| <[u8; 32]>::try_from(r.as_slice()).ok())
        .map(Zeroizing::new);
    drop(Zeroizing::new(shares));
    let old_root = old_root.ok_or_else(|| {
        ApiError::signature_invalid("the approvals' shares do not combine into a root")
    })?;
    let approved_by: Vec<u8> = collected
        .iter()
        .filter_map(|s| s.first().copied())
        .collect();
    let rotation = rotate_root(node, &keys, &old_root, &request.proposal, &approved_by).await?;
    Ok(RotateReply {
        rotated: true,
        approvals: collected.len(),
        rotation: Some(rotation),
    })
}

/// Everything after the quorum, in one transaction: every wrapped row opened under `old_root`
/// and re-sealed under a new root, the new root split 2-of-3 and sealed to the proposal's
/// custodians, the rotation row with its receipt, and the audit row. A failure anywhere before the
/// commit leaves the database as it was, so the old shares still open it.
pub async fn rotate_root(
    node: &Node,
    keys: &Intermediates,
    old_root: &[u8; 32],
    proposal: &RotationProposal,
    approved_by: &[u8],
) -> Result<Rotation, ApiError> {
    let digest = proposal.digest().map_err(malformed)?;
    let nonce = decode32("proposal.nonce", &proposal.nonce)?;
    let new_root = Zeroizing::new(random::<32>()?);
    let mut tx = node.pool.begin().await?;
    // From the first statement, no node appends, and so commits a route's rows, under the keys
    // this transaction replaces, and no seal pass runs beside it.
    audit::lock_chain(&mut tx).await?;
    store::lock_seal(&mut tx).await?;
    if store::data_epoch(&mut *tx).await? != keys.metadata.epoch() {
        return Err(audit::stale_keys());
    }
    let rows = sqlx::query!(
        r#"select purpose::text as "purpose!", wrapped from intermediate_keys
           order by purpose for update"#
    )
    .fetch_all(&mut *tx)
    .await?;
    let mut rewrapped = Vec::new();
    let mut db_volume_wrapped = None;
    for row in &rows {
        let purpose = row.purpose.as_bytes();
        let plain = aead_open(old_root, purpose, &row.wrapped).ok_or_else(|| {
            ApiError::signature_invalid(
                "the approvals' shares do not reconstruct the current root KEK",
            )
        })?;
        if row.purpose == "tenant-kek-root" && plain.as_slice() != keys.tenant_kek_root.as_slice() {
            return Err(ApiError::internal(
                "the database's tenant-kek-root is not the one this node serves",
            ));
        }
        if row.purpose == data_key::PURPOSE {
            let held = DataKey::decode(&plain)?;
            if !keys.data.as_ref().is_some_and(|d| d.same_as(&held)) {
                return Err(ApiError::internal(
                    "the database's data key is not the one this node serves",
                ));
            }
            // Replaced below, not re-wrapped.
            continue;
        }
        let wrapped = aead_seal(&new_root, purpose, &plain)?;
        if aead_open(&new_root, purpose, &wrapped).as_deref() != Some(&plain) {
            return Err(ApiError::internal(
                "a re-wrapped intermediate does not open",
            ));
        }
        sqlx::query!(
            "update intermediate_keys set wrapped = $2
              where purpose = $1::text::intermediate_purpose",
            row.purpose,
            wrapped,
        )
        .execute(&mut *tx)
        .await?;
        if row.purpose == crate::db_volume::DB_VOLUME {
            db_volume_wrapped = Some(wrapped);
        }
        rewrapped.push(row.purpose.clone());
    }
    for required in ["ca", "tenant-kek-root"] {
        if !rewrapped.iter().any(|p| p == required) {
            return Err(ApiError::internal(format!(
                "the database holds no {required} to re-wrap"
            )));
        }
    }

    // The new data key, and every row re-encrypted under it.
    let data = DataKey::next(
        keys.metadata.epoch(),
        keys.metadata.audit_keys_since_first_rotation(),
    )?;
    let next = Intermediates::new(
        keys.tenant_kek_root.clone(),
        keys.ca_key_der.clone(),
        keys.ca_cert_der.clone(),
    )?
    .with_db_volume(keys.db_volume.clone())
    .with_data(Some(data.clone()))?;
    sqlx::query!(
        "insert into intermediate_keys (purpose, wrapped, epoch) values ('data-key', $1, $2)
           on conflict (purpose) do update set wrapped = $1, epoch = $2",
        data.wrap(&new_root)?,
        data.epoch,
    )
    .execute(&mut *tx)
    .await?;
    let rekeyed = store::rekey(&mut tx, &keys.metadata, &next.metadata).await?;

    let shares = Gf256::split_bytes(
        2,
        3,
        new_root.as_slice(),
        rand_core::UnwrapErr(getrandom::SysRng),
    )
    .map_err(|e| ApiError::internal(format!("shamir: {e:?}")))?;
    let shares: Vec<Zeroizing<Vec<u8>>> = shares.into_iter().map(Zeroizing::new).collect();
    check_split(&shares, &new_root)?;
    let aad: [u8; 32] = Sha256::digest(&node.runtime_spki).into();
    let shares_hpke: Vec<Sealed> = shares
        .iter()
        .zip(&proposal.custodians)
        .map(|(share, custodian)| alpha_crypto::seal(custodian, INFO_UNSEAL_SHARE, &aad, share))
        .collect::<Result<_, _>>()
        .map_err(|e| ApiError::internal(format!("seal share: {e}")))?;
    drop(shares);

    let id = Uuid::now_v7();
    let response = json!({
        "rotation_id": id.to_string(),
        "proposal_sha256": sha256_hex(&digest),
        "kms_node_spki_sha256": sha256_label(&node.runtime_spki),
        "custodians_sha256": proposal.custodians.iter()
            .map(|c| sha256_label(c.as_bytes())).collect::<Vec<_>>(),
        "shares_hpke_sha256": shares_hpke.iter()
            .map(sealed_sha256).collect::<Result<Vec<_>, _>>().map_err(malformed)?,
        "approved_by_shares": approved_by,
        "rewrapped": rewrapped,
        "db_volume_wrapped_sha256": db_volume_wrapped.as_deref().map(sha256_label),
        "data_key_epoch": data.epoch,
        "rekeyed": rekeyed,
    });
    let request = serde_json::to_value(proposal).map_err(malformed)?;
    let receipt = control::receipt(node, ROTATION_ROUTE, &request, response.clone())?;
    let rotation = Rotation {
        id: id.to_string(),
        proposal: proposal.clone(),
        shares_hpke,
        db_volume_wrapped: db_volume_wrapped
            .as_deref()
            .map(|w| BASE64_URL_SAFE_NO_PAD.encode(w)),
        receipt,
    };
    let stored = sqlx::query!(
        "insert into custodian_rotations (id, nonce, rotation) values ($1, $2, $3)
           on conflict (nonce) do nothing",
        id,
        nonce.as_slice(),
        serde_json::to_value(&rotation).map_err(malformed)?,
    )
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if stored != 1 {
        return Err(ApiError::new(
            "nonce_invalid",
            "the proposal's nonce has already rotated the root",
        ));
    }
    // The first row of the new epoch, sealed under its audit key.
    let appended = audit::node("custodians.rotate", "ok", response)
        .insert(&mut tx, &node.chain, Some(&next.metadata))
        .await?;
    tx.commit().await?;
    appended.committed(&node.chain);
    drop(new_root);
    *node.phase.write() = Phase::Serving(Arc::new(next));
    Ok(rotation)
}

/// Every pair of the three shares combines into the new root, before any of them leaves.
fn check_split(shares: &[Zeroizing<Vec<u8>>], root: &[u8; 32]) -> Result<(), ApiError> {
    for (a, b) in [(0, 1), (0, 2), (1, 2)] {
        let pair: Vec<Vec<u8>> = [a, b]
            .iter()
            .filter_map(|&i| shares.get(i).map(|s| s.to_vec()))
            .collect();
        let combined = Gf256::combine_bytes(&pair).map(Zeroizing::new);
        drop(Zeroizing::new(pair));
        if combined.ok().as_deref().map(Vec::as_slice) != Some(root.as_slice()) {
            return Err(ApiError::internal("the new root's shares do not combine"));
        }
    }
    Ok(())
}
