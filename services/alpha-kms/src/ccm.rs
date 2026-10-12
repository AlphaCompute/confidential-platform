//! PRD-06 I5: a Fortanix CCM-attested workload asks for a leaf, so it can call Alpha services.
//!
//! The leaf is a different kind from an Instance's: its SANs are `alphacompute-ccm://…` and
//! `urn:alphacompute:ccm-zone:…` (`alpha_channel::cert::ccm_sans`), so nothing that reads an
//! Instance leaf (the KMS's secrets and derived keys, `alpha-runtime`, `alpha_client::Pin`)
//! accepts it, and no Revision is named. It is issued only when, in order: the nonce is ours; the
//! release-signed platform document pins the CCM zone (`fortanix_ccm`); the CCM evidence verifies
//! (`alpha_attest::ccm::appraise_ccm`, which refuses every certificate until Fortanix answers F5
//! and F8); the organization the workload names has allow-listed that CCM identity in that zone,
//! unrevoked and validly signed by its key. Every request writes one `attest.ccm` audit row.

use std::sync::Arc;
use std::time::SystemTime;

use alpha_attest::ccm::{self, CcmAppraised, CcmEvidence};
use alpha_attest::{AppraisalError, Verdict, Verifiers};
use alpha_channel::cert::{CcmSans, ccm_sans};
use alpha_core::{CcmIdentityId, OrgId, context};
use axum::Json;
use axum::extract::State;
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use p256::pkcs8::DecodePublicKey;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::audit::Audit;
use crate::body::Body;
use crate::control::CcmIdentityPayload;
use crate::error::ApiError;
use crate::instance::{check_nonce, decode32};
use crate::keys::{self, SignatureObject};
use crate::{Node, certs, rfc3339};

pub const CCM_RESULT_FORMAT: &str = "alphacompute-ccm-attestation-result/1";
pub const ATTEST_CCM_ROUTE: &str = "attest.ccm";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttestCcmRequest {
    /// The P-256 key the leaf certifies, base64url SPKI, as for `POST /v1/attest`.
    pub runtime_pubkey: String,
    pub nonce: String,
    /// The organization whose allow-list the workload claims; checked, never trusted.
    pub org_id: OrgId,
    pub evidence: CcmEvidence,
}

/// `alphacompute-ccm-attestation-result/1`: what the KMS established. It names no Revision and
/// no measurement, because alpha-kms appraised no evidence itself; `verifiers` says Fortanix.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CcmAttestationResult {
    pub format: String,
    pub verdict: Verdict,
    pub org_id: OrgId,
    pub ccm_identity_id: CcmIdentityId,
    pub ccm: CcmAppraised,
    pub runtime_pubkey_sha256: String,
    pub evidence_sha256: String,
    pub verified_at: String,
    pub policy_version: u64,
    pub verifiers: Verifiers,
}

pub async fn attest_ccm(
    State(node): State<Arc<Node>>,
    Body(request, _): Body<AttestCcmRequest>,
) -> Result<Json<Value>, ApiError> {
    attest_ccm_audited(&node, &request, None).await.map(Json)
}

/// [`attest_ccm`] over a CCM appraisal the caller supplies: every step after
/// `appraise_ccm`, the platform document's zone pin and the audit row included. No route reaches
/// it. Until Fortanix names the identity fields (F5, F8) `appraise_ccm` refuses every
/// certificate, so the KMS's tests run the rest of I5 through this.
pub(crate) async fn attest_ccm_verified(
    node: &Node,
    request: &AttestCcmRequest,
    appraised: CcmAppraised,
) -> Result<Value, ApiError> {
    attest_ccm_audited(node, request, Some(appraised)).await
}

async fn attest_ccm_audited(
    node: &Node,
    request: &AttestCcmRequest,
    appraised: Option<CcmAppraised>,
) -> Result<Value, ApiError> {
    let spki = BASE64_URL_SAFE_NO_PAD
        .decode(&request.runtime_pubkey)
        .map_err(|_| ApiError::malformed("runtime_pubkey: not base64url"))?;
    p256::PublicKey::from_public_key_der(&spki)
        .map_err(|_| ApiError::malformed("runtime_pubkey: not a P-256 SPKI"))?;
    let actor = keys::sha256_hex(&spki);
    let evidence_json = alpha_core::jcs(&json!(request.evidence))
        .map_err(|e| ApiError::malformed(format!("evidence: {e}")))?;
    let evidence_sha256 = Sha256::digest(evidence_json).to_vec();
    let now = node.now();
    let result =
        match attest_ccm_inner(node, &spki, request, appraised, &evidence_sha256, now).await {
            Ok((leaf, result)) => {
                receipt(node, request, &leaf, &result, now).map(|r| (leaf, result, r))
            }
            Err(e) => Err(e),
        };
    let (outcome, details, org_id, object) = match &result {
        Ok((_, result, _)) => (
            "ok",
            json!(result),
            Some(Uuid::from(result.org_id)),
            Some(format!("ccm_identity:{}", result.ccm_identity_id)),
        ),
        Err(e) => (e.outcome(), e.details(), None, None),
    };
    Audit {
        actor_kind: "instance",
        actor: &actor,
        action: ATTEST_CCM_ROUTE,
        org_id,
        object,
        outcome,
        details,
        evidence_sha256: Some(evidence_sha256),
    }
    .insert(&node.pool)
    .await?;
    let (leaf_der, result, receipt) = result?;
    Ok(json!({
        "certificate_chain": [certs::pem(&leaf_der), node.intermediates()?.ca_pem()],
        "not_after": rfc3339(crate::later(now, certs::LEAF_TTL)?),
        "attestation_result": result,
        "attestation_receipt": receipt,
    }))
}

struct CcmIdentityRow {
    id: Uuid,
    org_id: Uuid,
    document: Value,
    created_by_key: Uuid,
    signature: Value,
    created_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
}

async fn attest_ccm_inner(
    node: &Node,
    spki: &[u8],
    request: &AttestCcmRequest,
    appraised: Option<CcmAppraised>,
    evidence_sha256: &[u8],
    now: SystemTime,
) -> Result<(Vec<u8>, CcmAttestationResult), ApiError> {
    let nonce = decode32("nonce", &request.nonce)?;
    check_nonce(&node.nonce_key, &nonce, now)?;
    let doc = node
        .platform_document()
        .ok_or_else(|| ApiError::new("attestation_unknown", "no platform document"))?;
    let pinned = ccm::pinned_zones(doc.fortanix_ccm.as_ref())?;
    let appraised = match appraised {
        Some(appraised) => appraised,
        None => ccm::appraise_ccm(
            &request.evidence,
            &nonce,
            spki,
            doc.fortanix_ccm.as_ref(),
            now,
        )?,
    };
    if !pinned.contains(&appraised.zone_ca_spki_sha256) {
        return Err(AppraisalError::Unknown(format!(
            "CCM zone {} is not pinned in the platform document",
            appraised.zone_ca_spki_sha256
        ))
        .into());
    }

    let zone = appraised
        .zone_ca_spki_sha256
        .strip_prefix("sha256:")
        .and_then(alpha_core::hex_bytes::<32>)
        .ok_or_else(|| ApiError::internal("zone digest"))?;
    let row = sqlx::query_as!(
        CcmIdentityRow,
        "select id, org_id, document, created_by_key, signature, created_at, revoked_at
         from ccm_identities where org_id = $1 and zone_ca_spki_sha256 = $2 and identity = $3",
        Uuid::from(request.org_id),
        zone.as_slice(),
        appraised.identity,
    )
    .fetch_optional(&node.pool)
    .await?
    .ok_or_else(|| {
        ApiError::new(
            "attestation_unknown",
            format!(
                "organization {} has not allow-listed this CCM identity in zone {}",
                request.org_id, appraised.zone_ca_spki_sha256
            ),
        )
    })?;
    if row.revoked_at.is_some() {
        return Err(ApiError::new(
            "policy_denied",
            "the organization revoked this CCM identity",
        ));
    }
    verify_allow_listing(node, &row, &appraised).await?;

    let keys = node.intermediates()?;
    let runtime_sha_hex = keys::sha256_hex(spki);
    let ccm_identity_id = CcmIdentityId::from(row.id);
    let leaf_der = certs::issue_leaf(
        &keys.ca_key()?,
        &keys.ca_cert_der,
        spki,
        ccm_sans(&CcmSans {
            org_id: request.org_id,
            ccm_identity_id,
            runtime_pubkey_sha256_hex: runtime_sha_hex.clone(),
            zone_ca_spki_sha256: appraised.zone_ca_spki_sha256.clone(),
        }),
        now,
    )?;
    let result = CcmAttestationResult {
        format: CCM_RESULT_FORMAT.into(),
        verdict: Verdict::Verified,
        org_id: request.org_id,
        ccm_identity_id,
        verifiers: Verifiers::of_ccm(&appraised),
        ccm: appraised,
        runtime_pubkey_sha256: format!("sha256:{runtime_sha_hex}"),
        evidence_sha256: format!("sha256:{}", hex::encode(evidence_sha256)),
        verified_at: rfc3339(now),
        policy_version: doc.version,
    };
    Ok((leaf_der, result))
}

/// The allow-listing as it is now: its stored document is what was signed, it names exactly
/// this zone and identity, and its signer's chain holds in the organization, as a Revision's is
/// checked on every attestation.
async fn verify_allow_listing(
    node: &Node,
    row: &CcmIdentityRow,
    appraised: &CcmAppraised,
) -> Result<(), ApiError> {
    let invalid = |m: &str| ApiError::signature_invalid(format!("ccm identity: {m}"));
    let document: CcmIdentityPayload =
        serde_json::from_value(row.document.clone()).map_err(|_| invalid("document"))?;
    if document.zone_ca_spki_sha256 != appraised.zone_ca_spki_sha256
        || document.identity != appraised.identity
    {
        return Err(invalid("the row differs from its signed document"));
    }
    let signature: SignatureObject =
        serde_json::from_value(row.signature.clone()).map_err(|_| invalid("signature object"))?;
    if signature.key_id.map(Uuid::from) != Some(row.created_by_key) {
        return Err(invalid("signer does not match"));
    }
    let keys = node.intermediates()?;
    let doc = node.platform_document();
    let chain = keys::verify_signed(
        &node.pool,
        &keys.tenant_kek_root,
        &signature,
        context::CCM_IDENTITY,
        &row.document,
        row.created_at,
        doc.as_deref().and_then(|d| d.signer.as_ref()),
    )
    .await?;
    if chain.key.org_id != row.org_id {
        return Err(invalid("signer is not of its organization"));
    }
    Ok(())
}

fn receipt(
    node: &Node,
    request: &AttestCcmRequest,
    leaf_der: &[u8],
    result: &CcmAttestationResult,
    now: SystemTime,
) -> Result<Value, ApiError> {
    let request = serde_json::to_value(request)
        .map_err(|e| ApiError::internal(format!("receipt request: {e}")))?;
    let response = json!({
        "attestation_result": result,
        "certificate_sha256": format!("sha256:{}", hex::encode(Sha256::digest(leaf_der))),
        "not_after": rfc3339(crate::later(now, certs::LEAF_TTL)?),
    });
    let leaf = certs::pem(&node.server_cert.leaf_der()?);
    let issued_at = node.now();
    let receipt = alpha_channel::receipt::issue(
        &node.runtime_key,
        leaf,
        ATTEST_CCM_ROUTE,
        &request,
        response,
        issued_at,
    )
    .map_err(|e| ApiError::internal(format!("receipt: {e}")))?;
    serde_json::to_value(receipt).map_err(|e| ApiError::internal(format!("receipt: {e}")))
}
