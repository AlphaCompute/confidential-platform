//! The Instance API: the stateless nonce, attestation into a one-hour leaf, and secrets and derived
//! keys over mTLS.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alpha_attest::{
    AnyEvidence, Appraised, AttestationResult, CocoAppraised, RESULT_FORMAT, Revision, Verdict,
    VerifiedQuote, appraise, kata, verify_quote,
};
use alpha_client::DerivedKey;
use alpha_client::tls::PeerCerts;
use alpha_core::coco::{self, CocoRevision};
use alpha_core::{ComposeHash, Signer, context};
use axum::Json;
use axum::body::Bytes;
use axum::extract::{Extension, Path, State};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use hmac::{Hmac, KeyInit, Mac};
use p256::pkcs8::DecodePublicKey;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::audit::Audit;
use crate::body::Body;
use crate::control::SecretPayload;
use crate::error::ApiError;
use crate::keys::{self, SignatureObject};
use crate::{CollateralSource, Node, certs, rfc3339};

pub const NONCE_MAX_AGE: Duration = Duration::from_secs(300);

fn unix(now: SystemTime) -> u64 {
    now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

/// `ts(8, BE) ‖ HMAC-SHA256(node_nonce_key, ts)[0..24]`.
pub fn mint_nonce(key: &[u8; 32], now: SystemTime) -> Result<[u8; 32], ApiError> {
    let ts = unix(now).to_be_bytes();
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|e| ApiError::internal(format!("hmac: {e}")))?;
    mac.update(&ts);
    let tag: [u8; 32] = mac.finalize().into_bytes().into();
    let (tag, _) = tag
        .split_first_chunk::<24>()
        .ok_or_else(|| ApiError::internal("hmac"))?;
    let mut nonce = [0u8; 32];
    for (dst, src) in nonce.iter_mut().zip(ts.iter().chain(tag)) {
        *dst = *src;
    }
    Ok(nonce)
}

pub fn check_nonce(key: &[u8; 32], nonce: &[u8; 32], now: SystemTime) -> Result<(), ApiError> {
    let (ts, _) = nonce
        .split_first_chunk::<8>()
        .ok_or_else(|| ApiError::internal("nonce"))?;
    let ts = u64::from_be_bytes(*ts);
    let minted = UNIX_EPOCH
        .checked_add(Duration::from_secs(ts))
        .ok_or_else(|| ApiError::new("nonce_invalid", "nonce timestamp overflows"))?;
    let expected = mint_nonce(key, minted)?;
    if expected != *nonce {
        return Err(ApiError::new("nonce_invalid", "nonce does not verify"));
    }
    let age = unix(now).saturating_sub(ts);
    if ts > unix(now) || age > NONCE_MAX_AGE.as_secs() {
        return Err(ApiError::new("nonce_invalid", "nonce is too old"));
    }
    Ok(())
}

pub async fn nonce(State(node): State<Arc<Node>>) -> Result<Json<Value>, ApiError> {
    let now = node.now();
    let nonce = mint_nonce(&node.nonce_key, now)?;
    Ok(Json(json!({
        "nonce": BASE64_URL_SAFE_NO_PAD.encode(nonce),
        "expires_at": rfc3339(crate::later(now, NONCE_MAX_AGE)?),
    })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestRequest {
    pub runtime_pubkey: String,
    pub nonce: String,
    /// `alphacompute-evidence/1` from a prototype CVM or `/2` from a Kata pod; any other format is
    /// malformed.
    pub evidence: AnyEvidence,
}

pub fn decode32(field: &str, text: &str) -> Result<[u8; 32], ApiError> {
    BASE64_URL_SAFE_NO_PAD
        .decode(text)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| ApiError::malformed(format!("{field}: expected 32 bytes base64url")))
}

pub async fn collateral(node: &Node, quote: &[u8]) -> Result<alpha_attest::Collateral, ApiError> {
    Ok(match &node.collateral {
        CollateralSource::Pccs(url) => alpha_attest::fetch_collateral(url, quote).await?,
        CollateralSource::Fixed(c) => (**c).clone(),
    })
}

/// A `revisions` row with what the checks need.
pub struct RevisionRow {
    pub app_id: Uuid,
    pub org_id: Uuid,
    pub compose: String,
    pub created_by_key: Uuid,
    pub signature: Value,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

pub async fn load_revision(
    exec: impl sqlx::PgExecutor<'_>,
    compose_hash: ComposeHash,
) -> Result<Option<RevisionRow>, ApiError> {
    Ok(sqlx::query_as!(
        RevisionRow,
        "select app_id, org_id, compose, created_by_key, signature, created_at, revoked_at
         from revisions where compose_hash = $1",
        compose_hash.as_bytes().as_slice()
    )
    .fetch_optional(exec)
    .await?)
}

/// The last appraisal step, on every attestation and every Instance call: the Revision's signature and
/// the signer's chain, from the row as it is now.
pub async fn verify_revision(
    exec: impl sqlx::PgExecutor<'_> + Copy,
    tenant_kek_root: &[u8; 32],
    compose_hash: ComposeHash,
    revision: &RevisionRow,
    signer: Option<&Signer>,
) -> Result<keys::Chain, ApiError> {
    if revision.revoked_at.is_some() {
        return Err(ApiError::new("revision_revoked", "revision is revoked"));
    }
    if alpha_core::compose_hash(&revision.compose) != compose_hash {
        return Err(ApiError::signature_invalid(
            "revision bytes do not hash to their key",
        ));
    }
    let signature: SignatureObject = serde_json::from_value(revision.signature.clone())
        .map_err(|_| ApiError::signature_invalid("revision signature object"))?;
    if signature.key_id.map(Uuid::from) != Some(revision.created_by_key) {
        return Err(ApiError::signature_invalid(
            "revision signer does not match",
        ));
    }
    let document = json!({ "app_id": revision.app_id, "compose": revision.compose });
    let chain = keys::verify_signed(
        exec,
        tenant_kek_root,
        &signature,
        context::REVISION,
        &document,
        revision.created_at,
        signer,
    )
    .await?;
    if chain.key.org_id != revision.org_id {
        return Err(ApiError::signature_invalid(
            "revision signer is not of its organization",
        ));
    }
    Ok(chain)
}

pub async fn attest(
    State(node): State<Arc<Node>>,
    Body(request, _): Body<AttestRequest>,
) -> Result<Json<Value>, ApiError> {
    attest_audited(&node, &request, None).await.map(Json)
}

/// [`attest`] for `alphacompute-evidence/2` over a TDX quote the caller has verified: every step
/// after DCAP, the audit row included. No route reaches it. The KMS's tests run the Kata pod's
/// cases through it over synthetic quotes, as `alpha_attest::kata` tests its profile, until B300
/// Kata captures exist (M1).
pub async fn attest_verified(
    node: &Node,
    request: &AttestRequest,
    verified: VerifiedQuote,
) -> Result<Value, ApiError> {
    attest_audited(node, request, Some(verified)).await
}

async fn attest_audited(
    node: &Node,
    request: &AttestRequest,
    verified: Option<VerifiedQuote>,
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
    let result = attest_inner(node, &spki, request, verified, now).await;
    let (outcome, details, org_id) = match &result {
        Ok((_, result)) => (
            "ok",
            json!(result),
            Some(Uuid::from(result.revision.org_id)),
        ),
        Err(e) => (e.outcome(), e.details(), None),
    };
    Audit {
        actor_kind: "instance",
        actor: &actor,
        action: "attest",
        org_id,
        object: result
            .as_ref()
            .ok()
            .map(|(_, result)| format!("revision:{}", result.revision.compose_hash)),
        outcome,
        details,
        evidence_sha256: Some(evidence_sha256),
    }
    .insert(&node.pool)
    .await?;
    let (leaf_der, result) = result?;
    Ok(json!({
        "certificate_chain": [certs::pem(&leaf_der), node.intermediates()?.ca_pem()],
        "not_after": rfc3339(crate::later(now, certs::LEAF_TTL)?),
        "attestation_result": result,
    }))
}

/// The leaf's DER and the result behind it. A Kata pod's quote is DCAP-verified here unless the
/// caller of [`attest_verified`] has done so.
async fn attest_inner(
    node: &Node,
    spki: &[u8],
    request: &AttestRequest,
    verified: Option<VerifiedQuote>,
    now: SystemTime,
) -> Result<(Vec<u8>, AttestationResult), ApiError> {
    let nonce = decode32("nonce", &request.nonce)?;
    check_nonce(&node.nonce_key, &nonce, now)?;
    let doc = node
        .platform_document()
        .ok_or_else(|| ApiError::new("attestation_unknown", "no platform document"))?;
    let appraised = match (&request.evidence, verified) {
        (AnyEvidence::V1(evidence), None) => {
            let collateral = collateral(node, &evidence.quote).await?;
            appraise(evidence, &nonce, spki, None, &doc, &collateral, now)?
        }
        (AnyEvidence::V1(_), Some(_)) => {
            return Err(ApiError::internal(
                "a verified quote comes with alphacompute-evidence/2 only",
            ));
        }
        (AnyEvidence::V2(evidence), verified) => {
            let verified = match verified {
                Some(verified) => verified,
                None => {
                    kata::check_cpu_kind(evidence)?;
                    let collateral = collateral(node, &evidence.cpu.quote).await?;
                    verify_quote(&evidence.cpu.quote, &collateral, &doc.policy, now)?
                }
            };
            // The TD checks, then (GPU class only) every backend the `gpu_policy` lists.
            kata::appraise_kata_tdx(
                evidence,
                verified,
                &nonce,
                spki,
                None,
                &doc,
                &node.config.gpu_backends,
            )
            .await?
        }
    };
    let keys = node.intermediates()?;
    let revision = load_revision(&node.pool, appraised.compose_hash)
        .await?
        .ok_or_else(|| unregistered(&appraised))?;
    verify_revision(
        &node.pool,
        &keys.tenant_kek_root,
        appraised.compose_hash,
        &revision,
        doc.signer.as_ref(),
    )
    .await?;
    check_platform(&revision, appraised.coco.as_ref())?;
    let runtime_sha_hex = appraised
        .runtime_pubkey_sha256
        .trim_start_matches("sha256:")
        .to_owned();
    let leaf_der = certs::issue_leaf(
        &keys.ca_key()?,
        &keys.ca_cert_der,
        spki,
        certs::instance_sans(
            revision.org_id.into(),
            revision.app_id.into(),
            &runtime_sha_hex,
            appraised.compose_hash,
        ),
        now,
    )?;
    let result = AttestationResult {
        format: RESULT_FORMAT.into(),
        verdict: Verdict::Verified,
        measured: appraised.measured,
        tcb_status: appraised.tcb_status,
        advisories: appraised.advisories,
        os_image: appraised.os_image,
        revision: Revision {
            compose_hash: appraised.compose_hash,
            app_id: revision.app_id.into(),
            org_id: revision.org_id.into(),
        },
        runtime_pubkey_sha256: appraised.runtime_pubkey_sha256,
        evidence_sha256: appraised.evidence_sha256,
        verified_at: rfc3339(now),
        policy_version: appraised.policy_version,
        coco: appraised.coco,
    };
    Ok((leaf_der, result))
}

fn unregistered(appraised: &Appraised) -> ApiError {
    let message = match &appraised.coco {
        None => format!("no revision {}", appraised.compose_hash),
        Some(coco) => format!(
            "no revision {}: the Revision v2 of this init-data (policy {}) is not registered",
            appraised.compose_hash, coco.policy_sha256
        ),
    };
    ApiError::new("attestation_unknown", message)
}

/// A registered compose is attested only by a prototype CVM (`alphacompute-evidence/1`) and a
/// registered Revision v2 only by a Kata pod (`kata-tdx/1`), whose findings must then be that
/// Revision's: its runtime class, init-data and policy digests, and exactly its GPUs, of its model.
/// The Revision hash already binds the init-data; held again here against the registered row, so
/// no leaf names a Revision whose GPUs were not the ones verified.
pub fn check_platform(
    revision: &RevisionRow,
    coco: Option<&CocoAppraised>,
) -> Result<(), ApiError> {
    let failed = |message: String| ApiError::new("attestation_failed", message);
    let is_v2 = coco::is_revision_v2(&revision.compose);
    let Some(coco) = coco else {
        if is_v2 {
            return Err(failed(
                "a Revision v2 is attested only by a Kata pod (alphacompute-evidence/2)".into(),
            ));
        }
        return Ok(());
    };
    if !is_v2 {
        return Err(failed(
            "a compose Revision is attested only by a prototype CVM (alphacompute-evidence/1)"
                .into(),
        ));
    }
    let registered = CocoRevision::check_registered(&revision.compose, revision.app_id.into())
        .map_err(|e| failed(format!("registered Revision v2: {e}")))?;
    if registered.runtime_class != coco.runtime_class
        || registered.initdata_sha256 != coco.initdata_sha256
        || registered.policy_sha256 != coco.policy_sha256
    {
        return Err(failed(
            "the appraised init-data is not the registered Revision v2's".into(),
        ));
    }
    let (count, model) = registered
        .gpu
        .as_ref()
        .map_or((0, None), |g| (g.count, Some(g.model.as_str())));
    if usize::try_from(count).ok() != Some(coco.gpus.len()) {
        return Err(failed(format!(
            "{} GPUs verified, the registered Revision expects {count}",
            coco.gpus.len()
        )));
    }
    if let Some(gpu) = coco.gpus.iter().find(|g| Some(g.model.as_str()) != model) {
        return Err(failed(format!(
            "gpu {}: model {} is not the registered Revision's",
            gpu.index, gpu.model
        )));
    }
    Ok(())
}

pub async fn get_secret(
    State(node): State<Arc<Node>>,
    Path(name): Path<String>,
    Extension(peer): Extension<PeerCerts>,
) -> Result<Json<Value>, ApiError> {
    let keys = node.intermediates()?;
    let verifier = certs::ca_verifier(&keys.ca_cert_der)?;
    let sans = certs::verify_to_ca(verifier.as_ref(), &peer.0, node.now())?;
    let identity = certs::parse_instance_sans(&sans)?;
    let result = get_secret_inner(&node, &keys.tenant_kek_root, &identity, &name).await;
    let (outcome, details) = match &result {
        Ok(_) => ("ok", json!({})),
        Err(e) => (e.outcome(), e.details()),
    };
    Audit {
        actor_kind: "instance",
        actor: &identity.runtime_pubkey_sha256_hex,
        action: "secret.get",
        org_id: Some(identity.org_id.into()),
        object: Some(format!("secret:{name}")),
        outcome,
        details,
        evidence_sha256: None,
    }
    .insert(&node.pool)
    .await?;
    result.map(Json)
}

async fn get_secret_inner(
    node: &Node,
    tenant_kek_root: &[u8; 32],
    identity: &certs::InstanceIdentity,
    name: &str,
) -> Result<Value, ApiError> {
    let doc = node.platform_document();
    let signer = doc.as_deref().and_then(|d| d.signer.as_ref());
    let revision = load_revision(&node.pool, identity.compose_hash)
        .await?
        .filter(|r| {
            r.org_id == Uuid::from(identity.org_id) && r.app_id == Uuid::from(identity.app_id)
        })
        .ok_or_else(|| ApiError::not_found("no such revision"))?;
    verify_revision(
        &node.pool,
        tenant_kek_root,
        identity.compose_hash,
        &revision,
        signer,
    )
    .await?;
    let secret = sqlx::query!(
        "select id, ciphertext, content_sha256, document, signed_by_key, signature
         from secrets where org_id = $1 and name = $2 and $3 = any(app_ids)",
        Uuid::from(identity.org_id),
        name,
        Uuid::from(identity.app_id),
    )
    .fetch_optional(&node.pool)
    .await?
    .ok_or_else(|| ApiError::not_found("no such secret for this app"))?;
    let signature: SignatureObject = serde_json::from_value(secret.signature)
        .map_err(|_| ApiError::signature_invalid("secret signature object"))?;
    if signature.key_id.map(Uuid::from) != Some(secret.signed_by_key) {
        return Err(ApiError::signature_invalid("secret signer does not match"));
    }
    // The signature covers the document alone, so the release decision is taken from the
    // document, not from the columns beside it.
    let document: SecretPayload = serde_json::from_value(secret.document.clone())
        .map_err(|_| ApiError::signature_invalid("secret document"))?;
    let content_sha256 = format!("sha256:{}", hex::encode(secret.content_sha256));
    if document.name != name || document.content_sha256 != content_sha256 {
        return Err(ApiError::signature_invalid(
            "secret row differs from its signed document",
        ));
    }
    if !document.app_ids.contains(&identity.app_id) {
        return Err(ApiError::not_found("no such secret for this app"));
    }
    let chain = keys::verify_signed(
        &node.pool,
        tenant_kek_root,
        &signature,
        context::SECRET,
        &secret.document,
        document.issued_at,
        signer,
    )
    .await?;
    if chain.key.org_id != Uuid::from(identity.org_id) {
        return Err(ApiError::signature_invalid(
            "secret signer is not of its organization",
        ));
    }
    let org_key = keys::org_key(tenant_kek_root, identity.org_id, &chain.anchor_spki)?;
    let value = keys::aead_open(&org_key, secret.id.as_bytes(), &secret.ciphertext)
        .ok_or_else(|| ApiError::internal("secret does not decrypt under org_key"))?;
    Ok(json!({
        "value": BASE64_URL_SAFE_NO_PAD.encode(&*value),
        "content_sha256": content_sha256,
        "issued_at": rfc3339(document.issued_at),
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeriveRequest {
    pub purpose: String,
}

/// The body is parsed here rather than by an extractor so that a malformed one is audited too.
pub async fn derive_key(
    State(node): State<Arc<Node>>,
    Extension(peer): Extension<PeerCerts>,
    body: Bytes,
) -> Result<Json<DerivedKey>, ApiError> {
    let keys = node.intermediates()?;
    let identity = certs::ca_verifier(&keys.ca_cert_der).and_then(|verifier| {
        let sans = certs::verify_to_ca(verifier.as_ref(), &peer.0, node.now())?;
        certs::parse_instance_sans(&sans)
    });
    let request = serde_json::from_slice::<DeriveRequest>(&body)
        .map_err(|e| ApiError::malformed(format!("body: {e}")));
    // A refused purpose is unbounded text from the peer; the error names the rule instead.
    let object = request
        .as_ref()
        .ok()
        .filter(|r| alpha_core::is_key_purpose(&r.purpose))
        .map(|r| format!("key:{}", r.purpose));
    let (actor, org_id, result) = match identity {
        Ok(identity) => {
            let result = match request {
                Ok(request) => {
                    derive_key_inner(&node, &keys.tenant_kek_root, &identity, &request.purpose)
                        .await
                }
                Err(e) => Err(e),
            };
            (
                identity.runtime_pubkey_sha256_hex.clone(),
                Some(Uuid::from(identity.org_id)),
                result,
            )
        }
        Err(e) => ("unauthenticated".to_owned(), None, Err(e)),
    };
    let (outcome, details) = match &result {
        Ok(_) => ("ok", json!({})),
        Err(e) => (e.outcome(), e.details()),
    };
    Audit {
        actor_kind: "instance",
        actor: &actor,
        action: "key.derive",
        org_id,
        object,
        outcome,
        details,
        evidence_sha256: None,
    }
    .insert(&node.pool)
    .await?;
    result.map(Json)
}

async fn derive_key_inner(
    node: &Node,
    tenant_kek_root: &[u8; 32],
    identity: &certs::InstanceIdentity,
    purpose: &str,
) -> Result<DerivedKey, ApiError> {
    if !alpha_core::is_key_purpose(purpose) {
        return Err(ApiError::malformed(
            "purpose: 1 to 64 of a-z, 0-9, '.', '_', '-', starting with a letter or digit",
        ));
    }
    let doc = node.platform_document();
    let revision = load_revision(&node.pool, identity.compose_hash)
        .await?
        .filter(|r| {
            r.org_id == Uuid::from(identity.org_id) && r.app_id == Uuid::from(identity.app_id)
        })
        .ok_or_else(|| ApiError::not_found("no such revision"))?;
    let chain = verify_revision(
        &node.pool,
        tenant_kek_root,
        identity.compose_hash,
        &revision,
        doc.as_deref().and_then(|d| d.signer.as_ref()),
    )
    .await?;
    let org_key = keys::org_key(tenant_kek_root, identity.org_id, &chain.anchor_spki)?;
    let key = keys::app_key(&org_key, identity.app_id, purpose)?;
    Ok(DerivedKey {
        key: Zeroizing::new(BASE64_URL_SAFE_NO_PAD.encode(key.as_slice())),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_is_hmac_bound_and_expires() {
        let key = [4u8; 32];
        let t0 = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let nonce = mint_nonce(&key, t0).unwrap();
        assert!(check_nonce(&key, &nonce, t0).is_ok());
        assert!(check_nonce(&key, &nonce, t0 + Duration::from_secs(299)).is_ok());
        assert_eq!(
            check_nonce(&key, &nonce, t0 + Duration::from_secs(301))
                .unwrap_err()
                .code,
            "nonce_invalid"
        );
        assert!(check_nonce(&key, &nonce, t0 - Duration::from_secs(1)).is_err());
        assert!(check_nonce(&[5u8; 32], &nonce, t0).is_err());
        let mut flipped = nonce;
        flipped[31] ^= 1;
        assert!(check_nonce(&key, &flipped, t0).is_err());
        assert_ne!(
            mint_nonce(&key, t0).unwrap(),
            mint_nonce(&key, t0 + Duration::from_secs(1)).unwrap()
        );
    }

    fn row(compose: String, app_id: Uuid) -> RevisionRow {
        RevisionRow {
            app_id,
            org_id: Uuid::now_v7(),
            compose,
            created_by_key: Uuid::now_v7(),
            signature: json!({}),
            created_at: Utc::now(),
            revoked_at: None,
        }
    }

    fn gpu(index: u32, model: &str) -> alpha_attest::VerifiedGpu {
        alpha_attest::VerifiedGpu {
            index,
            device_id: format!("ueid-{index}"),
            model: model.into(),
            driver_version: "575.51.03".into(),
            vbios_version: "97.00.9a.00.01".into(),
            cc_mode: true,
            nonce: [0; 32],
        }
    }

    /// A registered Revision v2 of eight B300s and what `kata-tdx/1` found for its pod.
    fn kata_pod() -> (RevisionRow, CocoAppraised) {
        let app = Uuid::now_v7();
        let revision = CocoRevision {
            format: coco::REVISION_FORMAT.into(),
            app_id: app.into(),
            initdata_sha256: alpha_core::compose_hash("init-data"),
            policy_sha256: alpha_core::compose_hash("policy"),
            runtime_class: coco::GPU_RUNTIME_CLASS.into(),
            gpu: Some(coco::GpuShape {
                count: 8,
                model: "B300".into(),
            }),
        };
        let found = CocoAppraised {
            profile: kata::PROFILE_KATA_TDX.into(),
            initdata_sha256: revision.initdata_sha256,
            policy_sha256: revision.policy_sha256,
            runtime_class: revision.runtime_class.clone(),
            gpus: (0..8).map(|i| gpu(i, "B300")).collect(),
            gpu_verifiers: Vec::new(),
        };
        (row(revision.canonical().unwrap(), app), found)
    }

    fn refused(result: Result<(), ApiError>, reason: &str) {
        let error = result.unwrap_err();
        assert_eq!(error.code, "attestation_failed");
        assert!(error.message.contains(reason), "{}", error.message);
    }

    #[test]
    fn a_revision_is_attested_only_by_its_own_platform_and_exactly_its_gpus() {
        let (revision, found) = kata_pod();
        assert!(check_platform(&revision, Some(&found)).is_ok());

        refused(
            check_platform(&revision, None),
            "a Revision v2 is attested only by a Kata pod",
        );
        let compose = row(r#"{"name":"app"}"#.into(), revision.app_id);
        assert!(check_platform(&compose, None).is_ok());
        refused(
            check_platform(&compose, Some(&found)),
            "a compose Revision is attested only by a prototype CVM",
        );

        let mut other = found.clone();
        other.policy_sha256 = alpha_core::compose_hash("another policy");
        refused(
            check_platform(&revision, Some(&other)),
            "not the registered Revision v2's",
        );
        let mut seven = found.clone();
        seven.gpus.pop();
        refused(
            check_platform(&revision, Some(&seven)),
            "7 GPUs verified, the registered Revision expects 8",
        );
        let mut h100 = found.clone();
        h100.gpus[3] = gpu(3, "H100");
        refused(
            check_platform(&revision, Some(&h100)),
            "gpu 3: model H100 is not the registered Revision's",
        );
        let mut foreign = revision;
        foreign.app_id = Uuid::now_v7();
        refused(
            check_platform(&foreign, Some(&found)),
            "registered Revision v2",
        );
    }
}
