//! Option B (PRD-02 deliverable 26): the KMS's side of the Trustee pods in the verifier pool
//! (`docs/trustee.md`). A Trustee pod is an attested App like any other: its leaf names its
//! Revision v2, which must be registered here and listed in the platform document's
//! `trustee.revisions`. Over mTLS with that leaf its feed:
//!
//! - reports each KBS attestation (`POST /v1/trustee/attestations`): the KMS verifies the token's
//!   signature under the Trustee App's token key, which it derives itself
//!   ([`alpha_trustee::ear::AS_TOKEN_PURPOSE`]), reads its claims, rebuilds the pod's Revision v2
//!   from the init-data the pod sent, and admits the pod only if its own rules would (reference
//!   values, TCB policy, the registered and unrevoked Revision, its GPUs);
//! - asks for one resource for one admitted pod (`POST /v1/trustee/releases`): released only if
//!   the admitted token still verifies and its claims still pass those rules under the platform
//!   document as it is now, the pod's Revision is still good, the resource is its own App's, the
//!   App's tenant-signed grant covers it, and the pod's state is fresh; audited with the pod's
//!   Revision;
//! - fetches what its Trustee decides by (`GET /v1/trustee/state`), generated now from the
//!   Revisions, grants and platform document, valid for `trustee.max_state_age_secs`;
//! - gets its KBS's TLS leaf (`POST /v1/trustee/kbs-leaf`), over its own attested key, naming
//!   `trustee.kbs_hostname`, so pods that trust the KMS CA reach no other KBS.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use alpha_attest::gpu::{self, GpuAppraisal, nras};
use alpha_attest::kata::kata_tdx_reference;
use alpha_attest::{AppraisalError, GpuVerifierKind, Measurement, PlatformDocument, VerifiedGpu};
use alpha_client::tls::PeerCerts;
use alpha_core::coco::{CocoRevision, InitData};
use alpha_core::{AppId, ComposeHash, OrgId, Trustee, context};
use alpha_trustee::ear::{AS_TOKEN_PURPOSE, PodClaims, token_signing_key, verify_token};
use alpha_trustee::policy::{self, AS_POLICY_CPU, AS_POLICY_GPU};
use alpha_trustee::resource::{GrantEntry, Resource, ResourceType};
use alpha_trustee::wire;
use axum::Json;
use axum::body::Bytes;
use axum::extract::{Extension, State};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use p256::ecdsa::VerifyingKey;
use serde_json::{Value, json};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::audit::Audit;
use crate::certs::{self, InstanceIdentity};
use crate::error::ApiError;
use crate::instance::{self, RevisionRow, load_revision, verify_revision};
use crate::keys::{self, SignatureObject};
use crate::{Intermediates, Node, rfc3339};

/// How far ahead of the KMS's clock a feed's `state_generated_at` may be.
const CLOCK_SKEW: Duration = Duration::from_secs(60);

/// A Trustee pod calling over mTLS: its leaf, its listed and registered Revision, and the
/// document that listed it.
pub struct Caller {
    pub identity: InstanceIdentity,
    pub spki: Vec<u8>,
    pub doc: Arc<PlatformDocument>,
    pub trustee: Trustee,
}

fn unlisted(message: impl Into<String>) -> ApiError {
    ApiError::new("attestation_unknown", message)
}

/// The leaf verifies to the CA, names a Revision the platform document lists as a Trustee build,
/// and that Revision is registered here, unrevoked and validly signed.
pub async fn caller(
    node: &Node,
    keys: &Intermediates,
    peer: &PeerCerts,
) -> Result<Caller, ApiError> {
    let verifier = certs::ca_verifier(&keys.ca_cert_der)?;
    let sans = certs::verify_to_ca(verifier.as_ref(), &peer.0, node.now())?;
    let identity = certs::parse_instance_sans(&sans)?;
    let leaf = peer
        .0
        .first()
        .ok_or_else(|| ApiError::new("cert_invalid", "no client certificate"))?;
    let spki = certs::spki_of(leaf)?;
    let doc = node
        .platform_document()
        .ok_or_else(|| unlisted("no platform document"))?;
    let trustee = doc
        .trustee
        .clone()
        .ok_or_else(|| unlisted("the platform document lists no Trustee"))?;
    if !trustee.lists(identity.compose_hash) {
        return Err(unlisted(format!(
            "revision {} is not a Trustee build the platform document lists",
            identity.compose_hash
        )));
    }
    let revision = load_revision(&node.pool, identity.compose_hash)
        .await?
        .filter(|r| {
            r.org_id == Uuid::from(identity.org_id) && r.app_id == Uuid::from(identity.app_id)
        })
        .ok_or_else(|| ApiError::not_found("no such revision"))?;
    verify_revision(
        &node.pool,
        &keys.tenant_kek_root,
        identity.compose_hash,
        &revision,
        doc.signer.as_ref(),
    )
    .await?;
    Ok(Caller {
        identity,
        spki,
        doc,
        trustee,
    })
}

/// The Apps of the Trustee builds the document lists: their resources are never released
/// through Trustee, so no grant can hand a Trustee pod's own keys to a pod.
pub async fn trustee_apps(
    exec: impl sqlx::PgExecutor<'_>,
    doc: &PlatformDocument,
) -> Result<Vec<Uuid>, ApiError> {
    let hashes: Vec<Vec<u8>> = doc
        .trustee
        .iter()
        .flat_map(|t| t.revisions.iter())
        .map(|r| r.compose_hash.as_bytes().to_vec())
        .collect();
    Ok(sqlx::query_scalar!(
        "select distinct app_id from revisions where compose_hash = any($1)",
        &hashes
    )
    .fetch_all(exec)
    .await?)
}

/// One audit row of a Trustee route, written whatever the outcome.
async fn audited(
    node: &Node,
    action: &str,
    actor: &str,
    org_id: Option<Uuid>,
    object: Option<String>,
    result: Result<Value, &ApiError>,
    evidence_sha256: Option<Vec<u8>>,
) -> Result<(), ApiError> {
    let (outcome, details) = match result {
        Ok(details) => ("ok", details),
        Err(e) => (e.outcome(), e.details()),
    };
    Audit {
        actor_kind: "instance",
        actor,
        action,
        org_id,
        object,
        outcome,
        details,
        evidence_sha256,
    }
    .insert(&node.pool)
    .await?;
    Ok(())
}

fn actor(caller: &Result<Caller, ApiError>) -> String {
    caller.as_ref().map_or_else(
        |_| "unauthenticated".to_owned(),
        |c| c.identity.runtime_pubkey_sha256_hex.clone(),
    )
}

fn body<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, ApiError> {
    let value = alpha_core::parse(bytes).map_err(|e| ApiError::malformed(format!("body: {e}")))?;
    serde_json::from_value(value).map_err(|e| ApiError::malformed(format!("body: {e}")))
}

/// What the KMS's own rules say of a pod Trustee attested: the registers one `kata-tdx` reference
/// value of the Revision's runtime class by `kata-tdx/1`'s own rule (every register handed to
/// [`kata_tdx_reference`], which compares MRTD and RTMR0..2 and, as the profile does, not the
/// guest's runtime register RTMR3), the TCB policy, no debug, and exactly the Revision's GPUs as
/// the KMS's GPU decision (`alpha_attest::gpu::check_gpus`) takes them. Trustee has checked the
/// quote's signature and collateral, the init-data's digest against MRCONFIGID, the nonces and
/// NRAS's signatures, and the KMS that Trustee's key signed the token; this is every policy
/// decision on what those checks found.
pub fn check_claims(
    doc: &PlatformDocument,
    revision: &CocoRevision,
    claims: &PodClaims,
) -> Result<(), ApiError> {
    use AppraisalError::*;

    if kata_tdx_reference(doc, &revision.runtime_class, &claims.measured()).is_none() {
        return Err(Unknown(format!(
            "no kata-tdx reference value for mrtd {} and runtime class {}",
            claims.mrtd, revision.runtime_class
        ))
        .into());
    }
    if !doc.policy.tcb_statuses.contains(&claims.tcb_status) {
        return Err(PolicyDenied(format!("tcb_status {}", claims.tcb_status)).into());
    }
    if let Some(advisory) = claims
        .advisories
        .iter()
        .find(|a| !doc.policy.tolerated_advisories.contains(a))
    {
        return Err(PolicyDenied(format!("advisory {advisory}")).into());
    }
    if claims.debug {
        return Err(PolicyDenied("debug TD".into()).into());
    }
    let Some(shape) = &revision.gpu else {
        if !claims.gpus.is_empty() {
            return Err(Failed(format!(
                "{} GPUs attested for a Revision that runs none",
                claims.gpus.len()
            ))
            .into());
        }
        return Ok(());
    };
    if let Some(refusal) = policy::gpu_refusal(doc) {
        return Err(Unknown(format!("no GPU through Trustee: {refusal}")).into());
    }
    let gpu_policy = doc
        .gpu_policy
        .as_ref()
        .ok_or_else(|| Unknown("no gpu_policy".into()))?;
    let mut gpus = Vec::with_capacity(claims.gpus.len());
    for (index, c) in claims.gpus.iter().enumerate() {
        if let Some(failure) = nras::claim_report(c, gpu_policy).into_iter().next() {
            return Err(Failed(format!("gpu {index}: {failure}")).into());
        }
        let text = |name: &str| {
            c.get(name)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| Failed(format!("gpu {index}: claim /{name} is missing")))
        };
        let hwmodel = text(nras::claims::HWMODEL)?;
        gpus.push(VerifiedGpu {
            index: u32::try_from(index).map_err(|_| Failed("gpu index".into()))?,
            device_id: text(nras::claims::UEID)?,
            model: gpu_policy
                .hwmodels
                .get(&hwmodel)
                .cloned()
                .ok_or_else(|| Failed(format!("gpu {index}: hwmodel {hwmodel:?}")))?,
            driver_version: text(nras::claims::DRIVER)?,
            vbios_version: text(nras::claims::VBIOS)?,
            // claim_report refuses a GPU whose CC-mode claim is not the policy's.
            cc_mode: true,
            // Trustee bound each report to its own nonce (the nonce-match claim above).
            nonce: [0; 32],
        });
    }
    gpu::check_gpus(
        Some(gpu_policy),
        shape,
        claims.gpus.len(),
        &[GpuAppraisal {
            verifier: GpuVerifierKind::Nras,
            gpus,
            token_sha256: [0; 32],
        }],
        &[0; 32],
    )?;
    Ok(())
}

/// The key the Attestation Service of `trustee`'s App signs tokens with: the App's derived key for
/// [`AS_TOKEN_PURPOSE`], derived here exactly as the Trustee pod's feed got it from
/// `/v1/keys/derive`. Pinned by the KMS's own key hierarchy to a Trustee build the release-signed
/// platform document lists, never taken from a token's header nor fetched.
async fn token_key(
    node: &Node,
    keys: &Intermediates,
    trustee: &InstanceIdentity,
) -> Result<VerifyingKey, ApiError> {
    let derived =
        instance::derive_key_inner(node, &keys.tenant_kek_root, trustee, AS_TOKEN_PURPOSE).await?;
    let bytes = Zeroizing::new(
        BASE64_URL_SAFE_NO_PAD
            .decode(derived.key.as_bytes())
            .map_err(|_| ApiError::internal("derived key"))?,
    );
    let scalar = Zeroizing::new(
        <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| ApiError::internal("derived key"))?,
    );
    Ok(*token_signing_key(&scalar)
        .map_err(ApiError::internal)?
        .verifying_key())
}

/// A token's claims once it verifies under `trustee`'s token key, now.
async fn verified_claims(
    node: &Node,
    keys: &Intermediates,
    trustee: &InstanceIdentity,
    token: &str,
) -> Result<PodClaims, ApiError> {
    let key = token_key(node, keys, trustee).await?;
    verify_token(token, &key, node.now())
        .and_then(|p| PodClaims::from_payload(&p))
        .map_err(|e| ApiError::new("attestation_failed", e))
}

/// The pod's registered Revision v2, rebuilt from the init-data it sent, whose digest must be the
/// token's MRCONFIGID.
async fn pod_revision(
    node: &Node,
    keys: &Intermediates,
    doc: &PlatformDocument,
    initdata: &[u8],
    claims: &PodClaims,
) -> Result<(CocoRevision, ComposeHash, RevisionRow), ApiError> {
    let failed = |m: String| ApiError::new("attestation_failed", m);
    let parsed = InitData::parse(initdata).map_err(|e| failed(format!("init-data: {e}")))?;
    if Measurement(parsed.mrconfigid()) != claims.mrconfigid {
        return Err(failed(
            "MRCONFIGID is not the digest of the init-data sent".into(),
        ));
    }
    let revision = parsed
        .revision()
        .map_err(|e| failed(format!("init-data: {e}")))?;
    let hash = revision
        .hash()
        .map_err(|e| failed(format!("revision: {e}")))?;
    let row = load_revision(&node.pool, hash).await?.ok_or_else(|| {
        ApiError::new(
            "attestation_unknown",
            format!("no revision {hash}: the Revision v2 of this init-data is not registered"),
        )
    })?;
    let registered = CocoRevision::check_registered(&row.compose, row.app_id.into())
        .map_err(|e| failed(format!("registered Revision v2: {e}")))?;
    if registered != revision {
        return Err(failed(
            "the init-data is not the registered Revision v2's".into(),
        ));
    }
    verify_revision(
        &node.pool,
        &keys.tenant_kek_root,
        hash,
        &row,
        doc.signer.as_ref(),
    )
    .await?;
    Ok((revision, hash, row))
}

pub async fn register_attestation(
    State(node): State<Arc<Node>>,
    Extension(peer): Extension<PeerCerts>,
    bytes: Bytes,
) -> Result<Json<wire::Admitted>, ApiError> {
    let keys = node.intermediates()?;
    let caller = caller(&node, &keys, &peer).await;
    let request = body::<wire::Attestation>(&bytes);
    let token_sha256 = request
        .as_ref()
        .ok()
        .map(|r| alpha_trustee::ear::token_sha256(&r.token).to_vec());
    let result = match (&caller, &request) {
        (Ok(caller), Ok(request)) => {
            admit(&node, &keys, caller, request, token_sha256.as_deref()).await
        }
        (Err(e), _) | (_, Err(e)) => Err(ApiError::new(e.code, e.message.clone())),
    };
    let org_id = result.as_ref().ok().map(|(_, org)| Uuid::from(*org));
    let object = result
        .as_ref()
        .ok()
        .map(|(a, _)| format!("revision:{}", a.revision));
    let details = result.as_ref().map(|(a, _)| {
        json!({
            "trustee_revision": caller.as_ref().map(|c| c.identity.compose_hash).ok(),
            "app_id": a.app_id,
            "mrconfigid": a.mrconfigid,
            "expires_at": a.expires_at,
        })
    });
    audited(
        &node,
        "trustee.attest",
        &actor(&caller),
        org_id,
        object,
        details,
        token_sha256,
    )
    .await?;
    result.map(|(a, _)| Json(a))
}

async fn admit(
    node: &Node,
    keys: &Intermediates,
    caller: &Caller,
    request: &wire::Attestation,
    token_sha256: Option<&[u8]>,
) -> Result<(wire::Admitted, OrgId), ApiError> {
    let token_sha256 = token_sha256.ok_or_else(|| ApiError::internal("token digest"))?;
    let claims = verified_claims(node, keys, &caller.identity, &request.token).await?;
    let now = node.now();
    let expires = SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(claims.expires))
        .ok_or_else(|| ApiError::malformed("token exp overflows"))?;
    if expires <= now {
        return Err(ApiError::new("attestation_failed", "the token has expired"));
    }
    let expires = expires.min(crate::later(now, certs::LEAF_TTL)?);
    let initdata = BASE64_URL_SAFE_NO_PAD
        .decode(&request.initdata)
        .map_err(|_| ApiError::malformed("initdata: not base64url"))?;
    let (revision, hash, row) = pod_revision(node, keys, &caller.doc, &initdata, &claims).await?;
    check_claims(&caller.doc, &revision, &claims)?;
    let mrconfigid = claims.mrconfigid.0.to_vec();
    let expires_at: DateTime<Utc> = expires.into();
    let mut tx = node.pool.begin().await?;
    let stale = node
        .now_utc()
        .checked_sub_signed(chrono::Duration::days(1))
        .ok_or_else(|| ApiError::internal("time underflows the clock"))?;
    sqlx::query!(
        "delete from trustee_attestations where expires_at < $1",
        stale
    )
    .execute(&mut *tx)
    .await?;
    let inserted = sqlx::query!(
        "insert into trustee_attestations (token_sha256, trustee_revision, revision, app_id, org_id, mrconfigid, expires_at, token)
         values ($1, $2, $3, $4, $5, $6, $7, $8) on conflict (token_sha256) do nothing",
        token_sha256,
        caller.identity.compose_hash.as_bytes().as_slice(),
        hash.as_bytes().as_slice(),
        row.app_id,
        row.org_id,
        &mrconfigid,
        expires_at,
        request.token,
    )
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if inserted == 0 {
        let same = sqlx::query_scalar!(
            "select revision = $2 from trustee_attestations where token_sha256 = $1",
            token_sha256,
            hash.as_bytes().as_slice(),
        )
        .fetch_one(&mut *tx)
        .await?;
        if same != Some(true) {
            return Err(ApiError::new(
                "already_exists",
                "this token is reported for another pod",
            ));
        }
    }
    tx.commit().await?;
    Ok((
        wire::Admitted {
            app_id: row.app_id.into(),
            revision: hash,
            mrconfigid: hex::encode(&mrconfigid),
            expires_at: rfc3339(expires_at),
        },
        row.org_id.into(),
    ))
}

/// A tenant's grant, its signature and its signer's chain checked as the row is now.
pub struct Grant {
    pub app_id: Uuid,
    pub org_id: Uuid,
    pub resources: Vec<GrantEntry>,
}

pub async fn load_grants(
    node: &Node,
    keys: &Intermediates,
    doc: &PlatformDocument,
    app: Option<Uuid>,
) -> Result<Vec<Grant>, ApiError> {
    let rows = sqlx::query!(
        "select app_id, org_id, document, signed_by_key, signature, issued_at from trustee_grants
         where $1::uuid is null or app_id = $1",
        app
    )
    .fetch_all(&node.pool)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let signature: SignatureObject = serde_json::from_value(row.signature)
            .map_err(|_| ApiError::signature_invalid("grant signature object"))?;
        if signature.key_id.map(Uuid::from) != Some(row.signed_by_key) {
            return Err(ApiError::signature_invalid("grant signer does not match"));
        }
        let payload: wire::GrantPayload = serde_json::from_value(row.document.clone())
            .map_err(|_| ApiError::signature_invalid("grant document"))?;
        if Uuid::from(payload.app_id) != row.app_id {
            return Err(ApiError::signature_invalid(
                "grant row differs from its signed document",
            ));
        }
        let chain = keys::verify_signed(
            &node.pool,
            &keys.tenant_kek_root,
            &signature,
            context::TRUSTEE_GRANT,
            &row.document,
            row.issued_at,
            doc.signer.as_ref(),
        )
        .await?;
        if chain.key.org_id != row.org_id {
            return Err(ApiError::signature_invalid(
                "grant signer is not of its organization",
            ));
        }
        out.push(Grant {
            app_id: row.app_id,
            org_id: row.org_id,
            resources: payload.resources,
        });
    }
    Ok(out)
}

fn stored_hash(bytes: &[u8]) -> Result<ComposeHash, ApiError> {
    <[u8; 32]>::try_from(bytes)
        .map(ComposeHash::from)
        .map_err(|_| ApiError::internal("stored revision hash"))
}

fn parse_time(field: &str, text: &str) -> Result<SystemTime, ApiError> {
    DateTime::parse_from_rfc3339(text)
        .map(|t| SystemTime::from(t.with_timezone(&Utc)))
        .map_err(|_| ApiError::malformed(format!("{field}: not RFC 3339")))
}

/// Refuses a feed acting on state older than the document allows, or from the future.
pub fn check_fresh(
    trustee: &Trustee,
    generated_at: SystemTime,
    now: SystemTime,
) -> Result<(), ApiError> {
    let stale = |m: String| ApiError::new("policy_denied", m);
    if generated_at > crate::later(now, CLOCK_SKEW)? {
        return Err(stale("the Trustee pod's state is from the future".into()));
    }
    let age = now.duration_since(generated_at).unwrap_or_default();
    if age > Duration::from_secs(u64::from(trustee.max_state_age_secs)) {
        return Err(stale(format!(
            "the Trustee pod's state is {}s old, more than trustee.max_state_age_secs {}",
            age.as_secs(),
            trustee.max_state_age_secs
        )));
    }
    Ok(())
}

pub async fn release(
    State(node): State<Arc<Node>>,
    Extension(peer): Extension<PeerCerts>,
    bytes: Bytes,
) -> Result<Json<wire::Released>, ApiError> {
    let keys = node.intermediates()?;
    let caller = caller(&node, &keys, &peer).await;
    let request = body::<wire::Release>(&bytes);
    // A refused resource name is unbounded text from the caller; only a parsed one is logged.
    let resource = request
        .as_ref()
        .ok()
        .and_then(|r| Resource::parse(&r.resource).ok());
    let result = match (&caller, &request) {
        (Ok(caller), Ok(request)) => release_inner(&node, &keys, caller, request).await,
        (Err(e), _) | (_, Err(e)) => Err(ApiError::new(e.code, e.message.clone())),
    };
    let org_id = result.as_ref().ok().map(|(_, pod)| pod.org_id);
    let details = result.as_ref().map(|(_, pod)| {
        json!({
            "trustee_revision": caller.as_ref().map(|c| c.identity.compose_hash).ok(),
            "revision": pod.revision,
            "token_sha256": request.as_ref().map(|r| r.token_sha256.clone()).ok(),
        })
    });
    audited(
        &node,
        "trustee.release",
        &actor(&caller),
        org_id,
        resource.map(|r| r.uri()),
        details,
        None,
    )
    .await?;
    result.map(|(released, _)| Json(released))
}

/// The admitted pod a release is for.
pub struct Pod {
    pub org_id: Uuid,
    pub app_id: Uuid,
    pub revision: ComposeHash,
}

async fn release_inner(
    node: &Node,
    keys: &Intermediates,
    caller: &Caller,
    request: &wire::Release,
) -> Result<(wire::Released, Pod), ApiError> {
    let now = node.now();
    check_fresh(
        &caller.trustee,
        parse_time("state_generated_at", &request.state_generated_at)?,
        now,
    )?;
    let resource = Resource::parse(&request.resource).map_err(ApiError::malformed)?;
    let token_sha256: [u8; 32] = request
        .token_sha256
        .strip_prefix("sha256:")
        .and_then(alpha_core::hex_bytes)
        .ok_or_else(|| ApiError::malformed("token_sha256: expected sha256:<hex>"))?;
    let row = sqlx::query!(
        "select trustee_revision, revision, app_id, org_id, mrconfigid, expires_at, token
         from trustee_attestations where token_sha256 = $1",
        token_sha256.as_slice()
    )
    .fetch_optional(&node.pool)
    .await?
    .filter(|r| r.expires_at > node.now_utc())
    .ok_or_else(|| {
        ApiError::new(
            "attestation_unknown",
            "no admitted attestation for this token, or it has expired",
        )
    })?;
    let registered_by = stored_hash(&row.trustee_revision)?;
    if !caller.trustee.lists(registered_by) {
        return Err(ApiError::new(
            "attestation_unknown",
            "the Trustee build that reported this attestation is no longer listed",
        ));
    }
    let revision = stored_hash(&row.revision)?;
    recheck(
        node,
        keys,
        caller,
        &row.token,
        &token_sha256,
        registered_by,
        revision,
    )
    .await?;
    let pod = Pod {
        org_id: row.org_id,
        app_id: row.app_id,
        revision,
    };
    if Uuid::from(resource.app) != row.app_id {
        return Err(ApiError::not_found("no such resource for this pod"));
    }
    if trustee_apps(&node.pool, &caller.doc)
        .await?
        .contains(&row.app_id)
    {
        return Err(ApiError::new(
            "policy_denied",
            "a Trustee App's resources are never released through Trustee",
        ));
    }
    let grants = load_grants(node, keys, &caller.doc, Some(row.app_id)).await?;
    if !grants
        .iter()
        .flat_map(|g| g.resources.iter())
        .any(|entry| entry.covers(&resource))
    {
        return Err(ApiError::new(
            "policy_denied",
            "the App's grant does not cover this resource",
        ));
    }
    // The pod's Revision as it is now: a revocation since the attestation refuses here.
    let identity = InstanceIdentity {
        org_id: row.org_id.into(),
        app_id: row.app_id.into(),
        runtime_pubkey_sha256_hex: hex::encode(token_sha256),
        compose_hash: revision,
    };
    let value = match resource.kind.secret_name(&resource.tag) {
        Some(name) => {
            let reply =
                instance::get_secret_inner(node, &keys.tenant_kek_root, &identity, &name).await?;
            let value = reply
                .get("value")
                .and_then(Value::as_str)
                .and_then(|v| BASE64_URL_SAFE_NO_PAD.decode(v).ok())
                .ok_or_else(|| ApiError::internal("secret value"))?;
            check_value(resource.kind, &value)?;
            value
        }
        None => {
            let derived =
                instance::derive_key_inner(node, &keys.tenant_kek_root, &identity, &resource.tag)
                    .await?;
            BASE64_URL_SAFE_NO_PAD
                .decode(derived.key.as_bytes())
                .map_err(|_| ApiError::internal("derived key"))?
        }
    };
    Ok((
        wire::Released {
            value: BASE64_URL_SAFE_NO_PAD.encode(&value),
            app_id: row.app_id.into(),
            mrconfigid: hex::encode(&row.mrconfigid),
        },
        pod,
    ))
}

/// The admitted row is not trusted alone: its token must still verify under the key of the Trustee
/// App that reported it, and its claims must still pass [`check_claims`] for the pod's registered
/// Revision v2 under the platform document as it is now. A reference value, TCB status, tolerated
/// advisory or GPU rule withdrawn since admission refuses the release.
async fn recheck(
    node: &Node,
    keys: &Intermediates,
    caller: &Caller,
    token: &str,
    token_sha256: &[u8; 32],
    registered_by: ComposeHash,
    revision: ComposeHash,
) -> Result<(), ApiError> {
    if alpha_trustee::ear::token_sha256(token) != *token_sha256 {
        return Err(ApiError::internal("stored token digest"));
    }
    let unknown = |m: &str| ApiError::new("attestation_unknown", m);
    let reporter = load_revision(&node.pool, registered_by)
        .await?
        .ok_or_else(|| unknown("the Trustee build that reported this attestation is gone"))?;
    let reporter = InstanceIdentity {
        org_id: reporter.org_id.into(),
        app_id: reporter.app_id.into(),
        runtime_pubkey_sha256_hex: String::new(),
        compose_hash: registered_by,
    };
    let claims = verified_claims(node, keys, &reporter, token).await?;
    let row = load_revision(&node.pool, revision)
        .await?
        .ok_or_else(|| unknown("the attested pod's Revision is gone"))?;
    let registered = CocoRevision::check_registered(&row.compose, row.app_id.into())
        .map_err(|e| ApiError::new("attestation_failed", format!("registered Revision v2: {e}")))?;
    check_claims(&caller.doc, &registered, &claims)
}

/// What the guest does with the value decides its form: a key-encryption key is 32 bytes, a
/// sealed secret's verification key a public P-256 JWK (never one holding its private part).
pub fn check_value(kind: ResourceType, value: &[u8]) -> Result<(), ApiError> {
    let bad = |m: &str| ApiError::new("policy_denied", format!("{}: {m}", kind.name()));
    match kind {
        ResourceType::ImageKey if value.len() != 32 => Err(bad("not a 32-byte key")),
        ResourceType::SealedSecretKey => {
            let jwk: Value =
                serde_json::from_slice(value).map_err(|_| bad("not a JSON Web Key"))?;
            let public_p256 = jwk.get("kty") == Some(&json!("EC"))
                && jwk.get("crv") == Some(&json!("P-256"))
                && jwk.get("x").is_some_and(Value::is_string)
                && jwk.get("y").is_some_and(Value::is_string)
                && jwk.get("d").is_none();
            if public_p256 {
                Ok(())
            } else {
                Err(bad("not a public P-256 JWK"))
            }
        }
        _ => Ok(()),
    }
}

pub async fn state(
    State(node): State<Arc<Node>>,
    Extension(peer): Extension<PeerCerts>,
) -> Result<Json<wire::State>, ApiError> {
    let keys = node.intermediates()?;
    let caller = caller(&node, &keys, &peer).await;
    let result = match &caller {
        Ok(caller) => state_inner(&node, &keys, caller).await,
        Err(e) => Err(ApiError::new(e.code, e.message.clone())),
    };
    // Only refusals: a pod fetches state every minute, and the state is a function of the rows
    // the other routes audit.
    if let Err(e) = &result {
        audited(
            &node,
            "trustee.state",
            &actor(&caller),
            None,
            None,
            Err(e),
            None,
        )
        .await?;
    }
    result.map(Json)
}

/// What the resource policy admits: every registered, unrevoked, validly signed Revision v2 of
/// an App with a grant whose MRCONFIGID a Trustee attestation showed, never a Trustee App's.
pub async fn admitted(
    node: &Node,
    keys: &Intermediates,
    doc: &PlatformDocument,
) -> Result<Vec<policy::Admitted>, ApiError> {
    let excluded = trustee_apps(&node.pool, doc).await?;
    let grants: BTreeMap<Uuid, Grant> = load_grants(node, keys, doc, None)
        .await?
        .into_iter()
        .filter(|g| !g.resources.is_empty() && !excluded.contains(&g.app_id))
        .map(|g| (g.app_id, g))
        .collect();
    let apps: Vec<Uuid> = grants.keys().copied().collect();
    let rows = sqlx::query!(
        r#"select distinct r.compose_hash, a.mrconfigid from revisions r
           join trustee_attestations a on a.revision = r.compose_hash
           where r.revoked_at is null and r.app_id = any($1)
           order by r.compose_hash"#,
        &apps
    )
    .fetch_all(&node.pool)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let hash = stored_hash(&row.compose_hash)?;
        let Some(revision) = load_revision(&node.pool, hash).await? else {
            continue;
        };
        if verify_revision(
            &node.pool,
            &keys.tenant_kek_root,
            hash,
            &revision,
            doc.signer.as_ref(),
        )
        .await
        .is_err()
        {
            continue;
        }
        let Ok(coco) = CocoRevision::check_registered(&revision.compose, revision.app_id.into())
        else {
            continue;
        };
        let Some(grant) = grants.get(&revision.app_id) else {
            continue;
        };
        let mrconfigid: [u8; 48] = row
            .mrconfigid
            .as_slice()
            .try_into()
            .map_err(|_| ApiError::internal("stored mrconfigid"))?;
        out.push(policy::Admitted {
            app: AppId::from(revision.app_id),
            mrconfigid: Measurement(mrconfigid),
            runtime_class: coco.runtime_class,
            gpu: coco.gpu,
            resources: grant.resources.clone(),
        });
    }
    Ok(out)
}

async fn state_inner(
    node: &Node,
    keys: &Intermediates,
    caller: &Caller,
) -> Result<wire::State, ApiError> {
    let doc = &caller.doc;
    let admitted = admitted(node, keys, doc).await?;
    let now = node.now();
    let mut entries: Vec<wire::StateEntry> = admitted
        .iter()
        .map(|a| wire::StateEntry {
            app_id: a.app,
            mrconfigid: hex::encode(a.mrconfigid.0),
        })
        .collect();
    entries.sort();
    Ok(wire::State {
        generated_at: rfc3339(now),
        not_after: rfc3339(crate::later(
            now,
            Duration::from_secs(u64::from(caller.trustee.max_state_age_secs)),
        )?),
        platform_version: doc.version,
        resource_policy: policy::resource_policy(&admitted, doc.gpu_policy.as_ref()),
        attestation_policies: BTreeMap::from([
            (
                AS_POLICY_CPU.to_owned(),
                policy::attestation_policy_cpu(doc),
            ),
            (
                AS_POLICY_GPU.to_owned(),
                policy::attestation_policy_gpu(doc),
            ),
        ]),
        reference_values: policy::reference_values(doc),
        nras_verifier_url: policy::nras_verifier_url(doc),
        admitted: entries,
    })
}

pub async fn kbs_leaf(
    State(node): State<Arc<Node>>,
    Extension(peer): Extension<PeerCerts>,
) -> Result<Json<wire::KbsLeaf>, ApiError> {
    let keys = node.intermediates()?;
    let caller = caller(&node, &keys, &peer).await;
    let now = node.now();
    let result = match &caller {
        Ok(caller) => certs::issue_server_leaf(
            &keys.ca_key()?,
            &keys.ca_cert_der,
            &caller.spki,
            &caller.trustee.kbs_hostname,
            now,
        )
        .map(|leaf| (leaf, caller.trustee.kbs_hostname.clone())),
        Err(e) => Err(ApiError::new(e.code, e.message.clone())),
    };
    let details = result
        .as_ref()
        .map(|(_, host)| json!({ "dns_name": host, "trustee_revision": caller.as_ref().map(|c| c.identity.compose_hash).ok() }));
    audited(
        &node,
        "trustee.kbs-leaf",
        &actor(&caller),
        None,
        None,
        details,
        None,
    )
    .await?;
    let (leaf, _) = result?;
    Ok(Json(wire::KbsLeaf {
        certificate_chain: vec![certs::pem(&leaf), keys.ca_pem()],
        not_after: rfc3339(crate::later(now, certs::LEAF_TTL)?),
    }))
}

#[cfg(test)]
mod tests {
    use alpha_core::coco::{CPU_RUNTIME_CLASS, GPU_RUNTIME_CLASS, GpuShape};
    use alpha_trustee::ear::sample::{hex48, payload};

    use super::*;

    fn doc() -> PlatformDocument {
        let rv = |class: &str, byte: u8| {
            json!({ "name": class, "kind": "kata-tdx", "runtime_class": class,
                    "values": { "mrtd": format!("sha384:{}", hex48(byte)),
                                "rtmr0": format!("sha384:{}", hex48(byte + 1)),
                                "rtmr1": format!("sha384:{}", hex48(byte + 2)),
                                "rtmr2": format!("sha384:{}", hex48(byte + 3)) } })
        };
        serde_json::from_value(json!({
            "version": 4, "issued_at": "2026-12-01T00:00:00Z",
            "policy": { "tcb_statuses": ["UpToDate"], "tolerated_advisories": ["INTEL-SA-1"] },
            "reference_values": [rv(CPU_RUNTIME_CLASS, 0x10), rv(GPU_RUNTIME_CLASS, 0x20)],
            "kms_ca_pem": "", "kms_revisions": [],
            "gpu_policy": {
                "allowed_models": ["B300"], "verifiers": ["nras"],
                "min_driver_version": "590.0",
                "hwmodels": { "GB110": "B300", "GH100": "H100" },
                "nras_cc_mode": { "pointer": "/x-nvidia-gpu-cc-mode", "equals": "on" }
            }
        }))
        .unwrap()
    }

    fn revision(class: &str, gpus: Option<u32>) -> CocoRevision {
        CocoRevision {
            format: alpha_core::coco::REVISION_FORMAT.into(),
            app_id: AppId::mint(),
            initdata_sha256: alpha_core::compose_hash("i"),
            policy_sha256: alpha_core::compose_hash("p"),
            runtime_class: class.into(),
            gpu: gpus.map(|count| GpuShape {
                count,
                model: "B300".into(),
            }),
        }
    }

    pub(crate) fn gpu_claims(ueid: &str) -> Value {
        let mut c = json!({ "hwmodel": "GB110", "ueid": ueid,
                            "x-nvidia-gpu-driver-version": "595.58.03",
                            "x-nvidia-gpu-vbios-version": "97.00.9a.00.01",
                            "x-nvidia-gpu-cc-mode": "on" });
        for (pointer, expect) in nras::claims::REQUIRED {
            let value = match expect {
                nras::claims::Expect::Text(t) => json!(t),
                _ => json!(true),
            };
            let mut at = &mut c;
            let segments: Vec<&str> = pointer.trim_start_matches('/').split('/').collect();
            for (i, s) in segments.iter().enumerate() {
                if i + 1 == segments.len() {
                    at[*s] = value.clone();
                } else {
                    if at.get(*s).is_none() {
                        at[*s] = json!({});
                    }
                    at = &mut at[*s];
                }
            }
        }
        c
    }

    fn claims(class_byte: u8, gpus: &[Value]) -> PodClaims {
        let r = [
            hex48(class_byte),
            hex48(class_byte + 1),
            hex48(class_byte + 2),
            hex48(class_byte + 3),
            hex48(5),
        ];
        PodClaims::from_payload(&payload(
            [&r[0], &r[1], &r[2], &r[3], &r[4]],
            &hex48(9),
            gpus,
            1_800_000_000,
        ))
        .unwrap()
    }

    fn refused(result: Result<(), ApiError>, code: &str, reason: &str) {
        let e = result.unwrap_err();
        assert_eq!(e.code, code, "{}", e.message);
        assert!(e.message.contains(reason), "{reason}: {}", e.message);
    }

    #[test]
    fn a_pod_trustee_attested_passes_only_the_kms_own_rules() {
        let d = doc();
        let cpu = revision(CPU_RUNTIME_CLASS, None);
        assert!(check_claims(&d, &cpu, &claims(0x10, &[])).is_ok());
        // The GPU guest's registers under a CPU Revision, and the reverse.
        refused(
            check_claims(&d, &cpu, &claims(0x20, &[])),
            "attestation_unknown",
            "no kata-tdx reference value",
        );
        let gpu8: Vec<Value> = (0..8).map(|i| gpu_claims(&format!("u{i}"))).collect();
        let b300x8 = revision(GPU_RUNTIME_CLASS, Some(8));
        assert!(check_claims(&d, &b300x8, &claims(0x20, &gpu8)).is_ok());
        refused(
            check_claims(&d, &b300x8, &claims(0x10, &gpu8)),
            "attestation_unknown",
            "no kata-tdx reference value",
        );
        refused(
            check_claims(&d, &cpu, &claims(0x10, &gpu8[..1])),
            "attestation_failed",
            "runs none",
        );
        refused(
            check_claims(&d, &b300x8, &claims(0x20, &gpu8[..7])),
            "attestation_failed",
            "7",
        );
        let mut twice = gpu8.clone();
        twice[7] = gpu_claims("u0");
        refused(
            check_claims(&d, &b300x8, &claims(0x20, &twice)),
            "attestation_failed",
            "another GPU of this pod",
        );
        let mut h100 = gpu8.clone();
        h100[3]["hwmodel"] = json!("GH100");
        refused(
            check_claims(&d, &b300x8, &claims(0x20, &h100)),
            "attestation_failed",
            "model H100",
        );
        let mut off = gpu8.clone();
        off[2]["x-nvidia-gpu-cc-mode"] = json!("off");
        refused(
            check_claims(&d, &b300x8, &claims(0x20, &off)),
            "attestation_failed",
            "CC-mode claim",
        );
        let mut ocsp = gpu8.clone();
        ocsp[1]["x-nvidia-gpu-attestation-report-cert-chain"]["x-nvidia-cert-ocsp-status"] =
            json!("revoked");
        refused(
            check_claims(&d, &b300x8, &claims(0x20, &ocsp)),
            "attestation_failed",
            "ocsp-status",
        );
        let mut old = gpu8;
        old[0]["x-nvidia-gpu-driver-version"] = json!("575.51.03");
        refused(
            check_claims(&d, &b300x8, &claims(0x20, &old)),
            "policy_denied",
            "driver version",
        );
    }

    /// Hacktron ACC-FD-102: the guest image is chosen by `kata-tdx/1`'s own rule, from every
    /// register the token carries, so no TD passes here that the KMS's own appraisal refuses.
    #[test]
    fn the_guest_image_is_chosen_by_kata_tdx_1s_rule_from_every_register() {
        let d = doc();
        let cpu = revision(CPU_RUNTIME_CLASS, None);
        let base = claims(0x10, &[]);
        assert!(check_claims(&d, &cpu, &base).is_ok());
        for register in 0..4 {
            let mut c = base.clone();
            let r = match register {
                0 => &mut c.mrtd,
                1 => &mut c.rtmr0,
                2 => &mut c.rtmr1,
                _ => &mut c.rtmr2,
            };
            r.0[47] ^= 1;
            refused(
                check_claims(&d, &cpu, &c),
                "attestation_unknown",
                "no kata-tdx reference value",
            );
        }
        // RTMR3 alone differing gets kata-tdx/1's verdict on the same registers: the profile
        // leaves the guest's runtime register out of the guest image, and binds what the pod runs
        // by MRCONFIGID instead.
        for byte in [0u8, 6, 0xee] {
            let mut c = base.clone();
            c.rtmr3 = Measurement([byte; 48]);
            let kms = kata_tdx_reference(&d, CPU_RUNTIME_CLASS, &c.measured()).is_some();
            assert_eq!(check_claims(&d, &cpu, &c).is_ok(), kms, "rtmr3 {byte:#x}");
        }
        // And no document can name an RTMR3 for either path to compare: it does not parse.
        let mut pinned = serde_json::to_value(&d).unwrap();
        pinned["reference_values"][0]["values"]["rtmr3"] = json!(format!("sha384:{}", hex48(5)));
        let error = serde_json::from_value::<PlatformDocument>(pinned).unwrap_err();
        assert!(error.to_string().contains("rtmr3"), "{error}");
    }

    #[test]
    fn the_tcb_policy_is_the_documents() {
        let d = doc();
        let cpu = revision(CPU_RUNTIME_CLASS, None);
        let mut c = claims(0x10, &[]);
        c.tcb_status = "OutOfDate".into();
        refused(
            check_claims(&d, &cpu, &c),
            "policy_denied",
            "tcb_status OutOfDate",
        );
        let mut c = claims(0x10, &[]);
        c.advisories = vec!["INTEL-SA-1".into()];
        assert!(check_claims(&d, &cpu, &c).is_ok());
        c.advisories.push("INTEL-SA-2".into());
        refused(
            check_claims(&d, &cpu, &c),
            "policy_denied",
            "advisory INTEL-SA-2",
        );
        let mut c = claims(0x10, &[]);
        c.debug = true;
        refused(check_claims(&d, &cpu, &c), "policy_denied", "debug");
    }

    #[test]
    fn no_gpu_passes_through_trustee_unless_nras_alone_vouches_as_the_document_says() {
        let gpu1 = [gpu_claims("u0")];
        let b300 = revision(GPU_RUNTIME_CLASS, Some(1));
        let mut d = doc();
        d.gpu_policy.as_mut().unwrap().verifiers =
            vec![GpuVerifierKind::Nras, GpuVerifierKind::FortanixCcm];
        refused(
            check_claims(&d, &b300, &claims(0x20, &gpu1)),
            "attestation_unknown",
            "NRAS alone",
        );
        let mut d = doc();
        d.gpu_policy = None;
        refused(
            check_claims(&d, &b300, &claims(0x20, &gpu1)),
            "attestation_unknown",
            "no gpu_policy",
        );
    }

    #[test]
    fn state_is_fresh_for_the_documents_bound_and_never_from_the_future() {
        let trustee: Trustee = serde_json::from_value(json!({
            "revisions": [], "kbs_hostname": "kbs.internal", "max_state_age_secs": 300
        }))
        .unwrap();
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        assert!(check_fresh(&trustee, now, now).is_ok());
        assert!(check_fresh(&trustee, now - Duration::from_secs(300), now).is_ok());
        refused(
            check_fresh(&trustee, now - Duration::from_secs(301), now),
            "policy_denied",
            "301s old",
        );
        assert!(check_fresh(&trustee, now + Duration::from_secs(60), now).is_ok());
        refused(
            check_fresh(&trustee, now + Duration::from_secs(61), now),
            "policy_denied",
            "future",
        );
    }

    #[test]
    fn a_released_value_has_the_form_its_type_needs() {
        assert!(check_value(ResourceType::Secret, b"anything").is_ok());
        assert!(check_value(ResourceType::ImageKey, &[7; 32]).is_ok());
        refused(
            check_value(ResourceType::ImageKey, &[7; 16]),
            "policy_denied",
            "32-byte",
        );
        let public = json!({ "kty": "EC", "crv": "P-256", "x": "AA", "y": "BB" });
        assert!(check_value(ResourceType::SealedSecretKey, public.to_string().as_bytes()).is_ok());
        let mut private = public.clone();
        private["d"] = json!("CC");
        refused(
            check_value(
                ResourceType::SealedSecretKey,
                private.to_string().as_bytes(),
            ),
            "policy_denied",
            "public P-256",
        );
        refused(
            check_value(ResourceType::SealedSecretKey, b"not json"),
            "policy_denied",
            "JSON Web Key",
        );
    }
}
