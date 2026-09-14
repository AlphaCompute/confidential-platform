//! The Node API: evidence, bootstrap on an empty database, unseal from two shares, join from the
//! other node, and the start rule.

use std::sync::Arc;

use alpha_attest::{Evidence, appraise, report_data};
use alpha_core::{OrgId, PrincipalId, signing_digest};
use alpha_crypto::{INFO_NODE_BOOTSTRAP, INFO_UNSEAL_SHARE, PublicKey, Sealed};
use axum::Json;
use axum::extract::{Extension, Query, State};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use ed25519_dalek::pkcs8::DecodePublicKey;
use p256::ecdsa::signature::Signer;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use vsss_rs::Gf256;
use zeroize::Zeroizing;

use crate::audit;
use crate::body::Body;
use crate::error::ApiError;
use crate::instance::{check_nonce, collateral, decode32};
use crate::keys::{self, aead_open, aead_seal};
use crate::tls::PeerCerts;
use crate::{Intermediates, Node, Phase, certs, random32};

pub const CONTEXT_BOOTSTRAP: &str = "alphacompute/node-bootstrap/v1";

fn runtime_spki_sha256(node: &Node) -> [u8; 32] {
    Sha256::digest(&node.runtime_spki).into()
}

#[derive(Deserialize)]
pub struct NonceQuery {
    pub nonce: String,
}

pub async fn evidence(
    State(node): State<Arc<Node>>,
    Query(query): Query<NonceQuery>,
) -> Result<Json<Value>, ApiError> {
    let nonce = decode32("nonce", &query.nonce)?;
    let xwing = node.xwing_key.public();
    let rd = report_data(&node.runtime_spki, &nonce, Some(xwing.as_bytes()));
    let quote = alpha_tsm::quote(&rd).map_err(|e| ApiError::internal(format!("quote: {e}")))?;
    Ok(Json(json!({
        "quote": BASE64_URL_SAFE_NO_PAD.encode(quote),
        "event_log": node.event_log,
        "runtime_pubkey": BASE64_URL_SAFE_NO_PAD.encode(&node.runtime_spki),
        "xwing_pubkey": xwing,
        "compose_hash": node.compose_hash,
    })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapRequest {
    pub body_hpke: Sealed,
}

/// What `alpha bootstrap` seals to the node.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapBody {
    pub custodians: [PublicKey; 3],
    pub anchor: Anchor,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Anchor {
    pub org_id: OrgId,
    pub principal_id: PrincipalId,
    pub public_key: String,
    pub label: String,
}

pub async fn bootstrap(
    State(node): State<Arc<Node>>,
    Body(request): Body<BootstrapRequest>,
) -> Result<Json<Value>, ApiError> {
    if !node.is_sealed() {
        return Err(ApiError::new("already_exists", "node is already serving"));
    }
    let aad = runtime_spki_sha256(&node);
    let body = alpha_crypto::open(
        &node.xwing_key,
        INFO_NODE_BOOTSTRAP,
        &aad,
        &request.body_hpke,
    )
    .map_err(|e| ApiError::malformed(format!("body_hpke: {e}")))?;
    let body: BootstrapBody =
        serde_json::from_slice(&body).map_err(|e| ApiError::malformed(format!("body: {e}")))?;
    let anchor_spki = BASE64_URL_SAFE_NO_PAD
        .decode(&body.anchor.public_key)
        .map_err(|_| ApiError::malformed("anchor public_key: not base64url"))?;
    ed25519_dalek::VerifyingKey::from_public_key_der(&anchor_spki)
        .map_err(|_| ApiError::malformed("anchor public_key: not an Ed25519 SPKI"))?;
    let now = node.now();

    let root = root_kek(&node);
    let tenant_kek_root = Zeroizing::new(random32());
    let (ca_key_der, ca_cert_der) = certs::new_ca(now);
    let ca_key_der = Zeroizing::new(ca_key_der);
    let mut tx = node.pool.begin().await?;
    sqlx::query!("lock table intermediate_keys in access exclusive mode")
        .execute(&mut *tx)
        .await?;
    let existing = sqlx::query_scalar!("select count(*) from intermediate_keys")
        .fetch_one(&mut *tx)
        .await?;
    if existing.unwrap_or(0) != 0 {
        return Err(ApiError::new("already_exists", "database is not empty"));
    }
    sqlx::query!(
        "insert into intermediate_keys (purpose, wrapped, public_part) values
           ('tenant-kek-root', $1, null), ('ca', $2, $3)",
        aead_seal(&root, b"tenant-kek-root", tenant_kek_root.as_slice()),
        aead_seal(&root, b"ca", &ca_key_der),
        ca_cert_der,
    )
    .execute(&mut *tx)
    .await?;
    let anchor_id: Uuid = alpha_core::KeyId::mint().into();
    let check = keys::anchor_check(&tenant_kek_root, body.anchor.org_id, &anchor_spki);
    sqlx::query!(
        "insert into principal_keys (id, org_id, principal_id, public_key, document, anchor_check)
         values ($1, $2, $3, $4, $5, $6)",
        anchor_id,
        Uuid::from(body.anchor.org_id),
        Uuid::from(body.anchor.principal_id),
        anchor_spki,
        json!(body.anchor),
        check.as_slice(),
    )
    .execute(&mut *tx)
    .await?;
    audit::node(
        "node.bootstrap",
        "ok",
        json!({ "org_id": body.anchor.org_id, "anchor_key": anchor_id }),
    )
    .insert(&mut *tx)
    .await?;
    tx.commit().await?;

    let shares = Gf256::split_bytes(
        2,
        3,
        root.as_slice(),
        rand_core::UnwrapErr(getrandom::SysRng),
    )
    .map_err(|e| ApiError::internal(format!("shamir: {e:?}")))?;
    let shares_hpke: Vec<Sealed> = shares
        .iter()
        .zip(&body.custodians)
        .map(|(share, custodian)| alpha_crypto::seal(custodian, INFO_UNSEAL_SHARE, &aad, share))
        .collect();
    drop(root);
    let keys = Intermediates {
        tenant_kek_root,
        ca_key_der,
        ca_cert_der,
    };
    let payload = json!({ "shares_hpke": shares_hpke, "kms_ca_pem": keys.ca_pem() });
    node.start_serving(keys)?;
    let signature: p256::ecdsa::Signature = node
        .runtime_key
        .sign(&signing_digest(CONTEXT_BOOTSTRAP, &payload));
    Ok(Json(json!({
        "payload": payload,
        "signature": {
            "algorithm": "ecdsa-p256",
            "signature": BASE64_URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        },
    })))
}

#[cfg(feature = "dev-root")]
fn root_kek(node: &Node) -> Zeroizing<[u8; 32]> {
    node.config
        .dev_root_kek
        .clone()
        .unwrap_or_else(|| Zeroizing::new(random32()))
}

#[cfg(not(feature = "dev-root"))]
fn root_kek(_: &Node) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(random32())
}

/// Unwraps both rows under `root`.
pub async fn unwrap_intermediates(node: &Node, root: &[u8; 32]) -> Result<Intermediates, ApiError> {
    let unwrap = |purpose: &str, wrapped: Option<Vec<u8>>| {
        wrapped
            .and_then(|w| aead_open(root, purpose.as_bytes(), &w))
            .ok_or_else(|| {
                ApiError::malformed(format!("{purpose} does not unwrap under this root"))
            })
    };
    let tenant = sqlx::query_scalar!(
        "select wrapped from intermediate_keys where purpose = 'tenant-kek-root'"
    )
    .fetch_optional(&node.pool)
    .await?;
    let ca =
        sqlx::query!("select wrapped, public_part from intermediate_keys where purpose = 'ca'")
            .fetch_optional(&node.pool)
            .await?;
    let tenant_kek_root = <[u8; 32]>::try_from(unwrap("tenant-kek-root", tenant)?.as_slice())
        .map(Zeroizing::new)
        .map_err(|_| ApiError::internal("tenant-kek-root is not 32 bytes"))?;
    let ca_key_der = unwrap("ca", ca.as_ref().map(|r| r.wrapped.clone()))?;
    Ok(Intermediates {
        tenant_kek_root,
        ca_key_der,
        ca_cert_der: ca.and_then(|r| r.public_part).unwrap_or_default(),
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsealRequest {
    pub share_hpke: Sealed,
}

pub async fn unseal(
    State(node): State<Arc<Node>>,
    Body(request): Body<UnsealRequest>,
) -> Result<Json<Value>, ApiError> {
    let aad = runtime_spki_sha256(&node);
    let share = alpha_crypto::open(
        &node.xwing_key,
        INFO_UNSEAL_SHARE,
        &aad,
        &request.share_hpke,
    )
    .map_err(|e| ApiError::malformed(format!("share_hpke: {e}")))?;
    let collected = {
        let mut phase = node.phase.write().unwrap();
        let Phase::Sealed { shares } = &mut *phase else {
            return Err(ApiError::new("already_exists", "node is already serving"));
        };
        if !shares.contains(&*share) {
            shares.push(share.to_vec());
        }
        shares.clone()
    };
    if collected.len() < 2 {
        return Ok(Json(json!({ "sealed": true, "shares": collected.len() })));
    }
    let outcome = async {
        let root = Gf256::combine_bytes(&collected)
            .ok()
            .and_then(|r| <[u8; 32]>::try_from(r.as_slice()).ok())
            .map(Zeroizing::new)
            .ok_or_else(|| ApiError::malformed("shares do not combine"))?;
        let keys = unwrap_intermediates(&node, &root).await?;
        node.start_serving(keys)
    }
    .await;
    if let Err(e) = outcome {
        if let Phase::Sealed { shares } = &mut *node.phase.write().unwrap() {
            shares.clear();
        }
        audit::node("node.unseal", "denied", e.details())
            .insert(&node.pool)
            .await?;
        return Err(e);
    }
    audit::node("node.unseal", "ok", json!({}))
        .insert(&node.pool)
        .await?;
    Ok(Json(json!({ "sealed": false, "shares": 2 })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinRequest {
    pub nonce: String,
    pub evidence: Evidence,
    pub xwing_pubkey: PublicKey,
}

pub async fn join(
    State(node): State<Arc<Node>>,
    Extension(peer): Extension<PeerCerts>,
    Body(request): Body<JoinRequest>,
) -> Result<Json<Value>, ApiError> {
    let leaf = peer
        .0
        .first()
        .ok_or_else(|| ApiError::new("cert_invalid", "no client certificate"))?;
    let spki = certs::spki_of(leaf)?;
    let actor = keys::sha256_hex(&spki);
    let result = join_inner(&node, &spki, &request).await;
    let (outcome, details) = match &result {
        Ok(compose_hash) => (
            "ok",
            json!({ "runtime_pubkey_sha256": actor, "compose_hash": compose_hash }),
        ),
        Err(e) => (e.outcome(), e.details()),
    };
    audit::node("node.join", outcome, details)
        .insert(&node.pool)
        .await?;
    result?;
    let keys = node.intermediates()?;
    Ok(Json(json!({
        "tenant_kek_root": BASE64_URL_SAFE_NO_PAD.encode(keys.tenant_kek_root.as_slice()),
        "ca_key": BASE64_URL_SAFE_NO_PAD.encode(keys.ca_key_der.as_slice()),
        "ca_cert": BASE64_URL_SAFE_NO_PAD.encode(&keys.ca_cert_der),
    })))
}

async fn join_inner(
    node: &Node,
    spki: &[u8],
    request: &JoinRequest,
) -> Result<alpha_core::ComposeHash, ApiError> {
    node.intermediates()?;
    let now = node.now();
    let nonce = decode32("nonce", &request.nonce)?;
    check_nonce(&node.nonce_key, &nonce, now)?;
    let doc = node
        .platform_document()
        .ok_or_else(|| ApiError::new("attestation_unknown", "no platform document"))?;
    let collateral = collateral(node, &request.evidence.quote).await?;
    let appraised = appraise(
        &request.evidence,
        &nonce,
        spki,
        Some(request.xwing_pubkey.as_bytes()),
        &doc,
        &collateral,
        now,
    )?;
    let requested = sqlx::query_scalar!(
        "select exists(select 1 from audit_log
           where action = 'node.join.request' and outcome = 'ok'
             and details->>'runtime_pubkey_sha256' = $1
             and ts > now() - interval '10 minutes')",
        keys::sha256_hex(spki),
    )
    .fetch_one(&node.pool)
    .await?;
    if !requested.unwrap_or(false) {
        return Err(ApiError::new(
            "not_found",
            "no node.join.request in the last 10 minutes",
        ));
    }
    Ok(appraised.compose_hash)
}

/// The start rule: sealed → the first endpoint whose `/ready` is 200 gets a
/// `node.join.request` row and a join; nothing ready → wait for unseal.
pub async fn try_join(node: &Node) -> Result<(), ApiError> {
    let doc = node
        .platform_document()
        .ok_or_else(|| ApiError::internal("no platform document to pin the other node"))?;
    let client = join_client(node, &doc.kms_ca_pem, &doc.kms_revisions)?;
    for endpoint in &node.config.kms_endpoints {
        let ready = client.get(format!("{endpoint}/ready")).send().await;
        if !ready.is_ok_and(|r| r.status().is_success()) {
            continue;
        }
        match join_via(node, &client, endpoint).await {
            Ok(()) => return Ok(()),
            Err(e) => eprintln!("join {endpoint}: {}", e.message),
        }
    }
    Err(ApiError::internal("no ready node to join"))
}

async fn join_via(node: &Node, client: &reqwest::Client, endpoint: &str) -> Result<(), ApiError> {
    let http = |e: reqwest::Error| ApiError::internal(format!("join: {e}"));
    let nonce: Value = client
        .post(format!("{endpoint}/v1/attest/nonce"))
        .send()
        .await
        .map_err(http)?
        .json()
        .await
        .map_err(http)?;
    let nonce_text = nonce["nonce"].as_str().unwrap_or_default().to_owned();
    let nonce = decode32("nonce", &nonce_text)?;
    audit::node(
        "node.join.request",
        "ok",
        json!({ "runtime_pubkey_sha256": keys::sha256_hex(&node.runtime_spki), "endpoint": endpoint }),
    )
    .insert(&node.pool)
    .await?;
    let xwing = node.xwing_key.public();
    let rd = report_data(&node.runtime_spki, &nonce, Some(xwing.as_bytes()));
    let quote = alpha_tsm::quote(&rd).map_err(|e| ApiError::internal(format!("quote: {e}")))?;
    let evidence = Evidence {
        format: alpha_attest::EVIDENCE_FORMAT.into(),
        quote,
        event_log: node.event_log.clone(),
    };
    let reply: Value = client
        .post(format!("{endpoint}/v1/node/join"))
        .json(&json!({ "nonce": nonce_text, "evidence": evidence, "xwing_pubkey": xwing }))
        .send()
        .await
        .map_err(http)?
        .error_for_status()
        .map_err(http)?
        .json()
        .await
        .map_err(http)?;
    let field = |name: &str| {
        reply[name]
            .as_str()
            .and_then(|s| BASE64_URL_SAFE_NO_PAD.decode(s).ok())
            .ok_or_else(|| ApiError::internal(format!("join reply: {name}")))
    };
    let tenant_kek_root = Zeroizing::new(
        <[u8; 32]>::try_from(field("tenant_kek_root")?.as_slice())
            .map_err(|_| ApiError::internal("join reply: tenant_kek_root"))?,
    );
    node.start_serving(Intermediates {
        tenant_kek_root,
        ca_key_der: Zeroizing::new(field("ca_key")?),
        ca_cert_der: field("ca_cert")?,
    })
}

/// An HTTPS client for the other node: our self-signed runtime certificate as identity, the
/// server pinned to `kms_ca_pem` and to a Revision in `kms_revisions`.
fn join_client(
    node: &Node,
    kms_ca_pem: &str,
    revisions: &[alpha_attest::KmsRevision],
) -> Result<reqwest::Client, ApiError> {
    let ca = rustls::pki_types::pem::PemObject::from_pem_slice(kms_ca_pem.as_bytes())
        .map_err(|e| ApiError::internal(format!("kms_ca_pem: {e}")))?;
    let verifier = crate::tls::PinnedServer::new(
        ca,
        revisions
            .iter()
            .map(|r| format!("urn:alphacompute:revision:{}", r.compose_hash))
            .collect(),
    )?;
    let cert = certs::self_signed(&certs::key_pair(&node.runtime_pkcs8), node.now());
    let config = crate::tls::client_config(verifier, cert, &node.runtime_pkcs8);
    reqwest::Client::builder()
        .tls_backend_preconfigured(config)
        .build()
        .map_err(|e| ApiError::internal(format!("client: {e}")))
}
