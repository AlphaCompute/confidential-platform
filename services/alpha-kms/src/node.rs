//! The Node API: evidence, bootstrap on an empty database, unseal from two shares, join from the
//! other node, and the start rule.

use std::sync::Arc;

use alpha_attest::{AnyEvidence, Appraised, VerifiedQuote, kata, report_data};
use alpha_client::tls::PeerCerts;
use alpha_client::{Client, Identity, JoinReply, JoinRequest, NodeEvidence, Pin, UnsealRequest};
use alpha_core::{context, signing_digest};
use alpha_crypto::{INFO_NODE_BOOTSTRAP, INFO_UNSEAL_SHARE, Sealed};
use axum::Json;
use axum::extract::{Extension, Query, State};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use p256::ecdsa::signature::Signer;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use vsss_rs::Gf256;
use zeroize::Zeroizing;

use crate::audit;
use crate::body::Body;
use crate::db_volume::{self, DB_VOLUME};
use crate::error::ApiError;
use crate::instance::{check_nonce, collateral, decode32};
use crate::keys::{self, aead_open, aead_seal};
use crate::{Intermediates, Node, Phase, certs, random};

fn runtime_spki_sha256(node: &Node) -> [u8; 32] {
    Sha256::digest(&node.runtime_spki).into()
}

#[derive(Deserialize)]
pub struct NonceQuery {
    pub nonce: String,
}

/// This node's evidence over the caller's nonce, its X-Wing key bound in `report_data[32..64]`: a
/// prototype node's quote and event log, or a Kata node's evidence v2 with its init-data.
pub async fn evidence(
    State(node): State<Arc<Node>>,
    Query(query): Query<NonceQuery>,
) -> Result<Json<NodeEvidence>, ApiError> {
    let nonce = decode32("nonce", &query.nonce)?;
    let xwing = node.xwing_key.public();
    let rd = report_data(&node.runtime_spki, &nonce, Some(xwing.as_bytes()));
    let (quote, event_log, evidence_v2) = match node.guest.evidence(&rd)? {
        AnyEvidence::V1(e) => (BASE64_URL_SAFE_NO_PAD.encode(e.quote), e.event_log, None),
        AnyEvidence::V2(e) => (String::new(), Vec::new(), Some(e)),
    };
    Ok(Json(NodeEvidence {
        quote,
        event_log,
        evidence_v2,
        runtime_pubkey: BASE64_URL_SAFE_NO_PAD.encode(&node.runtime_spki),
        xwing_pubkey: xwing,
        compose_hash: node.compose_hash,
    }))
}

pub use alpha_client::{BootstrapBody, BootstrapRequest};

pub async fn bootstrap(
    State(node): State<Arc<Node>>,
    Body(request, _): Body<BootstrapRequest>,
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
    let now = node.now();

    let root = root_kek(&node)?;
    let tenant_kek_root = Zeroizing::new(random()?);
    let db_volume = Zeroizing::new(random::<32>()?);
    let (ca_key_der, ca_cert_der) = certs::new_ca(now)?;
    let ca_key_der = Zeroizing::new(ca_key_der);
    let wrapped_tenant = aead_seal(&root, b"tenant-kek-root", tenant_kek_root.as_slice())?;
    let wrapped_ca = aead_seal(&root, b"ca", &ca_key_der)?;
    let wrapped_db = aead_seal(&root, DB_VOLUME.as_bytes(), db_volume.as_slice())?;
    let keys = Intermediates::new(tenant_kek_root, ca_key_der, ca_cert_der)?
        .with_db_volume(Some(db_volume.clone()));
    // With the database closed (M2(a) genesis: its volume key is made here), the rows wait in
    // memory until it opens; otherwise they are written before the shares leave.
    let kms_ca_pem = keys.ca_pem();
    let keys = if db_volume::database_closed(&node).await {
        let genesis = db_volume::Genesis {
            rows: vec![
                ("tenant-kek-root", wrapped_tenant, None),
                ("ca", wrapped_ca, Some(keys.ca_cert_der.clone())),
                (DB_VOLUME, wrapped_db.clone(), None),
            ],
            keys,
        };
        db_volume::bootstrap_waiting(&node, root.clone(), db_volume, genesis);
        None
    } else {
        let mut tx = node.pool.begin().await?;
        let inserted = sqlx::query!(
            "insert into intermediate_keys (purpose, wrapped, public_part) values
               ('tenant-kek-root', $1, null), ('ca', $2, $3), ('db-volume', $4, null)
               on conflict (purpose) do nothing",
            wrapped_tenant,
            wrapped_ca,
            keys.ca_cert_der,
            wrapped_db,
        )
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if inserted != 3 {
            return Err(ApiError::new("already_exists", "database is not empty"));
        }
        audit::node("node.bootstrap", "ok", json!({}))
            .insert(&mut tx, Some(&keys.metadata))
            .await?;
        tx.commit().await?;
        Some(keys)
    };

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
        .collect::<Result<_, _>>()
        .map_err(|e| ApiError::internal(format!("seal share: {e}")))?;
    drop(root);
    let payload = json!({
        "shares_hpke": shares_hpke,
        "kms_ca_pem": kms_ca_pem,
        "db_volume_wrapped": BASE64_URL_SAFE_NO_PAD.encode(&wrapped_db),
    });
    let digest = signing_digest(context::NODE_BOOTSTRAP, &payload)
        .map_err(|e| ApiError::internal(format!("payload: {e}")))?;
    if let Some(keys) = keys {
        node.start_serving(keys).await?;
    }
    let signature: p256::ecdsa::Signature = node.runtime_key.sign(&digest);
    Ok(Json(json!({
        "payload": payload,
        "signature": {
            "algorithm": "ecdsa-p256",
            "signature": BASE64_URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        },
    })))
}

fn root_kek(_node: &Node) -> Result<Zeroizing<[u8; 32]>, ApiError> {
    #[cfg(feature = "dev-root")]
    if let Some(root) = &_node.config.dev_root_kek {
        return Ok(root.clone());
    }
    Ok(Zeroizing::new(random()?))
}

/// Unwraps every row under `root`: both intermediates, and the database's volume key when the
/// database has one.
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
    let db_volume =
        sqlx::query_scalar!("select wrapped from intermediate_keys where purpose = 'db-volume'")
            .fetch_optional(&node.pool)
            .await?
            .map(|wrapped| {
                unwrap(DB_VOLUME, Some(wrapped)).and_then(|key| {
                    <[u8; 32]>::try_from(key.as_slice())
                        .map(Zeroizing::new)
                        .map_err(|_| ApiError::internal("db-volume is not 32 bytes"))
                })
            })
            .transpose()?;
    Ok(Intermediates::new(
        tenant_kek_root,
        ca_key_der,
        ca.and_then(|r| r.public_part).unwrap_or_default(),
    )?
    .with_db_volume(db_volume))
}

pub async fn unseal(
    State(node): State<Arc<Node>>,
    Body(request, _): Body<UnsealRequest>,
) -> Result<Json<Value>, ApiError> {
    let aad = runtime_spki_sha256(&node);
    let share = alpha_crypto::open(
        &node.xwing_key,
        INFO_UNSEAL_SHARE,
        &aad,
        &request.share_hpke,
    )
    .map_err(|e| ApiError::malformed(format!("share_hpke: {e}")))?;
    let wrapped = request
        .db_volume_wrapped
        .as_deref()
        .map(|w| alpha_client::decode("db_volume_wrapped", w))
        .transpose()
        .map_err(|e| ApiError::malformed(e.to_string()))?;
    let collected = {
        let mut phase = node.phase.write();
        let Phase::Sealed { shares } = &mut *phase else {
            return Err(ApiError::new("already_exists", "node is already serving"));
        };
        if !shares.contains(&*share) {
            shares.push(share.to_vec());
        }
        let mut extras = node.unseal_extras.lock();
        if wrapped.is_some() {
            extras.db_volume_wrapped = wrapped;
        }
        extras.document_version = extras
            .document_version
            .max(request.platform_document_version.unwrap_or(0));
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
        db_volume::enter(&node, root).await
    }
    .await;
    let entered = match outcome {
        Ok(entered) => entered,
        Err(e) => {
            if let Phase::Sealed { shares } = &mut *node.phase.write() {
                shares.clear();
            }
            *node.unseal_extras.lock() = db_volume::UnsealExtras::default();
            let _ = node
                .audit(audit::node("node.unseal", "denied", e.details()))
                .await;
            return Err(e);
        }
    };
    let database = match entered {
        db_volume::Entered::Serving => "open",
        db_volume::Entered::Waiting => "waiting",
    };
    node.audit_or_hold("node.unseal", "ok", json!({ "database": database }))
        .await?;
    Ok(Json(
        json!({ "sealed": false, "shares": 2, "database": database }),
    ))
}

pub async fn join(
    State(node): State<Arc<Node>>,
    Extension(peer): Extension<PeerCerts>,
    Body(request, _): Body<JoinRequest>,
) -> Result<Json<Value>, ApiError> {
    let leaf = peer
        .0
        .first()
        .ok_or_else(|| ApiError::new("cert_invalid", "no client certificate"))?;
    let spki = certs::spki_of(leaf)?;
    join_audited(&node, &spki, &request, None).await.map(Json)
}

/// [`join`] for a Kata node's `alphacompute-evidence/2` over a TDX quote the caller has verified:
/// every step after DCAP, the audit row included, for the client certificate key `spki`. No route
/// reaches it. The KMS's tests join Kata nodes through it over synthetic quotes, as
/// [`crate::instance::attest_verified`] attests Kata pods, until B300 Kata captures exist (M1).
pub async fn join_verified(
    node: &Node,
    spki: &[u8],
    request: &JoinRequest,
    verified: VerifiedQuote,
) -> Result<Value, ApiError> {
    join_audited(node, spki, request, Some(verified)).await
}

async fn join_audited(
    node: &Node,
    spki: &[u8],
    request: &JoinRequest,
    verified: Option<VerifiedQuote>,
) -> Result<Value, ApiError> {
    let actor = keys::sha256_hex(spki);
    let result = join_inner(node, spki, request, verified).await;
    let (outcome, details) = match &result {
        Ok(appraised) => (
            "ok",
            json!({
                "runtime_pubkey_sha256": actor,
                "compose_hash": appraised.compose_hash,
                "os_image": appraised.os_image,
                "coco": appraised.coco,
            }),
        ),
        Err(e) => (e.outcome(), e.details()),
    };
    node.audit(audit::node("node.join", outcome, details))
        .await?;
    result?;
    let keys = node.intermediates()?;
    let mut reply = json!({
        "tenant_kek_root": BASE64_URL_SAFE_NO_PAD.encode(keys.tenant_kek_root.as_slice()),
        "ca_key": BASE64_URL_SAFE_NO_PAD.encode(keys.ca_key_der.as_slice()),
        "ca_cert": BASE64_URL_SAFE_NO_PAD.encode(&keys.ca_cert_der),
    });
    if let (Some(key), Value::Object(fields)) = (&keys.db_volume, &mut reply) {
        fields.insert(
            "db_volume_key".into(),
            json!(BASE64_URL_SAFE_NO_PAD.encode(key.as_slice())),
        );
    }
    Ok(reply)
}

/// The joining node's appraisal is the one a custodian's CLI runs before unsealing
/// ([`alpha_attest::node`]): prototype evidence, or `kata-tdx/1` on the CPU class, listed in
/// `kms_revisions` for that profile.
async fn join_inner(
    node: &Node,
    spki: &[u8],
    request: &JoinRequest,
    verified: Option<VerifiedQuote>,
) -> Result<Appraised, ApiError> {
    node.intermediates()?;
    let now = node.now();
    let nonce = decode32("nonce", &request.nonce)?;
    check_nonce(&node.nonce_key, &nonce, now)?;
    let doc = node
        .platform_document()
        .ok_or_else(|| ApiError::new("attestation_unknown", "no platform document"))?;
    let xwing = request.xwing_pubkey.as_bytes();
    let appraised = match (&request.evidence, verified) {
        (AnyEvidence::V1(_), Some(_)) => {
            return Err(ApiError::internal(
                "a verified quote comes with alphacompute-evidence/2 only",
            ));
        }
        (AnyEvidence::V2(evidence), Some(verified)) => {
            alpha_attest::node::appraise_kata_node(evidence, verified, &nonce, spki, xwing, &doc)?
        }
        (evidence, None) => {
            if let AnyEvidence::V2(evidence) = evidence {
                kata::check_cpu_kind(evidence)?;
            }
            let collateral = collateral(node, evidence.quote()).await?;
            alpha_attest::node::appraise_node(
                evidence,
                &nonce,
                spki,
                xwing,
                &doc,
                &collateral,
                now,
            )?
        }
    };
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
    Ok(appraised)
}

/// The start rule: sealed → the first endpoint whose `/ready` is 200 gets a
/// `node.join.request` row and a join; nothing ready → wait for unseal.
pub async fn try_join(node: &Node) -> Result<(), ApiError> {
    let doc = node
        .platform_document()
        .ok_or_else(|| ApiError::internal("no platform document to pin the other node"))?;
    for endpoint in &node.config.kms_endpoints {
        // One node per client: the nonce is bound to the node that minted it.
        let client = join_client(node, endpoint, &doc.kms_ca_pem, &doc.kms_revisions)?;
        if !client.ready().await.is_ok_and(|r| !r.sealed) {
            continue;
        }
        match join_via(node, &client, endpoint).await {
            Ok(()) => return Ok(()),
            Err(e) => eprintln!("join {endpoint}: {}", e.message),
        }
    }
    Err(ApiError::internal("no ready node to join"))
}

async fn join_via(node: &Node, client: &Client, endpoint: &str) -> Result<(), ApiError> {
    let http = |e: alpha_client::Error| ApiError::internal(format!("join: {e}"));
    let nonce = client.attest_nonce().await.map_err(http)?.nonce;
    let request = join_request(node, nonce, endpoint).await?;
    let reply = client.join(&request).await.map_err(http)?;
    finish_join(node, &reply).await
}

/// The joining side's request over the serving node's `nonce`: a `node.join.request` row, which
/// the serving node requires, then this node's evidence with its X-Wing key bound.
pub async fn join_request(
    node: &Node,
    nonce: String,
    endpoint: &str,
) -> Result<JoinRequest, ApiError> {
    let raw = decode32("nonce", &nonce)?;
    node.audit(audit::node(
        "node.join.request",
        "ok",
        json!({ "runtime_pubkey_sha256": keys::sha256_hex(&node.runtime_spki), "endpoint": endpoint }),
    ))
    .await?;
    let xwing = node.xwing_key.public();
    let rd = report_data(&node.runtime_spki, &raw, Some(xwing.as_bytes()));
    Ok(JoinRequest {
        nonce,
        evidence: node.guest.evidence(&rd)?,
        xwing_pubkey: xwing,
    })
}

/// Serves with the intermediates the other node handed over.
pub async fn finish_join(node: &Node, reply: &JoinReply) -> Result<(), ApiError> {
    let field = |name: &str, text: &str| {
        alpha_client::decode(name, text).map_err(|e| ApiError::internal(format!("join reply: {e}")))
    };
    let tenant_kek_root = Zeroizing::new(
        <[u8; 32]>::try_from(field("tenant_kek_root", &reply.tenant_kek_root)?.as_slice())
            .map_err(|_| ApiError::internal("join reply: tenant_kek_root"))?,
    );
    let db_volume = reply
        .db_volume_key
        .as_deref()
        .map(|key| {
            <[u8; 32]>::try_from(field("db_volume_key", key)?.as_slice())
                .map(Zeroizing::new)
                .map_err(|_| ApiError::internal("join reply: db_volume_key"))
        })
        .transpose()?;
    let keys = Intermediates::new(
        tenant_kek_root,
        Zeroizing::new(field("ca_key", &reply.ca_key)?),
        field("ca_cert", &reply.ca_cert)?,
    )?
    .with_db_volume(db_volume);
    node.start_serving(keys).await
}

/// An HTTPS client for the other node: our self-signed runtime certificate as identity, the
/// server pinned to `kms_ca_pem` and to a Revision in `kms_revisions`.
fn join_client(
    node: &Node,
    endpoint: &str,
    kms_ca_pem: &str,
    revisions: &[alpha_attest::KmsRevision],
) -> Result<Client, ApiError> {
    let internal = |e: alpha_client::Error| ApiError::internal(e.to_string());
    let ca = alpha_client::tls::cert_from_pem(kms_ca_pem).map_err(internal)?;
    let pin = Pin::CaAndRevisions(ca, revisions.iter().map(|r| r.compose_hash).collect());
    let cert = certs::self_signed(&certs::key_pair(&node.runtime_pkcs8)?, node.now())?;
    let identity = Identity {
        chain: vec![cert],
        pkcs8: node.runtime_pkcs8.to_vec(),
    };
    Client::with_identity(vec![endpoint.to_owned()], pin, Some(identity)).map_err(internal)
}
