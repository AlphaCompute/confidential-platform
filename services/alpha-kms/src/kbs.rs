//! `alpha-kbs`: the KBS protocol CoCo's guest components speak, served by the KMS over its own
//! appraisal and its own secrets, so the Confidential Data Hub in a Kata pod fetches registry
//! credentials, image keys and sealed-secret keys from this authority (PRD-02 P1; doc 04,
//! Decision 1, option C). `docs/kbs.md` has the protocol, the resource names and the threat model.
//!
//! Pinned to KBS protocol 0.4.0 as guest-components [`GUEST_COMPONENTS`] speaks it: the commit
//! kata-containers 4.1.0's `versions.yaml` builds into the guest (`coco-guest-components`), whose
//! KBS client is wire-identical to v0.21.0's (Kata 4.0.0) for everything used here
//! (`attestation-agent/kbs_protocol`, kbs-types 0.18.0):
//!
//! 1. `POST /kbs/v0/auth` takes `{version, tee, extra-params}` and returns `{nonce, extra-params}`:
//!    our stateless five-minute nonce (as `POST /v1/attest/nonce`), base64, and `sha384` as the
//!    runtime-data hash.
//! 2. `POST /kbs/v0/attest` takes `{init-data, runtime-data: {nonce, tee-pubkey}, tee-evidence}`.
//!    The TD quote's `report_data` is SHA-384 of the JCS of `{tee-pubkey, nonce,
//!    additional-evidence}`, zero-padded; each GPU report is over the first 32 bytes of SHA-384
//!    of the JCS of `{nonce, tee-pubkey}`. Appraised by `kata-tdx/1` and admitted exactly as
//!    `POST /v1/attest` does ([`instance::appraise_kata`], [`instance::admit`]), it returns
//!    `{token}`, which also comes back as the `kbs-session-id` cookie.
//! 3. `GET /kbs/v0/resource/<repository>/<type>/<tag>` with that token as a bearer (CDH) or
//!    cookie (the attestation agent's own client) returns the resource as a JWE sealed to the
//!    `tee-pubkey` the quote bound ([`jwe`]).

pub mod jwe;
pub mod token;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use alpha_attest::{
    AttestationResult, CpuEvidence, CpuKind, EVIDENCE_FORMAT_V2, EvidenceV2, VerifiedQuote, kata,
};
use alpha_core::AppId;
use alpha_core::coco::InitData;
use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::prelude::{BASE64_STANDARD, BASE64_URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256, Sha384};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::audit::Audit;
use crate::error::ApiError;
use crate::{Intermediates, Node, certs, instance, keys};

/// guest-components at the commit kata-containers 4.1.0 pins (v0.21.0 is da8d93f2).
pub const GUEST_COMPONENTS: &str = "d4dce5ce62294cfa741225f7e5b4527ea276f326";
/// `KBS_PROTOCOL_VERSION` of that commit; Trustee 258ea4ac accepts exactly this version too.
pub const PROTOCOL_VERSION: &str = "0.4.0";
/// The only TEE `kata-tdx/1` appraises.
pub const TEE: &str = "tdx";
/// The runtime-data hash the challenge selects; also the client's default.
pub const HASH_ALGORITHM: &str = "sha384";
/// Additional-evidence key of NVIDIA's devices (kbs-types `Tee::Nvidia`).
pub const NVIDIA_TEE: &str = alpha_tsm::coco::NVIDIA_TEE;
pub const SESSION_COOKIE: &str = "kbs-session-id";
/// The format the attestation agent declares for the init-data it forwards.
pub const INITDATA_FORMAT: &str = "toml";
const ERROR_TYPE_PREFIX: &str = "https://github.com/confidential-containers/kbs/errors";

/// The TEE key of `runtime-data`, as the attestation agent exports its default key pair
/// (`TeeKeyAlgorithm::EcdhEsA256KwP256`). It must be exactly that: the quote binds the JSON the
/// agent sent, so no field the KMS does not use may ride along.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeeKey {
    pub kty: String,
    pub crv: String,
    pub alg: String,
    pub x: String,
    pub y: String,
}

impl TeeKey {
    /// The P-256 key every resource is sealed to. RSA and P-521 keys, which the agent can be
    /// configured to use, are refused rather than supported.
    pub fn public_key(&self) -> Result<p256::PublicKey, ApiError> {
        if (self.kty.as_str(), self.crv.as_str(), self.alg.as_str()) != ("EC", jwe::CRV, jwe::ALG) {
            return Err(ApiError::malformed(format!(
                "tee-pubkey: only an EC {} key for {} (the attestation agent's default) is accepted",
                jwe::CRV,
                jwe::ALG
            )));
        }
        let coordinate = |text: &str| {
            BASE64_URL_SAFE_NO_PAD
                .decode(text)
                .ok()
                .filter(|b| b.len() == 32)
                .ok_or_else(|| ApiError::malformed("tee-pubkey: a coordinate is not 32 bytes"))
        };
        let sec1 = [vec![4u8], coordinate(&self.x)?, coordinate(&self.y)?].concat();
        p256::PublicKey::from_sec1_bytes(&sec1)
            .map_err(|_| ApiError::malformed("tee-pubkey: not a point on P-256"))
    }

    /// SHA-256 of its JCS: the key an attestation names, in audit rows and the result.
    pub fn sha256(&self) -> Result<[u8; 32], ApiError> {
        let value = serde_json::to_value(self).map_err(|e| ApiError::internal(e.to_string()))?;
        let jcs = alpha_core::jcs(&value).map_err(|e| ApiError::internal(e.to_string()))?;
        Ok(Sha256::digest(jcs).into())
    }
}

#[derive(Deserialize)]
struct AuthRequest {
    version: String,
    tee: String,
    #[serde(rename = "extra-params", default)]
    extra_params: Value,
}

/// kbs-types' `Attestation`. Fields it may gain are ignored: everything the KMS relies on is
/// bound by the quote or by MRCONFIGID.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Attestation {
    #[serde(default)]
    pub init_data: Option<KbsInitData>,
    pub runtime_data: RuntimeData,
    pub tee_evidence: CompositeEvidence,
}

#[derive(Debug, Deserialize)]
pub struct KbsInitData {
    pub format: String,
    pub body: String,
}

#[derive(Debug, Deserialize)]
pub struct RuntimeData {
    pub nonce: String,
    #[serde(rename = "tee-pubkey")]
    pub tee_pubkey: Value,
}

#[derive(Debug, Deserialize)]
pub struct CompositeEvidence {
    pub primary_evidence: Value,
    pub additional_evidence: String,
}

/// The attestation agent's TDX evidence (`attester/src/tdx`): the quote and the CCEL, base64.
#[derive(Deserialize)]
struct TdxEvidence {
    quote: String,
    #[serde(default)]
    cc_eventlog: Option<String>,
}

/// A refusal as the KBS client reads it: kbs-types' `ErrorInformation`, with the status that
/// decides what the client does next. 401 makes it attest again and retry; 404 ends the request.
#[derive(Debug)]
pub struct KbsError {
    pub status: StatusCode,
    pub kind: &'static str,
    pub error: ApiError,
}

impl KbsError {
    fn with(status: StatusCode, kind: &'static str, error: ApiError) -> Self {
        Self {
            status,
            kind,
            error,
        }
    }
}

impl From<ApiError> for KbsError {
    fn from(error: ApiError) -> Self {
        let (status, kind) = match error.code {
            "internal" => (StatusCode::INTERNAL_SERVER_ERROR, "InternalError"),
            "sealed" => (StatusCode::SERVICE_UNAVAILABLE, "Sealed"),
            "rate_limited" => (StatusCode::TOO_MANY_REQUESTS, "RateLimited"),
            "not_found" | "kbs_disabled" => (StatusCode::NOT_FOUND, "ResourceNotFound"),
            "token_missing" => (StatusCode::UNAUTHORIZED, "TokenNotFound"),
            "token_invalid" => (StatusCode::UNAUTHORIZED, "TokenVerifierError"),
            _ => (StatusCode::UNAUTHORIZED, "AttestationError"),
        };
        Self::with(status, kind, error)
    }
}

impl IntoResponse for KbsError {
    fn into_response(self) -> Response {
        let body = json!({
            "type": format!("{ERROR_TYPE_PREFIX}/{}", self.kind),
            "detail": format!("{}: {}", self.error.code, self.error.message),
        });
        (self.status, Json(body)).into_response()
    }
}

/// The facade answers only on a node configured with the hostname pods reach it under; without
/// one it refuses everything (fail closed).
fn enabled(node: &Node) -> Result<(), ApiError> {
    match node.config.kbs_hostname {
        Some(_) => Ok(()),
        None => Err(ApiError::new(
            "kbs_disabled",
            "the KBS facade is not enabled on this node (ALPHACOMPUTE_KBS_HOSTNAME)",
        )),
    }
}

fn unix(now: SystemTime) -> u64 {
    now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

pub async fn auth(State(node): State<Arc<Node>>, body: Bytes) -> Response {
    match auth_inner(&node, &body) {
        Ok(challenge) => Json(challenge).into_response(),
        Err(e) => KbsError::from(e).into_response(),
    }
}

fn auth_inner(node: &Node, body: &[u8]) -> Result<Value, ApiError> {
    enabled(node)?;
    let request: AuthRequest =
        serde_json::from_slice(body).map_err(|e| ApiError::malformed(format!("Request: {e}")))?;
    if request.version != PROTOCOL_VERSION {
        return Err(ApiError::new(
            "policy_denied",
            format!(
                "KBS Client Protocol Version Mismatch: expect ={PROTOCOL_VERSION} while the request is {}",
                request.version
            ),
        ));
    }
    if request.tee != TEE {
        return Err(ApiError::new(
            "policy_denied",
            format!("tee {:?}: only tdx is appraised (kata-tdx/1)", request.tee),
        ));
    }
    if let Some(param) = request.extra_params.get("supported-hash-algorithms") {
        let supported = param.as_array().ok_or_else(|| {
            ApiError::new("policy_denied", "supported-hash-algorithms must be an array")
        })?;
        if !supported.iter().any(|a| a.as_str() == Some(HASH_ALGORITHM)) {
            return Err(ApiError::new(
                "policy_denied",
                format!("the client does not support {HASH_ALGORITHM}"),
            ));
        }
    }
    let nonce = instance::mint_nonce(&node.nonce_key, node.now())?;
    Ok(json!({
        "nonce": BASE64_STANDARD.encode(nonce),
        "extra-params": { "selected-hash-algorithm": HASH_ALGORITHM },
    }))
}

pub async fn attest(State(node): State<Arc<Node>>, body: Bytes) -> Response {
    match attest_audited(&node, &body, None).await {
        Ok(token) => token_reply(token),
        Err(e) => e.into_response(),
    }
}

fn token_reply(token: String) -> Response {
    let cookie = format!(
        "{SESSION_COOKIE}={token}; Path=/kbs/v0; Max-Age={}; Secure; HttpOnly; SameSite=Strict",
        certs::LEAF_TTL.as_secs()
    );
    let mut response = Json(json!({ "token": token })).into_response();
    if let Ok(cookie) = HeaderValue::from_str(&cookie) {
        response.headers_mut().insert(header::SET_COOKIE, cookie);
    }
    response
}

/// [`attest`] over a TDX quote the caller has verified: every step after DCAP, the audit row
/// included. No route reaches it; the KMS's tests run Kata pods through it over synthetic quotes,
/// as `instance::attest_verified` does for `POST /v1/attest`.
pub async fn attest_verified(
    node: &Node,
    body: &[u8],
    verified: VerifiedQuote,
) -> Result<String, ApiError> {
    attest_audited(node, body, Some(verified))
        .await
        .map_err(|e| e.error)
}

async fn attest_audited(
    node: &Node,
    body: &[u8],
    verified: Option<VerifiedQuote>,
) -> Result<String, KbsError> {
    enabled(node)?;
    let value =
        alpha_core::parse(body).map_err(|e| ApiError::malformed(format!("Attestation: {e}")));
    let evidence_sha256 = Sha256::digest(
        value
            .as_ref()
            .ok()
            .and_then(|v| alpha_core::jcs(v).ok())
            .unwrap_or_else(|| body.to_vec()),
    )
    .to_vec();
    let attestation = value.and_then(|v| {
        Attestation::deserialize(&v).map_err(|e| ApiError::malformed(format!("Attestation: {e}")))
    });
    let tee_key = attestation
        .as_ref()
        .ok()
        .and_then(|a| serde_json::from_value::<TeeKey>(a.runtime_data.tee_pubkey.clone()).ok());
    let actor = tee_key
        .as_ref()
        .and_then(|k| k.sha256().ok())
        .map_or_else(|| "unauthenticated".to_owned(), hex::encode);
    let now = node.now();
    let result = match &attestation {
        Ok(attestation) => attest_inner(node, attestation, verified, now).await,
        Err(e) => Err(ApiError::new(e.code, e.message.clone())),
    };
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
        action: "kbs.attest",
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
    .await
    .map_err(ApiError::from)?;
    Ok(result?.0)
}

/// The token and the result behind it.
async fn attest_inner(
    node: &Node,
    attestation: &Attestation,
    verified: Option<VerifiedQuote>,
    now: SystemTime,
) -> Result<(String, AttestationResult), ApiError> {
    let tee_key: TeeKey = serde_json::from_value(attestation.runtime_data.tee_pubkey.clone())
        .map_err(|e| ApiError::malformed(format!("tee-pubkey: {e}")))?;
    tee_key.public_key()?;
    let nonce: [u8; 32] = BASE64_STANDARD
        .decode(&attestation.runtime_data.nonce)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| ApiError::new("nonce_invalid", "nonce is not one this KMS issued"))?;
    instance::check_nonce(&node.nonce_key, &nonce, now)?;
    let doc = node
        .platform_document()
        .ok_or_else(|| ApiError::new("attestation_unknown", "no platform document"))?;
    let evidence = evidence_v2(attestation)?;
    let binding = binding(attestation, &tee_key)?;
    let appraised = instance::appraise_kata(node, &evidence, verified, &binding, &doc, now).await?;
    let revision = instance::admit(node, &doc, &appraised).await?;
    let result = instance::attestation_result(appraised, &revision, now);
    let keys = node.intermediates()?;
    let iat = unix(now);
    let claims = token::Claims {
        iss: token::ISSUER.into(),
        iat,
        exp: iat.saturating_add(certs::LEAF_TTL.as_secs()),
        revision: result.revision.clone(),
        tee_pubkey: tee_key,
        evidence_sha256: result.evidence_sha256.clone(),
    };
    let key = token::token_key(&keys.tenant_kek_root)?;
    let token = token::issue(&key, &claims)?;
    Ok((token, result))
}

fn failed(message: impl Into<String>) -> ApiError {
    ApiError::new("attestation_failed", message)
}

/// The KBS attestation as `alphacompute-evidence/2`, so `kata-tdx/1` appraises it unchanged. The
/// runtime class is the init-data's own: the KBS protocol carries no claim of one, and step 7's
/// check that the claim is the measured init-data's holds trivially.
pub fn evidence_v2(attestation: &Attestation) -> Result<EvidenceV2, ApiError> {
    let initdata = attestation.init_data.as_ref().ok_or_else(|| {
        failed("no init-data: the attestation agent must forward the pod's init-data")
    })?;
    if initdata.format != INITDATA_FORMAT {
        return Err(failed(format!("init-data format {:?}", initdata.format)));
    }
    let initdata = initdata.body.clone().into_bytes();
    let runtime_class = InitData::parse(&initdata)
        .and_then(|d| d.revision())
        .map_err(|e| failed(format!("init-data: {e}")))?
        .runtime_class;

    let primary: TdxEvidence =
        serde_json::from_value(attestation.tee_evidence.primary_evidence.clone())
            .map_err(|e| ApiError::malformed(format!("tdx evidence: {e}")))?;
    let quote = BASE64_STANDARD
        .decode(primary.quote.trim())
        .map_err(|_| ApiError::malformed("tdx evidence: quote is not base64"))?;
    let event_log = match primary.cc_eventlog.as_deref().map(str::trim) {
        Some(log) if !log.is_empty() => {
            let ccel = BASE64_STANDARD
                .decode(log)
                .map_err(|_| ApiError::malformed("tdx evidence: cc_eventlog is not base64"))?;
            alpha_tsm::boot_events(&ccel).map_err(|e| failed(format!("cc_eventlog: {e}")))?
        }
        _ => Vec::new(),
    };

    Ok(EvidenceV2 {
        format: EVIDENCE_FORMAT_V2.into(),
        cpu: CpuEvidence {
            kind: CpuKind::Tdx,
            quote,
            event_log,
        },
        gpus: gpus(&attestation.tee_evidence.additional_evidence)?,
        initdata,
        runtime_class,
    })
}

/// The GPUs in the additional evidence: NVIDIA's devices, NVSwitches left out. Evidence of any
/// other device is refused, never ignored, as GPU evidence from a CPU pod is.
fn gpus(additional: &str) -> Result<Vec<alpha_attest::GpuEvidence>, ApiError> {
    if additional.is_empty() {
        return Ok(Vec::new());
    }
    let devices: serde_json::Map<String, Value> = serde_json::from_str(additional)
        .map_err(|e| ApiError::malformed(format!("additional evidence: {e}")))?;
    let mut gpus = Vec::new();
    for (tee, evidence) in devices {
        if tee != NVIDIA_TEE {
            return Err(failed(format!(
                "additional evidence from {tee:?} is not appraised"
            )));
        }
        gpus = alpha_tsm::coco::nvidia_gpus(evidence).map_err(|e| failed(e.to_string()))?;
    }
    Ok(gpus)
}

/// What the attestation agent bound, recomputed from what it sent: `report_data` is SHA-384 of
/// the JCS of `{tee-pubkey, nonce, additional-evidence}` zero-padded to 64 bytes
/// (`rcar_client.rs` `get_composite_evidence`, the TDX attester's `resize`); the GPU nonce is the
/// first 32 bytes of SHA-384 of the JCS of `{nonce, tee-pubkey}` (the NVIDIA attester's).
pub fn binding(attestation: &Attestation, tee_key: &TeeKey) -> Result<kata::Binding, ApiError> {
    let runtime = &attestation.runtime_data;
    let jcs = |value: &Value| {
        alpha_core::jcs(value).map_err(|e| ApiError::malformed(format!("runtime-data: {e}")))
    };
    let primary = jcs(&json!({
        "tee-pubkey": runtime.tee_pubkey,
        "nonce": runtime.nonce,
        "additional-evidence": attestation.tee_evidence.additional_evidence,
    }))?;
    let device = jcs(&json!({ "nonce": runtime.nonce, "tee-pubkey": runtime.tee_pubkey }))?;
    let mut report_data = [0u8; 64];
    for (dst, src) in report_data.iter_mut().zip(Sha384::digest(primary)) {
        *dst = src;
    }
    let mut gpu_nonce = [0u8; 32];
    for (dst, src) in gpu_nonce.iter_mut().zip(Sha384::digest(device)) {
        *dst = src;
    }
    Ok(kata::Binding::exact(
        report_data,
        gpu_nonce,
        tee_key.sha256()?,
    ))
}

/// What `<repository>/<type>/<tag>` names. The repository is the App id, in its canonical
/// lowercase form, of the pod asking; the type picks one of the KMS's two release paths.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resource {
    /// `<app>/secret/<name>`: the organization's Secret `name`, if its signed document lists
    /// the App, exactly as `GET /v1/secrets/{name}` releases it.
    Secret { app: AppId, name: String },
    /// `<app>/key/<purpose>`: the App's derived key for `purpose`, the 32 bytes
    /// `POST /v1/keys/derive` returns for it.
    Key { app: AppId, purpose: String },
}

impl Resource {
    // ponytail: Option B (deliverable 26) settles which resources CDH's secure mount, encrypted
    // images and sealed secrets ask for and under which names `alpha coco render` writes them;
    // until then `secret` and `key` are the only types and every other name is not found.
    pub fn parse(repository: &str, kind: &str, tag: &str) -> Result<Self, ApiError> {
        let app = repository
            .parse::<AppId>()
            .ok()
            .filter(|app| app.to_string() == repository)
            .ok_or_else(|| ApiError::not_found("repository: not an App id"))?;
        match kind {
            "secret" if alpha_core::is_secret_name(tag) => Ok(Self::Secret {
                app,
                name: tag.to_owned(),
            }),
            "key" if alpha_core::is_key_purpose(tag) => Ok(Self::Key {
                app,
                purpose: tag.to_owned(),
            }),
            "secret" | "key" => Err(ApiError::not_found(format!("{kind}: not a valid name"))),
            _ => Err(ApiError::not_found(
                "type: only secret and key resources exist",
            )),
        }
    }

    fn app(&self) -> AppId {
        match self {
            Self::Secret { app, .. } | Self::Key { app, .. } => *app,
        }
    }
}

/// The bearer token (CDH's token client) or else the session cookie (the agent's RCAR client).
fn presented_token(headers: &HeaderMap) -> Option<String> {
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|t| t.trim().to_owned());
    bearer.or_else(|| {
        headers
            .get_all(header::COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(';'))
            .filter_map(|c| c.trim().split_once('='))
            .find(|(name, _)| *name == SESSION_COOKIE)
            .map(|(_, value)| value.to_owned())
    })
}

pub async fn resource(
    State(node): State<Arc<Node>>,
    Path((repository, kind, tag)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Response {
    let token = presented_token(&headers);
    match resource_audited(&node, token.as_deref(), &repository, &kind, &tag).await {
        Ok(jwe) => Json(jwe).into_response(),
        Err(e) => e.into_response(),
    }
}

async fn resource_audited(
    node: &Node,
    token: Option<&str>,
    repository: &str,
    kind: &str,
    tag: &str,
) -> Result<Value, KbsError> {
    enabled(node)?;
    let keys = node.intermediates()?;
    let claims = token
        .ok_or_else(|| ApiError::new("token_missing", "no attestation token"))
        .and_then(|t| {
            let key = token::token_key(&keys.tenant_kek_root)?;
            token::verify(&key, t, unix(node.now()))
        });
    let resource = Resource::parse(repository, kind, tag);
    // A refused name is unbounded text from the peer; the error names the rule instead.
    let object = resource
        .as_ref()
        .ok()
        .map(|_| format!("resource:{repository}/{kind}/{tag}"));
    let (actor, org_id, result) = match claims {
        Ok(claims) => {
            let actor = claims
                .tee_pubkey
                .sha256()
                .map_or_else(|_| "unauthenticated".to_owned(), hex::encode);
            let org_id = Some(Uuid::from(claims.revision.org_id));
            (actor, org_id, release(node, &keys, &claims, resource).await)
        }
        Err(e) => ("unauthenticated".to_owned(), None, Err(KbsError::from(e))),
    };
    let (outcome, details) = match &result {
        Ok(_) => ("ok", json!({})),
        Err(e) => (e.error.outcome(), e.error.details()),
    };
    Audit {
        actor_kind: "instance",
        actor: &actor,
        action: "kbs.resource",
        org_id,
        object,
        outcome,
        details,
        evidence_sha256: None,
    }
    .insert(&node.pool)
    .await
    .map_err(ApiError::from)?;
    result
}

/// Deny by default: the token's Revision as it is now, then a resource of exactly that pod's
/// App, then that App's release rule. Nothing else reaches a value.
async fn release(
    node: &Node,
    keys: &Intermediates,
    claims: &token::Claims,
    resource: Result<Resource, ApiError>,
) -> Result<Value, KbsError> {
    let root = &keys.tenant_kek_root;
    let revision = &claims.revision;
    // A Revision revoked (or re-signed away) since the token was issued: 401, so the client
    // attests again and that attestation is refused, with its reason, in its own audit row.
    let chain = instance::current_revision(
        node,
        root,
        revision.org_id,
        revision.app_id,
        revision.compose_hash,
    )
    .await
    .map_err(|e| match e.code {
        "internal" => KbsError::from(e),
        _ => KbsError::with(StatusCode::UNAUTHORIZED, "PolicyDeny", e),
    })?;
    let resource = resource?;
    if resource.app() != revision.app_id {
        return Err(ApiError::not_found("no such resource for this pod's App").into());
    }
    let value: Zeroizing<Vec<u8>> = match &resource {
        Resource::Secret { name, .. } => {
            instance::open_secret(node, root, revision.org_id, revision.app_id, name)
                .await
                .map_err(|e| match e.code {
                    "internal" | "not_found" => KbsError::from(e),
                    _ => KbsError::with(StatusCode::FORBIDDEN, "PolicyDeny", e),
                })?
                .value
        }
        Resource::Key { purpose, .. } => {
            let org_key = keys::org_key(root, revision.org_id, &chain.anchor_spki)?;
            Zeroizing::new(keys::app_key(&org_key, revision.app_id, purpose)?.to_vec())
        }
    };
    Ok(jwe::seal(&claims.tee_pubkey.public_key()?, &value)?)
}

#[cfg(test)]
mod tests;
