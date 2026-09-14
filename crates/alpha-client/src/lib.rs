//! Client for the three APIs of `alpha-kms`: a list of endpoints tried in turn on a connection
//! failure or a 5xx (never on a 4xx), one pinned TLS configuration, typed bodies for every route,
//! the error envelope as one error, and the signing helper for the Control bodies.

#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )
)]
pub mod platform;
pub mod tls;

use alpha_attest::{AttestationResult, EVIDENCE_FORMAT, EventLogEntry, Evidence};
use alpha_core::{
    AppId, ComposeHash, KeyId, OrgId, PrincipalId, SecretId, context, signing_digest,
};
use alpha_crypto::{PublicKey, Sealed};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer, SigningKey};
use p256::ecdsa::signature::Verifier;
use p256::pkcs8::DecodePublicKey;
use reqwest::Method;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub use tls::{Identity, Pin};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The KMS error envelope `{ "error": { code, message, request_id } }`.
    #[error(transparent)]
    Api(ApiError),
    /// No endpoint answered.
    #[error("{0}")]
    Connect(String),
    /// A pin, a body or a reply that does not have the expected shape.
    #[error("{0}")]
    Invalid(String),
}

#[derive(Debug, Deserialize, thiserror::Error)]
#[error("{code}: {message} (request {request_id})")]
pub struct ApiError {
    pub code: String,
    pub message: String,
    pub request_id: String,
}

#[derive(Deserialize)]
struct Envelope {
    error: ApiError,
}

fn api_error(endpoint: &str, status: reqwest::StatusCode, bytes: &[u8]) -> Error {
    match serde_json::from_slice::<Envelope>(bytes) {
        Ok(envelope) => Error::Api(envelope.error),
        Err(_) => Error::Invalid(format!("{endpoint}: {status} without an error envelope")),
    }
}

/// `{ "key_id", "algorithm": "ed25519", "signature" }`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureObject {
    pub key_id: KeyId,
    pub algorithm: String,
    pub signature: String,
}

/// The body of every Control mutation.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signed {
    pub payload: Value,
    pub signature: SignatureObject,
}

/// Route 3 alone carries the value beside the signed document.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PutSecretBody {
    pub payload: Value,
    pub signature: SignatureObject,
    pub value: String,
}

pub fn sign(ctx: &str, payload: Value, key_id: KeyId, key: &SigningKey) -> Signed {
    let digest = signing_digest(ctx, &payload);
    Signed {
        payload,
        signature: SignatureObject {
            key_id,
            algorithm: "ed25519".into(),
            signature: BASE64_URL_SAFE_NO_PAD.encode(key.sign(&digest).to_bytes()),
        },
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Ready {
    pub sealed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Nonce {
    pub nonce: String,
    pub expires_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestRequest {
    pub runtime_pubkey: String,
    pub nonce: String,
    pub evidence: Evidence,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttestReply {
    pub certificate_chain: Vec<String>,
    pub not_after: String,
    pub attestation_result: AttestationResult,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Secret {
    pub value: String,
    pub content_sha256: String,
    pub issued_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevisionRegistered {
    pub compose_hash: ComposeHash,
    pub app_id: AppId,
    pub org_id: OrgId,
    pub created_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevisionRevoked {
    pub compose_hash: ComposeHash,
    pub revoked_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecretPut {
    pub id: SecretId,
    pub name: String,
    pub app_ids: Vec<AppId>,
    pub content_sha256: String,
    pub issued_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyRegistered {
    pub id: KeyId,
    pub principal_id: PrincipalId,
    pub org_id: OrgId,
    pub created_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyRevoked {
    pub key_id: KeyId,
    pub revoked_at: String,
    pub reason: String,
}

/// `GET /v1/node/evidence`: the quote is base64url, `runtime_pubkey` the P-256 SPKI DER.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeEvidence {
    pub quote: String,
    pub event_log: Vec<EventLogEntry>,
    pub runtime_pubkey: String,
    pub xwing_pubkey: PublicKey,
    pub compose_hash: ComposeHash,
}

impl NodeEvidence {
    pub fn evidence(&self) -> Result<Evidence, Error> {
        Ok(Evidence {
            format: EVIDENCE_FORMAT.into(),
            quote: decode("quote", &self.quote)?,
            event_log: self.event_log.clone(),
        })
    }

    pub fn runtime_spki(&self) -> Result<Vec<u8>, Error> {
        decode("runtime_pubkey", &self.runtime_pubkey)
    }
}

pub fn decode(field: &str, text: &str) -> Result<Vec<u8>, Error> {
    BASE64_URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|_| Error::Invalid(format!("{field}: not base64url")))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapRequest {
    pub body_hpke: Sealed,
}

/// What `alpha bootstrap` seals to the node.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapBody {
    pub custodians: [PublicKey; 3],
    pub anchor: Anchor,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Anchor {
    pub org_id: OrgId,
    pub principal_id: PrincipalId,
    pub public_key: String,
    pub label: String,
}

/// The reply as received; `payload` is typed only after its signature has been checked.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapReply {
    pub payload: Value,
    pub signature: NodeSignature,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeSignature {
    pub algorithm: String,
    pub signature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapPayload {
    pub shares_hpke: Vec<Sealed>,
    pub kms_ca_pem: String,
    pub anchor_key_id: KeyId,
}

impl BootstrapReply {
    /// ECDSA P-256 (r‖s) by the node's runtime key over `signing_digest(NODE_BOOTSTRAP, payload)`.
    pub fn verify(&self, runtime_spki: &[u8]) -> Result<BootstrapPayload, Error> {
        let refuse = |m: &str| Error::Invalid(format!("bootstrap reply: {m}"));
        if self.signature.algorithm != "ecdsa-p256" {
            return Err(refuse("algorithm is not ecdsa-p256"));
        }
        let key = p256::ecdsa::VerifyingKey::from_public_key_der(runtime_spki)
            .map_err(|_| refuse("runtime_pubkey is not a P-256 SPKI"))?;
        let signature = decode("signature", &self.signature.signature)
            .ok()
            .and_then(|b| p256::ecdsa::Signature::from_slice(&b).ok())
            .ok_or_else(|| refuse("signature is not r‖s"))?;
        key.verify(
            &signing_digest(context::NODE_BOOTSTRAP, &self.payload),
            &signature,
        )
        .map_err(|_| refuse("signature does not verify under the node's runtime key"))?;
        serde_json::from_value(self.payload.clone()).map_err(|e| refuse(&e.to_string()))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsealRequest {
    pub share_hpke: Sealed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnsealReply {
    pub sealed: bool,
    pub shares: usize,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinRequest {
    pub nonce: String,
    pub evidence: Evidence,
    pub xwing_pubkey: PublicKey,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JoinReply {
    pub tenant_kek_root: String,
    pub ca_key: String,
    pub ca_cert: String,
}

pub struct Client {
    endpoints: Vec<String>,
    http: reqwest::Client,
}

impl Client {
    pub fn new(endpoints: Vec<String>, pin: Pin) -> Result<Self, Error> {
        Self::with_identity(endpoints, pin, None)
    }

    pub fn with_identity(
        endpoints: Vec<String>,
        pin: Pin,
        identity: Option<Identity>,
    ) -> Result<Self, Error> {
        if endpoints.is_empty() {
            return Err(Error::Invalid("no endpoints".into()));
        }
        let http = reqwest::Client::builder()
            .tls_backend_preconfigured(tls::client_config(Some(pin), identity)?)
            .build()
            .map_err(|e| Error::Invalid(format!("http client: {e}")))?;
        Ok(Self {
            endpoints: endpoints
                .into_iter()
                .map(|e| e.trim_end_matches('/').to_owned())
                .collect(),
            http,
        })
    }

    /// Walks the endpoints: a connection failure or a 5xx moves to the next one, a 4xx is final.
    async fn request<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<T, Error> {
        let mut last = Error::Connect("no endpoints".into());
        for endpoint in &self.endpoints {
            let mut request = self
                .http
                .request(method.clone(), format!("{endpoint}{path}"));
            if let Some(body) = body {
                request = request.json(body);
            }
            let response = match request.send().await {
                Ok(r) => r,
                Err(e) => {
                    last = Error::Connect(format!("{endpoint}: {e}"));
                    continue;
                }
            };
            let status = response.status();
            let bytes = response
                .bytes()
                .await
                .map_err(|e| Error::Connect(format!("{endpoint}: {e}")))?;
            if status.is_success() {
                return serde_json::from_slice(&bytes)
                    .map_err(|e| Error::Invalid(format!("{method} {path}: reply: {e}")));
            }
            last = api_error(endpoint, status, &bytes);
            if !status.is_server_error() {
                return Err(last);
            }
        }
        Err(last)
    }

    async fn post<T: DeserializeOwned>(
        &self,
        path: &str,
        body: &impl Serialize,
    ) -> Result<T, Error> {
        self.request(Method::POST, path, Some(&json!(body))).await
    }

    pub async fn ready(&self) -> Result<Ready, Error> {
        self.request(Method::GET, "/ready", None).await
    }

    // Instance API

    pub async fn attest_nonce(&self) -> Result<Nonce, Error> {
        self.request(Method::POST, "/v1/attest/nonce", None).await
    }

    pub async fn attest(&self, body: &AttestRequest) -> Result<AttestReply, Error> {
        self.post("/v1/attest", body).await
    }

    pub async fn get_secret(&self, name: &str) -> Result<Secret, Error> {
        self.request(Method::GET, &format!("/v1/secrets/{name}"), None)
            .await
    }

    // Control API

    pub async fn register_revision(&self, body: &Signed) -> Result<RevisionRegistered, Error> {
        self.post("/v1/revisions", body).await
    }

    pub async fn revoke_revision(
        &self,
        compose_hash: ComposeHash,
        body: &Signed,
    ) -> Result<RevisionRevoked, Error> {
        self.post(&format!("/v1/revisions/{compose_hash}/revoke"), body)
            .await
    }

    pub async fn put_secret(&self, name: &str, body: &PutSecretBody) -> Result<SecretPut, Error> {
        self.request(
            Method::PUT,
            &format!("/v1/secrets/{name}"),
            Some(&json!(body)),
        )
        .await
    }

    pub async fn register_key(&self, body: &Signed) -> Result<KeyRegistered, Error> {
        self.post("/v1/keys", body).await
    }

    pub async fn revoke_key(&self, key_id: KeyId, body: &Signed) -> Result<KeyRevoked, Error> {
        self.post(&format!("/v1/keys/{key_id}/revoke"), body).await
    }

    // Node API; the evidence route is [`fetch_node_evidence`], the pin comes from its reply.

    pub async fn bootstrap(&self, body: &BootstrapRequest) -> Result<BootstrapReply, Error> {
        self.post("/v1/node/bootstrap", body).await
    }

    pub async fn unseal(&self, body: &UnsealRequest) -> Result<UnsealReply, Error> {
        self.post("/v1/node/unseal", body).await
    }

    pub async fn join(&self, body: &JoinRequest) -> Result<JoinReply, Error> {
        self.post("/v1/node/join", body).await
    }
}

/// A sealed node's evidence over an unpinned connection, together with the SPKI the server
/// proved possession of: the quote authenticates the node, and the caller must check that
/// this SPKI is the attested `runtime_pubkey` before anything is sealed to the node.
pub async fn fetch_node_evidence(
    endpoint: &str,
    nonce: &[u8; 32],
) -> Result<(NodeEvidence, Vec<u8>), Error> {
    let endpoint = endpoint.trim_end_matches('/');
    let http = reqwest::Client::builder()
        .tls_backend_preconfigured(tls::client_config(None, None)?)
        .tls_info(true)
        .build()
        .map_err(|e| Error::Invalid(format!("http client: {e}")))?;
    let response = http
        .get(format!(
            "{endpoint}/v1/node/evidence?nonce={}",
            BASE64_URL_SAFE_NO_PAD.encode(nonce)
        ))
        .send()
        .await
        .map_err(|e| Error::Connect(format!("{endpoint}: {e}")))?;
    let leaf = response
        .extensions()
        .get::<reqwest::tls::TlsInfo>()
        .and_then(|info| info.peer_certificate().map(<[u8]>::to_vec))
        .ok_or_else(|| Error::Invalid("no server certificate on the connection".into()))?;
    let spki = tls::spki_of(&leaf)?;
    let status = response.status();
    let bytes = response
        .bytes()
        .await
        .map_err(|e| Error::Connect(format!("{endpoint}: {e}")))?;
    if !status.is_success() {
        return Err(api_error(endpoint, status, &bytes));
    }
    let evidence = serde_json::from_slice(&bytes)
        .map_err(|e| Error::Invalid(format!("node evidence: {e}")))?;
    Ok((evidence, spki))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_reply_is_typed_only_after_its_signature_verifies() {
        use p256::ecdsa::signature::Signer as _;
        use p256::pkcs8::EncodePublicKey;
        let node = p256::ecdsa::SigningKey::from_bytes((&[3u8; 32]).into()).unwrap();
        let spki = node.verifying_key().to_public_key_der().unwrap().into_vec();
        let payload = serde_json::json!({
            "shares_hpke": [], "kms_ca_pem": "pem", "anchor_key_id": KeyId::mint()
        });
        let sig: p256::ecdsa::Signature =
            node.sign(&signing_digest(context::NODE_BOOTSTRAP, &payload));
        let reply = BootstrapReply {
            payload: payload.clone(),
            signature: NodeSignature {
                algorithm: "ecdsa-p256".into(),
                signature: BASE64_URL_SAFE_NO_PAD.encode(sig.to_bytes()),
            },
        };
        assert_eq!(reply.verify(&spki).unwrap().kms_ca_pem, "pem");
        let other = p256::ecdsa::SigningKey::from_bytes((&[4u8; 32]).into()).unwrap();
        let other_spki = other
            .verifying_key()
            .to_public_key_der()
            .unwrap()
            .into_vec();
        assert!(reply.verify(&other_spki).is_err());
        let mut tampered = reply.clone();
        tampered.payload["kms_ca_pem"] = serde_json::json!("other");
        assert!(tampered.verify(&spki).is_err());
        let mut alg = reply.clone();
        alg.signature.algorithm = "ed25519".into();
        assert!(alg.verify(&spki).is_err());
    }
}
