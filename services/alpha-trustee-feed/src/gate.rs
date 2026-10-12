//! The Trustee pod's only door, and the KBS's resource backend.
//!
//! The gate terminates the KBS's public TLS (port 8443, through the passthrough ingress) inside
//! the TD with a one-hour leaf alpha-kms issues for `trustee.kbs_hostname` over this pod's
//! attested key, and passes three requests on to the KBS on loopback:
//!
//! - `POST /kbs/v0/auth`, as it is.
//! - `POST /kbs/v0/attest`: the KBS's answer, its attestation token, reaches the pod only once
//!   alpha-kms has admitted the attestation (`POST /v1/trustee/attestations`), given the token and
//!   the init-data the pod sent. Without init-data there is no Revision to admit, and no answer.
//! - `GET /kbs/v0/resource/<App id>/<type>/<tag>`: first alpha-kms releases the resource for the
//!   pod whose token the request carries (`POST /v1/trustee/releases`), which it audits with that
//!   pod's Revision; then, one request at a time, the KBS evaluates its own (generated) policy over
//!   the token and, if it allows, reads the value from [`vault_router`], which hands it that one
//!   value for that one path once; the KBS seals it to the pod's TEE key.
//!
//! Everything else, the admin API included, is not found. Requests are refused while the state
//! is stale, and the KBS then holds the deny-all policy.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use alpha_core::AppId;
use alpha_trustee::ear::{token_payload, token_sha256};
use alpha_trustee::resource::Resource;
use alpha_trustee::{vault, wire};
use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use parking_lot::{Mutex, RwLock};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::admin::Admin;
use crate::files::KBS_ADDR;
use crate::kms::{Kms, KmsError};
use crate::{Clock, Error};

/// An attestation with eight GPUs' evidence is a few hundred kilobytes.
const BODY_LIMIT: usize = 4 << 20;
/// The KBS waits on the Attestation Service, which waits on NRAS.
const KBS_TIMEOUT: Duration = Duration::from_secs(90);
const SESSION_COOKIE: &str = "kbs-session-id";
const MAX_SESSIONS: usize = 4096;

/// What the KBS holds now, from one state of the KMS.
struct Installed {
    generated_at: String,
    not_after: SystemTime,
    resource_policy: String,
    admitted: BTreeSet<(AppId, String)>,
}

/// A value the KMS released, for the one resource path the request in flight reads.
struct Stash {
    path: String,
    value: Zeroizing<Vec<u8>>,
}

pub struct Feed<K> {
    kms: K,
    admin: Admin,
    kbs: reqwest::Client,
    kbs_base: String,
    clock: Clock,
    vault_token: String,
    /// The NRAS URL the Attestation Service was configured with at start.
    nras_verifier_url: String,
    installed: RwLock<Option<Installed>>,
    /// `kbs-session-id` to the token the KBS issued that session, and when it expires.
    sessions: Mutex<BTreeMap<String, (String, SystemTime)>>,
    forward: tokio::sync::Mutex<()>,
    stash: Mutex<Option<Stash>>,
}

fn parse_time(text: &str) -> Result<SystemTime, Error> {
    chrono::DateTime::parse_from_rfc3339(text)
        .map(SystemTime::from)
        .map_err(|e| Error::State(format!("{text:?}: {e}")))
}

/// The KBS protocol's error body (kbs-types `ErrorInformation`); the KBS protocol answers 401 to
/// every refusal but a bad path, which is 404.
fn refusal(status: StatusCode, kind: &str, detail: &str) -> Response {
    let body = json!({
        "type": format!("https://github.com/confidential-containers/kbs/errors/{kind}"),
        "detail": detail,
    });
    (status, axum::Json(body)).into_response()
}

fn unavailable(detail: &str) -> Response {
    refusal(StatusCode::SERVICE_UNAVAILABLE, "Unavailable", detail)
}

impl<K: Kms> Feed<K> {
    pub fn new(
        kms: K,
        admin: Admin,
        kbs_base: String,
        vault_token: String,
        nras_verifier_url: String,
        clock: Clock,
    ) -> Result<Self, Error> {
        let kbs = reqwest::Client::builder()
            .no_proxy()
            .timeout(KBS_TIMEOUT)
            .build()
            .map_err(|e| Error::Kbs(format!("http client: {e}")))?;
        Ok(Self {
            kms,
            admin,
            kbs,
            kbs_base,
            clock,
            vault_token,
            nras_verifier_url,
            installed: RwLock::new(None),
            sessions: Mutex::new(BTreeMap::new()),
            forward: tokio::sync::Mutex::new(()),
            stash: Mutex::new(None),
        })
    }

    fn now(&self) -> SystemTime {
        (self.clock)()
    }

    /// Whether the KBS holds a state that is still within its `not_after`.
    pub fn fresh(&self) -> bool {
        let now = self.now();
        self.installed
            .read()
            .as_ref()
            .is_some_and(|i| now < i.not_after)
    }

    fn admits(&self, app: AppId, mrconfigid: &str) -> bool {
        self.installed
            .read()
            .as_ref()
            .is_some_and(|i| i.admitted.contains(&(app, mrconfigid.to_owned())))
    }

    /// Fetches the state and installs it; when that fails and what the KBS holds has expired, the
    /// KBS gets the deny-all policy and the gate refuses every request.
    pub async fn sync(&self) -> Result<(), Error> {
        let result = match self.kms.state().await {
            Ok(state) => self.install(state).await,
            Err(e) => Err(Error::Kms(e.to_string())),
        };
        if result.is_err() && !self.fresh() {
            self.withdraw().await;
        }
        result
    }

    async fn install(&self, state: wire::State) -> Result<(), Error> {
        let not_after = parse_time(&state.not_after)?;
        parse_time(&state.generated_at)?;
        if not_after <= self.now() {
            return Err(Error::State("the state has already expired".into()));
        }
        // ponytail: the Attestation Service reads its NRAS URL at start only; a platform document
        // naming another one needs the Trustee pods rolled, and until then this pod refuses.
        if state.nras_verifier_url != self.nras_verifier_url {
            return Err(Error::State(format!(
                "the platform document names NRAS at {}, this pod's Attestation Service calls {}: roll the Trustee pods",
                state.nras_verifier_url, self.nras_verifier_url
            )));
        }
        self.admin.install(&state).await?;
        *self.installed.write() = Some(Installed {
            generated_at: state.generated_at,
            not_after,
            resource_policy: state.resource_policy,
            admitted: state
                .admitted
                .into_iter()
                .map(|e| (e.app_id, e.mrconfigid))
                .collect(),
        });
        Ok(())
    }

    async fn withdraw(&self) {
        *self.installed.write() = None;
        if let Err(e) = self.admin.deny_all().await {
            eprintln!("alpha-trustee-feed: deny-all policy: {e}");
        }
    }

    async fn forward(
        &self,
        method: Method,
        path: &str,
        headers: &HeaderMap,
        body: Bytes,
    ) -> Result<(StatusCode, HeaderMap, Bytes), String> {
        let mut request = self.kbs.request(method, format!("{}{path}", self.kbs_base));
        for name in [header::CONTENT_TYPE, header::COOKIE, header::AUTHORIZATION] {
            for value in headers.get_all(&name) {
                request = request.header(&name, value);
            }
        }
        let response = request
            .body(body)
            .send()
            .await
            .map_err(|e| format!("kbs: {e}"))?;
        let status = response.status();
        let mut out = HeaderMap::new();
        for name in [header::CONTENT_TYPE, header::SET_COOKIE] {
            for value in response.headers().get_all(&name) {
                out.append(&name, value.clone());
            }
        }
        let body = response.bytes().await.map_err(|e| format!("kbs: {e}"))?;
        Ok((status, out, body))
    }

    fn remember_session(&self, headers: &HeaderMap, token: &str) {
        let Some(session) = headers
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .find_map(|c| cookie_value(c, SESSION_COOKIE))
        else {
            return;
        };
        let expires = token_payload(token)
            .ok()
            .and_then(|p| p.get("exp").and_then(Value::as_u64))
            .and_then(|exp| SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(exp)));
        let Some(expires) = expires else {
            return;
        };
        let now = self.now();
        let mut sessions = self.sessions.lock();
        sessions.retain(|_, (_, until)| *until > now);
        if sessions.len() >= MAX_SESSIONS {
            return;
        }
        sessions.insert(session.to_owned(), (token.to_owned(), expires));
    }

    /// The token a resource request carries: a bearer token (CDH's), or the one the KBS issued
    /// the session its cookie names (the attestation agent's own client).
    fn token_of(&self, headers: &HeaderMap) -> Option<String> {
        if let Some(bearer) = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
        {
            return Some(bearer.trim().to_owned());
        }
        let now = self.now();
        let sessions = self.sessions.lock();
        headers
            .get_all(header::COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|c| c.split(';'))
            .find_map(|c| cookie_value(c, SESSION_COOKIE))
            .and_then(|id| sessions.get(id))
            .filter(|(_, until)| *until > now)
            .map(|(token, _)| token.clone())
    }
}

/// `value` of `name=value` at the start of a cookie header item.
fn cookie_value<'a>(item: &'a str, name: &str) -> Option<&'a str> {
    let (key, rest) = item.trim().split_once('=')?;
    if key != name {
        return None;
    }
    rest.split(';')
        .next()
        .map(str::trim)
        .filter(|v| !v.is_empty())
}

fn passthrough((status, headers, body): (StatusCode, HeaderMap, Bytes)) -> Response {
    let mut response = (status, body).into_response();
    for (name, value) in &headers {
        response.headers_mut().append(name, value.clone());
    }
    response
}

/// The init-data the attestation carries (`init-data.body`, TOML), as bytes.
fn init_data(body: &[u8]) -> Option<Vec<u8>> {
    let value: Value = serde_json::from_slice(body).ok()?;
    let init = value.get("init-data")?;
    if init.get("format").and_then(Value::as_str) != Some("toml") {
        return None;
    }
    init.get("body")
        .and_then(Value::as_str)
        .map(|b| b.as_bytes().to_vec())
}

pub fn router<K: Kms>(feed: Arc<Feed<K>>) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/ready", get(ready::<K>))
        .route("/kbs/v0/auth", post(auth::<K>))
        .route("/kbs/v0/attest", post(attest::<K>))
        .route(
            "/kbs/v0/resource/{repository}/{kind}/{tag}",
            get(resource::<K>),
        )
        .fallback(|| async { refusal(StatusCode::NOT_FOUND, "InvalidRequestPath", "not found") })
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
        .with_state(feed)
}

async fn ready<K: Kms>(State(feed): State<Arc<Feed<K>>>) -> Response {
    if feed.fresh() {
        "ok".into_response()
    } else {
        unavailable("no current state from alpha-kms")
    }
}

async fn auth<K: Kms>(
    State(feed): State<Arc<Feed<K>>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !feed.fresh() {
        return unavailable("no current state from alpha-kms");
    }
    match feed
        .forward(Method::POST, "/kbs/v0/auth", &headers, body)
        .await
    {
        Ok(reply) => passthrough(reply),
        Err(e) => unavailable(&e),
    }
}

async fn attest<K: Kms>(
    State(feed): State<Arc<Feed<K>>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !feed.fresh() {
        return unavailable("no current state from alpha-kms");
    }
    let Some(initdata) = init_data(&body) else {
        return refusal(
            StatusCode::UNAUTHORIZED,
            "RcarAttestFailed",
            "the attestation carries no TOML init-data",
        );
    };
    let reply = match feed
        .forward(Method::POST, "/kbs/v0/attest", &headers, body)
        .await
    {
        Ok(reply) => reply,
        Err(e) => return unavailable(&e),
    };
    if reply.0 != StatusCode::OK {
        return passthrough(reply);
    }
    let Some(token) = serde_json::from_slice::<Value>(&reply.2)
        .ok()
        .and_then(|v| v.get("token").and_then(Value::as_str).map(str::to_owned))
    else {
        return unavailable("the KBS answered without a token");
    };
    let admitted = feed
        .kms
        .attested(wire::Attestation {
            token: token.clone(),
            initdata: BASE64_URL_SAFE_NO_PAD.encode(&initdata),
        })
        .await;
    match admitted {
        Ok(_) => {
            feed.remember_session(&reply.1, &token);
            passthrough(reply)
        }
        Err(KmsError::Refused { code, message }) => refusal(
            StatusCode::UNAUTHORIZED,
            "RcarAttestFailed",
            &format!("alpha-kms refused the attestation: {code}: {message}"),
        ),
        Err(KmsError::Unreachable(e)) => unavailable(&format!("alpha-kms: {e}")),
    }
}

async fn resource<K: Kms>(
    State(feed): State<Arc<Feed<K>>>,
    Path((repository, kind, tag)): Path<(String, String, String)>,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let not_found = |detail: &str| refusal(StatusCode::NOT_FOUND, "ResourceNotFound", detail);
    if uri.query().is_some() {
        return not_found("a resource read takes no query");
    }
    let Ok(resource) = Resource::from_segments(&[&repository, &kind, &tag]) else {
        return not_found("not kbs:///<App id>/<type>/<tag>");
    };
    let Some(generated_at) = feed
        .installed
        .read()
        .as_ref()
        .map(|i| i.generated_at.clone())
        .filter(|_| feed.fresh())
    else {
        return unavailable("no current state from alpha-kms");
    };
    let Some(token) = feed.token_of(&headers) else {
        return refusal(
            StatusCode::UNAUTHORIZED,
            "TokenNotFound",
            "no attestation token",
        );
    };
    let released = feed
        .kms
        .release(wire::Release {
            token_sha256: format!("sha256:{}", hex::encode(token_sha256(&token))),
            resource: resource.uri(),
            state_generated_at: generated_at,
        })
        .await;
    let released = match released {
        Ok(released) => released,
        Err(KmsError::Refused { code, message }) => {
            let detail = format!("alpha-kms refused the release: {code}: {message}");
            return match code.as_str() {
                "not_found" | "malformed" | "policy_denied" => not_found(&detail),
                _ => refusal(StatusCode::UNAUTHORIZED, "PolicyDeny", &detail),
            };
        }
        Err(KmsError::Unreachable(e)) => return unavailable(&format!("alpha-kms: {e}")),
    };
    let Ok(value) = BASE64_URL_SAFE_NO_PAD
        .decode(&released.value)
        .map(Zeroizing::new)
    else {
        return unavailable("alpha-kms released a value that is not base64url");
    };
    // The pod was admitted after this KBS's policy was generated: install a newer one first.
    if !feed.admits(released.app_id, &released.mrconfigid) {
        if let Err(e) = feed.sync().await {
            return unavailable(&e.to_string());
        }
        if !feed.admits(released.app_id, &released.mrconfigid) {
            return refusal(
                StatusCode::UNAUTHORIZED,
                "PolicyDeny",
                "the KBS's policy does not admit this pod",
            );
        }
    }
    let _one_at_a_time = feed.forward.lock().await;
    // A KBS restarted since the last install runs its built-in policy; ours goes back first.
    let policy = feed
        .installed
        .read()
        .as_ref()
        .map(|i| i.resource_policy.clone());
    let Some(policy) = policy else {
        return unavailable("no current state from alpha-kms");
    };
    if let Err(e) = feed.admin.resource_policy(&policy).await {
        return unavailable(&e.to_string());
    }
    *feed.stash.lock() = Some(Stash {
        path: resource.path(),
        value,
    });
    let reply = feed
        .forward(
            Method::GET,
            &format!("/kbs/v0/resource/{}", resource.path()),
            &headers,
            Bytes::new(),
        )
        .await;
    feed.stash.lock().take();
    match reply {
        Ok(reply) => passthrough(reply),
        Err(e) => unavailable(&e),
    }
}

/// The KBS's `Vault` resource backend's server, on loopback: the stashed value for its path,
/// once, to the KBS's token; nothing otherwise.
pub fn vault_router<K: Kms>(feed: Arc<Feed<K>>) -> Router {
    Router::new()
        .route("/v1/{*path}", get(vault_read::<K>))
        .fallback(|| async { vault_missing() })
        .with_state(feed)
}

fn vault_missing() -> Response {
    (StatusCode::NOT_FOUND, axum::Json(json!({ "errors": [] }))).into_response()
}

async fn vault_read<K: Kms>(
    State(feed): State<Arc<Feed<K>>>,
    Path(path): Path<String>,
    headers: HeaderMap,
) -> Response {
    let presented = headers
        .get("x-vault-token")
        .map(HeaderValue::as_bytes)
        .unwrap_or_default();
    if !alpha_client::bearer_matches(presented, feed.vault_token.as_bytes()) {
        return (
            StatusCode::FORBIDDEN,
            axum::Json(json!({ "errors": ["permission denied"] })),
        )
            .into_response();
    }
    let Some(wanted) = path.strip_prefix(&format!("{}/", vault::MOUNT)) else {
        return vault_missing();
    };
    let mut stash = feed.stash.lock();
    if stash.as_ref().is_none_or(|s| s.path != wanted) {
        return vault_missing();
    }
    match stash.take() {
        Some(s) => axum::Json(vault::kv1_read_reply(&s.value)).into_response(),
        None => vault_missing(),
    }
}

/// The KBS, as the gate reaches it.
pub fn kbs_base() -> String {
    format!("http://{KBS_ADDR}")
}

#[cfg(test)]
mod tests;
