//! The gate between a fake KMS and a fake KBS that behaves as Trustee v0.21.0's does on the
//! paths the gate uses: sessions by cookie, a token from `/attest`, admin endpoints behind the
//! feed's EdDSA token, and resource reads through the Vault backend on the feed's loopback port.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, UNIX_EPOCH};

use alpha_trustee::ear::sample::{hex48, payload, token as sample_token};
use alpha_trustee::policy::DENY_ALL;
use alpha_trustee::wire;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use ed25519_dalek::SigningKey;
use ed25519_dalek::Verifier;
use serde_json::{Value, json};

use super::*;
use crate::kms::{Kms, KmsError};

const APP: &str = "01994b3e-5c8a-7d3e-9a1b-2c3d4e5f6a7b";
const T0: u64 = 1_800_000_000;

fn at(secs: u64) -> String {
    alpha_runtime::socket::rfc3339(UNIX_EPOCH + Duration::from_secs(secs))
}

#[derive(Default)]
struct FakeKms {
    state: Mutex<Option<wire::State>>,
    admit: Mutex<Option<KmsError>>,
    release: Mutex<Option<KmsError>>,
    value: Mutex<Vec<u8>>,
    attestations: Mutex<Vec<wire::Attestation>>,
    releases: Mutex<Vec<wire::Release>>,
}

#[derive(Clone)]
struct Fake(Arc<FakeKms>);

impl Kms for Fake {
    async fn attested(&self, body: wire::Attestation) -> Result<wire::Admitted, KmsError> {
        self.0.attestations.lock().push(body);
        if let Some(e) = self.0.admit.lock().clone() {
            return Err(e);
        }
        Ok(wire::Admitted {
            app_id: APP.parse().unwrap(),
            revision: alpha_core::compose_hash("r"),
            mrconfigid: hex48(9),
            expires_at: at(T0 + 300),
        })
    }

    async fn release(&self, body: wire::Release) -> Result<wire::Released, KmsError> {
        self.0.releases.lock().push(body);
        if let Some(e) = self.0.release.lock().clone() {
            return Err(e);
        }
        Ok(wire::Released {
            value: BASE64_URL_SAFE_NO_PAD.encode(&*self.0.value.lock()),
            app_id: APP.parse().unwrap(),
            mrconfigid: hex48(9),
        })
    }

    async fn state(&self) -> Result<wire::State, KmsError> {
        self.0
            .state
            .lock()
            .clone()
            .ok_or_else(|| KmsError::Unreachable("down".into()))
    }
}

fn state(admitted: bool, generated: u64) -> wire::State {
    wire::State {
        generated_at: at(generated),
        not_after: at(generated + 300),
        platform_version: 4,
        resource_policy: format!("package policy\n# generated at {generated}\n"),
        attestation_policies: [
            ("default_cpu".into(), "cpu".into()),
            ("default_gpu".into(), "gpu".into()),
        ]
        .into_iter()
        .collect(),
        reference_values: r#"{"version":"0.1.0","type":"sample","payload":"e30="}"#.into(),
        nras_verifier_url: "https://nras.example/v4/attest".into(),
        admitted: if admitted {
            vec![wire::StateEntry {
                app_id: APP.parse().unwrap(),
                mrconfigid: hex48(9),
            }]
        } else {
            Vec::new()
        },
    }
}

/// The KBS: what the gate forwards, and what it does with the feed's admin calls and Vault.
struct FakeKbs {
    admin: ed25519_dalek::VerifyingKey,
    vault: String,
    vault_token: String,
    token: String,
    resource_policy: Mutex<String>,
    installed: Mutex<Vec<String>>,
    resource_reads: AtomicUsize,
    attests: AtomicUsize,
}

fn admin_ok(kbs: &FakeKbs, headers: &HeaderMap) -> bool {
    let Some(token) = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    else {
        return false;
    };
    let parts: Vec<&str> = token.split('.').collect();
    let Ok(sig) = BASE64_URL_SAFE_NO_PAD.decode(parts[2]) else {
        return false;
    };
    let sig = ed25519_dalek::Signature::from_slice(&sig).unwrap();
    kbs.admin
        .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig)
        .is_ok()
}

async fn fake_kbs(kbs: Arc<FakeKbs>) -> String {
    async fn admin(
        State(kbs): State<Arc<FakeKbs>>,
        Path(endpoint): Path<String>,
        headers: HeaderMap,
        body: String,
    ) -> StatusCode {
        if !admin_ok(&kbs, &headers) {
            return StatusCode::UNAUTHORIZED;
        }
        if endpoint == "resource-policy" {
            let b64: Value = serde_json::from_str(&body).unwrap();
            let rego = BASE64_URL_SAFE_NO_PAD
                .decode(b64["policy"].as_str().unwrap())
                .unwrap();
            *kbs.resource_policy.lock() = String::from_utf8(rego).unwrap();
        }
        kbs.installed.lock().push(endpoint);
        StatusCode::OK
    }
    async fn auth() -> impl IntoResponse {
        (
            [("set-cookie", "kbs-session-id=s1; Path=/kbs/v0; HttpOnly")],
            Json(json!({ "nonce": "n", "extra-params": {} })),
        )
    }
    async fn attest(
        State(kbs): State<Arc<FakeKbs>>,
        headers: HeaderMap,
    ) -> axum::response::Response {
        kbs.attests.fetch_add(1, Ordering::SeqCst);
        if headers.get("cookie").and_then(|v| v.to_str().ok()) != Some("kbs-session-id=s1") {
            return StatusCode::UNAUTHORIZED.into_response();
        }
        (
            [("set-cookie", "kbs-session-id=s1; Path=/kbs/v0; HttpOnly")],
            Json(json!({ "token": kbs.token })),
        )
            .into_response()
    }
    async fn resource(
        State(kbs): State<Arc<FakeKbs>>,
        Path((a, b, c)): Path<(String, String, String)>,
        headers: HeaderMap,
    ) -> axum::response::Response {
        kbs.resource_reads.fetch_add(1, Ordering::SeqCst);
        let bearer = headers.get("authorization").and_then(|v| v.to_str().ok());
        let cookie = headers.get("cookie").and_then(|v| v.to_str().ok());
        let authorized =
            bearer == Some(&format!("Bearer {}", kbs.token)) || cookie == Some("kbs-session-id=s1");
        if !authorized || kbs.resource_policy.lock().as_str() == DENY_ALL {
            return StatusCode::UNAUTHORIZED.into_response();
        }
        let reply = reqwest::Client::new()
            .get(format!("{}/v1/alpha/{a}/{b}/{c}", kbs.vault))
            .header("x-vault-token", &kbs.vault_token)
            .send()
            .await
            .unwrap();
        if reply.status() != StatusCode::OK {
            return StatusCode::UNAUTHORIZED.into_response();
        }
        let value: Value = reply.json().await.unwrap();
        Json(json!({ "sealed": value["data"]["data"] })).into_response()
    }
    let app = axum::Router::new()
        .route("/kbs/v0/auth", post(auth))
        .route("/kbs/v0/attest", post(attest))
        .route("/kbs/v0/resource/{a}/{b}/{c}", get(resource))
        .route("/kbs/v0/{endpoint}", post(admin))
        .with_state(kbs);
    serve(app).await
}

async fn serve(app: axum::Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    url
}

struct Rig {
    kms: Arc<FakeKms>,
    kbs: Arc<FakeKbs>,
    feed: Arc<Feed<Fake>>,
    gate: String,
    vault: String,
    clock: Arc<AtomicU64>,
    http: reqwest::Client,
    /// The session cookie, kept as the attestation agent's client keeps it.
    cookie: Mutex<Option<String>>,
    pod_token: String,
}

async fn rig() -> Rig {
    let clock = Arc::new(AtomicU64::new(T0));
    let tick = clock.clone();
    let now: Clock =
        Arc::new(move || UNIX_EPOCH + Duration::from_secs(tick.load(Ordering::SeqCst)));
    let admin_key = SigningKey::from_bytes(&[3; 32]);
    let kms = Arc::new(FakeKms::default());
    *kms.state.lock() = Some(state(true, T0));
    *kms.value.lock() = b"hunter2".to_vec();
    let pod_token = sample_token(&payload(
        [&hex48(1), &hex48(2), &hex48(3), &hex48(4), &hex48(5)],
        &hex48(9),
        &[],
        T0 + 300,
    ));
    // The vault router's port is known only once it listens, and the KBS needs it; the KBS's
    // port is known only once it listens, and the feed needs it. A placeholder feed breaks the
    // cycle: the vault port is bound first.
    let vault_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let vault = format!("http://{}", vault_listener.local_addr().unwrap());
    let kbs = Arc::new(FakeKbs {
        admin: admin_key.verifying_key(),
        vault: vault.clone(),
        vault_token: "vt".into(),
        token: pod_token.clone(),
        resource_policy: Mutex::new(String::new()),
        installed: Mutex::new(Vec::new()),
        resource_reads: AtomicUsize::new(0),
        attests: AtomicUsize::new(0),
    });
    let kbs_url = fake_kbs(kbs.clone()).await;
    let admin = Admin::with_key(admin_key, kbs_url.clone(), now.clone()).unwrap();
    let feed = Arc::new(
        Feed::new(
            Fake(kms.clone()),
            admin,
            kbs_url,
            "vt".into(),
            "https://nras.example/v4/attest".into(),
            now,
        )
        .unwrap(),
    );
    let vault_app = vault_router(feed.clone());
    tokio::spawn(async move { axum::serve(vault_listener, vault_app).await.unwrap() });
    let gate = serve(router(feed.clone())).await;
    Rig {
        kms,
        kbs,
        feed,
        gate,
        vault,
        clock,
        http: reqwest::Client::new(),
        cookie: Mutex::new(None),
        pod_token,
    }
}

const ATTESTATION: &str = r#"{"init-data":{"format":"toml","body":"algorithm = \"sha384\"\n"},"runtime-data":{"nonce":"n","tee-pubkey":{}},"tee-evidence":{"primary_evidence":{},"additional_evidence":"{}"}}"#;

impl Rig {
    async fn send(&self, mut request: reqwest::RequestBuilder) -> (StatusCode, Value) {
        if let Some(cookie) = self.cookie.lock().clone() {
            request = request.header("cookie", cookie);
        }
        let r = request.send().await.unwrap();
        if let Some(set) = r.headers().get("set-cookie").and_then(|v| v.to_str().ok()) {
            *self.cookie.lock() = set.split(';').next().map(str::to_owned);
        }
        (r.status(), r.json().await.unwrap_or(Value::Null))
    }

    async fn post(&self, path: &str, body: &str) -> (StatusCode, Value) {
        self.send(
            self.http
                .post(format!("{}{path}", self.gate))
                .header("content-type", "application/json")
                .body(body.to_owned()),
        )
        .await
    }

    async fn get(&self, path: &str, bearer: Option<&str>) -> (StatusCode, Value) {
        let mut r = self.http.get(format!("{}{path}", self.gate));
        if let Some(b) = bearer {
            r = r.bearer_auth(b);
        }
        self.send(r).await
    }

    async fn attested(&self) -> String {
        assert_eq!(self.post("/kbs/v0/auth", "{}").await.0, StatusCode::OK);
        let (status, reply) = self.post("/kbs/v0/attest", ATTESTATION).await;
        assert_eq!(status, StatusCode::OK, "{reply}");
        reply["token"].as_str().unwrap().to_owned()
    }

    fn advance(&self, secs: u64) {
        self.clock.fetch_add(secs, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn a_pod_alpha_kms_admitted_reads_exactly_the_value_alpha_kms_released() {
    let r = rig().await;
    assert_eq!(
        r.get("/ready", None).await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    r.feed.sync().await.unwrap();
    assert_eq!(
        *r.kbs.installed.lock(),
        [
            "attestation-policy",
            "attestation-policy",
            "reference-value",
            "resource-policy"
        ]
    );
    assert_eq!(r.get("/ready", None).await.0, StatusCode::OK);

    let token = r.attested().await;
    assert_eq!(token, r.pod_token);
    let reported = r.kms.attestations.lock().pop().unwrap();
    assert_eq!(reported.token, token);
    assert_eq!(
        BASE64_URL_SAFE_NO_PAD.decode(reported.initdata).unwrap(),
        b"algorithm = \"sha384\"\n"
    );

    let path = format!("/kbs/v0/resource/{APP}/secret/db");
    let (status, reply) = r.get(&path, Some(&token)).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["sealed"], json!(b"hunter2"));
    let asked = r.kms.releases.lock().pop().unwrap();
    assert_eq!(asked.resource, format!("kbs:///{APP}/secret/db"));
    assert_eq!(
        asked.token_sha256,
        format!("sha256:{}", hex::encode(token_sha256(&token)))
    );
    assert_eq!(asked.state_generated_at, at(T0));
    // Once, for that request: nothing is left for the backend afterwards.
    assert!(r.feed.stash.lock().is_none());
    let left = reqwest::Client::new()
        .get(format!("{}/v1/alpha/{APP}/secret/db", r.vault))
        .header("x-vault-token", "vt")
        .send()
        .await
        .unwrap();
    assert_eq!(left.status(), StatusCode::NOT_FOUND);

    // The attestation agent's own client reads by its session cookie.
    let (status, reply) = r.get(&path, None).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
}

#[tokio::test]
async fn the_pod_gets_no_token_alpha_kms_did_not_admit() {
    let r = rig().await;
    r.feed.sync().await.unwrap();
    *r.kms.admit.lock() = Some(KmsError::Refused {
        code: "attestation_unknown".into(),
        message: "no revision".into(),
    });
    assert_eq!(r.post("/kbs/v0/auth", "{}").await.0, StatusCode::OK);
    let (status, reply) = r.post("/kbs/v0/attest", ATTESTATION).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(reply.get("token").is_none(), "{reply}");
    assert!(reply["detail"].as_str().unwrap().contains("no revision"));
    // Unreachable is no admission either.
    *r.kms.admit.lock() = Some(KmsError::Unreachable("down".into()));
    assert_eq!(
        r.post("/kbs/v0/attest", ATTESTATION).await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    // Without init-data there is no Revision; the KBS is not even asked.
    let before = r.kbs.attests.load(Ordering::SeqCst);
    let without = ATTESTATION.replace(
        r#""init-data":{"format":"toml","body":"algorithm = \"sha384\"\n"},"#,
        "",
    );
    assert_eq!(
        r.post("/kbs/v0/attest", &without).await.0,
        StatusCode::UNAUTHORIZED
    );
    let json_initdata = ATTESTATION.replace(r#""format":"toml""#, r#""format":"json""#);
    assert_eq!(
        r.post("/kbs/v0/attest", &json_initdata).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(r.kbs.attests.load(Ordering::SeqCst), before);
}

#[tokio::test]
async fn nothing_reaches_the_kbs_resource_backend_that_alpha_kms_refused() {
    let r = rig().await;
    r.feed.sync().await.unwrap();
    let token = r.attested().await;
    let path = format!("/kbs/v0/resource/{APP}/secret/db");
    for (code, status) in [
        ("policy_denied", StatusCode::NOT_FOUND),
        ("not_found", StatusCode::NOT_FOUND),
        ("revision_revoked", StatusCode::UNAUTHORIZED),
        ("attestation_unknown", StatusCode::UNAUTHORIZED),
    ] {
        *r.kms.release.lock() = Some(KmsError::Refused {
            code: code.into(),
            message: "no".into(),
        });
        assert_eq!(r.get(&path, Some(&token)).await.0, status, "{code}");
    }
    *r.kms.release.lock() = Some(KmsError::Unreachable("down".into()));
    assert_eq!(
        r.get(&path, Some(&token)).await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(r.kbs.resource_reads.load(Ordering::SeqCst), 0);
    // No token at all: alpha-kms is not even asked.
    let asked = r.kms.releases.lock().len();
    let anonymous = reqwest::Client::new()
        .get(format!("{}{path}", r.gate))
        .send()
        .await
        .unwrap();
    assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(r.kms.releases.lock().len(), asked);
}

#[tokio::test]
async fn stale_state_withdraws_everything() {
    let r = rig().await;
    r.feed.sync().await.unwrap();
    let token = r.attested().await;
    *r.kms.state.lock() = None;
    // Within not_after a failed fetch changes nothing.
    r.advance(299);
    assert!(r.feed.sync().await.is_err());
    assert!(r.feed.fresh());
    let path = format!("/kbs/v0/resource/{APP}/secret/db");
    assert_eq!(r.get(&path, Some(&token)).await.0, StatusCode::OK);
    // Past it, the KBS gets the deny-all policy and the gate refuses.
    r.advance(2);
    assert!(r.feed.sync().await.is_err());
    assert!(!r.feed.fresh());
    assert_eq!(r.kbs.resource_policy.lock().as_str(), DENY_ALL);
    let asked = r.kms.releases.lock().len();
    assert_eq!(
        r.get(&path, Some(&token)).await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        r.post("/kbs/v0/attest", ATTESTATION).await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        r.get("/ready", None).await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        r.kms.releases.lock().len(),
        asked,
        "alpha-kms is not asked on stale state"
    );
    // A state that has already expired is not installed either.
    *r.kms.state.lock() = Some(state(true, T0));
    assert!(r.feed.sync().await.is_err());
    assert!(!r.feed.fresh());
    *r.kms.state.lock() = Some(state(true, T0 + 301));
    r.feed.sync().await.unwrap();
    assert!(r.feed.fresh());
}

#[tokio::test]
async fn the_admin_api_and_everything_but_the_protocol_is_not_found() {
    let r = rig().await;
    r.feed.sync().await.unwrap();
    for (method, path) in [
        ("POST", "/kbs/v0/resource-policy"),
        ("GET", "/kbs/v0/resource-policy"),
        ("POST", "/kbs/v0/attestation-policy"),
        ("POST", "/kbs/v0/reference-value"),
        ("GET", "/kbs/v0/reference-value/alpha_kata_tdx"),
        ("POST", &format!("/kbs/v0/resource/{APP}/secret/db")),
        ("DELETE", &format!("/kbs/v0/resource/{APP}/secret/db")),
        ("GET", "/kbs/v0/external/plugin/x"),
        ("GET", "/metrics"),
    ] {
        let reply = r
            .http
            .request(method.parse().unwrap(), format!("{}{path}", r.gate))
            .send()
            .await
            .unwrap();
        assert!(
            matches!(
                reply.status(),
                StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED
            ),
            "{method} {path}: {}",
            reply.status()
        );
    }
    let token = r.attested().await;
    for path in [
        format!("/kbs/v0/resource/{APP}/secret/db?version=1"),
        format!("/kbs/v0/resource/{}/secret/db", APP.to_uppercase()),
        "/kbs/v0/resource/default/secret/db".to_owned(),
        format!("/kbs/v0/resource/{APP}/token/db"),
    ] {
        assert_eq!(
            r.get(&path, Some(&token)).await.0,
            StatusCode::NOT_FOUND,
            "{path}"
        );
    }
    assert!(r.kms.releases.lock().is_empty());
}

#[tokio::test]
async fn a_pod_admitted_after_the_last_state_waits_for_a_state_that_admits_it() {
    let r = rig().await;
    *r.kms.state.lock() = Some(state(false, T0));
    r.feed.sync().await.unwrap();
    let token = r.attested().await;
    let path = format!("/kbs/v0/resource/{APP}/secret/db");
    // Still not in the next state either: refused, the KBS never asked.
    assert_eq!(r.get(&path, Some(&token)).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(r.kbs.resource_reads.load(Ordering::SeqCst), 0);
    *r.kms.state.lock() = Some(state(true, T0));
    let (status, reply) = r.get(&path, Some(&token)).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
}

#[tokio::test]
async fn a_restarted_kbs_gets_the_policy_back_before_any_read() {
    let r = rig().await;
    r.feed.sync().await.unwrap();
    let token = r.attested().await;
    *r.kbs.resource_policy.lock() = "package policy\ndefault allow := true\n".into();
    let (status, _) = r
        .get(&format!("/kbs/v0/resource/{APP}/secret/db"), Some(&token))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        r.kbs.resource_policy.lock().as_str(),
        format!("package policy\n# generated at {T0}\n")
    );
}

#[tokio::test]
async fn the_resource_backend_answers_only_the_kbs_and_only_the_stashed_path() {
    let r = rig().await;
    *r.feed.stash.lock() = Some(Stash {
        path: format!("{APP}/secret/db"),
        value: Zeroizing::new(b"v".to_vec()),
    });
    let read = |token: &'static str, path: String| {
        let vault = r.vault.clone();
        async move {
            reqwest::Client::new()
                .get(format!("{vault}{path}"))
                .header("x-vault-token", token)
                .send()
                .await
                .unwrap()
                .status()
        }
    };
    assert_eq!(
        read("wrong", format!("/v1/alpha/{APP}/secret/db")).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        read("vt", format!("/v1/alpha/{APP}/secret/other")).await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        read("vt", format!("/v1/other/{APP}/secret/db")).await,
        StatusCode::NOT_FOUND
    );
    assert!(r.feed.stash.lock().is_some(), "a wrong path takes nothing");
    assert_eq!(
        read("vt", format!("/v1/alpha/{APP}/secret/db")).await,
        StatusCode::OK
    );
    assert_eq!(
        read("vt", format!("/v1/alpha/{APP}/secret/db")).await,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn a_state_naming_another_nras_is_not_installed() {
    let r = rig().await;
    let mut other = state(true, T0);
    other.nras_verifier_url = "https://elsewhere.example/v4/attest".into();
    *r.kms.state.lock() = Some(other);
    let e = r.feed.sync().await.unwrap_err();
    assert!(e.to_string().contains("roll the Trustee pods"), "{e}");
    assert!(!r.feed.fresh());
    assert!(
        r.kbs
            .installed
            .lock()
            .iter()
            .all(|e| e == "resource-policy")
    );
}

#[test]
fn a_session_cookie_is_read_from_set_cookie_and_cookie_headers() {
    assert_eq!(
        cookie_value("kbs-session-id=abc; Path=/", "kbs-session-id"),
        Some("abc")
    );
    assert_eq!(
        cookie_value(" kbs-session-id=abc", "kbs-session-id"),
        Some("abc")
    );
    assert_eq!(cookie_value("other=abc", "kbs-session-id"), None);
    assert_eq!(cookie_value("kbs-session-id=", "kbs-session-id"), None);
}
