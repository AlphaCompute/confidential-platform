//! A fake RedPill shared by `lib.rs` and `upstream.rs`'s tests: the report route answers a
//! configurable status/body/delay, the completions route always 200s, and both count the
//! requests they actually received.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};

#[derive(Clone)]
pub(crate) struct ReportBehavior {
    pub status: StatusCode,
    pub body: String,
    pub delay: Option<Duration>,
}

pub(crate) fn answering(status: StatusCode, body: &str) -> ReportBehavior {
    ReportBehavior {
        status,
        body: body.to_string(),
        delay: None,
    }
}

pub(crate) fn test_state(
    config: crate::Config,
    caller_bearer: &[u8],
    provider_key: &str,
) -> Arc<crate::AppState> {
    let upstream = crate::Upstream::new(&config).unwrap();
    Arc::new(crate::AppState {
        config,
        secrets: parking_lot::RwLock::new(crate::Secrets {
            provider_key: Some(zeroize::Zeroizing::new(provider_key.to_string())),
            caller_bearer: zeroize::Zeroizing::new(caller_bearer.to_vec()),
            admin_bearer: zeroize::Zeroizing::new(ADMIN_BEARER.to_vec()),
        }),
        upstream,
        own: Default::default(),
        // Never reached unless a test routes to an organization's model; those replace it.
        org_clients: crate::org_models::Clients::new(
            rustls::pki_types::CertificateDer::from(Vec::new()),
            Arc::new(NoCert),
            crate::COMPLETION_TIMEOUT,
        ),
        // Never connects unless a test reaches the database; those use `fresh_database`.
        pool: sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://127.0.0.1:1/none")
            .unwrap(),
        keys_key: zeroize::Zeroizing::new([7; 32]),
        usage_tasks: Default::default(),
    })
}

#[derive(Debug)]
struct NoCert;

impl rustls::client::ResolvesClientCert for NoCert {
    fn resolve(
        &self,
        _: &[&[u8]],
        _: &[rustls::SignatureScheme],
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        None
    }
    fn has_certs(&self) -> bool {
        false
    }
}

pub(crate) const ADMIN_BEARER: &[u8] = b"admin-bearer";

/// A fresh database per test, migrated; `None` when `DATABASE_URL` is unset.
pub(crate) async fn fresh_database() -> Option<sqlx::PgPool> {
    let admin_url = std::env::var("DATABASE_URL").ok()?;
    let admin = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&admin_url)
        .await
        .unwrap();
    let name = format!("alpha_inference_test_{}", uuid::Uuid::now_v7().simple());
    sqlx::query(sqlx::AssertSqlSafe(format!("create database {name}")))
        .execute(&admin)
        .await
        .unwrap();
    let mut url = reqwest::Url::parse(&admin_url).unwrap();
    url.set_path(&format!("/{name}"));
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(url.as_str())
        .await
        .unwrap();
    crate::keys::migrate(&pool).await.unwrap();
    Some(pool)
}

/// A `Config` pointing at `upstream_url` with `models` allowlisted — everything both test
/// modules need for a config that never has to pass the `https://` check `Config::build` runs.
pub(crate) fn test_config(upstream_url: &str, models: &[&str]) -> crate::Config {
    crate::Config {
        models: models.iter().map(|s| (*s).to_string()).collect(),
        own: Default::default(),
        external: Some(crate::External {
            upstream_url: upstream_url.to_string(),
            pccs_url: "https://pccs.example".to_string(),
            upstream_policy: alpha_attest::Policy {
                tcb_statuses: vec!["UpToDate".into()],
                tolerated_advisories: vec![],
            },
        }),
    }
}

#[derive(Clone)]
struct FakeState {
    behavior: ReportBehavior,
    report_hits: Arc<AtomicUsize>,
    completions_hits: Arc<AtomicUsize>,
}

async fn report_route(State(state): State<FakeState>) -> Response {
    state.report_hits.fetch_add(1, Ordering::SeqCst);
    if let Some(delay) = state.behavior.delay {
        tokio::time::sleep(delay).await;
    }
    (state.behavior.status, state.behavior.body.clone()).into_response()
}

async fn completions_route(State(state): State<FakeState>) -> StatusCode {
    state.completions_hits.fetch_add(1, Ordering::SeqCst);
    StatusCode::OK
}

pub(crate) async fn spawn_fake_upstream(
    behavior: ReportBehavior,
) -> (String, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let state = FakeState {
        behavior,
        report_hits: Arc::new(AtomicUsize::new(0)),
        completions_hits: Arc::new(AtomicUsize::new(0)),
    };
    let report_hits = state.report_hits.clone();
    let completions_hits = state.completions_hits.clone();
    let app = Router::new()
        .route("/attestation/report", get(report_route))
        .route("/chat/completions", post(completions_route))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}"), report_hits, completions_hits)
}
