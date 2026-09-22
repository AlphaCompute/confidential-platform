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

/// A `Config` pointing at `upstream_url` with `models` allowlisted — everything both test
/// modules need for a config that never has to pass the `https://` check `Config::build` runs.
pub(crate) fn test_config(upstream_url: &str, models: &[&str]) -> crate::Config {
    crate::Config {
        upstream_url: upstream_url.to_string(),
        models: models.iter().map(|s| (*s).to_string()).collect(),
        pccs_url: "https://pccs.example".to_string(),
        upstream_policy: alpha_attest::Policy {
            tcb_statuses: vec!["UpToDate".into()],
            tolerated_advisories: vec![],
        },
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
