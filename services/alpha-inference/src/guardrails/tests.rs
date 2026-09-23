use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::State;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::routing::post;
use parking_lot::Mutex;
use tower::ServiceExt;

use super::*;
use crate::test_support::{test_config, test_state};

fn policy(url: &str) -> Value {
    json!({
        "checks_url": url,
        "model": "local/safety-model",
        "input": {"rails": {"input": {"flows": ["check input"]}}},
        "output": {"rails": {"output": {"flows": ["check output"]}}},
    })
}

fn verdict(phase: &str, status: &str) -> String {
    json!({"status": status, "rails_status": {format!("check {phase}"): {"status": status}}})
        .to_string()
}

fn request(stream: bool) -> Value {
    json!({"model": "m1", "messages": [{"role": "user", "content": "private input"}], "stream": stream})
}

fn completion() -> Value {
    json!({
        "id": "chatcmpl-test", "object": "chat.completion", "created": 123, "model": "m1",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "private output"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7}
    })
}

#[test]
fn config_requires_local_transport_and_complete_phase_policies() {
    let base = policy("http://127.0.0.1:8000/apis/guardrails/v2/workspaces/default/checks");
    assert!(Config::parse(&base.to_string()).is_ok());
    for url in [
        "https://guardrails.example/apis/guardrails/v2/workspaces/default/checks",
        "http://localhost:8000/apis/guardrails/v2/workspaces/default/checks",
        "http://127.0.0.1/apis/guardrails/v2/workspaces/default/checks",
        "http://127.0.0.1:8000/v1/chat/completions",
        "http://secret@127.0.0.1:8000/apis/guardrails/v2/workspaces/default/checks",
        "http://127.0.0.1:8000/apis/guardrails/v2/workspaces/default/checks?config_id=other",
    ] {
        let mut invalid = base.clone();
        invalid["checks_url"] = json!(url);
        assert!(Config::parse(&invalid.to_string()).is_err(), "{url}");
    }
    for (pointer, value) in [
        ("/model", json!("")),
        ("/input/rails/input/flows", json!([])),
        (
            "/output/rails/output/flows",
            json!(["check output", "check output"]),
        ),
        ("/input/rails/input/flows", json!([null])),
        ("/input", json!({"config_id": "mutable"})),
    ] {
        let mut invalid = base.clone();
        *invalid.pointer_mut(pointer).unwrap() = value;
        assert!(Config::parse(&invalid.to_string()).is_err());
    }
    let mut mixed = base.clone();
    mixed["input"]["rails"]["output"] = json!({"flows": ["check output"]});
    assert!(Config::parse(&mixed.to_string()).is_err());
    let mut unknown = base;
    unknown["fail_open"] = json!(true);
    assert!(Config::parse(&unknown.to_string()).is_err());
    assert!(Config::parse("").is_err());
}

#[test]
fn only_explicit_success_from_every_required_rail_allows_content() {
    assert!(
        evaluate_verdict(
            &json!({"status": "success", "rails_status": {"a": {"status": "success"}}}),
            &["a"]
        )
        .is_ok()
    );
    for invalid in [
        json!({}),
        json!({"status": "success"}),
        json!({"status": "success", "rails_status": {}}),
        json!({"status": "success", "rails_status": {"a": {"status": "skipped"}}}),
        json!({"status": "error", "rails_status": {"a": {"status": "success"}}}),
        json!({"status": "success", "rails_status": {"b": {"status": "success"}}}),
    ] {
        assert!(matches!(
            evaluate_verdict(&invalid, &["a"]),
            Err(Error::GuardrailsUnavailable)
        ));
    }
    assert!(matches!(
        evaluate_verdict(&json!({"status": "blocked"}), &["a"]),
        Err(Error::GuardrailsBlocked)
    ));
    assert!(matches!(
        evaluate_verdict(
            &json!({"status": "success", "rails_status": {"a": {"status": "blocked"}}}),
            &["a"]
        ),
        Err(Error::GuardrailsBlocked)
    ));
}

#[derive(Clone)]
struct Fixture {
    input: (StatusCode, String),
    output: (StatusCode, String),
    provider: (StatusCode, String),
    seen: Arc<Mutex<Vec<(String, HeaderMap, Value)>>>,
    output_gate: Option<Arc<Semaphore>>,
    readiness_gate: Option<Arc<Semaphore>>,
    delay: Duration,
}

impl Default for Fixture {
    fn default() -> Self {
        Self {
            input: (StatusCode::OK, verdict("input", "success")),
            output: (StatusCode::OK, verdict("output", "success")),
            provider: (StatusCode::OK, completion().to_string()),
            seen: Arc::new(Mutex::new(Vec::new())),
            output_gate: None,
            readiness_gate: None,
            delay: Duration::ZERO,
        }
    }
}

async fn checker(
    State(f): State<Fixture>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let is_output = body["messages"].as_array().unwrap().len() == 2;
    let is_readiness = body["messages"][0]["content"] == "readiness probe";
    f.seen.lock().push((
        if is_output { "output" } else { "input" }.into(),
        headers,
        body,
    ));
    if is_readiness && let Some(gate) = &f.readiness_gate {
        let _permit = gate.acquire().await.unwrap();
    }
    tokio::time::sleep(f.delay).await;
    if is_output && let Some(gate) = &f.output_gate {
        let _permit = gate.acquire().await.unwrap();
    }
    let (status, body) = if is_output { f.output } else { f.input };
    (status, [(header::LOCATION, "/chat/completions")], body).into_response()
}

async fn provider(
    State(f): State<Fixture>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    f.seen.lock().push(("provider".into(), headers, body));
    f.provider.into_response()
}

async fn setup(fixture: Fixture, trust_provider: bool) -> (Arc<crate::AppState>, Router) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let app = Router::new()
        .route(
            "/apis/guardrails/v2/workspaces/default/checks",
            post(checker),
        )
        .route("/chat/completions", post(provider))
        .with_state(fixture);
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let mut config = test_config(&base, &["m1"]);
    config.guardrails = Some(
        Config::parse(
            &policy(&format!(
                "{base}/apis/guardrails/v2/workspaces/default/checks"
            ))
            .to_string(),
        )
        .unwrap(),
    );
    let state = test_state(config, b"caller-secret", "provider-secret");
    if trust_provider {
        state
            .upstream
            .trust_test_client(
                "m1",
                reqwest::Client::builder()
                    .no_proxy()
                    .redirect(reqwest::redirect::Policy::none())
                    .build()
                    .unwrap(),
            )
            .await;
    }
    (state.clone(), crate::router(state))
}

async fn call(app: Router, payload: Value) -> (StatusCode, HeaderMap, String) {
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/chat/completions")
                .header(header::AUTHORIZATION, "Bearer caller-secret")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = String::from_utf8(
        to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    (status, headers, body)
}

#[tokio::test]
async fn allowed_json_checks_both_phases_and_keeps_credentials_separate() {
    let f = Fixture::default();
    let (_, app) = setup(f.clone(), true).await;
    let (status, _, body) = call(app, request(false)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(serde_json::from_str::<Value>(&body).unwrap(), completion());
    let seen = f.seen.lock();
    assert_eq!(
        seen.iter().map(|s| s.0.as_str()).collect::<Vec<_>>(),
        ["input", "provider", "output"]
    );
    assert_eq!(
        seen[1].1.get(header::AUTHORIZATION).unwrap(),
        "Bearer provider-secret"
    );
    for index in [0, 2] {
        assert!(!seen[index].1.contains_key(header::AUTHORIZATION));
        assert!(!seen[index].2.to_string().contains("secret"));
        assert!(seen[index].2["guardrails"]["config"].is_object());
        assert!(seen[index].2["guardrails"].get("config_id").is_none());
    }
    assert!(
        seen[2].2["messages"][1]["content"]
            .as_str()
            .unwrap()
            .contains("private output")
    );
}

#[tokio::test]
async fn all_history_tool_definitions_and_results_are_in_the_checked_envelope() {
    let f = Fixture::default();
    let (_, app) = setup(f.clone(), true).await;
    let payload = json!({"model": "m1", "messages": [
        {"role": "system", "content": "system-marker"},
        {"role": "user", "content": [{"type": "text", "text": "user-marker"}]},
        {"role": "assistant", "content": null, "tool_calls": [{"id": "call1", "type": "function",
            "function": {"name": "lookup", "arguments": "history-argument-marker"}}]},
        {"role": "tool", "tool_call_id": "call1", "content": "tool-result-marker"}
    ], "tools": [{"type": "function", "function": {"name": "lookup", "description": "definition-marker"}}]});
    assert_eq!(call(app, payload.clone()).await.0, StatusCode::OK);
    let seen = f.seen.lock();
    let checked: Value =
        serde_json::from_str(seen[0].2["messages"][0]["content"].as_str().unwrap()).unwrap();
    assert_eq!(checked, payload);
}

#[test]
fn documented_configuration_parses_and_policy_digest_tracks_changes() {
    let example = include_str!("../../GUARDRAILS.md")
        .split("```json\n")
        .nth(1)
        .unwrap()
        .split("\n```")
        .next()
        .unwrap();
    let config = Config::parse(example).unwrap();
    let first = Guardrails::new(config.clone()).unwrap();
    let mut changed = config;
    changed.output["prompts"][0]["content"] = json!("different policy");
    assert_ne!(
        first.policy_digest(),
        Guardrails::new(changed).unwrap().policy_digest()
    );
}

#[tokio::test]
async fn input_block_stops_before_provider_verification_or_generation() {
    let f = Fixture {
        input: (StatusCode::OK, verdict("input", "blocked")),
        ..Fixture::default()
    };
    let (_, app) = setup(f.clone(), false).await;
    let (status, _, body) = call(app, request(true)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body.contains("guardrails_blocked"));
    assert_eq!(f.seen.lock().len(), 1);
}

#[tokio::test]
async fn unverified_provider_cannot_be_bypassed_by_an_allow_verdict() {
    let f = Fixture::default();
    let (_, app) = setup(f.clone(), false).await;
    let (status, _, body) = call(app, request(false)).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert!(body.contains("upstream_unverified"));
    assert_eq!(f.seen.lock().len(), 1);
}

#[tokio::test]
async fn blocked_output_releases_no_completion_json_or_sse() {
    for stream in [false, true] {
        let f = Fixture {
            output: (StatusCode::OK, verdict("output", "blocked")),
            ..Fixture::default()
        };
        let (_, app) = setup(f.clone(), true).await;
        let (status, _, body) = call(app, request(stream)).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(!body.contains("private"));
        assert!(!body.contains("data:"));
        assert_eq!(f.seen.lock().len(), 3);
    }
}

#[tokio::test]
async fn streaming_waits_for_approval_and_preserves_tools_reasoning_and_usage() {
    let gate = Arc::new(Semaphore::new(0));
    let mut result = completion();
    result["choices"][0]["message"] = json!({"role": "assistant", "content": null,
        "reasoning_content": "private reasoning", "tool_calls": [{"id": "call1", "type": "function",
        "function": {"name": "lookup", "arguments": "{\"query\":\"private argument\"}"}}]});
    result["choices"][0]["finish_reason"] = json!("tool_calls");
    let f = Fixture {
        provider: (StatusCode::OK, result.to_string()),
        output_gate: Some(gate.clone()),
        ..Fixture::default()
    };
    let (_, app) = setup(f.clone(), true).await;
    let mut payload = request(true);
    payload["stream_options"] = json!({"include_usage": true});
    let mut pending = tokio::spawn(call(app, payload));
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if f.seen.lock().len() == 3 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(30), &mut pending)
            .await
            .is_err()
    );
    gate.add_permits(1);
    let (status, headers, body) = pending.await.unwrap();
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::CONTENT_TYPE], "text/event-stream");
    let frames: Vec<Value> = body
        .split("\n\n")
        .filter_map(|line| line.strip_prefix("data: "))
        .filter(|line| *line != "[DONE]")
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(
        frames[0]["choices"][0]["delta"]["tool_calls"][0]["index"],
        0
    );
    assert_eq!(
        frames[0]["choices"][0]["delta"]["reasoning_content"],
        "private reasoning"
    );
    assert_eq!(frames[1]["choices"][0]["finish_reason"], "tool_calls");
    assert_eq!(frames[2]["usage"], result["usage"]);
    assert!(body.ends_with("data: [DONE]\n\n"));
    let seen = f.seen.lock();
    assert_eq!(seen[1].2["stream"], false);
    assert!(seen[1].2.get("stream_options").is_none());
    assert!(seen[2].2.to_string().contains("private argument"));
    assert!(seen[2].2.to_string().contains("private reasoning"));
}

#[tokio::test]
async fn checker_errors_missing_rails_redirects_and_oversize_verdicts_fail_closed() {
    for reply in [
        (StatusCode::INTERNAL_SERVER_ERROR, "private error".into()),
        (StatusCode::TEMPORARY_REDIRECT, String::new()),
        (StatusCode::OK, "not JSON".into()),
        (
            StatusCode::OK,
            r#"{"status":"success","rails_status":{}}"#.into(),
        ),
        (StatusCode::OK, "x".repeat(VERDICT_LIMIT + 1)),
    ] {
        for phase in ["input", "output"] {
            let mut f = Fixture::default();
            if phase == "input" {
                f.input = reply.clone();
            } else {
                f.output = reply.clone();
            }
            let (_, app) = setup(f.clone(), true).await;
            let (status, _, body) = call(app, request(true)).await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
            assert!(body.contains("guardrails_unavailable"));
            assert!(!body.contains("private"));
            assert_eq!(f.seen.lock().len(), if phase == "input" { 1 } else { 3 });
        }
    }
}

#[tokio::test]
async fn no_guard_contact_for_unauthorized_unknown_or_unsupported_requests() {
    let f = Fixture::default();
    let (_, app) = setup(f.clone(), true).await;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/chat/completions")
                .body(Body::from(request(false).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let mut unknown = request(false);
    unknown["model"] = json!("other");
    assert_eq!(call(app.clone(), unknown).await.0, StatusCode::NOT_FOUND);
    for payload in [
        json!({"model": "m1", "messages": []}),
        json!({"model": "m1", "messages": [{"role": "user", "content": [{"type": "image_url", "image_url": {"url": "https://private"}}]}]}),
        json!({"model": "m1", "messages": [{"role": "user", "content": "hi"}], "guardrails": {"config_id": "bypass"}}),
        json!({"model": "m1", "messages": [{"role": "user", "content": "x".repeat(CONTENT_LIMIT)}]}),
    ] {
        assert_eq!(call(app.clone(), payload).await.0, StatusCode::BAD_REQUEST);
    }
    assert!(f.seen.lock().is_empty());
}

#[tokio::test]
async fn provider_errors_oversize_and_nontext_outputs_are_never_relayed() {
    let mut multimodal = completion();
    multimodal["choices"][0]["message"]["audio"] = json!({"data": "private audio"});
    for reply in [
        (StatusCode::BAD_REQUEST, "private provider error".into()),
        (StatusCode::OK, "x".repeat(CONTENT_LIMIT + 1)),
        (StatusCode::OK, "data: private stream\n\n".into()),
        (StatusCode::OK, multimodal.to_string()),
    ] {
        let f = Fixture {
            provider: reply,
            ..Fixture::default()
        };
        let (_, app) = setup(f.clone(), true).await;
        let (status, _, body) = call(app, request(true)).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert!(!body.contains("private"));
        assert_eq!(f.seen.lock().len(), 2);
    }
}

#[tokio::test]
async fn checker_deadline_and_capacity_are_fail_closed() {
    let f = Fixture {
        delay: Duration::from_millis(100),
        ..Fixture::default()
    };
    let (state, _) = setup(f, false).await;
    let mut guard = Guardrails::new(state.config.guardrails.clone().unwrap()).unwrap();
    guard.client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_millis(10))
        .build()
        .unwrap();
    assert!(matches!(
        guard.check("private input", None).await,
        Err(Error::GuardrailsUnavailable)
    ));
    let permits: Vec<_> = (0..8).map(|_| guard.acquire().unwrap()).collect();
    assert!(matches!(guard.acquire(), Err(Error::GuardrailsUnavailable)));
    drop(permits);
    assert!(guard.acquire().is_ok());
}

#[tokio::test]
async fn unauthenticated_readiness_cannot_starve_authenticated_completions() {
    // Hold readiness checks indefinitely while ordinary completion checks can succeed.
    // Before the fix, eight public probes consume every completion permit.
    let f = Fixture {
        readiness_gate: Some(Arc::new(Semaphore::new(0))),
        ..Fixture::default()
    };
    let (_, app) = setup(f.clone(), true).await;
    let mut probes = Vec::new();
    for index in 0..8 {
        let mut builder = Request::builder().uri("/ready");
        if index % 2 == 0 {
            builder = builder.header(header::AUTHORIZATION, "Bearer wrong");
        }
        probes.push(tokio::spawn(
            app.clone().oneshot(builder.body(Body::empty()).unwrap()),
        ));
    }
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if probes.iter().all(|probe| probe.is_finished()) || f.seen.lock().len() == 8 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("probes must either be rejected or reach the stalled checker");

    let (status, _, body) =
        tokio::time::timeout(Duration::from_secs(2), call(app.clone(), request(false)))
            .await
            .expect("completion must proceed while readiness checks are stalled");
    assert_eq!(
        status,
        StatusCode::OK,
        "readiness probes denied the authenticated completion: {body}"
    );
    assert_eq!(
        f.seen
            .lock()
            .iter()
            .map(|seen| seen.0.clone())
            .collect::<Vec<_>>(),
        ["input", "provider", "output"]
    );
    for probe in probes {
        assert_eq!(
            probe.await.unwrap().unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
    }
    let health = app
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(health.status(), StatusCode::OK);
}

#[tokio::test]
async fn readiness_requires_both_rails_as_well_as_provider_verification() {
    for blocked in [false, true] {
        let mut f = Fixture::default();
        if blocked {
            f.output = (StatusCode::OK, verdict("output", "blocked"));
        }
        let (_, app) = setup(f, true).await;
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/ready")
                    .header(header::AUTHORIZATION, "Bearer caller-secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            if blocked {
                StatusCode::SERVICE_UNAVAILABLE
            } else {
                StatusCode::OK
            }
        );
    }
}
