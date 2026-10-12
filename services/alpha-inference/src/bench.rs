//! The benchmark behind `alpha-inference-bench`: the checked-in prompt set (`slo/prompts.json`)
//! sent as streamed chat completions to an OpenAI-compatible endpoint, one model per upstream,
//! measured for TTFT, latency, tokens/s and errors, then summarised for [`slo::evaluate`].
//!
//! A response is read for timing and token counts as it arrives and then dropped: its text is
//! never printed, kept or written anywhere. Of an error answer only the status and, when it is
//! one of the front's fixed codes, `error.code` are read.
//!
//! Through alpha-inference, a stream is held until the judge allows it, so the TTFT the bench sees
//! there includes moderation and the whole generation; the front's own metrics have the
//! upstream's TTFT.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::{Value, json};

use crate::metrics::{self, SseMeter, Usage};
use crate::slo::{self, Summary};
use crate::{COMPLETION_TIMEOUT, Error};

/// The checked-in prompt set.
pub const DEFAULT_PROMPTS: &str = include_str!("../slo/prompts.json");

/// An error answer is read this far for its code, no further.
const ERROR_BODY_LIMIT: usize = 64 * 1024;

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Prompt {
    pub id: String,
    pub max_tokens: u32,
    pub messages: Vec<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PromptSet {
    #[allow(dead_code)]
    about: String,
    prompts: Vec<Prompt>,
}

pub fn parse_prompts(text: &str) -> Result<Vec<Prompt>, Error> {
    let set: PromptSet =
        serde_json::from_str(text).map_err(|e| Error::internal(format!("prompts: {e}")))?;
    if set.prompts.is_empty() {
        return Err(Error::internal("prompts: the set is empty"));
    }
    let mut ids = std::collections::BTreeSet::new();
    for p in &set.prompts {
        if p.id.is_empty() || !ids.insert(p.id.as_str()) {
            return Err(Error::internal(format!(
                "prompts: id {:?} is empty or repeated",
                p.id
            )));
        }
        if p.messages.is_empty() || p.max_tokens == 0 {
            return Err(Error::internal(format!(
                "prompts: {} has no messages or no max_tokens",
                p.id
            )));
        }
    }
    Ok(set.prompts)
}

/// A model to measure and the upstream it stands for (`own` or `external`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub upstream: String,
    pub model: String,
}

/// `<upstream>=<model>`, the upstream `own` or `external`.
pub fn parse_target(text: &str) -> Result<Target, Error> {
    let (upstream, model) = text
        .split_once('=')
        .ok_or_else(|| Error::internal(format!("{text:?} is not <upstream>=<model>")))?;
    if upstream != metrics::OWN && upstream != metrics::EXTERNAL {
        return Err(Error::internal(format!(
            "upstream {upstream:?} is neither {} nor {}",
            metrics::OWN,
            metrics::EXTERNAL
        )));
    }
    if model.is_empty() {
        return Err(Error::internal(format!("{text:?} names no model")));
    }
    Ok(Target {
        upstream: upstream.to_owned(),
        model: model.to_owned(),
    })
}

/// How one request ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Ok,
    /// A fixed class: one of the front's error codes, `http_4xx`, `http_5xx`, `transport`, or
    /// `no_output` for a 2xx stream that said nothing.
    Failed(&'static str),
}

/// One request's measurements: no text.
#[derive(Clone, Debug)]
pub struct Sample {
    pub status: Option<u16>,
    pub outcome: Outcome,
    pub latency: Duration,
    pub usage: Usage,
}

impl Sample {
    fn server_error(&self) -> bool {
        match self.outcome {
            Outcome::Ok => false,
            Outcome::Failed(_) => self
                .status
                .is_none_or(|s| s >= 500 || (200..300).contains(&s)),
        }
    }
}

fn error_class(status: u16, body: &[u8]) -> &'static str {
    let code = serde_json::from_slice::<Value>(body).ok().and_then(|v| {
        v.get("error")
            .and_then(|e| e.get("code"))
            .and_then(Value::as_str)
            .and_then(|code| {
                metrics::ERROR_CODES
                    .iter()
                    .chain(&["unauthorized"])
                    .find(|known| **known == code)
                    .copied()
            })
    });
    code.unwrap_or(if status >= 500 {
        "http_5xx"
    } else {
        "http_4xx"
    })
}

/// One streamed completion of `prompt` on `model` at `endpoint` (an OpenAI base, `/v1`
/// included).
pub async fn measure(
    client: &reqwest::Client,
    endpoint: &str,
    bearer: &str,
    model: &str,
    prompt: &Prompt,
) -> Sample {
    let body = json!({
        "model": model,
        "messages": prompt.messages,
        "max_tokens": prompt.max_tokens,
        "temperature": 0,
        "stream": true,
        "stream_options": { "include_usage": true },
    });
    let started = Instant::now();
    let failed = |status: Option<u16>, class| Sample {
        status,
        outcome: Outcome::Failed(class),
        latency: started.elapsed(),
        usage: Usage::default(),
    };
    let sent = client
        .post(format!("{endpoint}/chat/completions"))
        .bearer_auth(bearer)
        .timeout(COMPLETION_TIMEOUT)
        .json(&body)
        .send()
        .await;
    let Ok(mut response) = sent else {
        return failed(None, "transport");
    };
    let status = response.status().as_u16();
    if !response.status().is_success() {
        let mut head = Vec::new();
        while let Ok(Some(chunk)) = response.chunk().await {
            head.extend_from_slice(&chunk);
            if head.len() >= ERROR_BODY_LIMIT {
                break;
            }
        }
        return failed(Some(status), error_class(status, &head));
    }
    let mut meter = SseMeter::default();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => meter.feed(&chunk, Instant::now()),
            Ok(None) => break,
            Err(_) => return failed(Some(status), "transport"),
        }
    }
    let done = Instant::now();
    meter.finish(done);
    if meter.first_output().is_none() {
        return failed(Some(status), "no_output");
    }
    Sample {
        status: Some(status),
        outcome: Outcome::Ok,
        latency: done.saturating_duration_since(started),
        usage: Usage::streamed(started, done, &meter),
    }
}

/// Every prompt `rounds` times on every target, one request at a time, keyed by upstream.
pub async fn run(
    client: &reqwest::Client,
    endpoint: &str,
    bearer: &str,
    targets: &[Target],
    prompts: &[Prompt],
    rounds: u32,
) -> BTreeMap<String, Vec<Sample>> {
    let mut samples: BTreeMap<String, Vec<Sample>> = BTreeMap::new();
    for _ in 0..rounds {
        for target in targets {
            for prompt in prompts {
                let sample = measure(client, endpoint, bearer, &target.model, prompt).await;
                samples
                    .entry(target.upstream.clone())
                    .or_default()
                    .push(sample);
            }
        }
    }
    samples
}

pub fn summarize(samples: &[Sample]) -> Summary {
    let ok: Vec<&Sample> = samples
        .iter()
        .filter(|s| s.outcome == Outcome::Ok)
        .collect();
    let ttft: Vec<f64> = ok
        .iter()
        .filter_map(|s| s.usage.ttft.map(|t| t.as_secs_f64()))
        .collect();
    let latency: Vec<f64> = ok.iter().map(|s| s.latency.as_secs_f64()).collect();
    let tps: Vec<f64> = ok
        .iter()
        .filter_map(|s| s.usage.tokens_per_second)
        .collect();
    let count = |f: &dyn Fn(&Sample) -> bool| {
        u64::try_from(samples.iter().filter(|s| f(s)).count()).unwrap_or(u64::MAX)
    };
    Summary {
        requests: u64::try_from(samples.len()).unwrap_or(u64::MAX),
        server_errors: count(&Sample::server_error),
        attestation_refusals: count(&|s| s.outcome == Outcome::Failed("upstream_unverified")),
        ttft_p50: slo::quantile(&ttft, 0.5),
        ttft_p95: slo::quantile(&ttft, 0.95),
        latency_p50: slo::quantile(&latency, 0.5),
        latency_p95: slo::quantile(&latency, 0.95),
        tokens_per_second_p50: slo::quantile(&tps, 0.5),
    }
}

/// The measurements per upstream, the errors by class, then the SLO report.
pub fn report(slo: &slo::Slo, samples: &BTreeMap<String, Vec<Sample>>) -> (String, bool) {
    let summaries: BTreeMap<String, Summary> = samples
        .iter()
        .map(|(upstream, s)| (upstream.clone(), summarize(s)))
        .collect();
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{:<10} {:>8} {:>8} {:>8} {:>9} {:>9} {:>11} {:>11} {:>12}",
        "upstream",
        "requests",
        "5xx",
        "attest",
        "ttft p50",
        "ttft p95",
        "latency p50",
        "latency p95",
        "tokens/s p50"
    );
    let secs = |v: Option<f64>| v.map_or_else(|| "-".to_owned(), |v| format!("{v:.3}s"));
    for (upstream, s) in &summaries {
        let _ = writeln!(
            out,
            "{:<10} {:>8} {:>8} {:>8} {:>9} {:>9} {:>11} {:>11} {:>12}",
            upstream,
            s.requests,
            s.server_errors,
            s.attestation_refusals,
            secs(s.ttft_p50),
            secs(s.ttft_p95),
            secs(s.latency_p50),
            secs(s.latency_p95),
            s.tokens_per_second_p50
                .map_or_else(|| "-".to_owned(), |v| format!("{v:.1}"))
        );
    }
    for (upstream, s) in samples {
        let mut classes: BTreeMap<&str, u64> = BTreeMap::new();
        for sample in s {
            if let Outcome::Failed(class) = sample.outcome {
                let n = classes.entry(class).or_default();
                *n = n.saturating_add(1);
            }
        }
        if !classes.is_empty() {
            let listed: Vec<String> = classes.iter().map(|(c, n)| format!("{c}={n}")).collect();
            let _ = writeln!(out, "errors {upstream}: {}", listed.join(" "));
        }
    }
    out.push('\n');
    let evaluated = slo::evaluate(slo, &summaries);
    out.push_str(&evaluated.render());
    (out, evaluated.passed())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::Router;
    use axum::extract::State;
    use axum::http::{HeaderMap, StatusCode, header};
    use axum::response::{IntoResponse, Response};
    use axum::routing::post;

    use super::*;

    const MARKER: &str = "bench-marker-5f0c1e7a";

    fn stream_body() -> String {
        let mut body = String::new();
        body.push_str(
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"\"}}]}\n\n",
        );
        for word in [MARKER, " and", " more"] {
            body.push_str(&format!(
                "data: {{\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"{word}\"}}}}]}}\n\n"
            ));
        }
        body.push_str("data: {\"choices\":[],\"usage\":{\"prompt_tokens\":9,\"completion_tokens\":3}}\n\ndata: [DONE]\n\n");
        body
    }

    type Seen = Arc<parking_lot::Mutex<Vec<Value>>>;

    async fn completions(
        State(seen): State<Seen>,
        headers: HeaderMap,
        body: axum::body::Bytes,
    ) -> Response {
        if headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            != Some("Bearer bench-bearer")
        {
            return StatusCode::UNAUTHORIZED.into_response();
        }
        let request: Value = serde_json::from_slice(&body).unwrap();
        seen.lock().push(request.clone());
        match request["model"].as_str().unwrap() {
            "good" => {
                ([(header::CONTENT_TYPE, "text/event-stream")], stream_body()).into_response()
            }
            "unverified" => (
                StatusCode::BAD_GATEWAY,
                axum::Json(json!({"error": {
                    "message": MARKER, "type": "upstream_error", "code": "upstream_unverified"
                }})),
            )
                .into_response(),
            "silent" => (
                [(header::CONTENT_TYPE, "text/event-stream")],
                "data: {\"choices\":[{\"delta\":{\"role\":\"assistant\"}}]}\n\ndata: [DONE]\n\n",
            )
                .into_response(),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, MARKER).into_response(),
        }
    }

    /// A local OpenAI-compatible server: `good` streams an answer with usage, `unverified`
    /// answers the front's attestation refusal, `silent` streams nothing, anything else 500s.
    async fn spawn_mock() -> (String, Seen) {
        let seen: Seen = Arc::default();
        let app = Router::new()
            .route("/v1/chat/completions", post(completions))
            .with_state(seen.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (format!("http://{addr}/v1"), seen)
    }

    #[test]
    fn the_checked_in_prompt_set_parses_and_a_bad_one_is_refused() {
        let prompts = parse_prompts(DEFAULT_PROMPTS).unwrap();
        assert!(prompts.len() >= 5);
        for bad in [
            r#"{"about":"","prompts":[]}"#,
            r#"{"about":"","prompts":[{"id":"a","max_tokens":1,"messages":[{}]},{"id":"a","max_tokens":1,"messages":[{}]}]}"#,
            r#"{"about":"","prompts":[{"id":"a","max_tokens":0,"messages":[{}]}]}"#,
            r#"{"about":"","prompts":[{"id":"a","max_tokens":1,"messages":[]}]}"#,
        ] {
            assert!(parse_prompts(bad).is_err(), "{bad}");
        }
        assert_eq!(
            parse_target("own=m").unwrap(),
            Target {
                upstream: "own".into(),
                model: "m".into()
            }
        );
        for bad in ["m", "redpill=m", "own="] {
            assert!(parse_target(bad).is_err(), "{bad}");
        }
    }

    #[tokio::test]
    async fn the_bench_measures_each_upstream_and_reports_against_the_slo_without_content() {
        let (endpoint, seen) = spawn_mock().await;
        let prompts = parse_prompts(DEFAULT_PROMPTS).unwrap();
        let targets = [
            parse_target("own=good").unwrap(),
            parse_target("external=unverified").unwrap(),
        ];
        let client = reqwest::Client::new();
        let samples = run(&client, &endpoint, "bench-bearer", &targets, &prompts, 3).await;

        let n = u64::try_from(prompts.len() * 3).unwrap();
        let own = summarize(&samples["own"]);
        assert_eq!(own.requests, n);
        assert_eq!(own.server_errors, 0);
        assert!(own.ttft_p50.is_some() && own.latency_p95.is_some());
        assert!(
            samples["own"]
                .iter()
                .all(|s| s.usage.output_tokens == Some(3))
        );
        let external = summarize(&samples["external"]);
        assert_eq!(external.requests, n);
        assert_eq!(external.server_errors, n);
        assert_eq!(external.attestation_refusals, n);

        // What was sent: the prompt set itself, streamed, for each target's model.
        let seen = seen.lock();
        assert_eq!(seen.len(), prompts.len() * 6);
        assert_eq!(seen[0]["model"], "good");
        assert_eq!(seen[0]["messages"], json!(prompts[0].messages));
        assert_eq!(seen[0]["stream"], true);

        let slo = slo::Slo::parse(slo::DEFAULT).unwrap();
        let (printed, passed) = report(&slo, &samples);
        assert!(!passed);
        assert!(
            printed.contains(&format!("errors external: upstream_unverified={n}")),
            "{printed}"
        );
        assert!(printed.contains("attestation refusal rate"), "{printed}");
        assert!(printed.contains("SLO NOT met"), "{printed}");
        assert!(!printed.contains(MARKER), "{printed}");
        assert!(!format!("{samples:?}").contains(MARKER));
    }

    #[tokio::test]
    async fn an_empty_stream_a_server_error_and_a_wrong_bearer_are_classified() {
        let (endpoint, _seen) = spawn_mock().await;
        let prompt = &parse_prompts(DEFAULT_PROMPTS).unwrap()[0];
        let client = reqwest::Client::new();
        let silent = measure(&client, &endpoint, "bench-bearer", "silent", prompt).await;
        assert_eq!(silent.outcome, Outcome::Failed("no_output"));
        assert!(silent.server_error());
        let broken = measure(&client, &endpoint, "bench-bearer", "other", prompt).await;
        assert_eq!(broken.outcome, Outcome::Failed("http_5xx"));
        let refused = measure(&client, &endpoint, "wrong", "good", prompt).await;
        assert_eq!(refused.outcome, Outcome::Failed("http_4xx"));
        assert!(!refused.server_error());
        let unreachable = measure(&client, "http://127.0.0.1:1/v1", "b", "good", prompt).await;
        assert_eq!(unreachable.outcome, Outcome::Failed("transport"));
        assert!(unreachable.server_error());
    }
}
