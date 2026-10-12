//! Per-upstream metrics in the Prometheus text format, served on their own listener
//! (`METRICS_PORT`), never on the members' TLS port.
//!
//! Nothing here can carry conversation text. Every label value is either a fixed string of this
//! file, `own` or `external`, or a model id from the measured `MODELS`: an observation for a model
//! outside it, or an error code or refusal reason outside the fixed lists, is dropped rather than
//! labelled, so the series are bounded by the configuration. The completion body is read only for
//! timing and token counts; its text is never kept.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::time::{Duration, Instant};

use axum::http::StatusCode;
use serde_json::Value;

use crate::{AppState, Config};

/// The two kinds of upstream, as labelled.
pub const OWN: &str = "own";
pub const EXTERNAL: &str = "external";

/// Every error code a member's completion can be refused with once its model is known: the
/// `code` of `Error`'s OpenAI-shaped body.
pub const ERROR_CODES: [&str; 9] = [
    "model_not_found",
    "upstream_unverified",
    "upstream",
    "upstream_refused",
    "content_blocked",
    "moderation_unavailable",
    "content_too_large",
    "content_not_judgeable",
    "internal",
];

const STATUS_CLASSES: [&str; 4] = ["2xx", "4xx", "5xx", "other"];

const LATENCY_BUCKETS: &[f64] = &[
    0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 20.0, 30.0, 60.0, 120.0, 300.0, 600.0,
];
const TTFT_BUCKETS: &[f64] = &[
    0.025, 0.05, 0.1, 0.25, 0.5, 0.75, 1.0, 1.5, 2.0, 3.0, 5.0, 10.0, 20.0, 60.0,
];
const TOKENS_PER_SECOND_BUCKETS: &[f64] = &[
    1.0, 5.0, 10.0, 20.0, 30.0, 50.0, 75.0, 100.0, 150.0, 200.0, 300.0, 500.0, 1000.0,
];
const CHECK_BUCKETS: &[f64] = &[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 20.0];

/// An SSE line longer than this is skipped, not buffered further.
const MAX_LINE: usize = 16 * 1024 * 1024;

/// A cumulative histogram with fixed upper bounds.
#[derive(Clone, Debug)]
struct Histogram {
    bounds: &'static [f64],
    /// One per bound, then `+Inf`; not cumulative until rendered.
    counts: Vec<u64>,
    sum: f64,
    count: u64,
}

impl Histogram {
    fn new(bounds: &'static [f64]) -> Self {
        Self {
            bounds,
            counts: vec![0; bounds.len().saturating_add(1)],
            sum: 0.0,
            count: 0,
        }
    }

    fn observe(&mut self, value: f64) {
        if !value.is_finite() || value < 0.0 {
            return;
        }
        let index = self
            .bounds
            .iter()
            .position(|bound| value <= *bound)
            .unwrap_or(self.bounds.len());
        if let Some(count) = self.counts.get_mut(index) {
            *count = count.saturating_add(1);
        }
        self.sum += value;
        self.count = self.count.saturating_add(1);
    }

    fn render(&self, out: &mut String, name: &str, labels: &[(&str, &str)]) {
        let mut cumulative = 0u64;
        for (bound, count) in self.bounds.iter().zip(&self.counts) {
            cumulative = cumulative.saturating_add(*count);
            let le = bound.to_string();
            let mut with_le = labels.to_vec();
            with_le.push(("le", &le));
            sample(out, &format!("{name}_bucket"), &with_le, cumulative);
        }
        let mut with_le = labels.to_vec();
        with_le.push(("le", "+Inf"));
        sample(out, &format!("{name}_bucket"), &with_le, self.count);
        sample(out, &format!("{name}_sum"), labels, self.sum);
        sample(out, &format!("{name}_count"), labels, self.count);
    }
}

fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out
}

fn sample(out: &mut String, name: &str, labels: &[(&str, &str)], value: impl std::fmt::Display) {
    let labels: Vec<String> = labels
        .iter()
        .map(|(k, v)| format!("{k}=\"{}\"", escape(v)))
        .collect();
    let _ = writeln!(out, "{name}{{{}}} {value}", labels.join(","));
}

fn family(out: &mut String, name: &str, kind: &str, help: &str) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} {kind}");
}

pub fn status_class(status: StatusCode) -> &'static str {
    if status.is_success() {
        "2xx"
    } else if status.is_client_error() {
        "4xx"
    } else if status.is_server_error() {
        "5xx"
    } else {
        "other"
    }
}

/// What one member's completion did, as far as metrics are concerned: no text.
#[derive(Clone, Debug)]
pub struct Observation {
    pub status: StatusCode,
    /// The error code it was refused with; one of [`ERROR_CODES`].
    pub error: Option<&'static str>,
    /// From the request's arrival to its answer, moderation included.
    pub elapsed: Duration,
    pub usage: Usage,
}

/// The upstream leg of a completion: set once the upstream answered 2xx.
#[derive(Clone, Debug, Default)]
pub struct Usage {
    /// Streamed only: from the upstream leg's start to its first chunk that says something.
    pub ttft: Option<Duration>,
    pub output_tokens: Option<u64>,
    /// Streamed only: the decode rate, `(tokens - 1) / (last byte - first output)`.
    pub tokens_per_second: Option<f64>,
}

impl Usage {
    /// `started` is when the upstream leg began (attestation check, connection and prefill
    /// included); `meter` has seen the whole body of a streamed completion.
    pub fn streamed(started: Instant, done: Instant, meter: &SseMeter) -> Self {
        let first = meter.first_output();
        let output_tokens = meter.output_tokens();
        let tokens_per_second = match (first, output_tokens) {
            (Some(first), Some(tokens)) if tokens >= 2 => {
                let decoding = done.saturating_duration_since(first).as_secs_f64();
                #[allow(clippy::cast_precision_loss)]
                let generated = tokens.saturating_sub(1) as f64;
                (decoding > 0.0).then(|| generated / decoding)
            }
            _ => None,
        };
        Self {
            ttft: first.map(|first| first.saturating_duration_since(started)),
            output_tokens,
            tokens_per_second,
        }
    }

    pub fn whole(body: &[u8]) -> Self {
        Self {
            ttft: None,
            output_tokens: json_output_tokens(body),
            tokens_per_second: None,
        }
    }
}

#[derive(Debug)]
struct RequestStats {
    duration: BTreeMap<&'static str, Histogram>,
    ttft: Histogram,
    tokens_per_second: Histogram,
    output_tokens: u64,
    errors: BTreeMap<&'static str, u64>,
}

struct ModelMetrics {
    model: String,
    upstream: &'static str,
    stats: parking_lot::Mutex<RequestStats>,
}

/// Request metrics for every allowlisted model, built once from the configuration.
pub struct Metrics {
    models: Vec<ModelMetrics>,
}

impl Metrics {
    pub fn new(config: &Config) -> Self {
        let models = config
            .models
            .iter()
            .map(|model| ModelMetrics {
                model: model.clone(),
                upstream: if config.model_servers.contains_key(model) {
                    OWN
                } else {
                    EXTERNAL
                },
                stats: parking_lot::Mutex::new(RequestStats {
                    duration: BTreeMap::new(),
                    ttft: Histogram::new(TTFT_BUCKETS),
                    tokens_per_second: Histogram::new(TOKENS_PER_SECOND_BUCKETS),
                    output_tokens: 0,
                    errors: ERROR_CODES.iter().map(|code| (*code, 0)).collect(),
                }),
            })
            .collect();
        Self { models }
    }

    /// Records a member's completion for `model`; nothing for a model outside `MODELS`.
    pub fn observe(&self, model: &str, observation: &Observation) {
        let Some(entry) = self.models.iter().find(|m| m.model == model) else {
            return;
        };
        let mut stats = entry.stats.lock();
        let class = status_class(observation.status);
        stats
            .duration
            .entry(class)
            .or_insert_with(|| Histogram::new(LATENCY_BUCKETS))
            .observe(observation.elapsed.as_secs_f64());
        if let Some(count) = observation
            .error
            .and_then(|code| stats.errors.get_mut(code))
        {
            *count = count.saturating_add(1);
        }
        let usage = &observation.usage;
        if let Some(ttft) = usage.ttft {
            stats.ttft.observe(ttft.as_secs_f64());
        }
        if let Some(rate) = usage.tokens_per_second {
            stats.tokens_per_second.observe(rate);
        }
        if let Some(tokens) = usage.output_tokens {
            stats.output_tokens = stats.output_tokens.saturating_add(tokens);
        }
    }
}

#[derive(Debug)]
struct CheckInner {
    checks: u64,
    /// Parallel to `CheckStats::reasons`.
    refusals: Vec<u64>,
    duration: Histogram,
}

/// One model's attestation checks: how many ran, how long they took and why each refusal was.
#[derive(Debug)]
pub struct CheckStats {
    reasons: &'static [&'static str],
    inner: parking_lot::Mutex<CheckInner>,
}

impl CheckStats {
    /// `reasons` is the fixed list of codes a refusal can carry.
    pub fn new(reasons: &'static [&'static str]) -> Self {
        Self {
            reasons,
            inner: parking_lot::Mutex::new(CheckInner {
                checks: 0,
                refusals: vec![0; reasons.len()],
                duration: Histogram::new(CHECK_BUCKETS),
            }),
        }
    }

    pub fn record(&self, elapsed: Duration, refused: Option<&'static str>) {
        let mut inner = self.inner.lock();
        inner.checks = inner.checks.saturating_add(1);
        inner.duration.observe(elapsed.as_secs_f64());
        if let Some(index) = refused.and_then(|r| self.reasons.iter().position(|c| *c == r))
            && let Some(count) = inner.refusals.get_mut(index)
        {
            *count = count.saturating_add(1);
        }
    }

    #[cfg(test)]
    pub(crate) fn checks(&self) -> u64 {
        self.inner.lock().checks
    }

    #[cfg(test)]
    pub(crate) fn refusals(&self, reason: &str) -> u64 {
        let index = self.reasons.iter().position(|r| *r == reason).unwrap();
        self.inner.lock().refusals[index]
    }
}

/// Everything above, in the Prometheus text format (0.0.4).
pub fn render(state: &AppState) -> String {
    let mut out = String::new();
    let models = &state.metrics.models;

    family(
        &mut out,
        "alpha_inference_request_duration_seconds",
        "histogram",
        "Members' chat completions from arrival to answer, moderation included.",
    );
    for m in models {
        let stats = m.stats.lock();
        for class in STATUS_CLASSES {
            if let Some(histogram) = stats.duration.get(class) {
                histogram.render(
                    &mut out,
                    "alpha_inference_request_duration_seconds",
                    &[
                        ("upstream", m.upstream),
                        ("model", &m.model),
                        ("status_class", class),
                    ],
                );
            }
        }
    }

    family(
        &mut out,
        "alpha_inference_ttft_seconds",
        "histogram",
        "Streamed completions: from the upstream leg's start (attestation check included) to its first output chunk.",
    );
    for m in models {
        m.stats.lock().ttft.render(
            &mut out,
            "alpha_inference_ttft_seconds",
            &[("upstream", m.upstream), ("model", &m.model)],
        );
    }

    family(
        &mut out,
        "alpha_inference_output_tokens_per_second",
        "histogram",
        "Streamed completions: output tokens after the first per second of decoding.",
    );
    for m in models {
        m.stats.lock().tokens_per_second.render(
            &mut out,
            "alpha_inference_output_tokens_per_second",
            &[("upstream", m.upstream), ("model", &m.model)],
        );
    }

    family(
        &mut out,
        "alpha_inference_output_tokens_total",
        "counter",
        "Output tokens of 2xx completions, from usage or, streamed without usage, output chunks.",
    );
    for m in models {
        let tokens = m.stats.lock().output_tokens;
        sample(
            &mut out,
            "alpha_inference_output_tokens_total",
            &[("upstream", m.upstream), ("model", &m.model)],
            tokens,
        );
    }

    family(
        &mut out,
        "alpha_inference_errors_total",
        "counter",
        "Members' completions refused, by the fixed error code of the answer.",
    );
    for m in models {
        let stats = m.stats.lock();
        for (code, count) in &stats.errors {
            sample(
                &mut out,
                "alpha_inference_errors_total",
                &[
                    ("upstream", m.upstream),
                    ("model", &m.model),
                    ("code", code),
                ],
                count,
            );
        }
    }

    let checks: Vec<(&'static str, &str, &CheckStats)> = state
        .own
        .check_stats()
        .map(|(model, stats)| (OWN, model, stats))
        .chain(
            state
                .upstream
                .check_stats()
                .map(|(model, stats)| (EXTERNAL, model, stats)),
        )
        .collect();
    family(
        &mut out,
        "alpha_inference_attestation_checks_total",
        "counter",
        "Attestation checks of an upstream run, inline or to keep it warm.",
    );
    for (upstream, model, stats) in &checks {
        sample(
            &mut out,
            "alpha_inference_attestation_checks_total",
            &[("upstream", upstream), ("model", model)],
            stats.inner.lock().checks,
        );
    }
    family(
        &mut out,
        "alpha_inference_attestation_refusals_total",
        "counter",
        "Attestation checks that refused the upstream, by reason code.",
    );
    for (upstream, model, stats) in &checks {
        let inner = stats.inner.lock();
        for (reason, count) in stats.reasons.iter().zip(&inner.refusals) {
            sample(
                &mut out,
                "alpha_inference_attestation_refusals_total",
                &[("upstream", upstream), ("model", model), ("reason", reason)],
                count,
            );
        }
    }
    family(
        &mut out,
        "alpha_inference_attestation_check_duration_seconds",
        "histogram",
        "How long an attestation check of an upstream took.",
    );
    for (upstream, model, stats) in &checks {
        stats.inner.lock().duration.render(
            &mut out,
            "alpha_inference_attestation_check_duration_seconds",
            &[("upstream", upstream), ("model", model)],
        );
    }
    out
}

/// Whether a stream chunk's `choices[].delta` says anything: text, reasoning, a refusal or a
/// tool call. A role-only first chunk does not.
fn has_output(chunk: &Value) -> bool {
    let says = |delta: &Value| {
        ["content", "reasoning_content", "reasoning", "refusal"]
            .iter()
            .any(|key| match delta.get(key) {
                Some(Value::String(text)) => !text.is_empty(),
                Some(Value::Array(parts)) => !parts.is_empty(),
                _ => false,
            })
            || delta
                .get("tool_calls")
                .and_then(Value::as_array)
                .is_some_and(|calls| !calls.is_empty())
            || delta.get("function_call").is_some_and(|v| !v.is_null())
    };
    chunk
        .get("choices")
        .and_then(Value::as_array)
        .is_some_and(|choices| choices.iter().any(|c| c.get("delta").is_some_and(says)))
}

fn completion_tokens(value: &Value) -> Option<u64> {
    value
        .get("usage")
        .and_then(|usage| usage.get("completion_tokens"))
        .and_then(Value::as_u64)
}

/// `usage.completion_tokens` of a whole (unstreamed) completion.
pub fn json_output_tokens(body: &[u8]) -> Option<u64> {
    serde_json::from_slice::<Value>(body)
        .ok()
        .as_ref()
        .and_then(completion_tokens)
}

/// Reads an OpenAI-style event stream as it arrives, keeping only the line in progress: when the
/// first chunk with output came, how many chunks had output, and the last `usage` seen.
#[derive(Debug, Default)]
pub struct SseMeter {
    partial: Vec<u8>,
    overlong: bool,
    first_output: Option<Instant>,
    output_chunks: u64,
    usage_tokens: Option<u64>,
}

impl SseMeter {
    pub fn feed(&mut self, bytes: &[u8], at: Instant) {
        let mut rest = bytes;
        while let Some(newline) = rest.iter().position(|b| *b == b'\n') {
            let (line, tail) = rest.split_at(newline);
            self.extend(line);
            let line = std::mem::take(&mut self.partial);
            if !std::mem::take(&mut self.overlong) {
                self.line(&line, at);
            }
            rest = tail.get(1..).unwrap_or_default();
        }
        self.extend(rest);
    }

    /// A last line without its newline.
    pub fn finish(&mut self, at: Instant) {
        let line = std::mem::take(&mut self.partial);
        if !std::mem::take(&mut self.overlong) {
            self.line(&line, at);
        }
    }

    fn extend(&mut self, bytes: &[u8]) {
        if self.partial.len().saturating_add(bytes.len()) > MAX_LINE {
            self.partial.clear();
            self.overlong = true;
        } else if !self.overlong {
            self.partial.extend_from_slice(bytes);
        }
    }

    fn line(&mut self, line: &[u8], at: Instant) {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(data) = line.strip_prefix(b"data:") else {
            return;
        };
        let data = data.trim_ascii();
        if data == b"[DONE]" {
            return;
        }
        let Ok(chunk) = serde_json::from_slice::<Value>(data) else {
            return;
        };
        if let Some(tokens) = completion_tokens(&chunk) {
            self.usage_tokens = Some(tokens);
        }
        if has_output(&chunk) {
            self.output_chunks = self.output_chunks.saturating_add(1);
            self.first_output.get_or_insert(at);
        }
    }

    pub fn first_output(&self) -> Option<Instant> {
        self.first_output
    }

    /// `usage.completion_tokens` when the stream carried it (`stream_options.include_usage`),
    /// else the chunks with output: one token per chunk is what vLLM streams by default.
    pub fn output_tokens(&self) -> Option<u64> {
        self.usage_tokens
            .or((self.output_chunks > 0).then_some(self.output_chunks))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_histogram_renders_cumulative_buckets_sum_and_count() {
        let mut h = Histogram::new(&[1.0, 2.0]);
        for v in [0.5, 1.5, 1.5, 9.0, f64::NAN, -1.0] {
            h.observe(v);
        }
        let mut out = String::new();
        h.render(&mut out, "x", &[("upstream", "own")]);
        assert_eq!(
            out,
            "x_bucket{upstream=\"own\",le=\"1\"} 1\n\
             x_bucket{upstream=\"own\",le=\"2\"} 3\n\
             x_bucket{upstream=\"own\",le=\"+Inf\"} 4\n\
             x_sum{upstream=\"own\"} 12.5\n\
             x_count{upstream=\"own\"} 4\n"
        );
    }

    #[test]
    fn label_values_are_escaped() {
        let mut out = String::new();
        sample(&mut out, "x", &[("model", "a\"b\\c\nd")], 1);
        assert_eq!(out, "x{model=\"a\\\"b\\\\c\\nd\"} 1\n");
    }

    #[test]
    fn the_meter_finds_the_first_output_chunk_across_split_lines_and_reads_usage() {
        let start = Instant::now();
        let later = start + Duration::from_millis(250);
        let mut meter = SseMeter::default();
        meter.feed(
            b"data: {\"choices\":[{\"delta\":{\"role\":\"assistant\",\"content\":\"\"}}]}\n\n",
            start,
        );
        assert_eq!(meter.first_output(), None);
        meter.feed(b"data: {\"choices\":[{\"delta\":{\"cont", start);
        meter.feed(b"ent\":\"hi\"}}]}\r\n\r\n", later);
        meter.feed(
            b"data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"id\":\"t\"}]}}]}\n\n",
            later,
        );
        assert_eq!(meter.first_output(), Some(later));
        assert_eq!(meter.output_tokens(), Some(2));
        meter.feed(
            b"data: {\"choices\":[],\"usage\":{\"completion_tokens\":7}}\n\ndata: [DONE]",
            later,
        );
        meter.finish(later);
        assert_eq!(meter.output_tokens(), Some(7));
    }

    #[test]
    fn streamed_usage_is_the_decode_rate_after_the_first_token() {
        let start = Instant::now();
        let mut meter = SseMeter::default();
        let first = start + Duration::from_millis(500);
        meter.feed(
            b"data: {\"choices\":[{\"delta\":{\"content\":\"a\"}}],\"usage\":{\"completion_tokens\":11}}\n",
            first,
        );
        let usage = Usage::streamed(start, first + Duration::from_secs(2), &meter);
        assert_eq!(usage.ttft, Some(Duration::from_millis(500)));
        assert_eq!(usage.output_tokens, Some(11));
        assert_eq!(usage.tokens_per_second, Some(5.0));
        assert_eq!(
            Usage::whole(br#"{"choices":[],"usage":{"completion_tokens":3}}"#).output_tokens,
            Some(3)
        );
    }
}
