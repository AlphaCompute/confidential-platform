//! The SLOs of attested inference per upstream (our own model servers and the external
//! provider), and the rule our own must keep against the external one, read from `slo/slo.toml`.
//! The same numbers are evaluated against a benchmark run ([`evaluate`]) and rendered as
//! Prometheus recording and alert rules over the front's metrics ([`prometheus_rules`], checked in
//! as `slo/rules.yaml`). An objective with too few requests behind it is no data, never a pass.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde::Deserialize;

use crate::Error;
use crate::metrics::{EXTERNAL, OWN};

/// The checked-in SLO definition.
pub const DEFAULT: &str = include_str!("../slo/slo.toml");

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Slo {
    /// The window every rate and quantile is taken over.
    pub window_minutes: u32,
    /// How long an alert's condition must hold before it fires.
    pub alert_for_minutes: u32,
    /// Below this many requests in a window or a run, an objective is no data.
    pub min_requests: u64,
    /// Exactly `own` and `external`.
    pub upstream: BTreeMap<String, Targets>,
    pub comparison: Comparison,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Targets {
    pub ttft_p50_seconds: f64,
    pub ttft_p95_seconds: f64,
    pub latency_p50_seconds: f64,
    pub latency_p95_seconds: f64,
    pub min_tokens_per_second_p50: f64,
    /// Server errors (5xx, or no answer at all) over requests.
    pub max_error_rate: f64,
    /// Requests refused because the upstream did not pass its attestation check, over requests.
    pub max_attestation_refusal_rate: f64,
}

/// Our own model servers against the external provider over the same window.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Comparison {
    /// Own p95 TTFT at most this many times the external provider's.
    pub ttft_p95_max_ratio: f64,
    /// Own p95 latency at most this many times the external provider's.
    pub latency_p95_max_ratio: f64,
    /// Own median tokens/s at least this fraction of the external provider's.
    pub tokens_per_second_p50_min_ratio: f64,
}

fn invalid(message: impl std::fmt::Display) -> Error {
    Error::internal(format!("SLO: {message}"))
}

impl Slo {
    pub fn parse(text: &str) -> Result<Self, Error> {
        let slo: Slo = toml::from_str(text).map_err(invalid)?;
        slo.validate()?;
        Ok(slo)
    }

    fn validate(&self) -> Result<(), Error> {
        if !(1..=1440).contains(&self.window_minutes) {
            return Err(invalid("window_minutes must be from 1 to 1440"));
        }
        if !(1..=1440).contains(&self.alert_for_minutes) {
            return Err(invalid("alert_for_minutes must be from 1 to 1440"));
        }
        if self.min_requests == 0 {
            return Err(invalid("min_requests must be at least 1"));
        }
        let names: Vec<&str> = self.upstream.keys().map(String::as_str).collect();
        if names != [EXTERNAL, OWN] {
            return Err(invalid(format!(
                "upstream must name exactly {OWN} and {EXTERNAL}, not {names:?}"
            )));
        }
        let positive = |name: String, v: f64| {
            if v.is_finite() && v > 0.0 {
                Ok(())
            } else {
                Err(invalid(format!("{name} must be a positive number")))
            }
        };
        let rate = |name: String, v: f64| {
            if (0.0..=1.0).contains(&v) {
                Ok(())
            } else {
                Err(invalid(format!("{name} must be from 0 to 1")))
            }
        };
        for (upstream, t) in &self.upstream {
            for (name, v) in [
                ("ttft_p50_seconds", t.ttft_p50_seconds),
                ("ttft_p95_seconds", t.ttft_p95_seconds),
                ("latency_p50_seconds", t.latency_p50_seconds),
                ("latency_p95_seconds", t.latency_p95_seconds),
                ("min_tokens_per_second_p50", t.min_tokens_per_second_p50),
            ] {
                positive(format!("{upstream}.{name}"), v)?;
            }
            rate(format!("{upstream}.max_error_rate"), t.max_error_rate)?;
            rate(
                format!("{upstream}.max_attestation_refusal_rate"),
                t.max_attestation_refusal_rate,
            )?;
            if t.ttft_p50_seconds > t.ttft_p95_seconds
                || t.latency_p50_seconds > t.latency_p95_seconds
            {
                return Err(invalid(format!(
                    "{upstream}: a p50 target is above its p95"
                )));
            }
        }
        let c = &self.comparison;
        for (name, v) in [
            ("ttft_p95_max_ratio", c.ttft_p95_max_ratio),
            ("latency_p95_max_ratio", c.latency_p95_max_ratio),
        ] {
            if !(v.is_finite() && v >= 1.0) {
                return Err(invalid(format!("comparison.{name} must be at least 1")));
            }
        }
        if !(c.tokens_per_second_p50_min_ratio > 0.0 && c.tokens_per_second_p50_min_ratio <= 1.0) {
            return Err(invalid(
                "comparison.tokens_per_second_p50_min_ratio must be above 0 and at most 1",
            ));
        }
        Ok(())
    }

    fn targets(&self, upstream: &str) -> Option<&Targets> {
        self.upstream.get(upstream)
    }
}

/// What one upstream did over a window or a benchmark run.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Summary {
    pub requests: u64,
    pub server_errors: u64,
    pub attestation_refusals: u64,
    pub ttft_p50: Option<f64>,
    pub ttft_p95: Option<f64>,
    pub latency_p50: Option<f64>,
    pub latency_p95: Option<f64>,
    pub tokens_per_second_p50: Option<f64>,
}

#[allow(clippy::cast_precision_loss)]
fn ratio(part: u64, whole: u64) -> Option<f64> {
    (whole > 0).then(|| part as f64 / whole as f64)
}

/// The nearest-rank `q` quantile of `values`, or `None` for none.
pub fn quantile(values: &[f64], q: f64) -> Option<f64> {
    let mut sorted: Vec<f64> = values.iter().copied().filter(|v| v.is_finite()).collect();
    sorted.sort_by(f64::total_cmp);
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    let rank = (q * sorted.len() as f64).ceil() as usize;
    sorted
        .get(rank.clamp(1, sorted.len().max(1)).saturating_sub(1))
        .copied()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    Fail,
    NoData,
}

impl Verdict {
    fn word(self) -> &'static str {
        match self {
            Verdict::Pass => "pass",
            Verdict::Fail => "FAIL",
            Verdict::NoData => "no data",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Check {
    /// `own`, `external`, or `own vs external`.
    pub scope: String,
    pub objective: &'static str,
    /// The target as printed, e.g. `<= 1.5s`.
    pub target: String,
    pub measured: Option<String>,
    pub verdict: Verdict,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Report {
    pub checks: Vec<Check>,
}

fn at_most(measured: Option<f64>, target: f64, enough: bool) -> Verdict {
    match measured {
        Some(m) if enough => {
            if m <= target {
                Verdict::Pass
            } else {
                Verdict::Fail
            }
        }
        _ => Verdict::NoData,
    }
}

fn at_least(measured: Option<f64>, target: f64, enough: bool) -> Verdict {
    match measured {
        Some(m) if enough => {
            if m >= target {
                Verdict::Pass
            } else {
                Verdict::Fail
            }
        }
        _ => Verdict::NoData,
    }
}

/// Every objective of `slo` against `summaries`, keyed by upstream (`own`, `external`).
pub fn evaluate(slo: &Slo, summaries: &BTreeMap<String, Summary>) -> Report {
    let empty = Summary::default();
    let mut checks = Vec::new();
    for upstream in [OWN, EXTERNAL] {
        let Some(t) = slo.targets(upstream) else {
            continue;
        };
        let s = summaries.get(upstream).unwrap_or(&empty);
        let enough = s.requests >= slo.min_requests;
        let mut push = |objective, target: String, measured: Option<String>, verdict| {
            checks.push(Check {
                scope: upstream.to_owned(),
                objective,
                target,
                measured,
                verdict,
            });
        };
        let secs = |v: Option<f64>| v.map(|v| format!("{v:.3}s"));
        for (objective, measured, target) in [
            ("ttft p50", s.ttft_p50, t.ttft_p50_seconds),
            ("ttft p95", s.ttft_p95, t.ttft_p95_seconds),
            ("latency p50", s.latency_p50, t.latency_p50_seconds),
            ("latency p95", s.latency_p95, t.latency_p95_seconds),
        ] {
            push(
                objective,
                format!("<= {target}s"),
                secs(measured),
                at_most(measured, target, enough),
            );
        }
        push(
            "tokens/s p50",
            format!(">= {}", t.min_tokens_per_second_p50),
            s.tokens_per_second_p50.map(|v| format!("{v:.1}")),
            at_least(s.tokens_per_second_p50, t.min_tokens_per_second_p50, enough),
        );
        for (objective, part, target) in [
            ("error rate", s.server_errors, t.max_error_rate),
            (
                "attestation refusal rate",
                s.attestation_refusals,
                t.max_attestation_refusal_rate,
            ),
        ] {
            let measured = ratio(part, s.requests);
            push(
                objective,
                format!("<= {target}"),
                measured.map(|v| format!("{v:.4}")),
                at_most(measured, target, enough),
            );
        }
    }

    let own = summaries.get(OWN).unwrap_or(&empty);
    let external = summaries.get(EXTERNAL).unwrap_or(&empty);
    let enough = own.requests >= slo.min_requests && external.requests >= slo.min_requests;
    let divided = |a: Option<f64>, b: Option<f64>| match (a, b) {
        (Some(a), Some(b)) if b > 0.0 => Some(a / b),
        _ => None,
    };
    let c = &slo.comparison;
    for (objective, measured, target, most) in [
        (
            "ttft p95, own/external",
            divided(own.ttft_p95, external.ttft_p95),
            c.ttft_p95_max_ratio,
            true,
        ),
        (
            "latency p95, own/external",
            divided(own.latency_p95, external.latency_p95),
            c.latency_p95_max_ratio,
            true,
        ),
        (
            "tokens/s p50, own/external",
            divided(own.tokens_per_second_p50, external.tokens_per_second_p50),
            c.tokens_per_second_p50_min_ratio,
            false,
        ),
    ] {
        checks.push(Check {
            scope: format!("{OWN} vs {EXTERNAL}"),
            objective,
            target: format!("{} {target}x", if most { "<=" } else { ">=" }),
            measured: measured.map(|v| format!("{v:.2}x")),
            verdict: if most {
                at_most(measured, target, enough)
            } else {
                at_least(measured, target, enough)
            },
        });
    }
    Report { checks }
}

impl Report {
    /// Every objective passed; no data is not a pass.
    pub fn passed(&self) -> bool {
        self.checks.iter().all(|c| c.verdict == Verdict::Pass)
    }

    pub fn render(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(
            out,
            "{:<16} {:<28} {:<12} {:<12} verdict",
            "scope", "objective", "target", "measured"
        );
        for c in &self.checks {
            let _ = writeln!(
                out,
                "{:<16} {:<28} {:<12} {:<12} {}",
                c.scope,
                c.objective,
                c.target,
                c.measured.as_deref().unwrap_or("-"),
                c.verdict.word()
            );
        }
        let count = |v: Verdict| self.checks.iter().filter(|c| c.verdict == v).count();
        let _ = writeln!(
            out,
            "SLO {}: {} passed, {} failed, {} without enough data",
            if self.passed() { "met" } else { "NOT met" },
            count(Verdict::Pass),
            count(Verdict::Fail),
            count(Verdict::NoData)
        );
        out
    }
}

/// `slo` as Prometheus recording and alert rules over the front's metrics, in the style of
/// alpha-infra's observability add-on (alerts named `Alpha…`).
pub fn prometheus_rules(slo: &Slo) -> String {
    let w = format!("{}m", slo.window_minutes);
    let for_ = format!("{}m", slo.alert_for_minutes);
    let requests = format!("upstream:alpha_inference_requests:increase{w}");
    let mut out = String::new();
    let _ = writeln!(
        out,
        "# Rendered from slo.toml by `alpha-inference-bench rules`; edit slo.toml and render again (a\n\
         # test fails while the two differ). Rates and quantiles over {w}, per upstream (own, external).\n\
         # Not loaded anywhere yet: no Prometheus scrapes alpha-inference's METRICS_PORT."
    );
    out.push_str("groups:\n- name: alpha-inference-slo\n  rules:\n");
    let record = |out: &mut String, name: &str, expr: &str| {
        let _ = writeln!(out, "  - record: {name}\n    expr: {expr}");
    };
    record(
        &mut out,
        &requests,
        &format!(
            "sum by (upstream) (increase(alpha_inference_request_duration_seconds_count[{w}]))"
        ),
    );
    for (q, label) in [("0.5", "p50"), ("0.95", "p95")] {
        record(
            &mut out,
            &format!("upstream:alpha_inference_ttft_seconds:{label}"),
            &format!(
                "histogram_quantile({q}, sum by (upstream, le) (rate(alpha_inference_ttft_seconds_bucket[{w}])))"
            ),
        );
        record(
            &mut out,
            &format!("upstream:alpha_inference_request_duration_seconds:{label}"),
            &format!(
                "histogram_quantile({q}, sum by (upstream, le) (rate(alpha_inference_request_duration_seconds_bucket{{status_class=\"2xx\"}}[{w}])))"
            ),
        );
    }
    record(
        &mut out,
        "upstream:alpha_inference_output_tokens_per_second:p50",
        &format!(
            "histogram_quantile(0.5, sum by (upstream, le) (rate(alpha_inference_output_tokens_per_second_bucket[{w}])))"
        ),
    );
    record(
        &mut out,
        "upstream:alpha_inference_error:ratio",
        &format!(
            "sum by (upstream) (rate(alpha_inference_request_duration_seconds_count{{status_class=\"5xx\"}}[{w}])) / sum by (upstream) (rate(alpha_inference_request_duration_seconds_count[{w}]))"
        ),
    );
    record(
        &mut out,
        "upstream:alpha_inference_attestation_refusal:ratio",
        &format!(
            "sum by (upstream) (rate(alpha_inference_errors_total{{code=\"upstream_unverified\"}}[{w}])) / sum by (upstream) (rate(alpha_inference_request_duration_seconds_count[{w}]))"
        ),
    );

    out.push_str("- name: alpha-inference-slo-alerts\n  rules:\n");
    // An alert per upstream also carries its upstream as a label, so the two rules of one name
    // differ.
    let alert = |out: &mut String,
                 name: &str,
                 upstream: Option<&str>,
                 expr: &str,
                 severity: &str,
                 summary: &str| {
        let _ = writeln!(
            out,
            "  - alert: {name}\n    expr: {expr}\n    for: {for_}\n    labels:\n      severity: {severity}"
        );
        if let Some(upstream) = upstream {
            let _ = writeln!(out, "      upstream: {upstream}");
        }
        let _ = writeln!(out, "    annotations:\n      summary: \"{summary}\"");
    };
    let enough = |upstream: &str| {
        format!(
            "{requests}{{upstream=\"{upstream}\"}} >= {}",
            slo.min_requests
        )
    };
    for upstream in [OWN, EXTERNAL] {
        let Some(t) = slo.targets(upstream) else {
            continue;
        };
        let guarded = |series: &str, op: &str, target: f64| {
            format!(
                "{series}{{upstream=\"{upstream}\"}} {op} {target} and on (upstream) {}",
                enough(upstream)
            )
        };
        for (name, series, what, target) in [
            (
                "AlphaInferenceTTFTP50High",
                "upstream:alpha_inference_ttft_seconds:p50",
                "p50 time to first token",
                t.ttft_p50_seconds,
            ),
            (
                "AlphaInferenceTTFTP95High",
                "upstream:alpha_inference_ttft_seconds:p95",
                "p95 time to first token",
                t.ttft_p95_seconds,
            ),
            (
                "AlphaInferenceLatencyP50High",
                "upstream:alpha_inference_request_duration_seconds:p50",
                "p50 completion latency",
                t.latency_p50_seconds,
            ),
            (
                "AlphaInferenceLatencyP95High",
                "upstream:alpha_inference_request_duration_seconds:p95",
                "p95 completion latency",
                t.latency_p95_seconds,
            ),
        ] {
            alert(
                &mut out,
                name,
                Some(upstream),
                &guarded(series, ">", target),
                "warning",
                &format!("{upstream}: {what} is above the SLO's {target}s over {w}"),
            );
        }
        alert(
            &mut out,
            "AlphaInferenceTokensPerSecondLow",
            Some(upstream),
            &guarded(
                "upstream:alpha_inference_output_tokens_per_second:p50",
                "<",
                t.min_tokens_per_second_p50,
            ),
            "warning",
            &format!(
                "{upstream}: median output tokens/s is below the SLO's {} over {w}",
                t.min_tokens_per_second_p50
            ),
        );
        alert(
            &mut out,
            "AlphaInferenceErrorRateHigh",
            Some(upstream),
            &guarded(
                "upstream:alpha_inference_error:ratio",
                ">",
                t.max_error_rate,
            ),
            "critical",
            &format!(
                "{upstream}: server errors are above the SLO's {} of requests over {w}",
                t.max_error_rate
            ),
        );
        alert(
            &mut out,
            "AlphaInferenceAttestationRefusalsHigh",
            Some(upstream),
            &guarded(
                "upstream:alpha_inference_attestation_refusal:ratio",
                ">",
                t.max_attestation_refusal_rate,
            ),
            "critical",
            &format!(
                "{upstream}: requests refused for a failed attestation check are above the SLO's {} over {w}",
                t.max_attestation_refusal_rate
            ),
        );
    }
    let c = &slo.comparison;
    let both = format!("and on () {} and on () {}", enough(OWN), enough(EXTERNAL));
    for (name, series, op, ratio, what) in [
        (
            "AlphaInferenceOwnTTFTBehindExternal",
            "upstream:alpha_inference_ttft_seconds:p95",
            ">",
            c.ttft_p95_max_ratio,
            "p95 time to first token is more than",
        ),
        (
            "AlphaInferenceOwnLatencyBehindExternal",
            "upstream:alpha_inference_request_duration_seconds:p95",
            ">",
            c.latency_p95_max_ratio,
            "p95 completion latency is more than",
        ),
        (
            "AlphaInferenceOwnThroughputBehindExternal",
            "upstream:alpha_inference_output_tokens_per_second:p50",
            "<",
            c.tokens_per_second_p50_min_ratio,
            "median output tokens/s is less than",
        ),
    ] {
        alert(
            &mut out,
            name,
            None,
            &format!(
                "{series}{{upstream=\"{OWN}\"}} {op} ignoring (upstream) {ratio} * {series}{{upstream=\"{EXTERNAL}\"}} {both}"
            ),
            "warning",
            &format!("own model servers: {what} {ratio}x the external provider's over {w}"),
        );
    }
    alert(
        &mut out,
        "AlphaInferenceMetricsAbsent",
        None,
        "absent(alpha_inference_attestation_checks_total)",
        "warning",
        "no alpha-inference metrics, so none of its SLO alerts can fire",
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_checked_in_slo_parses() {
        let slo = Slo::parse(DEFAULT).unwrap();
        assert_eq!(slo.upstream.len(), 2);
    }

    #[test]
    fn the_checked_in_rules_are_rendered_from_the_checked_in_slo() {
        let rendered = prometheus_rules(&Slo::parse(DEFAULT).unwrap());
        assert_eq!(
            rendered,
            include_str!("../slo/rules.yaml"),
            "render again: cargo run -p alpha-inference --bin alpha-inference-bench -- rules > services/alpha-inference/slo/rules.yaml"
        );
    }

    fn edited(from: &str, to: &str) -> Result<Slo, Error> {
        assert!(DEFAULT.contains(from), "{from}");
        Slo::parse(&DEFAULT.replacen(from, to, 1))
    }

    #[test]
    fn an_slo_that_cannot_be_evaluated_is_refused() {
        for (from, to, names) in [
            ("[upstream.external]", "[upstream.redpill]", "upstream"),
            (
                "window_minutes = 30",
                "window_minutes = 0",
                "window_minutes",
            ),
            ("min_requests = 20", "min_requests = 0", "min_requests"),
            (
                "ttft_p50_seconds = 0.5",
                "ttft_p50_seconds = -1.0",
                "ttft_p50",
            ),
            (
                "ttft_p50_seconds = 0.5",
                "ttft_p50_seconds = nan",
                "ttft_p50",
            ),
            ("ttft_p50_seconds = 0.5", "ttft_p50_seconds = 9.0", "p50"),
            (
                "max_error_rate = 0.01",
                "max_error_rate = 2.0",
                "max_error_rate",
            ),
            (
                "ttft_p95_max_ratio = 1.25",
                "ttft_p95_max_ratio = 0.5",
                "ttft_p95_max_ratio",
            ),
            (
                "tokens_per_second_p50_min_ratio = 0.8",
                "tokens_per_second_p50_min_ratio = 1.5",
                "tokens_per_second_p50_min_ratio",
            ),
            ("min_requests = 20", "min_requests = 20\nextra = 1", "extra"),
        ] {
            let err = edited(from, to).unwrap_err().to_string();
            assert!(err.contains(names), "{to}: {err}");
        }
    }

    fn summary(ttft: f64, latency: f64, tps: f64, requests: u64) -> Summary {
        Summary {
            requests,
            server_errors: 0,
            attestation_refusals: 0,
            ttft_p50: Some(ttft),
            ttft_p95: Some(ttft),
            latency_p50: Some(latency),
            latency_p95: Some(latency),
            tokens_per_second_p50: Some(tps),
        }
    }

    fn verdict(report: &Report, scope: &str, objective: &str) -> Verdict {
        report
            .checks
            .iter()
            .find(|c| c.scope == scope && c.objective == objective)
            .unwrap()
            .verdict
    }

    #[test]
    fn every_objective_passes_only_on_enough_data_within_its_target() {
        let slo = Slo::parse(DEFAULT).unwrap();
        let both = BTreeMap::from([
            (OWN.to_owned(), summary(0.4, 5.0, 60.0, 100)),
            (EXTERNAL.to_owned(), summary(0.4, 5.0, 60.0, 100)),
        ]);
        let report = evaluate(&slo, &both);
        assert!(report.passed(), "{}", report.render());

        let mut slow = both.clone();
        slow.insert(OWN.to_owned(), summary(1.0, 5.0, 50.0, 100));
        let report = evaluate(&slo, &slow);
        assert_eq!(verdict(&report, OWN, "ttft p50"), Verdict::Fail);
        assert_eq!(verdict(&report, OWN, "ttft p95"), Verdict::Pass);
        assert_eq!(
            verdict(&report, "own vs external", "ttft p95, own/external"),
            Verdict::Fail
        );
        assert_eq!(
            verdict(&report, "own vs external", "tokens/s p50, own/external"),
            Verdict::Pass
        );
        assert!(!report.passed());
        assert!(report.render().contains("SLO NOT met"));

        let mut few = both.clone();
        few.insert(OWN.to_owned(), summary(0.4, 5.0, 60.0, 3));
        let report = evaluate(&slo, &few);
        assert_eq!(verdict(&report, OWN, "ttft p50"), Verdict::NoData);
        assert_eq!(
            verdict(&report, "own vs external", "ttft p95, own/external"),
            Verdict::NoData
        );
        assert_eq!(verdict(&report, EXTERNAL, "ttft p50"), Verdict::Pass);
        assert!(!report.passed());

        let report = evaluate(&slo, &BTreeMap::new());
        assert!(report.checks.iter().all(|c| c.verdict == Verdict::NoData));
    }

    #[test]
    fn rates_count_server_errors_and_attestation_refusals_over_requests() {
        let slo = Slo::parse(DEFAULT).unwrap();
        let mut own = summary(0.4, 5.0, 60.0, 100);
        own.server_errors = 2;
        own.attestation_refusals = 2;
        let report = evaluate(
            &slo,
            &BTreeMap::from([
                (OWN.to_owned(), own),
                (EXTERNAL.to_owned(), summary(0.4, 5.0, 60.0, 100)),
            ]),
        );
        assert_eq!(verdict(&report, OWN, "error rate"), Verdict::Fail);
        assert_eq!(
            verdict(&report, OWN, "attestation refusal rate"),
            Verdict::Fail
        );
        assert_eq!(verdict(&report, EXTERNAL, "error rate"), Verdict::Pass);
    }

    #[test]
    fn quantiles_are_nearest_rank() {
        let values: Vec<f64> = (1..=20).map(f64::from).collect();
        assert_eq!(quantile(&values, 0.5), Some(10.0));
        assert_eq!(quantile(&values, 0.95), Some(19.0));
        assert_eq!(quantile(&[3.0], 0.95), Some(3.0));
        assert_eq!(quantile(&[], 0.5), None);
    }
}
