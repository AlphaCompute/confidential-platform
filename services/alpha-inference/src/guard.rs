//! Moderation at the front, for every model: before a member's request reaches any upstream, the
//! new turn's text is judged by `alpha-guard` under this front's own measured `GUARD_POLICY`;
//! after the upstream answers, the whole completion is held, its text, reasoning and tool calls
//! judged together with the turn, and only an allowed one is released, byte for byte. Anything
//! but a clear `allow` — a block, an error, a timeout, a judge that cannot be reached — releases
//! nothing. The one exemption is `alpha-guard`'s own judging calls, which present the separate
//! `judge-bearer` and may only name a model in `JUDGE_MODELS`; without it, judging a completion
//! would itself need judging.
//!
//! The judge is dialled as every caller dials it: this Instance's own leaf as the client
//! certificate, the connection pinned to the KMS CA and one of `GUARD_REVISIONS` inside the
//! handshake. The leaf is renewed hourly, so the client is rebuilt on every refresh.
//!
//! Log lines carry the phase, the outcome, the model and the elapsed time — never the text.

use std::time::{Duration, Instant};

use alpha_client::runtime::RuntimeIdentity;
use alpha_client::tls::{Identity, Pin};
use alpha_core::ComposeHash;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::Error;

/// What `alpha-guard` accepts for `user` and `response` together.
pub const CONTENT_LIMIT: usize = 128 * 1024;
/// A turn's text is judged in windows of this size...
const INPUT_WINDOW: usize = 120 * 1024;
/// ...and a completion in windows of this size, each with the end of the turn as context.
const OUTPUT_WINDOW: usize = 104 * 1024;
const CONTEXT_TAIL: usize = 16 * 1024;
/// More windows than this in one phase is refused rather than judged for minutes.
const MAX_WINDOWS: usize = 16;
const MAX_CATEGORIES: usize = 32;
const MAX_CATEGORY_LEN: usize = 512;
const JUDGE_TIMEOUT: Duration = Duration::from_secs(60);

/// This front's policy, sent with every check; changing it is a new Revision of the front.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub model: String,
    pub categories: Vec<String>,
}

/// The measured moderation settings. All four are required: there is no Revision of the front
/// that serves a member without a judge.
#[derive(Clone, Debug)]
pub struct GuardConfig {
    /// `alpha-guard`'s origin, `https://host[:port]`, no path.
    pub url: String,
    pub revisions: Vec<ComposeHash>,
    pub policy: Policy,
    /// The models `judge-bearer` may name; `policy.model` is one of them.
    pub judge_models: Vec<String>,
}

fn origin(name: &str, raw: &str) -> Result<String, Error> {
    let url = reqwest::Url::parse(raw).map_err(|e| Error::internal(format!("{name}: {e}")))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || url.path() != "/"
        || url.query().is_some()
        || !url.username().is_empty()
    {
        return Err(Error::internal(format!(
            "{name} must be an https origin without a path"
        )));
    }
    Ok(url.as_str().trim_end_matches('/').to_owned())
}

fn list(raw: Option<String>) -> Vec<String> {
    raw.unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

impl GuardConfig {
    /// `models` is the front's whole allowlist: every judge model must be one of them.
    pub fn build(get: &impl Fn(&str) -> Option<String>, models: &[String]) -> Result<Self, Error> {
        let url = origin(
            "GUARD_URL",
            &get("GUARD_URL").ok_or_else(|| Error::internal("GUARD_URL is required"))?,
        )?;
        let revisions = list(get("GUARD_REVISIONS"))
            .iter()
            .map(|s| {
                s.parse::<ComposeHash>()
                    .map_err(|_| Error::internal(format!("GUARD_REVISIONS: '{s}' is not valid")))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if revisions.is_empty() {
            return Err(Error::internal("GUARD_REVISIONS names nothing"));
        }
        let policy: Policy = serde_json::from_str(
            &get("GUARD_POLICY").ok_or_else(|| Error::internal("GUARD_POLICY is required"))?,
        )
        .map_err(|e| Error::internal(format!("GUARD_POLICY: {e}")))?;
        if policy.model.trim().is_empty()
            || policy.categories.is_empty()
            || policy.categories.len() > MAX_CATEGORIES
            || policy.categories.iter().any(|c| {
                c.trim().is_empty() || c.len() > MAX_CATEGORY_LEN || c.contains(['\n', '\r', '<'])
            })
        {
            return Err(Error::internal(
                "GUARD_POLICY needs a model and 1 to 32 one-line categories without '<'",
            ));
        }
        let judge_models = list(get("JUDGE_MODELS"));
        if judge_models.is_empty() {
            return Err(Error::internal("JUDGE_MODELS names nothing"));
        }
        if let Some(stray) = judge_models.iter().find(|m| !models.contains(m)) {
            return Err(Error::internal(format!(
                "JUDGE_MODELS names {stray}, which is not in MODELS"
            )));
        }
        if !judge_models.contains(&policy.model) {
            return Err(Error::internal(
                "GUARD_POLICY's model must be one of JUDGE_MODELS",
            ));
        }
        Ok(Self {
            url,
            revisions,
            policy,
            judge_models,
        })
    }
}

/// Why a member's request or its completion was not released.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    Blocked,
    Unavailable,
    TooLarge,
}

impl From<Refusal> for Error {
    fn from(refusal: Refusal) -> Self {
        match refusal {
            Refusal::Blocked => Error::ContentBlocked,
            Refusal::Unavailable => Error::ModerationUnavailable,
            Refusal::TooLarge => Error::ContentTooLarge,
        }
    }
}

enum Judge {
    Remote {
        url: String,
        revisions: Vec<ComposeHash>,
        kms_ca: CertificateDer<'static>,
        client: parking_lot::RwLock<reqwest::Client>,
    },
    /// Tests only: every turn check answers `input`, every completion check `output`.
    #[cfg(test)]
    Fixed {
        input: Result<(), Refusal>,
        output: Result<(), Refusal>,
    },
}

pub struct Guard {
    policy: Policy,
    judge: Judge,
}

/// This Instance's chain and key as a client identity: what the judge reads the caller's App
/// from.
fn client_identity(identity: &RuntimeIdentity) -> Result<Identity, Error> {
    let chain: Vec<Vec<u8>> = CertificateDer::pem_slice_iter(identity.certificate_chain.as_bytes())
        .map(|c| c.map(|c| c.to_vec()))
        .collect::<Result<_, _>>()
        .map_err(|e| Error::internal(format!("certificate chain: {e}")))?;
    Ok(Identity {
        chain,
        pkcs8: identity.tls_private_key.to_vec(),
    })
}

fn judge_client(
    kms_ca: &CertificateDer<'static>,
    revisions: &[ComposeHash],
    identity: &RuntimeIdentity,
) -> Result<reqwest::Client, Error> {
    let tls = alpha_client::tls::client_config(
        Some(Pin::CaAndInstanceRevisions(
            kms_ca.clone(),
            revisions.to_vec(),
        )),
        Some(client_identity(identity)?),
        alpha_client::system_time_provider(),
    )
    .map_err(|e| Error::internal(format!("guard tls: {e}")))?;
    reqwest::Client::builder()
        .tls_backend_preconfigured(tls)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(JUDGE_TIMEOUT)
        .build()
        .map_err(|e| Error::internal(format!("guard client: {e}")))
}

impl Guard {
    pub fn new(
        config: &GuardConfig,
        kms_ca: CertificateDer<'static>,
        identity: &RuntimeIdentity,
    ) -> Result<Self, Error> {
        let client = judge_client(&kms_ca, &config.revisions, identity)?;
        Ok(Self {
            policy: config.policy.clone(),
            judge: Judge::Remote {
                url: config.url.clone(),
                revisions: config.revisions.clone(),
                kms_ca,
                client: parking_lot::RwLock::new(client),
            },
        })
    }

    #[cfg(test)]
    pub(crate) fn fixed(input: Result<(), Refusal>, output: Result<(), Refusal>) -> Self {
        Self {
            policy: Policy {
                model: "guard".into(),
                categories: vec!["Violence".into()],
            },
            judge: Judge::Fixed { input, output },
        }
    }

    /// Presents the renewed leaf from the next check on.
    pub fn renew(&self, identity: &RuntimeIdentity) -> Result<(), Error> {
        match &self.judge {
            Judge::Remote {
                revisions,
                kms_ca,
                client,
                ..
            } => {
                *client.write() = judge_client(kms_ca, revisions, identity)?;
                Ok(())
            }
            #[cfg(test)]
            Judge::Fixed { .. } => Ok(()),
        }
    }

    async fn check(&self, user: &str, response: Option<&str>) -> Result<(), Refusal> {
        let (url, client) = match &self.judge {
            Judge::Remote { url, client, .. } => (url, client.read().clone()),
            #[cfg(test)]
            Judge::Fixed { input, output } => {
                return if response.is_some() { *output } else { *input };
            }
        };
        let mut body = json!({ "policy": self.policy, "user": user });
        if let (Some(response), Some(map)) = (response, body.as_object_mut()) {
            map.insert("response".into(), Value::String(response.to_owned()));
        }
        let answer = client
            .post(format!("{url}/v1/check"))
            .json(&body)
            .send()
            .await
            .map_err(|_| Refusal::Unavailable)?;
        if !answer.status().is_success() {
            return Err(Refusal::Unavailable);
        }
        let verdict: Value = answer.json().await.map_err(|_| Refusal::Unavailable)?;
        match verdict.get("verdict").and_then(Value::as_str) {
            Some("allow") => Ok(()),
            Some("block") => Err(Refusal::Blocked),
            _ => Err(Refusal::Unavailable),
        }
    }

    /// Judges the new turn before anything is sent upstream.
    pub async fn check_input(&self, model: &str, input: &str) -> Result<(), Refusal> {
        let started = Instant::now();
        let outcome = self.check_input_windows(input).await;
        log("input", model, &outcome, started);
        outcome
    }

    async fn check_input_windows(&self, input: &str) -> Result<(), Refusal> {
        if input.is_empty() {
            return Ok(());
        }
        let windows = windows(input, INPUT_WINDOW);
        if windows.len() > MAX_WINDOWS {
            return Err(Refusal::TooLarge);
        }
        for window in windows {
            self.check(window, None).await?;
        }
        Ok(())
    }

    /// Judges a completion, with the end of the turn as context, before it is released.
    pub async fn check_output(
        &self,
        model: &str,
        input: &str,
        output: &str,
    ) -> Result<(), Refusal> {
        let started = Instant::now();
        let outcome = self.check_output_windows(input, output).await;
        log("output", model, &outcome, started);
        outcome
    }

    async fn check_output_windows(&self, input: &str, output: &str) -> Result<(), Refusal> {
        if output.is_empty() {
            return Ok(());
        }
        let context = tail(input, CONTEXT_TAIL);
        let windows = windows(output, OUTPUT_WINDOW);
        if windows.len() > MAX_WINDOWS {
            return Err(Refusal::TooLarge);
        }
        for window in windows {
            self.check(context, Some(window)).await?;
        }
        Ok(())
    }
}

fn log(phase: &str, model: &str, outcome: &Result<(), Refusal>, started: Instant) {
    let outcome = match outcome {
        Ok(()) => "allow",
        Err(Refusal::Blocked) => "block",
        Err(Refusal::Unavailable) => "unavailable",
        Err(Refusal::TooLarge) => "too_large",
    };
    eprintln!(
        "alpha-inference: guard phase={phase} outcome={outcome} model={model} elapsed_ms={}",
        started.elapsed().as_millis()
    );
}

/// `text` cut into pieces of at most `max` bytes, each on a char boundary.
pub fn windows(text: &str, max: usize) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = text;
    while !rest.is_empty() {
        let mut cut = rest.len().min(max);
        while cut > 0 && !rest.is_char_boundary(cut) {
            cut = cut.saturating_sub(1);
        }
        if cut == 0 {
            // `max` is smaller than one char: take the char whole rather than loop.
            cut = rest.chars().next().map_or(rest.len(), char::len_utf8);
        }
        let (head, tail) = rest.split_at(cut);
        out.push(head);
        rest = tail;
    }
    out
}

/// The last `max` bytes of `text`, on a char boundary.
fn tail(text: &str, max: usize) -> &str {
    let mut start = text.len().saturating_sub(max);
    while start < text.len() && !text.is_char_boundary(start) {
        start = start.saturating_add(1);
    }
    text.get(start..).unwrap_or_default()
}

/// The text of a message's `content`: a string, or the `text` of its text parts.
fn content_text(content: Option<&Value>, out: &mut String) {
    match content {
        Some(Value::String(text)) => push(out, text),
        Some(Value::Array(parts)) => {
            for part in parts {
                if let Some(text) = part.get("text").and_then(Value::as_str) {
                    push(out, text);
                }
            }
        }
        _ => {}
    }
}

fn push(out: &mut String, text: &str) {
    if text.is_empty() {
        return;
    }
    if !out.is_empty() {
        out.push('\n');
    }
    out.push_str(text);
}

/// The new turn: every message after the last assistant message (all of them on the first
/// turn), each as `role: text`. Image and audio parts are not judged here.
pub fn turn_input(request: &Value) -> String {
    let messages = request
        .get("messages")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let start = messages
        .iter()
        .rposition(|m| m.get("role").and_then(Value::as_str) == Some("assistant"))
        .map_or(0, |i| i.saturating_add(1));
    let mut out = String::new();
    for message in messages.iter().skip(start) {
        let role = message
            .get("role")
            .and_then(Value::as_str)
            .unwrap_or("user");
        let mut text = String::new();
        content_text(message.get("content"), &mut text);
        if !text.is_empty() {
            push(&mut out, &format!("{role}: {text}"));
        }
    }
    out
}

/// What a choice's `message` (or a stream chunk's `delta`) says: content, reasoning and tool
/// calls, appended in order.
fn message_text(message: &Value, out: &mut String) {
    content_text(message.get("content"), out);
    for field in ["reasoning_content", "reasoning"] {
        if let Some(text) = message.get(field).and_then(Value::as_str) {
            push(out, text);
        }
    }
    if let Some(calls) = message.get("tool_calls").and_then(Value::as_array) {
        for call in calls {
            if let Some(function) = call.get("function") {
                for field in ["name", "arguments"] {
                    if let Some(text) = function.get(field).and_then(Value::as_str) {
                        push(out, text);
                    }
                }
            }
        }
    }
}

fn choices_text(chunk: &Value, key: &str, out: &mut String) {
    if let Some(choices) = chunk.get("choices").and_then(Value::as_array) {
        for choice in choices {
            if let Some(message) = choice.get(key) {
                message_text(message, out);
            }
        }
    }
}

/// Everything a completion says, from a JSON body or an event stream. A stream's deltas are
/// joined without separators, as the model wrote them.
pub fn completion_text(body: &[u8]) -> String {
    let mut out = String::new();
    if let Ok(parsed) = serde_json::from_slice::<Value>(body) {
        choices_text(&parsed, "message", &mut out);
        return out;
    }
    let text = String::from_utf8_lossy(body);
    let mut streamed = String::new();
    for line in text.lines() {
        let Some(data) = line.strip_prefix("data:").map(str::trim) else {
            continue;
        };
        if data == "[DONE]" {
            continue;
        }
        if let Ok(chunk) = serde_json::from_str::<Value>(data) {
            let mut piece = String::new();
            choices_text(&chunk, "delta", &mut piece);
            streamed.push_str(&piece);
        }
    }
    push(&mut out, &streamed);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(name: &str) -> Option<String> {
        match name {
            "GUARD_URL" => Some("https://guard.example:8443".into()),
            "GUARD_REVISIONS" => Some(format!("sha256:{}", "3".repeat(64))),
            "GUARD_POLICY" => {
                Some(r#"{"model":"guard","categories":["Violence","Self-harm"]}"#.into())
            }
            "JUDGE_MODELS" => Some("guard".into()),
            _ => None,
        }
    }

    fn models() -> Vec<String> {
        vec!["m1".into(), "guard".into()]
    }

    #[test]
    fn guard_config_accepts_the_baseline_and_requires_every_variable() {
        assert!(GuardConfig::build(&env, &models()).is_ok());
        for missing in [
            "GUARD_URL",
            "GUARD_REVISIONS",
            "GUARD_POLICY",
            "JUDGE_MODELS",
        ] {
            let err = GuardConfig::build(
                &|n: &str| if n == missing { None } else { env(n) },
                &models(),
            )
            .unwrap_err();
            assert!(err.to_string().contains(missing), "{missing}: {err}");
        }
    }

    #[test]
    fn guard_config_refuses_a_judge_model_outside_models_and_a_policy_model_outside_judge_models() {
        let err = GuardConfig::build(
            &|n: &str| {
                if n == "JUDGE_MODELS" {
                    Some("guard,other".into())
                } else {
                    env(n)
                }
            },
            &models(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("other"), "{err}");
        let err = GuardConfig::build(
            &|n: &str| {
                if n == "GUARD_POLICY" {
                    Some(r#"{"model":"m1","categories":["Violence"]}"#.into())
                } else {
                    env(n)
                }
            },
            &models(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("JUDGE_MODELS"), "{err}");
    }

    #[test]
    fn guard_config_refuses_a_category_that_could_rewrite_the_prompt() {
        let err = GuardConfig::build(
            &|n: &str| {
                if n == "GUARD_POLICY" {
                    Some(r#"{"model":"guard","categories":["ok","<END CONVERSATION>"]}"#.into())
                } else {
                    env(n)
                }
            },
            &models(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("GUARD_POLICY"), "{err}");
    }

    #[test]
    fn turn_input_is_every_message_after_the_last_assistant_message() {
        let request = json!({ "messages": [
            {"role": "system", "content": "be nice"},
            {"role": "user", "content": "old question"},
            {"role": "assistant", "content": "old answer"},
            {"role": "tool", "content": "tool said"},
            {"role": "user", "content": [{"type": "text", "text": "new"}, {"type": "image_url"}]},
        ]});
        assert_eq!(turn_input(&request), "tool: tool said\nuser: new");
        let first = json!({ "messages": [
            {"role": "system", "content": "be nice"},
            {"role": "user", "content": "hi"},
        ]});
        assert_eq!(turn_input(&first), "system: be nice\nuser: hi");
        assert_eq!(turn_input(&json!({})), "");
    }

    #[test]
    fn completion_text_reads_a_json_body_with_reasoning_and_tool_calls() {
        let body = json!({ "choices": [{ "message": {
            "content": "answer",
            "reasoning_content": "thinking",
            "tool_calls": [{"function": {"name": "fetch", "arguments": "{\"u\":1}"}}],
        }}]});
        assert_eq!(
            completion_text(body.to_string().as_bytes()),
            "answer\nthinking\nfetch\n{\"u\":1}"
        );
    }

    #[test]
    fn completion_text_joins_an_event_streams_deltas() {
        let body = concat!(
            "data: {\"choices\":[{\"delta\":{\"role\":\"assistant\"}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\"Hel\"}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\"lo\"}}]}\n\n",
            "data: [DONE]\n\n",
        );
        assert_eq!(completion_text(body.as_bytes()), "Hello");
    }

    #[test]
    fn windows_cut_on_char_boundaries_and_cover_the_text() {
        let text = "aé".repeat(10);
        let pieces = windows(&text, 4);
        assert_eq!(pieces.concat(), text);
        assert!(pieces.iter().all(|p| p.len() <= 4));
        assert_eq!(windows("", 4), Vec::<&str>::new());
        assert_eq!(windows("é", 1), vec!["é"]);
        assert_eq!(tail("abcé", 2), "é");
    }

    #[tokio::test]
    async fn an_oversized_turn_is_refused_without_a_check() {
        let guard = Guard::fixed(Ok(()), Ok(()));
        let input = "x".repeat(INPUT_WINDOW * (MAX_WINDOWS + 1));
        assert_eq!(
            guard.check_input("m1", &input).await,
            Err(Refusal::TooLarge)
        );
        assert!(
            INPUT_WINDOW <= CONTENT_LIMIT
                && OUTPUT_WINDOW.saturating_add(CONTEXT_TAIL) <= CONTENT_LIMIT
        );
    }
}
