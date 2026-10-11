//! Moderation at the front, for every model: before a member's request reaches any upstream, the
//! whole prompt the model will read — every message of every role, the history the caller sent
//! included, and the tool definitions — is judged by `alpha-guard` under this front's own
//! measured `GUARD_POLICY`; after the upstream answers, the whole completion is held, its text,
//! reasoning and tool calls judged together with the end of the prompt, and only an allowed one
//! is released, byte for byte. Anything but a clear `allow` — a block, an error, a timeout, a
//! judge that cannot be reached, a request or completion the front cannot read as text —
//! releases nothing. The one exemption is `alpha-guard`'s own judging calls, which present the
//! separate `judge-bearer` and may only name a model in `JUDGE_MODELS`; without it, judging a
//! completion would itself need judging.
//!
//! A request the judge cannot read is refused rather than passed: one whose last message is the
//! assistant's (the model would continue it, not answer it), one with image, audio or other
//! non-text parts, one that brings its own chat template or asks for log probabilities
//! (alternative tokens nobody judged), and one with no text at all. The measured `GUARD_ALLOW`
//! may admit the first two.
//!
//! The judge is dialled as every caller dials it: this Instance's own leaf as the client
//! certificate, the connection pinned to the KMS CA and one of `GUARD_REVISIONS` inside the
//! handshake. The leaf is renewed hourly, so the client is rebuilt on every refresh. The judge
//! pins this front back by App, not by Revision: this front's Revision names the judge's, so the
//! judge's cannot name this front's.
//!
//! Log lines carry the phase, the outcome, the model and the elapsed time — never the text.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use alpha_client::runtime::RuntimeIdentity;
use alpha_client::tls::{Identity, Pin};
use alpha_core::ComposeHash;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::Error;

/// What `alpha-guard` accepts for `user` and `response` together.
pub const CONTENT_LIMIT: usize = 128 * 1024;
/// A prompt's text is judged in windows of this size...
const INPUT_WINDOW: usize = 120 * 1024;
/// ...and a completion in windows of this size, each with the end of the prompt as context.
const OUTPUT_WINDOW: usize = 104 * 1024;
const CONTEXT_TAIL: usize = 16 * 1024;
/// More windows than this in one phase is refused rather than judged for minutes.
const MAX_WINDOWS: usize = 16;
const MAX_CATEGORIES: usize = 32;
const MAX_CATEGORY_LEN: usize = 512;
const JUDGE_TIMEOUT: Duration = Duration::from_secs(60);
/// One phase, every window of it, gets at most this long; then nothing is released.
const JUDGE_PHASE_TIMEOUT: Duration = Duration::from_secs(180);
/// A prompt window the judge allowed is not asked about again for this long: a conversation's
/// earlier windows are the same text on every turn, so only what changed goes to the judge.
const ALLOWED_TTL: Duration = Duration::from_secs(600);
const ALLOWED_CAP: usize = 4096;

/// This front's policy, sent with every check; changing it is a new Revision of the front.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub model: String,
    pub categories: Vec<String>,
}

/// What a member's request may carry that the judge cannot read; each is refused unless the
/// measured `GUARD_ALLOW` names it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Allow {
    /// `assistant_prefill`: a last message from the assistant, which the model continues rather
    /// than answers. Its text is judged with the rest.
    pub assistant_prefill: bool,
    /// `non_text_parts`: image, audio, file and other non-text content parts. Only their `text`,
    /// if any, is judged; what the image or sound says is not.
    pub non_text_parts: bool,
}

impl Allow {
    fn parse(raw: Option<String>) -> Result<Self, Error> {
        let mut allow = Allow::default();
        for item in list(raw) {
            match item.as_str() {
                "assistant_prefill" => allow.assistant_prefill = true,
                "non_text_parts" => allow.non_text_parts = true,
                other => {
                    return Err(Error::internal(format!(
                        "GUARD_ALLOW: '{other}' is not assistant_prefill or non_text_parts"
                    )));
                }
            }
        }
        Ok(allow)
    }
}

/// The measured moderation settings. The first four are required: there is no Revision of the
/// front that serves a member without a judge.
#[derive(Clone, Debug)]
pub struct GuardConfig {
    /// `alpha-guard`'s origin, `https://host[:port]`, no path.
    pub url: String,
    pub revisions: Vec<ComposeHash>,
    pub policy: Policy,
    /// The models `judge-bearer` may name; `policy.model` is one of them.
    pub judge_models: Vec<String>,
    /// `GUARD_ALLOW`, optional: what a request may carry that the judge cannot read.
    pub allow: Allow,
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
        let allow = Allow::parse(get("GUARD_ALLOW"))?;
        Ok(Self {
            url,
            revisions,
            policy,
            judge_models,
            allow,
        })
    }
}

/// Why a member's request or its completion was not released.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    Blocked,
    Unavailable,
    TooLarge,
    /// The request carries something the judge cannot read and the policy does not admit.
    Unjudgeable,
}

impl From<Refusal> for Error {
    fn from(refusal: Refusal) -> Self {
        match refusal {
            Refusal::Blocked => Error::ContentBlocked,
            Refusal::Unavailable => Error::ModerationUnavailable,
            Refusal::TooLarge => Error::ContentTooLarge,
            Refusal::Unjudgeable => Error::ContentUnjudgeable,
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
    /// Tests only: every prompt check answers `input`, every completion check `output`, and
    /// every check is recorded as `(user, response)`.
    #[cfg(test)]
    Fixed {
        input: Result<(), Refusal>,
        output: Result<(), Refusal>,
        seen: parking_lot::Mutex<Vec<(String, Option<String>)>>,
    },
}

pub struct Guard {
    policy: Policy,
    allow: Allow,
    judge: Judge,
    /// Prompt windows the judge allowed, by SHA-256, with when.
    allowed: parking_lot::Mutex<HashMap<[u8; 32], Instant>>,
}

/// This Instance's chain and key as a client identity: what the judge, and a model server that
/// pins its callers, read the caller's App from.
pub(crate) fn client_identity(identity: &RuntimeIdentity) -> Result<Identity, Error> {
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

fn digest(window: &str) -> [u8; 32] {
    Sha256::digest(window.as_bytes()).into()
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
            allow: config.allow,
            judge: Judge::Remote {
                url: config.url.clone(),
                revisions: config.revisions.clone(),
                kms_ca,
                client: parking_lot::RwLock::new(client),
            },
            allowed: parking_lot::Mutex::new(HashMap::new()),
        })
    }

    #[cfg(test)]
    pub(crate) fn fixed(input: Result<(), Refusal>, output: Result<(), Refusal>) -> Self {
        Self::fixed_allowing(input, output, Allow::default())
    }

    #[cfg(test)]
    pub(crate) fn fixed_allowing(
        input: Result<(), Refusal>,
        output: Result<(), Refusal>,
        allow: Allow,
    ) -> Self {
        Self {
            policy: Policy {
                model: "guard".into(),
                categories: vec!["Violence".into()],
            },
            allow,
            judge: Judge::Fixed {
                input,
                output,
                seen: parking_lot::Mutex::new(Vec::new()),
            },
            allowed: parking_lot::Mutex::new(HashMap::new()),
        }
    }

    /// Every check the test judge was asked, as `(user, response)`.
    #[cfg(test)]
    pub(crate) fn seen(&self) -> Vec<(String, Option<String>)> {
        match &self.judge {
            Judge::Fixed { seen, .. } => seen.lock().clone(),
            Judge::Remote { .. } => Vec::new(),
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
            Judge::Fixed {
                input,
                output,
                seen,
            } => {
                seen.lock()
                    .push((user.to_owned(), response.map(str::to_owned)));
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

    fn recently_allowed(&self, key: &[u8; 32]) -> bool {
        let mut allowed = self.allowed.lock();
        match allowed.get(key) {
            Some(at) if at.elapsed() < ALLOWED_TTL => true,
            Some(_) => {
                allowed.remove(key);
                false
            }
            None => false,
        }
    }

    fn remember_allowed(&self, key: [u8; 32]) {
        let mut allowed = self.allowed.lock();
        if allowed.len() >= ALLOWED_CAP {
            allowed.retain(|_, at| at.elapsed() < ALLOWED_TTL);
            if allowed.len() >= ALLOWED_CAP {
                allowed.clear();
            }
        }
        allowed.insert(key, Instant::now());
    }

    /// Renders a member's request as the model will read it and judges it before anything is
    /// sent upstream. The rendered prompt comes back: the completion is judged against its end.
    pub async fn check_input(&self, model: &str, request: &Value) -> Result<String, Refusal> {
        let started = Instant::now();
        let outcome = match prompt_input(request, self.allow) {
            Ok(input) => {
                match tokio::time::timeout(JUDGE_PHASE_TIMEOUT, self.check_input_windows(&input))
                    .await
                {
                    Ok(Ok(())) => Ok(input),
                    Ok(Err(refusal)) => Err(refusal),
                    Err(_) => Err(Refusal::Unavailable),
                }
            }
            Err(refusal) => Err(refusal),
        };
        log(
            "input",
            model,
            outcome.as_ref().map(|_| ()).map_err(|r| *r),
            started,
        );
        outcome
    }

    async fn check_input_windows(&self, input: &str) -> Result<(), Refusal> {
        if input.is_empty() {
            return Err(Refusal::Unjudgeable);
        }
        let windows = windows(input, INPUT_WINDOW);
        if windows.len() > MAX_WINDOWS {
            return Err(Refusal::TooLarge);
        }
        for window in windows {
            let key = digest(window);
            if self.recently_allowed(&key) {
                continue;
            }
            self.check(window, None).await?;
            self.remember_allowed(key);
        }
        Ok(())
    }

    /// Judges a held completion, with the end of the prompt as context, before it is released.
    /// A body the front cannot read as a completion, or one that says nothing it can read, is not
    /// released.
    pub async fn check_output(&self, model: &str, input: &str, body: &[u8]) -> Result<(), Refusal> {
        let started = Instant::now();
        let outcome = match completion_text(body) {
            Some(output) if !output.is_empty() => {
                match tokio::time::timeout(
                    JUDGE_PHASE_TIMEOUT,
                    self.check_output_windows(input, &output),
                )
                .await
                {
                    Ok(outcome) => outcome,
                    Err(_) => Err(Refusal::Unavailable),
                }
            }
            _ => Err(Refusal::Unavailable),
        };
        log("output", model, outcome, started);
        outcome
    }

    async fn check_output_windows(&self, input: &str, output: &str) -> Result<(), Refusal> {
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

fn log(phase: &str, model: &str, outcome: Result<(), Refusal>, started: Instant) {
    let outcome = match outcome {
        Ok(()) => "allow",
        Err(Refusal::Blocked) => "block",
        Err(Refusal::Unavailable) => "unavailable",
        Err(Refusal::TooLarge) => "too_large",
        Err(Refusal::Unjudgeable) => "unjudgeable",
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

/// The text of a completion message's `content`: a string, or the `text` of its parts.
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

/// Every string anywhere in `value`, in order.
fn strings(value: &Value, out: &mut String) {
    match value {
        Value::String(text) => push(out, text),
        Value::Array(items) => items.iter().for_each(|v| strings(v, out)),
        Value::Object(map) => map.values().for_each(|v| strings(v, out)),
        _ => {}
    }
}

/// The text of a request message's `content`: a string, or its parts. A text or refusal part is
/// read; any other part is refused unless the policy admits non-text parts, and then only its
/// `text`, if any, is read.
fn prompt_content(content: Option<&Value>, allow: Allow, out: &mut String) -> Result<(), Refusal> {
    match content {
        None | Some(Value::Null) => Ok(()),
        Some(Value::String(text)) => {
            push(out, text);
            Ok(())
        }
        Some(Value::Array(parts)) => {
            for part in parts {
                let field = match part.get("type").and_then(Value::as_str) {
                    Some("text") => "text",
                    Some("refusal") => "refusal",
                    _ if allow.non_text_parts => {
                        if let Some(text) = part.get("text").and_then(Value::as_str) {
                            push(out, text);
                        }
                        continue;
                    }
                    _ => return Err(Refusal::Unjudgeable),
                };
                let text = part
                    .get(field)
                    .and_then(Value::as_str)
                    .ok_or(Refusal::Unjudgeable)?;
                push(out, text);
            }
            Ok(())
        }
        Some(_) => Err(Refusal::Unjudgeable),
    }
}

/// What a message says besides its content: reasoning, a refusal and tool calls (current and
/// legacy), in order.
fn message_extras(message: &Value, out: &mut String) {
    for field in ["reasoning_content", "reasoning", "refusal"] {
        if let Some(text) = message.get(field).and_then(Value::as_str) {
            push(out, text);
        }
    }
    let calls: Vec<&Value> = message
        .get("tool_calls")
        .and_then(Value::as_array)
        .map(|calls| calls.iter().filter_map(|c| c.get("function")).collect())
        .unwrap_or_default();
    for function in calls.into_iter().chain(message.get("function_call")) {
        for field in ["name", "arguments"] {
            if let Some(text) = function.get(field).and_then(Value::as_str) {
                push(out, text);
            }
        }
    }
}

/// Whether a request asks for log probabilities: alternative tokens the judge never sees.
fn asks_for_logprobs(request: &Value) -> bool {
    request.get("logprobs").and_then(Value::as_bool) == Some(true)
        || request
            .get("top_logprobs")
            .and_then(Value::as_u64)
            .is_some_and(|n| n > 0)
        || request.get("prompt_logprobs").is_some_and(|v| !v.is_null())
}

/// The whole prompt of a chat request as the judge reads it: the tool and function definitions
/// first (they precede the conversation in a rendered prompt, and keep each turn's earlier
/// windows identical), the template arguments and documents a template renders, then every
/// message of every role in order as `role: text` — content, reasoning, refusals and tool calls.
/// Refused when it carries what cannot be judged (see the module docs).
pub fn prompt_input(request: &Value, allow: Allow) -> Result<String, Refusal> {
    if request.get("chat_template").is_some_and(|v| !v.is_null()) || asks_for_logprobs(request) {
        return Err(Refusal::Unjudgeable);
    }
    let mut out = String::new();
    for key in ["tools", "functions"] {
        match request.get(key) {
            None | Some(Value::Null) => {}
            Some(Value::Array(items)) => {
                for item in items {
                    push(&mut out, &format!("{key}: {item}"));
                }
            }
            Some(_) => return Err(Refusal::Unjudgeable),
        }
    }
    for key in ["chat_template_kwargs", "documents"] {
        match request.get(key) {
            None | Some(Value::Null) => {}
            Some(value @ (Value::Object(_) | Value::Array(_))) => {
                let mut text = String::new();
                strings(value, &mut text);
                if !text.is_empty() {
                    push(&mut out, &format!("{key}: {text}"));
                }
            }
            Some(_) => return Err(Refusal::Unjudgeable),
        }
    }
    let messages = request
        .get("messages")
        .and_then(Value::as_array)
        .filter(|m| !m.is_empty())
        .ok_or(Refusal::Unjudgeable)?;
    for message in messages {
        let role = message
            .get("role")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let label = match message.get("name").and_then(Value::as_str) {
            Some(name) => format!("{role} ({name})"),
            None => role.to_owned(),
        };
        let mut text = String::new();
        prompt_content(message.get("content"), allow, &mut text)?;
        message_extras(message, &mut text);
        if !text.is_empty() {
            push(&mut out, &format!("{label}: {text}"));
        }
    }
    let last_role = messages
        .last()
        .and_then(|m| m.get("role"))
        .and_then(Value::as_str);
    if last_role == Some("assistant") && !allow.assistant_prefill {
        return Err(Refusal::Unjudgeable);
    }
    if out.is_empty() {
        return Err(Refusal::Unjudgeable);
    }
    Ok(out)
}

/// What a choice's `message` (or a stream chunk's `delta`) says: content, reasoning, a refusal
/// and tool calls, appended in order.
fn message_text(message: &Value, out: &mut String) {
    content_text(message.get("content"), out);
    message_extras(message, out);
}

/// The text of every choice in `chunk` under `key`, or `None` when `chunk` has no `choices`
/// array or a choice carries log probabilities, which hold tokens the judge would never see.
fn choices_text(chunk: &Value, key: &str, out: &mut String) -> Option<()> {
    let choices = chunk.get("choices").and_then(Value::as_array)?;
    for choice in choices {
        if choice.get("logprobs").is_some_and(|v| !v.is_null()) {
            return None;
        }
        if let Some(message) = choice.get(key) {
            message_text(message, out);
        }
    }
    Some(())
}

/// Everything a completion says, from a JSON body or an event stream, or `None` when the body is
/// neither a completion nor a stream of completion chunks the front can read. A stream's deltas
/// are joined without separators, as the model wrote them.
pub fn completion_text(body: &[u8]) -> Option<String> {
    let mut out = String::new();
    if let Ok(parsed) = serde_json::from_slice::<Value>(body) {
        choices_text(&parsed, "message", &mut out)?;
        return Some(out);
    }
    let text = std::str::from_utf8(body).ok()?;
    let mut streamed = String::new();
    let mut chunks = 0usize;
    for line in text.lines() {
        let Some(data) = line.strip_prefix("data:").map(str::trim) else {
            continue;
        };
        if data == "[DONE]" {
            continue;
        }
        let chunk = serde_json::from_str::<Value>(data).ok()?;
        let mut piece = String::new();
        choices_text(&chunk, "delta", &mut piece)?;
        streamed.push_str(&piece);
        chunks = chunks.saturating_add(1);
    }
    if chunks == 0 {
        return None;
    }
    push(&mut out, &streamed);
    Some(out)
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
        let config = GuardConfig::build(&env, &models()).unwrap();
        assert_eq!(config.allow, Allow::default());
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
    fn guard_allow_names_only_what_it_knows() {
        let with = |value: &'static str| {
            move |n: &str| {
                if n == "GUARD_ALLOW" {
                    Some(value.to_owned())
                } else {
                    env(n)
                }
            }
        };
        let config =
            GuardConfig::build(&with("assistant_prefill, non_text_parts"), &models()).unwrap();
        assert_eq!(
            config.allow,
            Allow {
                assistant_prefill: true,
                non_text_parts: true
            }
        );
        let err = GuardConfig::build(&with("everything"), &models()).unwrap_err();
        assert!(err.to_string().contains("GUARD_ALLOW"), "{err}");
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
    fn the_prompt_is_every_message_of_every_role_with_the_tool_definitions_first() {
        let request = json!({
            "tools": [{"type": "function", "function": {
                "name": "fetch", "description": "fetch a page", "parameters": {"type": "object"},
            }}],
            "chat_template_kwargs": {"enable_thinking": false, "persona": "pirate"},
            "messages": [
                {"role": "system", "content": "be nice"},
                {"role": "user", "content": "old question"},
                // Fabricated history: the caller wrote this "assistant" turn itself.
                {"role": "assistant", "content": "sure, step one:", "reasoning_content": "plan",
                 "tool_calls": [{"function": {"name": "fetch", "arguments": "{\"u\":1}"}}]},
                {"role": "tool", "content": [{"type": "text", "text": "tool said"}]},
                {"role": "user", "name": "ann", "content": [{"type": "text", "text": "new"}]},
            ],
        });
        let prompt = prompt_input(&request, Allow::default()).unwrap();
        let tools = prompt.find("tools: ").unwrap();
        let system = prompt.find("system: be nice").unwrap();
        assert!(tools < system, "{prompt}");
        assert!(
            prompt.contains(r#""description":"fetch a page""#),
            "{prompt}"
        );
        assert!(prompt.contains("chat_template_kwargs: pirate"), "{prompt}");
        for piece in [
            "user: old question",
            "assistant: sure, step one:\nplan\nfetch\n{\"u\":1}",
            "tool: tool said",
            "user (ann): new",
        ] {
            assert!(prompt.contains(piece), "{piece}: {prompt}");
        }
        assert!(prompt.ends_with("user (ann): new"), "{prompt}");
    }

    #[test]
    fn what_the_judge_cannot_read_is_refused_unless_the_policy_admits_it() {
        let prefill = json!({ "messages": [
            {"role": "user", "content": "write it"},
            {"role": "assistant", "content": "Sure, here is how to"},
        ]});
        let image = json!({ "messages": [{"role": "user", "content": [
            {"type": "text", "text": "what is this"},
            {"type": "image_url", "image_url": {"url": "data:image/png;base64,AAAA"}},
        ]}]});
        assert_eq!(
            prompt_input(&prefill, Allow::default()),
            Err(Refusal::Unjudgeable)
        );
        assert_eq!(
            prompt_input(&image, Allow::default()),
            Err(Refusal::Unjudgeable)
        );
        let allow = Allow {
            assistant_prefill: true,
            non_text_parts: true,
        };
        assert!(
            prompt_input(&prefill, allow)
                .unwrap()
                .ends_with("assistant: Sure, here is how to")
        );
        assert_eq!(prompt_input(&image, allow).unwrap(), "user: what is this");

        for refused in [
            json!({}),
            json!({ "messages": [] }),
            json!({ "messages": [{"role": "user", "content": ""}] }),
            json!({ "messages": [{"role": "user", "content": 7}] }),
            json!({ "messages": [{"role": "user", "content": [{"type": "text"}]}] }),
            json!({ "messages": [{"role": "user", "content": "hi"}], "tools": "x" }),
            json!({ "messages": [{"role": "user", "content": "hi"}], "documents": "x" }),
            json!({ "messages": [{"role": "user", "content": "hi"}], "chat_template": "{{x}}" }),
            json!({ "messages": [{"role": "user", "content": "hi"}], "logprobs": true }),
            json!({ "messages": [{"role": "user", "content": "hi"}], "top_logprobs": 5 }),
            json!({ "messages": [{"role": "user", "content": "hi"}], "prompt_logprobs": 1 }),
        ] {
            assert_eq!(
                prompt_input(&refused, allow),
                Err(Refusal::Unjudgeable),
                "{refused}"
            );
        }
        let plain = json!({ "messages": [{"role": "user", "content": "hi"}],
            "logprobs": false, "chat_template": null });
        assert_eq!(prompt_input(&plain, Allow::default()).unwrap(), "user: hi");
    }

    #[test]
    fn completion_text_reads_a_json_body_with_reasoning_refusal_and_tool_calls() {
        let body = json!({ "choices": [{ "message": {
            "content": "answer",
            "reasoning_content": "thinking",
            "refusal": "no",
            "tool_calls": [{"function": {"name": "fetch", "arguments": "{\"u\":1}"}}],
        }}]});
        assert_eq!(
            completion_text(body.to_string().as_bytes()).unwrap(),
            "answer\nthinking\nno\nfetch\n{\"u\":1}"
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
        assert_eq!(completion_text(body.as_bytes()).unwrap(), "Hello");
    }

    #[test]
    fn a_body_the_front_cannot_read_is_no_completion() {
        let with_logprobs = json!({ "choices": [{
            "message": {"content": "a"},
            "logprobs": {"content": [{"token": "a", "top_logprobs": [{"token": "b"}]}]},
        }]});
        for unreadable in [
            b"not a completion".to_vec(),
            br#"{"object":"error"}"#.to_vec(),
            b"data: {not json}\n\n".to_vec(),
            b"data: [DONE]\n\n".to_vec(),
            with_logprobs.to_string().into_bytes(),
        ] {
            assert_eq!(
                completion_text(&unreadable),
                None,
                "{}",
                String::from_utf8_lossy(&unreadable)
            );
        }
    }

    #[tokio::test]
    async fn an_unreadable_or_empty_completion_is_never_released() {
        let guard = Guard::fixed(Ok(()), Ok(()));
        let empty = json!({ "choices": [{ "message": {"content": ""} }] }).to_string();
        for body in ["garbage".as_bytes(), empty.as_bytes()] {
            assert_eq!(
                guard.check_output("m1", "user: q", body).await,
                Err(Refusal::Unavailable)
            );
        }
        assert!(guard.seen().is_empty());
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
    async fn an_oversized_prompt_is_refused_without_a_check() {
        let guard = Guard::fixed(Ok(()), Ok(()));
        let request = json!({ "messages": [
            {"role": "user", "content": "x".repeat(INPUT_WINDOW * (MAX_WINDOWS + 1))},
        ]});
        assert_eq!(
            guard.check_input("m1", &request).await,
            Err(Refusal::TooLarge)
        );
        assert!(guard.seen().is_empty());
        assert!(
            INPUT_WINDOW <= CONTENT_LIMIT
                && OUTPUT_WINDOW.saturating_add(CONTEXT_TAIL) <= CONTENT_LIMIT
        );
    }

    #[tokio::test]
    async fn a_conversations_earlier_windows_are_judged_once() {
        let guard = Guard::fixed(Ok(()), Ok(()));
        let history = "h".repeat(INPUT_WINDOW * 2);
        let turn = |n: usize| {
            let mut messages = vec![json!({"role": "user", "content": history})];
            for i in 0..n {
                messages.push(json!({"role": "assistant", "content": format!("a{i}")}));
                messages.push(json!({"role": "user", "content": format!("q{i}")}));
            }
            json!({ "messages": messages })
        };
        guard.check_input("m1", &turn(1)).await.unwrap();
        assert_eq!(guard.seen().len(), 3);
        // The next turn repeats the first two windows byte for byte; only the last changed.
        guard.check_input("m1", &turn(2)).await.unwrap();
        let seen = guard.seen();
        assert_eq!(seen.len(), 4);
        assert!(seen.last().unwrap().0.ends_with("user: q1"));
        // A refused window is never remembered as allowed.
        let blocking = Guard::fixed(Err(Refusal::Blocked), Ok(()));
        for _ in 0..2 {
            assert_eq!(
                blocking.check_input("m1", &turn(1)).await,
                Err(Refusal::Blocked)
            );
        }
        assert_eq!(blocking.seen().len(), 2);
    }
}
