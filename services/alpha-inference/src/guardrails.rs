//! Checks-only NeMo integration. The checker shares this App's confidential VM and
//! network namespace. No remote guard endpoint, redirect or proxy receives a conversation.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use axum::response::{IntoResponse, Response};
use axum::{Json, http::header};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::{Semaphore, SemaphorePermit};

use crate::Error;

pub const CONTENT_LIMIT: usize = 64 * 1024;
const VERDICT_LIMIT: usize = 64 * 1024;
const CHECK_TIMEOUT: Duration = Duration::from_secs(30);
pub const COMPLETION_TIMEOUT: Duration = Duration::from_secs(120);

/// Inline policies belong in the measured Compose, never in caller-supplied JSON or
/// mutable NeMo config IDs. Each phase has its own nonempty list of required rails.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    checks_url: String,
    model: String,
    input: Value,
    output: Value,
}

impl Config {
    pub fn parse(raw: &str) -> Result<Self, Error> {
        let invalid = || Error::internal("invalid GUARDRAILS_CONFIG");
        let config: Self = serde_json::from_str(raw).map_err(|_| invalid())?;
        let url = reqwest::Url::parse(&config.checks_url).map_err(|_| invalid())?;
        // Literal loopback, with an explicit port: no DNS rebinding and no remote HTTP.
        if url.scheme() != "http"
            || url.host_str() != Some("127.0.0.1")
            || url.port().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || !url.path().starts_with("/apis/guardrails/v2/workspaces/")
            || !url.path().ends_with("/checks")
            || config.model.trim().is_empty()
        {
            return Err(invalid());
        }
        required_rails(&config.input, "input").map_err(|_| invalid())?;
        required_rails(&config.output, "output").map_err(|_| invalid())?;
        Ok(config)
    }
}

fn required_rails<'a>(policy: &'a Value, phase: &str) -> Result<Vec<&'a str>, Error> {
    let rails = policy
        .get("rails")
        .and_then(Value::as_object)
        .ok_or(Error::GuardrailsUnavailable)?;
    // Do not accidentally invoke the other phase against a missing message.
    if rails.keys().any(|key| key != phase) {
        return Err(Error::GuardrailsUnavailable);
    }
    let flows = rails
        .get(phase)
        .and_then(|v| v.get("flows"))
        .and_then(Value::as_array)
        .ok_or(Error::GuardrailsUnavailable)?;
    let names: Vec<&str> = flows.iter().filter_map(Value::as_str).collect();
    if names.is_empty()
        || names.len() != flows.len()
        || names.iter().any(|name| name.trim().is_empty())
        || names.iter().collect::<BTreeSet<_>>().len() != names.len()
    {
        return Err(Error::GuardrailsUnavailable);
    }
    Ok(names)
}

pub struct Guardrails {
    config: Config,
    client: reqwest::Client,
    digest: String,
    capacity: Semaphore,
}

impl Guardrails {
    pub fn new(config: Config) -> Result<Self, Error> {
        let digest = hex::encode(Sha256::digest(
            json!({
                "checks_url": config.checks_url,
                "model": config.model,
                "input": config.input,
                "output": config.output,
            })
            .to_string()
            .as_bytes(),
        ));
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(CHECK_TIMEOUT)
            .build()
            .map_err(|_| Error::internal("guardrail client"))?;
        Ok(Self {
            config,
            client,
            digest,
            capacity: Semaphore::new(8),
        })
    }

    pub fn policy_digest(&self) -> &str {
        &self.digest
    }

    /// Hold through input check, generation, output check and response construction.
    pub fn acquire(&self) -> Result<SemaphorePermit<'_>, Error> {
        self.capacity
            .try_acquire()
            .map_err(|_| Error::GuardrailsUnavailable)
    }

    /// Screen the complete textual JSON envelope, including history, system prompts,
    /// tool definitions/results/arguments and reasoning. The policy must be written and
    /// evaluated for this representation; this is not authorization to execute tools.
    pub async fn check(&self, request: &str, output: Option<&str>) -> Result<(), Error> {
        let (phase, policy) = if output.is_some() {
            ("output", &self.config.output)
        } else {
            ("input", &self.config.input)
        };
        let mut messages = vec![json!({"role": "user", "content": request})];
        if let Some(output) = output {
            messages.push(json!({"role": "assistant", "content": output}));
        }
        let started = Instant::now();
        let result = async {
            let response = self
                .client
                .post(&self.config.checks_url)
                .json(&json!({
                    "model": self.config.model,
                    "messages": messages,
                    "guardrails": {"config": policy},
                }))
                .send()
                .await
                .map_err(|_| Error::GuardrailsUnavailable)?;
            if !response.status().is_success() {
                return Err(Error::GuardrailsUnavailable);
            }
            let bytes = read_bounded(response, VERDICT_LIMIT)
                .await
                .map_err(|_| Error::GuardrailsUnavailable)?;
            let verdict: Value =
                serde_json::from_slice(&bytes).map_err(|_| Error::GuardrailsUnavailable)?;
            evaluate_verdict(&verdict, &required_rails(policy, phase)?)
        }
        .await;
        let outcome = match &result {
            Ok(()) => "allowed",
            Err(Error::GuardrailsBlocked) => "blocked",
            Err(_) => "unavailable",
        };
        // Fixed labels and a digest only: no bodies, rail messages, URLs or credentials.
        eprintln!(
            "alpha-inference: guardrails phase={phase} outcome={outcome} policy_sha256={} elapsed_ms={}",
            self.digest,
            started.elapsed().as_millis()
        );
        result
    }
}

fn evaluate_verdict(verdict: &Value, required: &[&str]) -> Result<(), Error> {
    let status = verdict.get("status").and_then(Value::as_str);
    if status == Some("blocked") {
        return Err(Error::GuardrailsBlocked);
    }
    let rails = verdict
        .get("rails_status")
        .and_then(Value::as_object)
        .ok_or(Error::GuardrailsUnavailable)?;
    if rails
        .values()
        .any(|rail| rail.get("status").and_then(Value::as_str) == Some("blocked"))
    {
        return Err(Error::GuardrailsBlocked);
    }
    if status != Some("success")
        || required.iter().any(|name| {
            rails
                .get(*name)
                .and_then(|rail| rail.get("status"))
                .and_then(Value::as_str)
                != Some("success")
        })
        || rails
            .values()
            .any(|rail| rail.get("status").and_then(Value::as_str) != Some("success"))
    {
        return Err(Error::GuardrailsUnavailable);
    }
    Ok(())
}

pub(crate) async fn read_bounded(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>, Error> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| Error::Upstream)? {
        if body
            .len()
            .checked_add(chunk.len())
            .is_none_or(|len| len > limit)
        {
            return Err(Error::Upstream);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Guarded calls support text and function tools, not images/audio/video or an unknown
/// protocol extension that could carry content the classifier cannot interpret.
pub(crate) fn validate_request(request: &Value) -> Result<(), Error> {
    let object = request.as_object().ok_or(Error::GuardrailsUnsupported)?;
    const FIELDS: &[&str] = &[
        "model",
        "messages",
        "stream",
        "stream_options",
        "temperature",
        "top_p",
        "max_tokens",
        "max_completion_tokens",
        "stop",
        "n",
        "seed",
        "frequency_penalty",
        "presence_penalty",
        "logit_bias",
        "logprobs",
        "top_logprobs",
        "response_format",
        "tools",
        "tool_choice",
        "parallel_tool_calls",
        "reasoning_effort",
        "user",
    ];
    if object.keys().any(|key| !FIELDS.contains(&key.as_str()))
        || request.get("stream").is_some_and(|v| !v.is_boolean())
        || request
            .get("n")
            .is_some_and(|v| !v.as_u64().is_some_and(|n| (1..=4).contains(&n)))
    {
        return Err(Error::GuardrailsUnsupported);
    }
    let messages = request
        .get("messages")
        .and_then(Value::as_array)
        .filter(|v| !v.is_empty())
        .ok_or(Error::GuardrailsUnsupported)?;
    for message in messages {
        validate_message(message)?;
    }
    if let Some(tools) = request.get("tools") {
        for tool in tools.as_array().ok_or(Error::GuardrailsUnsupported)? {
            if tool.get("type").and_then(Value::as_str) != Some("function") {
                return Err(Error::GuardrailsUnsupported);
            }
        }
    }
    Ok(())
}

fn validate_message(message: &Value) -> Result<(), Error> {
    let object = message.as_object().ok_or(Error::GuardrailsUnsupported)?;
    if object.keys().any(|key| {
        ![
            "role",
            "content",
            "name",
            "tool_calls",
            "tool_call_id",
            "refusal",
            "reasoning_content",
            "reasoning",
        ]
        .contains(&key.as_str())
    }) || !message
        .get("role")
        .and_then(Value::as_str)
        .is_some_and(|role| ["user", "assistant", "system", "developer", "tool"].contains(&role))
    {
        return Err(Error::GuardrailsUnsupported);
    }
    if let Some(content) = message.get("content") {
        match content {
            Value::Null | Value::String(_) => {}
            Value::Array(parts)
                if parts.iter().all(|part| {
                    part.get("type").and_then(Value::as_str) == Some("text")
                        && part.get("text").is_some_and(Value::is_string)
                        && part.as_object().is_some_and(|o| o.len() == 2)
                }) => {}
            _ => return Err(Error::GuardrailsUnsupported),
        }
    }
    for key in ["refusal", "reasoning_content", "reasoning"] {
        if message
            .get(key)
            .is_some_and(|v| !v.is_null() && !v.is_string())
        {
            return Err(Error::GuardrailsUnsupported);
        }
    }
    if let Some(calls) = message.get("tool_calls").filter(|v| !v.is_null()) {
        for call in calls.as_array().ok_or(Error::GuardrailsUnsupported)? {
            if call.get("type").and_then(Value::as_str) != Some("function")
                || !call
                    .get("function")
                    .and_then(|f| f.get("name"))
                    .is_some_and(Value::is_string)
                || !call
                    .get("function")
                    .and_then(|f| f.get("arguments"))
                    .is_some_and(Value::is_string)
            {
                return Err(Error::GuardrailsUnsupported);
            }
        }
    }
    Ok(())
}

pub(crate) fn validate_completion(completion: &Value) -> Result<(), Error> {
    if completion.get("object").and_then(Value::as_str) != Some("chat.completion")
        || !completion.get("id").is_some_and(Value::is_string)
        || !completion.get("model").is_some_and(Value::is_string)
        || !completion.get("created").is_some_and(Value::is_u64)
    {
        return Err(Error::Upstream);
    }
    let choices = completion
        .get("choices")
        .and_then(Value::as_array)
        .filter(|v| !v.is_empty() && v.len() <= 4)
        .ok_or(Error::Upstream)?;
    let mut indices = BTreeSet::new();
    for choice in choices {
        let index = choice
            .get("index")
            .and_then(Value::as_u64)
            .ok_or(Error::Upstream)?;
        if !indices.insert(index) || !choice.get("finish_reason").is_some_and(Value::is_string) {
            return Err(Error::Upstream);
        }
        let message = choice.get("message").ok_or(Error::Upstream)?;
        validate_message(message).map_err(|_| Error::Upstream)?;
        if message.get("role").and_then(Value::as_str) != Some("assistant") {
            return Err(Error::Upstream);
        }
    }
    Ok(())
}

/// All bytes are already approved. Buffering intentionally trades token latency for
/// atomic release, including complete tool arguments and reasoning fields.
pub(crate) fn completion_response(
    completion: Value,
    stream: bool,
    include_usage: bool,
) -> Result<Response, Error> {
    if !stream {
        return Ok(([(header::CACHE_CONTROL, "no-store")], Json(completion)).into_response());
    }
    let mut chunk = completion.clone();
    let object = chunk.as_object_mut().ok_or(Error::Upstream)?;
    object.insert("object".into(), json!("chat.completion.chunk"));
    object.insert("usage".into(), Value::Null);
    let choices = object
        .get_mut("choices")
        .and_then(Value::as_array_mut)
        .ok_or(Error::Upstream)?;
    let mut endings = Vec::new();
    for choice in choices {
        let object = choice.as_object_mut().ok_or(Error::Upstream)?;
        let mut delta = object.remove("message").ok_or(Error::Upstream)?;
        if let Some(calls) = delta.get_mut("tool_calls").and_then(Value::as_array_mut) {
            for (index, call) in calls.iter_mut().enumerate() {
                call.as_object_mut()
                    .ok_or(Error::Upstream)?
                    .insert("index".into(), json!(index));
            }
        }
        endings.push(json!({"index": object.get("index"), "delta": {}, "finish_reason": object.get("finish_reason")}));
        object.insert("delta".into(), delta);
        object.insert("finish_reason".into(), Value::Null);
    }
    let mut body = format!("data: {chunk}\n\n");
    chunk
        .as_object_mut()
        .ok_or(Error::Upstream)?
        .insert("choices".into(), json!(endings));
    body.push_str(&format!("data: {chunk}\n\n"));
    if include_usage {
        let object = chunk.as_object_mut().ok_or(Error::Upstream)?;
        object.insert("choices".into(), json!([]));
        object.insert(
            "usage".into(),
            completion.get("usage").cloned().unwrap_or(Value::Null),
        );
        body.push_str(&format!("data: {chunk}\n\n"));
    }
    body.push_str("data: [DONE]\n\n");
    Ok((
        [
            (header::CONTENT_TYPE, "text/event-stream"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        body,
    )
        .into_response())
}

#[cfg(test)]
mod tests;
