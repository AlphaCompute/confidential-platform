# alpha-inference

The platform's inference front: an App of its own with two kinds of upstream, chosen per model by the measured environment.

- **Our own model servers** (`MODEL_SERVERS`): one `alpha-model-server` App per model — an OpenAI-compatible server on a whole confidential-computing GPU in a Kata TDX pod VM — reached only over TLS pinned to this Instance's KMS CA and one of that model's Revisions, inside the handshake.
- **The external provider** (RedPill) for every other allowlisted model: forwarded only after a live check of its gateway attestation, run in this service's own measured code, has passed for that model within the last minute.

Either way, any error, timeout or mismatch answers `upstream_unverified` and sends nothing. A model never moves from one kind to the other on its own: which kind serves a model is part of the Revision.

Whatever the model, every member's turn is judged by `alpha-guard` before it reaches an upstream, and every completion is judged before it is released (see *Moderation*). Only the judge's own calls are exempt.

## Configuration (environment only)

| Variable | Meaning |
|---|---|
| `MODELS` | comma-separated model ids allowed through; the first is the default for `/ready` |
| `MODEL_SERVERS` | optional JSON object, model id → `{"url": "https://host[:port]", "revisions": ["sha256:..."], "bearer": "<secret name>"}`: the allowlisted models our own model servers serve, each pinned to the KMS CA and one of its Revisions, each with its own bearer read from the Secret `bearer` names; every key must be in `MODELS`, every url an https origin without a path, every Revision list non-empty, every bearer a lowercase Secret name |
| `UPSTREAM_URL` | RedPill's OpenAI-compatible base, `/v1` included, `https://` only (e.g. `https://api.redpill.ai/v1`); required only when some model in `MODELS` is not in `MODEL_SERVERS` |
| `PCCS_URL` | PCCS for DCAP collateral, fetched at most once a minute per model (`https://` only); required as `UPSTREAM_URL` is |
| `UPSTREAM_POLICY` | JSON of `alpha_attest::Policy` (`tcb_statuses`, `tolerated_advisories`) the report's quote must satisfy; required as `UPSTREAM_URL` is |
| `GUARD_URL` | `alpha-guard`'s origin, `https://host[:port]`, no path; required |
| `GUARD_REVISIONS` | comma-separated `sha256:` Revisions of the judge this front asks; required |
| `GUARD_POLICY` | JSON `{"model": "...", "categories": ["..."]}`, 1 to 32 one-line categories without `<`: what this front refuses, judged by `model`; required, and changing it is a new Revision |
| `JUDGE_MODELS` | comma-separated models the judge's own bearer may name, each in `MODELS`; must include `GUARD_POLICY`'s model; required |
| `GUARD_ALLOW` | optional, comma-separated: what a member's request may carry that the judge cannot read. `assistant_prefill` admits a last message from the assistant (the model continues it); `non_text_parts` admits image, audio and other non-text parts (only their `text`, if any, is judged). Unset, both are refused |

Secrets, released only to this App's Revision, and read only when this Revision uses them: `judge-bearer` (always; the bearer `alpha-guard` presents as its own `inference-bearer`; must be set and differ from `caller-bearer`, or the front refuses to start), `caller-bearer` (always; compared by SHA-256 digest against every `/v1` request's `Authorization: Bearer` header before any upstream contact), `redpill-api-key` (when some model is RedPill's; RedPill's own key, never sent to any other App, never released to a caller) and, for each of our model servers, the Secret its `MODEL_SERVERS` entry names in `bearer` (sent only over that server's pinned connection, never to RedPill, another model server or a caller). Each model server declares the same value as its own Secret of that name, so one server's bearer opens no other.

## Routes

- `GET /v1/models` — RedPill's models: the allowlisted entries of its public listing (bare `{id, object}` when RedPill lists none of them); ours: `{id, object, "owned_by": "alphacompute"}` from `MODEL_SERVERS`. No check: it carries no conversation.
- `GET /v1/models/{model}` — `200 {"id","object":"model","owned_by":"alphacompute"|"redpill"}` once that model's check has passed within the last minute; `404 model_not_found` outside the allowlist; `502 upstream_unverified` otherwise.
- `POST /v1/chat/completions` — the body forwarded unchanged over the model's pinned connection, the caller's bearer replaced by that upstream's own credential, status/content-type/stream relayed; `404 model_not_found` outside the allowlist, checked before any upstream contact; `502 upstream_unverified` when the check fails; `502 upstream` when the pinned connection itself fails, or when the completion has not ended 600 seconds after the request started (body included).
- `POST /v1/chat/completions` also answers, for a member: `403 content_blocked` when the prompt or the completion is blocked, `503 moderation_unavailable` when the judge gives no verdict, or the completion is no body the front can read, or says nothing it can read, `413 content_too_large` when there is more than the judge can be asked about, `400 content_not_judgeable` when the request carries what the judge cannot read (see *Moderation*), and the upstream's own 4xx/5xx status with a fixed `upstream_refused` error, never the upstream's body, when the upstream refuses the request. With the judge's bearer, a model outside `JUDGE_MODELS` answers `404 model_not_found`.
- `GET /healthz` (process only) and `GET /ready` (200 once the default model verifies) need no bearer.

Errors are OpenAI-shaped: `{"error":{"message","type","code"}}`; the `upstream_unverified` message is always "The model provider did not pass verification, so nothing was sent."

## Moderation

For a member's request (`caller-bearer`), before any upstream contact, the whole prompt the model will read goes to `alpha-guard`'s `POST /v1/check` with `GUARD_POLICY`: the `tools` and `functions` definitions first, then the strings of `chat_template_kwargs` and `documents`, then every message of every role in order as `role: text` — content, reasoning, refusals and tool calls, the system prompt and any history the caller sent included, since a caller can write "assistant" turns itself. Text over the judge's 128 KiB is judged in windows (120 KiB for the prompt, 104 KiB for the completion), at most 16 per phase and at most 180 seconds per phase. A prompt window the judge allowed is remembered by its SHA-256 for ten minutes, so on the next turn of the same conversation only the windows that changed are judged again.

Refused with `400 content_not_judgeable`, before the judge or any upstream is asked: a request with no messages or no text; a last message from the assistant (prefill: the model would continue the caller's text, not answer it) unless `GUARD_ALLOW` names `assistant_prefill`; an image, audio or other non-text part unless it names `non_text_parts`; a request's own `chat_template` (a template is code: what it renders cannot be read from it); and `logprobs`, `top_logprobs` or `prompt_logprobs`, which return alternative tokens nobody judged.

Then the upstream's answer is held whole (up to 16 MiB, and at most 600 seconds), its text, reasoning, refusal and tool calls are read from the JSON body or the event stream's deltas, and judged with the last 16 KiB of the prompt as context. Only on `allow` is the held answer released, byte for byte, with the upstream's status and content type. A body that is no completion the front can read, one whose choices carry log probabilities, or one that says nothing it can read is not released (`503 moderation_unavailable`). An upstream error is not relayed either: the member gets its status with a fixed `upstream_refused` error.

Within one completion there is no streaming under moderation: a caller asking for `stream: true` gets the whole event stream at once, after the judge.

The judge is dialled as any caller dials it: this Instance's leaf as the client certificate (renewed with every refresh), the connection pinned to the KMS CA and one of `GUARD_REVISIONS`. `alpha-guard`'s `CALLER_APPS` must therefore list this front's App. In the other direction `alpha-guard` pins this front by App (its `INFERENCE_APPS`), never by Revision: this front's Revision contains `GUARD_REVISIONS`, so a judge that pinned this front's Revision back could never be registered (each Revision would contain the other's hash). Register the judge first, then this front with the judge's Revision in `GUARD_REVISIONS`. Its own calls back here present `judge-bearer` and are not judged again; they may name only a model in `JUDGE_MODELS`. Logs carry the phase, the outcome, the model and the elapsed time — never the text.

**What this leaves open:** the judge sees only text, so a Revision whose `GUARD_ALLOW` names `non_text_parts` serves images and audio nobody judged. The prompt is judged as the front renders it, not through the model's own chat template, and a window is judged on its own, so a request split across a window boundary is judged in two pieces.

## Our own model servers

A model server's `alpha-runtime` sidecar terminates TLS with the one-hour Instance leaf the KMS issued after appraising the pod VM's evidence, and this front pins every connection to it with `Pin::CaAndInstanceRevisions`: the chain must end at this Instance's own KMS CA (the last certificate of its own chain, already checked by its runtime against the measured CA) and the leaf must carry one of the model's `revisions`, or the handshake fails before a request byte. No report is read here — the KMS's appraisal is the check, and the leaf is its readable form. This front presents its own Instance leaf as the client certificate (renewed with every refresh), and a model server's runtime admits only an Instance of this front's App (`ALPHACOMPUTE_TLS_CALLER_APPS`): nobody else reaches any of vLLM's routes, including the ones outside `/v1` that vLLM's API key does not cover. The server pins this front by App, not by Revision, because this front's Revision names the server's.

Before a model is used, and at most once a minute (one check in flight per model): `GET {url}/v1/models` with that server's bearer over the pinned connection must answer 2xx and list the model. The Revision the leaf carried is logged on each passing check (`alpha-inference: model <m> served by alphacompute revision sha256:...`), so an operator can tie a model to the measured build that served it; a failure is logged by code (`handshake`, `status`, `not_served`) and model only. Every completion also logs the Revision of the leaf on its own connection and the status (`alpha-inference: model <m> completion served by alphacompute revision sha256:... status=200`), so each chat is tied to the build that served it, not only the last check.

**What this covers:** that the server is an Instance the KMS appraised for a listed Revision of the model server. What that appraisal includes for the GPU — that the GPUs are in confidential-computing mode, their attestation report and certificate chain, driver and VBIOS measurements against reference values — is the KMS's appraisal policy for that Revision (PRD-02), not something this front re-checks. A model server Revision whose policy does not require GPU evidence would pass here too; registering such a Revision is the control.

## The gateway check

Before forwarding any request for a model, and at most once a minute per model: a fresh 32-byte nonce; `GET {UPSTREAM_URL}/attestation/report?model=<m>&nonce=<nonce>&signing_algo=ecdsa&version=2`, read over an unpinned connection that never carries the RedPill key; the returned TDX quote verified with `alpha_attest::verify_quote` against PCCS collateral and `UPSTREAM_POLICY`; and a check that `report_data` equals `SHA-256(signing address ‖ SHA-256(the connection's own observed TLS key)) ‖ nonce` — binding the quote to the actual connection this process made, not to anything the report claims about itself. A pass pins every forwarding connection for that model to that exact key until the check expires; a failed refetch clears even a previously good result.

**What this proves:** the specific TDX-attested CVM whose certificate terminated this session to RedPill produced a fresh, Intel-PCS-verifying quote bound to this nonce and this TLS session.

**What this leaves open:** the quote covers RedPill's gateway CVM (reports zero GPUs), not the GPU host actually running the model; no specific completion is bound to the attested key (RedPill's per-completion signature endpoint is untested); RedPill's own routing behind its gateway is trusted. The product page and chat window must not claim more than this.

## Tests

`cargo test -p alpha-inference` runs the golden and failure-mode tests: `check_report` against a real captured RedPill report (`testdata/redpill/`) and against it mutated (wrong nonce, wrong SPKI, a tampered quote byte, a policy that denies the TCB status, expired collateral); every way the report endpoint can fail (refused, non-2xx, timeout, non-JSON, a missing field); the 60-second reuse window and refetch on expiry; two concurrent checks on a cold model sharing one fetch; SPKI pinning on the forwarding connection; and the router (bearer required before any upstream contact, a model outside the allowlist refused before any upstream contact, `Config::build`'s refusals). Moderation is tested against a fixed judge that records what it is asked: the whole prompt, a fabricated history and the tool definitions reach it; a prefill, a non-text part, a request's own chat template, log probabilities and a request with no text are refused before the judge or any upstream; a completion is released only on allow, never when the body is unreadable, empty or an upstream error; and a conversation's earlier windows are judged once.

The live test proves the whole front end to end against the real RedPill API and is `#[ignore]`d unless a key is present:

```sh
REDPILL_API_KEY="$(cat path/to/key)" cargo test -p alpha-inference -- --include-ignored
```

It never prints the key, and no test data under `testdata/redpill/` carries one — every fixture there came from a keyless `GET`.
