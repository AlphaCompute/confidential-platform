# alpha-guard

The platform's content judge: an App of its own that an attested Instance calls with its own policy and a piece of conversation, and that answers allow or block. The policy belongs to the caller and lives in the caller's measured environment, so changing it is a new Revision of the caller; this service keeps nothing and enforces nothing — the caller does. The judging model is reached only through the inference front (`alpha-inference`), pinned by the KMS CA and the front's Revision, so which provider serves the model is the front's concern and a model the platform serves itself later needs no change here.

## Configuration (environment only)

| Variable | Meaning |
|---|---|
| `INFERENCE_URL` | the front's origin, `https://host[:port]`, no path |
| `INFERENCE_REVISIONS` | comma-separated `sha256:` Revisions of the front this judge will talk to |
| `CALLER_APPS` | comma-separated App ids whose Instances may ask for a verdict |

One Secret, released only to this App's Revision: `inference-bearer`, the bearer the front expects.

## Routes

- `POST /v1/check` — needs a client certificate of an attested Instance (chained to the KMS CA in the handshake) whose App is in `CALLER_APPS`. Body: `{"policy": {"model", "categories": [...]}, "user": "...", "response": "..."?}`, `user` and `response` together at most 128 KiB, each category one line without `<`, 1 to 32 of them. Answers `200 {"verdict": "allow"|"block", "categories": [...], "policy_sha256": "sha256:..."}`; `categories` names the policy's own lines the judge cited. `401 cert_invalid` without an Instance leaf, `403 not_allowed` for an App outside the list, `400 malformed` for a bad body or a model the front does not serve, `502 no_verdict` when the front or the judge fails or the judge's answer is not a clear rating. A caller treats anything but `200` as no verdict and does not release the content.
- `GET /healthz` (process only) and `GET /ready` (the front's `/healthz` answers over the pinned connection) need no certificate.

The prompt is Nemotron Safety Guard's content-safety template with the policy's categories as the taxonomy, sent with `temperature: 0` and `reasoning_effort: none`. Logs carry the caller's App, the phase, the outcome, the policy digest and the elapsed time — never the text, the categories or the judge's answer.

**What this leaves open:** a general instruction-following judge is less accurate than a dedicated classifier and can be steered by text written to look like its own answer; the conversation-block delimiters are neutralised, nothing more. The judge sees whatever the caller sends, with the same confidentiality as any request through the front.

## Tests

`cargo test -p alpha-guard` covers the prompt and the verdict parser (every answer shape the allowlisted models were seen to give, and every non-answer refused), `Config::build`'s refusals, and the router against a local fake front: no Instance leaf, a KMS node's leaf or an unlisted App never reaches the judge, a malformed or oversized body never reaches it, a missing or unclear rating is never an allow, and the policy, text and bearer reach the front as sent.

The live test runs the template and the parser against RedPill's allowlisted models directly and is `#[ignore]`d unless a key is present:

```sh
REDPILL_API_KEY="$(cat path/to/key)" cargo test -p alpha-guard -- --include-ignored
```
