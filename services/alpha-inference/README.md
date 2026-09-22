# alpha-inference

The platform's inference front: an App of its own, whose provider is RedPill. Every `/v1` route forwards to RedPill only after a live check of RedPill's gateway attestation, run in this service's own measured code, has passed for that model within the last minute; any error, timeout or mismatch answers `upstream_unverified` and sends nothing.

## Configuration (environment only)

| Variable | Meaning |
|---|---|
| `UPSTREAM_URL` | RedPill's OpenAI-compatible base, `/v1` included, `https://` only (e.g. `https://api.redpill.ai/v1`) |
| `MODELS` | comma-separated model ids allowed through; the first is the default for `/ready` |
| `PCCS_URL` | PCCS for DCAP collateral, fetched at most once a minute per model (`https://` only) |
| `UPSTREAM_POLICY` | JSON of `alpha_attest::Policy` (`tcb_statuses`, `tolerated_advisories`) the report's quote must satisfy |

Two Secrets, released only to this App's Revision: `redpill-api-key` (RedPill's own key; never sent to any other App, never released to a caller) and `caller-bearer` (compared by SHA-256 digest against every `/v1` request's `Authorization: Bearer` header before any upstream contact).

## Routes

- `GET /v1/models` — the allowlisted entries of RedPill's public listing (bare `{id, object}` when RedPill lists none of them). No gateway check: it carries no conversation.
- `GET /v1/models/{model}` — `200 {"id","object":"model","owned_by":"redpill"}` once the gateway check has passed for that model within the last minute; `404 model_not_found` outside the allowlist; `502 upstream_unverified` otherwise.
- `POST /v1/chat/completions` — the body forwarded unchanged over the connection the gateway check pinned, the caller's bearer replaced by the RedPill key, status/content-type/stream relayed; `404 model_not_found` outside the allowlist, checked before any upstream contact; `502 upstream_unverified` when the gateway check fails; `502 upstream` when the pinned connection itself fails.
- `GET /healthz` (process only) and `GET /ready` (200 once the default model verifies) need no bearer.

Errors are OpenAI-shaped: `{"error":{"message","type","code"}}`; the `upstream_unverified` message is always "The model provider did not pass verification, so nothing was sent."

## The gateway check

Before forwarding any request for a model, and at most once a minute per model: a fresh 32-byte nonce; `GET {UPSTREAM_URL}/attestation/report?model=<m>&nonce=<nonce>&signing_algo=ecdsa&version=2`, read over an unpinned connection that never carries the RedPill key; the returned TDX quote verified with `alpha_attest::verify_quote` against PCCS collateral and `UPSTREAM_POLICY`; and a check that `report_data` equals `SHA-256(signing address ‖ SHA-256(the connection's own observed TLS key)) ‖ nonce` — binding the quote to the actual connection this process made, not to anything the report claims about itself. A pass pins every forwarding connection for that model to that exact key until the check expires; a failed refetch clears even a previously good result.

**What this proves:** the specific TDX-attested CVM whose certificate terminated this session to RedPill produced a fresh, Intel-PCS-verifying quote bound to this nonce and this TLS session.

**What this leaves open:** the quote covers RedPill's gateway CVM (reports zero GPUs), not the GPU host actually running the model; no specific completion is bound to the attested key (RedPill's per-completion signature endpoint is untested); RedPill's own routing behind its gateway is trusted. The product page and chat window must not claim more than this.

## Tests

`cargo test -p alpha-inference` runs the golden and failure-mode tests: `check_report` against a real captured RedPill report (`testdata/redpill/`) and against it mutated (wrong nonce, wrong SPKI, a tampered quote byte, a policy that denies the TCB status, expired collateral); every way the report endpoint can fail (refused, non-2xx, timeout, non-JSON, a missing field); the 60-second reuse window and refetch on expiry; two concurrent checks on a cold model sharing one fetch; SPKI pinning on the forwarding connection; and the router (bearer required before any upstream contact, a model outside the allowlist refused before any upstream contact, `Config::build`'s refusals).

The live test proves the whole front end to end against the real RedPill API and is `#[ignore]`d unless a key is present:

```sh
REDPILL_API_KEY="$(cat path/to/key)" cargo test -p alpha-inference -- --include-ignored
```

It never prints the key, and no test data under `testdata/redpill/` carries one — every fixture there came from a keyless `GET`.
