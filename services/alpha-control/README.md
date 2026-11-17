# alpha-control

The control plane: Organizations, their operational API keys and their Apps. It holds no roster key and no Secret value. No bearer credential it accepts can register, revoke, enrol or seal anything; only a signature that the KMS verifies does that.

## Routes

| Method and path | Bearer | Answer |
|---|---|---|
| `POST /v1/orgs` | operator token, or a key with scope `onboard` | Creates an unrooted Organization from `{name, owner_email, links?: [{issuer, external_id}], deploy_key?: {scopes}}` and answers `{org_id, deploy_key?: {id, token, scopes}}`. The token shows only once. A link that names another Organization is `409`. |
| `PUT /v1/apps/{slug}` | a key with scope `apps:write` | Finds or creates the App and answers `{app_id, slug, endpoint}`. A slug of another Organization is `409`. Slugs are global and never reused. |
| `GET /healthz`, `GET /ready` | none | The process; the database. |

Errors are `{"error": {"code", "message", "request_id"}}`. The codes are `unauthorized`, `forbidden`, `malformed`, `not_found`, `conflict` and `internal`. Every mutation writes an `audit_log` row in its own transaction.

## Configuration (environment only)

| Variable | Meaning |
|---|---|
| `ALPHACOMPUTE_DATABASE_URL` | Postgres, database `alpha_control` |
| `ALPHACOMPUTE_OPERATOR_TOKEN_SHA256` | 64 hex digits: the SHA-256 of the operator's bearer |
| `ALPHACOMPUTE_PUBLIC_NAME` | the API's DNS name, for example `api.alphacompute.cc` |
| `ALPHACOMPUTE_ACME_KEY` | 64 hex digits; the ACME account key and the certificate key derive from it |

`alpha-control migrate` applies `migrations/` and returns. Otherwise the API listens on `:8443` (TLS 1.3, `http/1.1`) and gets a Let's Encrypt certificate for the public name through TLS-ALPN-01 on the same port, behind the SNI passthrough Gateway. `/healthz` and `/ready` also listen on plain `:8080` for the kubelet, because the API port has no certificate until the first order completes. SIGTERM drains open connections for at most ten seconds.

## Tests

`cargo test -p alpha-control` runs the slug rules. With `DATABASE_URL` set, `tests/db.rs` makes a database per test and checks that only the operator or an onboarding key creates an Organization, that it is created unrooted, that an onboarding key cannot hand out another onboarding key, and that a key reaches only the Apps of its own Organization.
