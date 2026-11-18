# alpha-control

The control plane: Organizations, their operational API keys and their Apps. It holds no roster key and no Secret value. No bearer credential it accepts can register, revoke, enrol or seal anything; only a signature that the KMS verifies does that.

## Routes

| Method and path | Bearer | Answer |
|---|---|---|
| `POST /v1/orgs` | operator token, or a key with scope `onboard` | Creates an unrooted Organization from `{name, owner_email, links?: [{issuer, external_id}], deploy_key?: {scopes}}` and answers `{org_id, deploy_key?: {id, token, scopes}}`. The token shows only once. An onboarding key may only claim links under the `issuer` on its row (`403` otherwise). A link that names another Organization, or repeats in the request, is `409`. A link names one Organization for good, so a repeated create with a used link, a retry after a lost response included, answers `409`. The deploy key token is shown once and cannot be recovered; the operator mints a new key once that route exists. |
| `PUT /v1/apps/{slug}` | a key with scope `apps:write` | Finds or creates the App and answers `{app_id, slug, endpoint}`. A slug of another Organization is `409`. Slugs are global and never reused. |
| `GET /healthz`, `GET /ready` | none | The process; the database. |

Errors are `{"error": {"code", "message", "request_id"}}`. The codes are `unauthorized`, `forbidden`, `malformed`, `conflict` and `internal`. Every mutation writes an `audit_log` row in its own transaction.

## Configuration (environment only)

| Variable | Meaning |
|---|---|
| `ALPHACOMPUTE_DATABASE_URL` | Postgres, database `alpha_control` |
| `ALPHACOMPUTE_OPERATOR_TOKEN_SHA256` | 64 hex digits: the SHA-256 of the operator's bearer |
| `ALPHACOMPUTE_PUBLIC_NAME` | the API's DNS name, for example `api.alphacompute.cc` |
| `ALPHACOMPUTE_ACME_KEY` | 64 hex digits; the ACME account key and the certificate key derive from it |

`alpha-control migrate` applies `migrations/` and returns. Otherwise the API listens on `:8443` (TLS 1.3, `http/1.1`) and gets a Let's Encrypt certificate for the public name through TLS-ALPN-01 on the same port, behind the SNI passthrough Gateway. `/healthz` and `/ready` also listen on plain `:8080` for the kubelet, because the API port has no certificate until the first order completes. SIGTERM drains open connections for at most ten seconds. Run one replica: the ACME challenge lives in the process.

No route mints an onboarding key. The operator inserts one: `insert into api_keys (id, token_sha256, scopes, issuer) values ('<uuid>', decode('<hex SHA-256 of the token>', 'hex'), '{onboard}', '<partner issuer>')`, with a null `org_id`.
