# alpha-control

The control plane: Organizations, their operational API keys and their Apps. It holds no roster key and no Secret value. No bearer credential it accepts can register, revoke, enrol or seal anything; only a signature that the KMS verifies does that.

## Routes

| Method and path | Bearer | Answer |
|---|---|---|
| `POST /v1/orgs` | operator token, or a key with scope `onboard` | Creates an unrooted Organization from `{name, owner_email, links?: [{issuer, external_id}], deploy_key?: {scopes}}` and answers `201 {org_id, deploy_key?: {id, token, scopes}}`. The token shows only once. An onboarding key may only claim links under the `issuer` on its row (`403` otherwise). A link that names another Organization, or repeats in the request, is `409`. A retry is a call by the same caller with the same name, `owner_email` and links within one hour of the first create. It answers `200` with the same `org_id`. If it asks for a deploy key, the key of the first answer is revoked and a new token is shown. Any other repeat of a used link is `409`. Without links, every call creates a new Organization. |
| `POST /v1/orgs/{org}/disable` | operator token | Every key of the Organization stops working. Its id stays claimed. `204`. |
| `DELETE /v1/orgs/{org}/keys/{id}` | operator token, or a key with scope `org:admin` in that Organization | Revokes the key. `204`. |
| `PUT /v1/apps/{slug}` | a key with scope `apps:write` | Finds or creates the App and answers `{app_id, slug, endpoint}`. A slug of another Organization is `409`. Slugs are global and never reused. |
| `POST /v1/apps/{slug}/revisions` | a key with scope `apps:write` | Takes `{catalog: <catalog file>}`. Verifies the file under the `catalog_key` of the current platform document and renders it for the App: its id and `<slug>.app.alphacompute.cc`. Checks the init-data against the document's `kata_policy` and `kms_ca_pem`, then stores it. Answers `201 {compose_hash}`, or `200` for a Revision already stored. It awaits approval by a roster key. A refused file is `400` with the catalog verdict in the message. |
| `GET /v1/apps/{slug}/revisions/{compose_hash}` | a key with scope `apps:read` | `{compose_hash, init_data, pod, shape, catalog}`. |
| `GET /healthz`, `GET /ready` | none | The process; the database. |

Errors are `{"error": {"code", "message", "request_id"}}`. The codes are `unauthorized`, `forbidden`, `malformed`, `not_found`, `conflict`, `unavailable` and `internal`. A revoked key, or any key of a disabled Organization, is `401`. Every mutation writes an `audit_log` row in its own transaction.

## Configuration (environment only)

| Variable | Meaning |
|---|---|
| `ALPHACOMPUTE_DATABASE_URL` | Postgres, database `alpha_control` |
| `ALPHACOMPUTE_OPERATOR_TOKEN_SHA256` | 64 hex digits: the SHA-256 of the operator's bearer |
| `ALPHACOMPUTE_PUBLIC_NAME` | the API's DNS name, for example `api.alphacompute.cc` |
| `ALPHACOMPUTE_PLATFORM_DOCUMENT_URL` | the release-signed platform document. `POST /v1/apps/{slug}/revisions` fetches it on each call; a version below the highest one accepted (kept in the database), or a failed fetch, is `503`. Build with feature `dev` to verify it under the dev release keys |
| `ALPHACOMPUTE_ACME_KEY` | 64 hex digits; the ACME account key and the certificate key derive from it |

`alpha-control migrate` applies `migrations/` and returns. Otherwise the API listens on `:8443` (TLS 1.3, `http/1.1`) and gets a Let's Encrypt certificate for the public name through TLS-ALPN-01 on the same port, behind the SNI passthrough Gateway. `/healthz` and `/ready` also listen on plain `:8080` for the kubelet, because the API port has no certificate until the first order completes. SIGTERM drains open connections for at most ten seconds. Run one replica: the ACME challenge lives in the process.

No route mints an onboarding key. The operator inserts one: `insert into api_keys (id, token_sha256, scopes, issuer) values ('<uuid>', decode('<hex SHA-256 of the token>', 'hex'), '{onboard}', '<partner issuer>')`, with a null `org_id`.
