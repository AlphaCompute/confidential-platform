# alpha-cpu-app

A demonstration tenant: the smallest App that shows what the platform gives one. It terminates TLS on its Endpoint with the leaf the KMS issued its Instance, and it uses its App's key, derived by the KMS through `keys/derive` for purpose `hmac`, without ever disclosing it. A caller that pins the KMS CA and the Revision in the leaf's SAN learns from one request that this exact compose attested and that the key reached it.

No configuration and no Secret: nobody supplies a value. The key is read from the runtime socket on every request and never kept.

## Routes

- `GET /healthz?challenge=<value>` — `200 {"schema_version": 1, "ready": true, "secret_access": true, "org_id", "app_id", "compose_hash", "challenge"}` when the App's key was obtained now; `secret_access` keeps its name and means exactly that. `challenge` is echoed, so the answer is not one recorded earlier. `503` when the key was not obtained: the runtime is gone or the KMS refused. Unlike the platform's own services, health here depends on the key — that dependency is what the route exists to show.
- `POST /v1/hmac` — the body, at most 64 KiB, answered with `200 {"hmac_sha256": "<hex>"}` under the App's key; `503` as above.

`app.example.yaml` is the spec to fill in and deploy.

**What this leaves open:** the key is the same for every Revision of the App and changes only with the organization's root key, so a new Revision does not rotate it. Revoking the Revision ends the runtime, and with it this process, at the next renewal.

## Tests

`cargo test -p alpha-kms --test runtime a_demonstration_app` runs the App against a real KMS and Postgres (`DATABASE_URL`), the runtime's socket and a CA-pinned client, with no Secret put.
