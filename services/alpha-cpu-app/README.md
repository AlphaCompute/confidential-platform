# alpha-cpu-app

A demonstration tenant: the smallest App that shows what the platform gives one. It terminates TLS on its Endpoint with the leaf the KMS issued its Instance, and it uses a Secret released to that Instance without ever disclosing it. A caller that pins the KMS CA and the Revision in the leaf's SAN learns from one request that this exact compose attested and that its Secret reached it.

No configuration. One Secret, `cpu-app-key`: at least 32 bytes, put by an admin of the organization for this App (`alpha call`), read from the runtime socket on every request and never kept.

## Routes

- `GET /healthz?challenge=<value>` — `200 {"schema_version": 1, "ready": true, "secret_access": true, "org_id", "app_id", "compose_hash", "challenge"}` when the Secret is readable now; `challenge` is echoed, so the answer is not one recorded earlier. `503` when it is not: the runtime is gone, the KMS refused, or the value is shorter than a key. Unlike the platform's own services, health here depends on the Secret — that dependency is what the route exists to show.
- `POST /v1/hmac` — the body, at most 64 KiB, answered with `200 {"hmac_sha256": "<hex>"}` under the Secret as the key; `503` as above.

`app.example.yaml` is the spec to fill in and deploy.

**What this leaves open:** the runtime caches a Secret until its leaf expires, so a Secret withdrawn from the App stays readable for up to an hour; revoking the Revision ends the runtime, and with it this process, at the next renewal.

## Tests

`cargo test -p alpha-kms --test runtime a_demonstration_app` runs the App against a real KMS and Postgres (`DATABASE_URL`), the runtime's socket and a CA-pinned client.
