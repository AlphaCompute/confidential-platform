# alpha-runtime

The sidecar inside every Instance. On start it makes a P-256 key in memory (one per Instance
life), asks the KMS for a nonce, quotes `report_data` over its key and the nonce through
the guest agent's socket, sends the quote and the dstack event log to `POST /v1/attest`, and keeps the
one-hour leaf it gets back, renewing it with fresh evidence ten minutes before it expires. If
the KMS answers `revision_revoked` — at the first attestation, a renewal, a secret or a key read — the
process exits with code 78 and the socket disappears. Startup and configuration refusals exit
with 1 and name the check; a drain on SIGTERM exits with 0.

Configuration is three environment variables and nothing else. `ALPHACOMPUTE_KMS_CA_SPKI_SHA256`
(`sha256:<hex>` of the KMS CA's SubjectPublicKeyInfo) and `ALPHACOMPUTE_KMS_REVISIONS`
(comma-separated `sha256:<hex>`) are in the measured compose and are all the runtime trusts:
before the first request it refuses a KMS whose chain does not end at a CA with that key or
whose leaf carries no listed Revision, and moves on to the next entry of
`ALPHACOMPUTE_KMS_ENDPOINTS`. An empty Revision list is refused at start.

The socket is `/run/alpha/runtime.sock`, HTTP/1.1 JSON, no authentication (access is the right
to the socket), and comes up only after the first attestation succeeded:

| Route | Reply |
|---|---|
| `GET /v1/identity` | `{app_id, org_id, compose_hash, certificate_chain, tls_private_key, attestation_result, app_compose}` — the ids and the hash are read from the leaf's SANs; `tls_private_key` is the PKCS#8 DER, base64url; `app_compose` is the Instance's `app-compose.json`, read once at start from the guest agent's `Info` and refused unless its SHA-256 is the leaf's Revision digest, so a service can show a client which compose it runs |
| `GET /v1/secrets/{name}` | the KMS reply, fetched over mTLS with the leaf and cached until the leaf expires; a KMS error passes through in its envelope with its status |
| `GET /v1/keys/{purpose}` | the KMS reply to `POST /v1/keys/derive` for that purpose, `{key}`, 32 bytes base64url: the App's own key, the same for every Revision of the App; fetched and cached like a secret, up to 64 purposes per leaf, beyond which a key is derived again on every read |
| `GET /healthz` | `{attested, cert_not_after}` |

With no valid leaf (the last renewal failed and the hour is over) the first three answer
`503 not_attested`. A cached secret or key is served until the leaf expires even after its Revision is
revoked; the next call that reaches the KMS is the one that ends the process.

## Tests

`cargo test -p alpha-runtime` covers the configuration parser, the renewal schedule and the
exit-code decision. The end-to-end tests are `services/alpha-kms/tests/runtime.rs` (they need
`DATABASE_URL`): a runtime holding the key of the `phala-0.5.9-1c-2g-keyed` capture, with a
quote source that hands out the captured quote for exactly the `report_data` that CVM quoted
over, attests against the in-process node clocked to the instant the capture's nonce was
minted — so `POST /v1/attest/nonce` returns that nonce and the appraisal is the real one. They
prove the four routes, the refusal of a compose that is not the leaf's Revision, a tenant backend pinning the KMS CA and reading the Revision from the
SAN URI with rustls and webpki alone, the refusal of a listener under another CA or with an
unlisted Revision (and the walk to the next endpoint), the cache expiring with the leaf, and
`revision_revoked` ending the runtime with 78.

What only a live CVM proves: the real quote and `Info` from the guest agent's socket, the real
event log from the CCEL table and `/run/log/dstack`, that the registered `compose_hash` equals
the CVM's `compose-hash` event (`docs/kms-spec.md` §7 item 9), and the image running on Phala
Cloud with the three host mounts of `docs/manifest.md`.

## Image

`images/manager/Dockerfile` builds the binary as a static musl executable in a stage with no
network (dependencies are fetched in the stage before) and ships it alone in a `scratch` image;
the base image is pinned by digest and every timestamp comes from `SOURCE_DATE_EPOCH`, so one
commit gives one image digest. `.github/workflows/release.yml` builds it twice, the second time
with `--no-cache`, and fails when the two differ.
