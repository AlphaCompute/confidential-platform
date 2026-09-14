# alpha-kms

The key broker of the trust plane: six tables, twelve `/v1` routes on one TLS port (`:8443`, TLS 1.3, `X25519MLKEM768`), plus `GET /healthz` (process only) and `GET /ready` (database checked, `{"sealed": …}`).

## Configuration (environment only)

| Variable | Meaning |
|---|---|
| `ALPHACOMPUTE_DATABASE_URL` | Postgres 18; the service user is a member of the `alpha_kms` role the migration creates |
| `ALPHACOMPUTE_KMS_ENDPOINTS` | comma-separated `https://…` of the KMS nodes; walked on a sealed start to `join` |
| `ALPHACOMPUTE_PCCS_URL` | PCCS for DCAP collateral, fetched per attestation |
| `ALPHACOMPUTE_PLATFORM_DOCUMENT_URL` | the release-signed platform document, fetched on start and every five minutes |
| `ALPHACOMPUTE_KMS_DEV_ROOT_KEK` | `dev-root` feature only: 64 hex digits used as the root KEK instead of the custodians' shares |

`alpha-kms migrate` applies `migrations/` (expand-only) and returns; run it as the schema owner. The service then reads its event log from the CCEL table and `/run/log/dstack`, generates its P-256 runtime key and X-Wing key, and comes up sealed: it joins the first ready endpoint or waits for two `unseal` shares (or, on an empty database, a `bootstrap`).

The release key's public half is `release-key.pub`; replacing it means rebuilding the image.

## Tests

`cargo test -p alpha-kms` runs the unit tests always and `tests/db.rs` when `DATABASE_URL` points at a Postgres the tests may `create database` in (each test makes its own). The db tests attest with real Phala quotes from `testdata/attest/*-keyed`, pinned to the capture's time, nonce key and collateral, and cover the server side of every route: bootstrap once, unseal with one and two shares, join only for an attested, listed, requesting node; the Control API's checks and idempotency; attestation, release, revocation on the next call, re-verification of a tampered row, the anchor and chain rules, `cert_invalid` for a self-signed client certificate; the monotone platform document; and the append-only audit role.

`tests/cli.rs` drives `alpha-cli`'s library functions against the same in-process node (`crates/alpha-cli/README.md`).

Not here: the `alpha-runtime` pins, the backup/restore drill, anything that needs a live CVM with configfs-tsm (`GET /v1/node/evidence`, a real `join` client run), and the HPKE/X-Wing known-answer tests (`alpha-crypto`).
