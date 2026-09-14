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

`cargo test -p alpha-kms` runs the unit tests always and `tests/db.rs` when `DATABASE_URL` points at a Postgres the tests may `create database` in (each test makes its own). The db tests attest with real Phala quotes from `testdata/attest/*-keyed`, pinned to the capture's time, nonce key and collateral, and cover kms-spec §7 items 1 (server side), 2, 3, 4, 5, 7 (server side: join checks, unseal with one and two shares, bootstrap on a non-empty database), 9 (route 1 checks, the repeat), 11 and 12.

Out of scope here and covered elsewhere: item 6 and the CLI halves of 1, 7 and 10 (`alpha-client`, `alpha-cli`), item 8 (backup/restore drill), item 9's real-CVM half and every `GET /v1/node/evidence` or `join` client run (a live CVM with configfs-tsm; the `alpha-runtime` deploy), item 10's KATs (`alpha-crypto`).
