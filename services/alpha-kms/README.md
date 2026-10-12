# alpha-kms

The key broker of the trust plane: six tables, fourteen `/v1` routes on one TLS port (`:8443`, TLS 1.3, `X25519MLKEM768`), plus `GET /healthz` (process only) and `GET /ready` (database checked, `{"sealed": …}`).

The Instance API is `POST /v1/attest/nonce`, `POST /v1/attest`, and two routes that need the Instance's leaf as a client certificate: `GET /v1/secrets/{name}` and `POST /v1/keys/derive`. The last answers `{"key"}`, 32 bytes derived from the organization's `org_key` and the leaf's App id for the requested `purpose`, the same for every Revision of the App; it is how an App holds a key no person ever sees, and nothing but an attested Instance reaches it.

`POST /v1/channel` answers an inner-channel handshake with the node's leaf and a ticket, and `PUT /v1/secrets/{name}` then takes the value either as `value` or as `sealed: {ticket, frame}`, whose plaintext begins with the signing digest of the put's payload, so a relay sees only ciphertext; any node of the deployment opens the ticket within ten minutes.

Control bodies are signed `ed25519` or `webauthn-es256`, a passkey's WebAuthn assertion over the same signing digest, accepted only on the origins and `rp_id` of the current platform document's `signer` and refused everywhere, stored signatures included, when the document has none; a passkey can be an organization's root key.

## Configuration (environment only)

| Variable | Meaning |
|---|---|
| `ALPHACOMPUTE_DATABASE_URL` | Postgres 18; the service user is a member of the `alpha_kms` role the migration creates |
| `ALPHACOMPUTE_KMS_ENDPOINTS` | comma-separated `https://…` of the KMS nodes; walked on a sealed start to `join` |
| `ALPHACOMPUTE_PCCS_URL` | PCCS for DCAP collateral, fetched per attestation |
| `ALPHACOMPUTE_PLATFORM_DOCUMENT_URL` | the release-signed platform document, fetched on start and every five minutes |
| `ALPHACOMPUTE_FORTANIX_CCM_URL` | optional `https://` endpoint of the Fortanix CCM GPU backend, which refuses every GPU until F8; unset, a `gpu_policy` listing `fortanix-ccm` refuses every GPU pod |
| `ALPHACOMPUTE_QUOTE_SOURCE` | unset or `dstack` on a prototype CVM; `coco-aa` (the CoCo attestation agent) or `coco-tsm` (configfs-tsm) on a Kata pod, as for `alpha-runtime` |
| `ALPHACOMPUTE_KMS_DEV_ROOT_KEK` | `dev-root` feature only: 64 hex digits used as the root KEK instead of the custodians' shares |

`alpha-kms migrate` applies `migrations/` (expand-only) and returns; run it as the schema owner. The service then learns what it is (`NodeGuest`): on a prototype CVM, its event log from the CCEL table and `/run/log/dstack`, whose compose-hash event is its Revision; on a Kata pod, the init-data it booted with (`/run/alpha-pod/cc_init_data`, projected from the pod's `cc_init_data` annotation), whose Revision v2 is its Revision and must name the CPU class `kata-qemu-tdx`. It generates its P-256 runtime key and X-Wing key and comes up sealed: it joins the first ready endpoint or waits for two `unseal` shares (or, on an empty database, a `bootstrap`). `GET /v1/node/evidence` serves a prototype node's quote and event log, or a Kata node's `alphacompute-evidence/2` (its init-data included) from the same CoCo source `alpha-runtime` uses; either way the X-Wing key is bound in `report_data[32..64]`. `GET /v1/node/key-ids` (PRD-05 draft) answers a serving node's CA key and certificate hashes and an HMAC check value of tenant-kek-root, for `alpha kms migrate` to show a join kept them. The serving node admits a joining node, and a custodian's CLI a node it seals to, through one appraisal, `alpha_attest::node` (`docs/kata-attestation.md`, "A KMS node on Kata").

The release key's public half is `release-key.pub`; replacing it means rebuilding the image.

The image is `images/kms/Dockerfile` (`alpha-kms`, or `alpha-kms-dev` with `--build-arg FEATURES=dev-root`), built and reproducibility-checked by `.github/workflows/release.yml`; the two nodes' compose and the operator's steps are `deploy/README.md`.

## Tests

`cargo test -p alpha-kms` runs the unit tests always and `tests/db.rs` when `DATABASE_URL` points at a Postgres the tests may `create database` in (each test makes its own). The db tests attest with real Phala quotes from `testdata/attest/*-keyed`, pinned to the capture's time, nonce key and collateral, and cover the server side of every route: bootstrap once, unseal with one and two shares, join only for an attested, listed, requesting node; the Control API's checks and idempotency; sealed puts and their refusals; attestation, release, revocation on the next call, the derived key's stability across Revisions and separation across Apps with an audit row for every refusal, re-verification of a tampered row, the anchor and chain rules, `cert_invalid` for a self-signed client certificate; the monotone platform document, a rollback refused with an audit row; and the append-only audit role.

`tests/passkey.rs`, on the same database, covers passkey signatures: a captured iCloud Keychain assertion claiming an organization, software passkeys on every Control route, attestation, secret read and key derivation, and the refusals without a signer, on a dropped origin, under another organization's key and for a stored row missing its fields.

`tests/kata.rs`, on the same database, covers Kata confidential pods (`docs/kata-attestation.md`) over synthetic quotes: Revision v2 registration, a GPU pod's and a CPU pod's leaf naming their Revision v2, evidence v2 through the route reaching DCAP, and an audit row for an unregistered or revoked Revision v2, a GPU backend the node does not run or that refuses, and a failed TD or GPU check. `tests/malicious_host.rs` is the malicious-host core suite (`docs/kata-attestation.md`): every case a hostile host can try on a Kata pod's attestation, each refused with its named reason and audit row; CI runs it as its own step.

`tests/kata_node.rs`, on the same database, covers a KMS node on Kata over synthetic quotes: its identity from CPU-class init-data, its evidence v2 served by `GET /v1/node/evidence`, genesis by three custodians through `alpha-cli`'s `verify_kata_node` and `bootstrap`, a second Kata node unsealed by two of them, a Kata node joining a prototype node (and refused, with its audit row, when its build is unlisted, listed as a prototype build, its quote binds another X-Wing key or no join was requested), evidence v2 through the join route reaching DCAP, and clients pinning the CA with both builds' Revisions.

`tests/cli.rs` drives `alpha-cli`'s library functions against the same in-process node (`crates/alpha-cli/README.md`).

Not here: the `alpha-runtime` pins, the backup/restore drill, anything that needs a live CVM with the guest agent's socket or a live Kata pod with its attestation agent (`GET /v1/node/evidence` of a prototype node, a DCAP-verified Kata node quote, a real `join` client run), and the HPKE/X-Wing known-answer tests (`alpha-crypto`).
