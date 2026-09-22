# alpha

Platform-document use now requires customer-owned freshness state. See [trust and identity migration](../../docs/trust-migration.md) before upgrading. Signing and unseal authority stay outside Rafay.

The command line of the trust plane: keys, signed Control calls, the platform document, deploys, and the custodians' `bootstrap` and `unseal`. Every command prints one JSON document on success; exit code 1 means a check refused (the message names it), 2 means usage.

## Configuration

Flags or environment, nothing else:

| Flag | Environment | Used by |
|---|---|---|
| `--endpoints a,b` | `ALPHACOMPUTE_KMS_ENDPOINTS` | `call`, `deploy` — tried in turn on a connection failure or a 5xx, never on a 4xx |
| `--platform-document-url` | `ALPHACOMPUTE_PLATFORM_DOCUMENT_URL` | `call`, `deploy`, `unseal`, `bootstrap` — fetched and verified under the compiled-in release key on every run |
| `--pccs-url` | `ALPHACOMPUTE_PCCS_URL` | `unseal`, `bootstrap`; default `https://pccs.phala.network` |
| `--shroud-url`, `--shroud-api-key` | `ALPHACOMPUTE_SHROUD_URL`, `ALPHACOMPUTE_SHROUD_API_KEY` | `deploy` without `--register-only`; the key goes to shroud-go only, never to the KMS |

The passphrase of a key file is prompted on the terminal, or read as one line from stdin when stdin is a pipe.

## Commands

- `alpha keygen --admin --out admin.key` — an Ed25519 key; prints its SPKI DER (base64url), the `public_key` of a key-registration document. `--custodian` makes an X-Wing key and prints its 1216-byte public key. One file format for both: the seed under scrypt (`log_n` 15, `r` 8, `p` 1) and AES-256-GCM, KDF and AEAD named in the file, the algorithm bound as AEAD aad.
- `alpha register-root-key --key root.key --principal-id <uuid> [--label text]` derives the new trust organization UUID from the root's canonical SPKI and signs its registration. Another root cannot first-claim that identifier. `--org-id` is optional only for replay of an existing legacy UUID bound to that exact root. Billing/product organization IDs remain separate and need an authorized mapping; see the migration document.
- `alpha call <route> --key admin.key --key-id <uuid> [--value file] payload.json` — one Control mutation: `register-revision`, `revoke-revision`, `put-secret`, `register-key`, `revoke-key`. The payload is signed under the route's context (`--context` overrides it) with `issued_at` filled from the clock when absent (never for `register-revision`) and, for `put-secret`, `content_sha256` computed from `--value`; the path comes from the payload (`compose_hash`, `name`, `key_id`). The server is pinned to `kms_ca_pem` of the platform document. `--key-id` is the roster id from the reply that registered the key.
- `alpha sign --release-key release.key document.json` — the signed artifact `{document, signature}` the release URL serves; the document must already be a well-formed platform document. `alpha sign --check artifact.json` verifies it under the compiled-in key and prints `version`, the SPKI SHA-256 of `kms_ca_pem` and the Revision list: the values a tenant puts into `ALPHACOMPUTE_KMS_CA_SPKI_SHA256` and `ALPHACOMPUTE_KMS_REVISIONS`.
- `alpha deploy --key admin.key --key-id <uuid> app.yaml` — the tenant's YAML (`testdata/manifest/05-deploy/app.yaml` is the shape: `app_id`, `services` with `image`, `environment` and `socket: true` for the containers that get `/run/alpha`, `runtime` with the image and the two pins, `resources` for the CVM shape) becomes `app-compose.json` in Phala's form with the `alpha-runtime` service last, is checked as the KMS will check it, signed and registered as a Revision, then handed to shroud-go's `POST /v1/apps/{id}/deploy` under the organization's API key. `--register-only` stops after the Revision. `docker: true` and command/entrypoint overrides are refused by the closed workload profile. A guest daemon socket would allow creating workloads outside the approved dependency set; approve a new immutable image instead. See [workload approval](../../docs/trust-migration.md#closed-workload-profile).
- `alpha unseal --share share-1.json --key custodian.key --endpoint https://node` — reads a sealed node's evidence, verifies it, and only then re-seals the custodian's share to that node. The share file keeps the highest platform-document `version` the custodian has verified; a document below it is refused.
- `alpha bootstrap --custodians c1.pub c2.pub c3.pub --endpoint https://node` — genesis on an empty database: the same verification as `unseal`, then the sealed body of three custodian public keys (each file holds what `keygen --custodian` printed). Genesis knows nothing of any organization: it generates the root KEK, splits it and writes the two intermediates. Writes `share-1.json` … `share-3.json` into the current directory (one per custodian, sealed to their key; hand each to its holder and delete it), prints `kms_ca_pem` (to be written into the platform document before it is re-signed) and its SPKI SHA-256.

What `unseal` and `bootstrap` check, in this order, before anything is sealed to a node: the platform document's release signature and that its `version` is not below the remembered one; a fresh 32-byte nonce in `GET /v1/node/evidence`; the evidence appraised locally with the node's X-Wing key bound in `report_data[32..64]`; the node's measured `compose_hash` in `kms_revisions`; the TLS server's SubjectPublicKeyInfo equal to the attested `runtime_pubkey`. The share or body is then sealed to that X-Wing key and posted over a connection pinned to that SPKI; `bootstrap` verifies the reply's ECDSA signature under `runtime_pubkey` before writing any share.

## Tests

`cargo test -p alpha-cli`: the key file, the route table, the compose generators against `testdata/manifest/05-deploy` and `06-kms-node` (`examples/kms_compose.rs` renders the KMS node's compose for the release workflow, `deploy/README.md`), `sign`/`--check`, and the verification function over the real keyed node quote in `testdata/attest/phala-0.5.9-1c-2g-keyed` — accepted over its own key; refused with a substituted `xwing_pubkey`, a platform document below the remembered version, a server key other than the attested one, or a Revision outside `kms_revisions`.

`cargo test -p alpha-kms --test cli` (with `DATABASE_URL`) drives the same library functions against an in-process node: `call` on all five Control routes and its refusal of a KMS whose chain does not end at the pinned CA, `register-root-key` claiming an identifier (a repeat of the document giving the same row, another key on that identifier refused) and the root key then registering a signing key, `deploy --register-only` with the vector, `sign`/`--check` feeding the node and the admin pin, and `bootstrap` succeeding once and never again followed by `unseal` of a second node with two shares.

What needs a live CVM and is not tested here: `GET /v1/node/evidence` itself (the quote comes from the guest agent's socket, so the in-process tests take the node's X-Wing key from the `Node` and cover the evidence path with the pure function), a real `unseal`/`bootstrap` run against a Phala node with collateral from the PCCS, and the shroud-go half of `deploy`, which only a live deploy exercises.
