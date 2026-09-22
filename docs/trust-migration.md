# Customer approval, freshness and identity migration

Customer root/signing keys and custodian unseal shares stay on customer-controlled systems. Rafay receives already approved compose bytes, hashes and public pins. It may request deployment and inspect readiness; it cannot create customer signatures, reset the platform journal, replace a CA or unseal KMS. Provider credentials, independent KMS signer pins and worker/payment/meter keys belong to Alpha's operational boundary, outside customer-editable catalogue variables.

## Provisioning encryption

Shroud and the Python helper require an independently installed compressed secp256k1 KMS signer pin. A v1 signed environment key must bind the expected 20-byte provider app ID, match the offered 32-byte key and be at most five minutes old or one minute in the future. Unsigned/legacy-only responses fail before credential encryption/commit. Install the Alpha-owned adapter from `integrations/dstack-tee` before running `deploy/phala.py`. Its SDK is pinned to `c12e96adaeea51d1c79608123d41a6f521db46cd`; transitive Python packages still need a fully hashed release lock before production qualification.

## Self-certifying organization IDs

Hash `alphacompute/trust-org/v1\0 || canonical_Ed25519_SPKI_DER` with SHA-256, take the first 16 bytes and set UUID version 8 and variant bits. The UUID carries 122 fingerprint bits; the complete SPKI remains the anchor. This is not a claim of 256-bit identifier collision resistance. The CLI derives it by default; another root cannot first-claim it.

Existing UUID/root pairs remain anchored to the exact old root and allow idempotent replay. No automatic rename or root substitution occurs. Registration's optional `--org-id` supports legacy replay. Billing organization UUIDs are distinct from trust IDs and need an authorized mapping. Migration to a derived ID is new enrollment: the customer signs new key/revision/secret records, applications adopt the new public identity, then old approvals are revoked and archived. Never move certificates, KDF inputs or ciphertext by editing an organization column.

## Closed workload profile

Registration admits one Compose document with explicit services using literal SHA-256 image digests and supported image, port, restart, literal environment and approved volume fields. Build, include, extends, env files, command/entrypoint overrides, unknown loader fields and arbitrary host mounts are rejected. The outer pre-launch script is absent or exactly `:\n`. Interpolation is restricted to named operational configuration of `alpha-runtime`/`alpha-kms`. Approval covers exact serialized compose bytes.

The grammar cannot establish whether an approved image downloads executable code after boot. Image acceptance must establish reviewed entrypoints, no runtime code/model/plugin download, a complete dependency inventory and pinned release provenance. Images requiring dynamic code loading are not qualified by this profile. The historical open fixture remains a hash/signature vector but cannot be registered.


The guest Docker socket option introduced in the CLI is incompatible with this profile and is rejected, even for a service with the runtime socket. The historical `07-deploy-docker` fixture remains a hash vector but cannot be generated or registered as an approved workload.

## Platform document freshness

Customers provision an empty journal at an absolute customer-owned path and obtain a positive minimum version independently. The CLI requires `--platform-state` / `ALPHACOMPUTE_PLATFORM_STATE` and `--platform-min-version` / `ALPHACOMPUTE_PLATFORM_MIN_VERSION`. `--platform-max-age-seconds` must be positive and at most 86400, including for CA rotation. New versions are locked, appended and fsynced before pins are used. Lower versions, same-version different contents, future/stale documents, torn journals and missing journals fail closed.

Preserve the journal across reinstalls/hosts, protect it against rollback and trust the local clock. Recover lost journals from customer checkpoints and an independent minimum; never silently re-create them. This does not solve database rollback. KMS endpoints are HTTPS origins only, one to four, without redirects, credentials, query, fragment or path. Connect/read/total deadlines are 5/10/15 seconds per endpoint; response bodies are at most 2 MiB.
