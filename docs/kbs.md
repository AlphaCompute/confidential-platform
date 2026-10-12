# The KBS facade (`alpha-kbs`)

`alpha-kms` speaks the Key Broker Service protocol of CoCo's guest components, so the Confidential Data Hub (CDH) and attestation agent (AA) in a Kata pod fetch resources (registry credentials, image decryption keys, sealed-secret keys, storage keys) from our authority instead of from Trustee (PRD-02 P1; doc 04, Decision 1, option C). It is also the server that CDH-managed encrypted storage, encrypted images and sealed secrets (Option B, deliverable 26) will use. The code is `services/alpha-kms/src/kbs.rs`.

## Where it runs: inside `alpha-kms`

The facade is three routes on the KMS's own listener, not a separate `services/alpha-kbs`:

- **One trust boundary.** Releasing a resource means opening a Secret under its organization's `org_key` or deriving an App key, both from `tenant_kek_root`, which exists only in the memory of a KMS TD after unseal. A separate service would either hold that root too (a second TD to attest, seal and audit) or receive plaintext secrets from the KMS over a new API (a second holder of every tenant secret). Either widens the boundary this facade exists to keep.
- **One database and one audit log.** Revisions, their revocation, Secrets and their signed documents, and the `audit_log` are the KMS's own tables. The facade reads them in the same process and writes its rows in the same append-only log, with no replication or second schema.
- **One appraisal.** The facade calls the same `instance::appraise_kata` and `instance::admit` as `POST /v1/attest`, so there is no second appraisal path that could drift.

The facade adds no state: the challenge nonce is the KMS's stateless five-minute nonce and the token is self-verifying, so any serving node answers any step.

## Pinned protocol

KBS protocol **0.4.0** (`/kbs/v0`) as guest-components commit [`d4dce5ce62294cfa741225f7e5b4527ea276f326`](https://github.com/confidential-containers/guest-components/tree/d4dce5ce62294cfa741225f7e5b4527ea276f326) speaks it. That is the `coco-guest-components` version in kata-containers 4.1.0's `versions.yaml`. It uses kbs-types 0.18.0. For everything used here (the RCAR client, CDH's token client, the TEE key pair and its JWE decryption, the TDX and NVIDIA attesters), its wire format is the same as v0.21.0 (`da8d93f2`, kbs-types 0.15.0), which Kata 4.0.0 and the plan's pinned stack ship. Trustee `258ea4ac` (both Kata releases) accepts exactly `=0.4.0` too. `kbs::GUEST_COMPONENTS` and `kbs::PROTOCOL_VERSION` record the pin. A guest built from another commit must be checked against these files before its version is accepted:

- `attestation-agent/kbs_protocol/src/client/{rcar_client,token_client}.rs`
- `attestation-agent/kbs_protocol/src/keypair.rs`
- `attestation-agent/deps/crypto/src/rust/ec.rs`
- `attestation-agent/attester/src/{tdx,nvidia}`

### 1. `POST /kbs/v0/auth`

The request is `{"version":"0.4.0","tee":"tdx","extra-params":{"supported-hash-algorithms":[…]}}`. It is refused (401) for any other version (`KBS Client Protocol Version Mismatch`), for any TEE other than `tdx`, and for a client that lists hash algorithms without `sha384`. The reply is:

```json
{"nonce": "<base64 of the KMS's 32-byte nonce>", "extra-params": {"selected-hash-algorithm": "sha384"}}
```

The nonce is the one `POST /v1/attest/nonce` mints: HMAC-bound to the node's nonce key, valid for five minutes. No session cookie is set.

### 2. `POST /kbs/v0/attest`

The request is kbs-types' `Attestation`:

```json
{
  "init-data": {"format": "toml", "body": "<the pod's init-data, verbatim>"},
  "runtime-data": {"nonce": "<from /auth>", "tee-pubkey": {"kty":"EC","crv":"P-256","alg":"ECDH-ES+A256KW","x":"…","y":"…"}},
  "tee-evidence": {
    "primary_evidence": {"quote": "<base64 TDX quote>", "cc_eventlog": "<base64 CCEL or null>"},
    "additional_evidence": "{\"nvidia\":{\"device_evidence_list\":[{\"arch\",\"uuid\",\"evidence\",\"certificate\"},…]}}"
  }
}
```

**Binding.** The agent places `SHA-384(JCS({"tee-pubkey", "nonce", "additional-evidence"}))`, zero-padded to 64 bytes, in the quote's `report_data`. It asks every GPU for a report over the first 32 bytes of `SHA-384(JCS({"nonce", "tee-pubkey"}))` (`rcar_client.rs` `get_composite_evidence`). The KMS recomputes both from the JSON it received (`kbs::binding`) and requires them byte for byte. The hex form that `POST /v1/attest` also accepts for the agent's REST API is not accepted here. So the quote binds the TEE key, the challenge nonce and every byte of the GPU evidence, and the GPU reports bind the key and nonce.

**TEE key.** Only the agent's default key is accepted: EC P-256 for `ECDH-ES+A256KW` (`tee_key_algorithm = "ECDH-ES+A256KW-P256"`, or unset). RSA and P-521 keys, and a key carrying any member beyond `kty, crv, alg, x, y`, are refused as `malformed`.

**Evidence.** The attestation becomes `alphacompute-evidence/2` (`kbs::evidence_v2`) and goes through `kata-tdx/1` unchanged (`docs/kata-attestation.md`):

- The quote is used as sent.
- The CCEL, when sent, is parsed as `alpha-runtime` parses the agent's (`alpha_tsm::boot_events`) and must replay to RTMR0..2.
- The init-data is required: without it, MRCONFIGID binds nothing.
- NVIDIA devices become GPU evidence, NVSwitches (`LS10`) left out (`alpha_tsm::coco::nvidia_gpus`). Additional evidence of any other device kind is refused, never ignored.
- The runtime class is the init-data's own, since the KBS protocol carries no claim of one; step 7's check (claim equals measured init-data) holds trivially.

The appraisal is DCAP and the TCB policy, the reference values for that runtime class, MRCONFIGID equal to the init-data digest, the `report_data` binding, then on the GPU class every backend the `gpu_policy` lists. The KMS's own checks follow, the same as for a leaf (`instance::admit`): a registered Revision v2, unrevoked and validly signed, whose runtime class, init-data, policy and GPUs are the appraised ones.

**Reply.** On success the reply is `{"token": "<JWT>"}`, also set as the cookie `kbs-session-id` (`Path=/kbs/v0; Secure; HttpOnly`) for the agent's own RCAR client. Every attempt, malformed bodies included, writes one `kbs.attest` audit row:

- `actor`: hex SHA-256 of the JCS of the TEE key, or `unauthenticated`.
- `evidence_sha256`: SHA-256 of the JCS of the body.
- On success: the organization, `object: revision:<hash>`, and the attestation result as `POST /v1/attest` records it, with `runtime_pubkey_sha256` naming the TEE key.
- On a refusal: `{"code", "message"}` with the reason of the first failing step.

**Token.** The token is an HS256 JWT (`kbs/token.rs`) under `HKDF-SHA256(tenant_kek_root, salt "alphacompute-kms/kbs-token/v1")`. Every serving node can verify a token any of them issued, and nothing outside a KMS TD can mint one. Its claims are:

```json
{"iss": "alphacompute-kms/kbs", "iat": …, "exp": iat + 3600,
 "revision": {"compose_hash", "app_id", "org_id"}, "tee-pubkey": {…}, "evidence_sha256": "sha256:…"}
```

It lives one hour, as a leaf does. The guest reads only `exp`. The KMS refuses any other header (`alg: none` included), a bad MAC, unknown claims and an expired token.

### 3. `GET /kbs/v0/resource/<repository>/<type>/<tag>`

The token comes as `Authorization: Bearer` (CDH's token client) or as the `kbs-session-id` cookie. The resource comes back as a flattened JWE sealed to the token's TEE key (`kbs/jwe.rs`, as Trustee's `ecdh_es_a256kw_p256`):

- Key agreement: `ECDH-ES+A256KW` with a fresh P-256 ephemeral key.
- KDF: Concat KDF (SHA-256, AlgorithmID `ECDH-ES+A256KW`, empty PartyUInfo and PartyVInfo, 256 bits).
- Key wrap: RFC 3394 of a fresh 256-bit content key.
- Content: `A256GCM`, with the AAD the base64url protected header `{"alg","enc","epk":{"crv","kty","x","y"}}` in the order the guest re-serializes it.

Only the pod holding that key's private half, generated inside the TD, can open it.

Every request writes one `kbs.resource` audit row: `actor` is the TEE key's digest (`unauthenticated` without a valid token), and `object` is `resource:<repository>/<type>/<tag>` (left out when the name is refused, since it is then unbounded text from the peer).

## Resource names

Deny by default. A name is one of these, with `<app>` the requesting pod's own App id in canonical lowercase hyphenated form:

| KBS URI | Released value | Rule |
|---|---|---|
| `kbs:///<app>/secret/<name>` | the organization's Secret `<name>` | exactly as `GET /v1/secrets/{name}`: its signed document lists the App, the row matches the document, the signer chains to the organization |
| `kbs:///<app>/key/<purpose>` | the App's derived key for `<purpose>`, 32 raw bytes | exactly as `POST /v1/keys/derive`: the same key for every Revision of the App |

A resource is released only after these checks, in this order (`kbs::release`):

1. The token verifies.
2. The token's Revision is, as its row is now, registered for that App and organization, unrevoked and validly signed. A Revision revoked after the token was issued gets 401, so the client attests again and that attestation is refused, with its reason, in a `kbs.attest` row.
3. The repository is the token's own App.
4. The type is `secret` or `key` and the tag is a valid Secret name or key purpose.
5. The App's release rule above.

Another App's id, upstream's `default` repository, any other type (`cert`, `resource-policy`, …), a name the KMS could not hold, and a Secret not listed for the App are all 404, with the same type whether the resource exists for someone else or not.

There is no write path. `POST`, `PUT` and `DELETE` on a resource are 405, and Trustee's admin endpoints (`resource-policy`, `attestation-policy`, `reference-value`, …) do not exist. Secrets enter only through the tenant-signed `PUT /v1/secrets/{name}`, and keys are derived, never stored. So no AlphaCompute operator holds a credential that reads a resource: every release is sealed to a key bound in a quote of a tenant-signed Revision.

Option B (deliverable 26) settles which resources CDH's secure mount, encrypted images and sealed secrets ask for. That is pending (`ponytail:` in `Resource::parse`). Until then `secret` and `key` are the only types, and the init-data generator writes URIs of these two forms, for example:

- `authenticated_registry_credentials_uri = "kbs:///<app>/secret/<name>"`
- a storage key: `kbs:///<app>/key/volume.<name>`

## Status codes the client acts on

Errors are kbs-types' `ErrorInformation`, `{"type": "https://github.com/confidential-containers/kbs/errors/<Kind>", "detail": "<code>: <message>"}`. The pinned client attests again on 401 (up to three times per request) and stops on 404.

| Status | Kind | When |
|---|---|---|
| 401 | `AttestationError` | `/auth` or `/attest` refused |
| 401 | `TokenNotFound`, `TokenVerifierError` | no token; a token that does not verify or has expired |
| 401 | `PolicyDeny` | the token's Revision is revoked or no longer verifies |
| 403 | `PolicyDeny` | a Secret row that does not match its signed document |
| 404 | `ResourceNotFound` | any name the rules above do not release; the facade disabled |
| 500 | `InternalError` | our fault |

## Reaching it: hostname and TLS

The facade answers only when `ALPHACOMPUTE_KBS_HOSTNAME` names the DNS name pods reach the KMS under. That name goes into the node's own leaf as a DNS SAN. Unset, every KBS route refuses with `kbs_disabled` (404) and no leaf carries a DNS name. Only node leaves ever carry a DNS name (Instance leaves have URI SANs only). A pod's KBS client trusting the KMS CA for this hostname therefore reaches a KMS node and nothing else the CA issued.

Which hostname, and whether it fronts the verifier pool's ingress or the dstack gateway, is pending (`ponytail:` at `alpha_kms::kbs_hostname`), with the init-data generator's CDH/KBS settings. Those settings (another change, in `alpha coco render`) are:

- AA `[token_configs.kbs]`: `url = "https://<hostname>"`, `cert` = the KMS CA PEM, `tee_key_algorithm` unset or `ECDH-ES+A256KW-P256`.
- CDH `[kbc]`: `name = "cc_kbc"`, the same `url`, `kbs_cert` = the same PEM.

TLS is the KMS listener's: TLS 1.3 with `X25519MLKEM768` only. The pinned guest's `reqwest` 0.13 uses rustls 0.23.40 with aws-lc-rs, whose default provider offers that group; confirm the handshake on the pinned guest image at M-B. TLS is what authenticates the KBS to the guest: a fake KBS could otherwise hand CDH a storage key it knows.

## Replay and what a hostile host gains

- **Challenge nonce.** It is stateless and valid for five minutes. Replaying an `/attest` body within that window yields a token for the same TEE key, which only the pod can use.
- **Token.** A token stolen in transit (TLS stops that) or replayed yields a JWE only the TEE key it names opens. Editing its claims, for example to swap in another key or App, breaks its MAC.
- **Binding.** A host that swaps the `tee-pubkey`, the nonce or the GPU evidence after the quote breaks the `report_data` binding.

| The host, or another pod | Refused with |
|---|---|
| a nonce another KMS minted, an expired one, or none | `nonce_invalid` |
| a quote over another challenge | `attestation_failed`: report_data is not bound to this key and nonce |
| its own `tee-pubkey` in place of the pod's | `attestation_failed`: report_data is not bound to this key and nonce |
| GPU evidence edited after the quote | `attestation_failed`: report_data is not bound |
| GPU reports over another nonce | `attestation_failed`: gpu `<i>`: report is not over this nonce |
| GPU evidence from a CPU-class pod | `attestation_failed`: … which runs no GPU |
| another pod's init-data | `attestation_failed`: MRCONFIGID is not the digest of the init-data sent |
| no init-data, an RSA key, a body that is not an `Attestation` | `attestation_failed`, `malformed` |
| an unregistered or revoked Revision | `attestation_unknown`, `revision_revoked` |
| a token of a since-revoked Revision | 401 `PolicyDeny` (`revision_revoked`) |
| another App's resource, an unknown type or name | 404 |
| no token, an expired, edited, foreign or `alg: none` token | 401 |

## Tests

- `services/alpha-kms/tests/kbs.rs` (Postgres, `DATABASE_URL`) runs pods over synthetic quotes through `kbs::attest_verified`, which no route reaches, as `tests/kata.rs` does through `instance::attest_verified`:
  - a GPU pod's and a CPU pod's handshake, with the audit rows;
  - their Secret and derived key opened as the guest opens them, the key equal to `/v1/keys/derive`'s;
  - every case in the table above;
  - the routes over TLS with a client that trusts only the KMS CA and resolves the hostname, as CDH does;
  - the facade off without a hostname;
  - no write or admin route.
- Without a database, `tests/kbs.rs` also opens sealed responses exactly as the guest's `decrypt_response` does, AAD re-serialization included, and checks a regression vector.
- The unit tests (`src/kbs/tests.rs`, `src/kbs/jwe.rs`, `src/kbs/token.rs`) take their vectors from upstream: kbs-types 0.18.0's `parse_attestation_ec`, `parse_request` and AAD vector, the agent's `Request`, the runtime-data JCS written out byte for byte, RFC 7518 Appendix C (Concat KDF) and RFC 3394 §4.6 (key wrap).
- `alpha_attest`'s `an_exact_binding_takes_report_data_byte_for_byte_and_its_own_gpu_nonce` covers the binding's half of `kata-tdx/1`.

Not yet: a capture from a B300 Kata pod's attestation agent (M1). The first one becomes a golden vector here, with its quote through the route's DCAP step.
