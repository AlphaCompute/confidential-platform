# Trustee, fed by alpha-kms (PRD-02 deliverable 26, Option B)

Option B gives Kata pods CoCo's own features that need a key broker: sealed secrets, encrypted
images, and (on a later Kata) KBS-keyed volumes. The guest's Confidential Data Hub (CDH) and
attestation agent (AA) speak the KBS protocol. Ryan Tharp decided the broker they talk to is
**Trustee v0.21.0** (KBS, Attestation Service, RVPS) in the verifier pool, "fed by alpha-kms"
(PRD Decision 1, option D; Q14). The generator side, the init-data that points a pod at the KBS,
and the resource contract are in `docs/encrypted-storage.md` (#93).

The risk the PRD names is "two verifiers whose policies must agree". This design makes Trustee a
second gate in front of alpha-kms, never a second authority: **alpha-kms decides every release
itself, for the exact pod, from its own platform document and Revisions, and audits it with that
pod's Revision.** Trustee's own policies are generated from the same inputs and can only refuse
more.

## The pieces

```
 workload pod (Kata TD)                 verifier pool: alpha-trustee pod (Kata TD)                 verifier pool
 ┌──────────────┐  TLS (KMS CA pin)     ┌─────────────────────────────────────────────────────┐    ┌──────────┐
 │ AA, CDH      │──passthrough ingress─▶│ alpha-trustee-feed :8443 (gate)                     │mTLS│ alpha-kms│
 └──────────────┘                       │   │ loopback only:                                  │───▶│          │
                                        │   ├─▶ KBS 127.0.0.1:8080 ── AS 127.0.0.1:50004 ─┐   │    └──────────┘
                                        │   │     │ Vault backend                 RVPS :50003   │
                                        │   └─ :8200 ◀┘ (one released value per request)      │
                                        └─────────────────────────────────────────────────────┘
```

- **Trustee images**: upstream v0.21.0 by digest (`deploy/coco/platform/env/alpha-trustee.env`;
  alpha-infra pins the same digests). KBS, AS and RVPS each listen on the TD's loopback only, as
  their pinned command lines say; no Service or port exposes them, so "reachable only from the
  KBS" holds inside the TD, not just by NetworkPolicy (which the host's CNI enforces).
- **`alpha-trustee-feed`** (`services/alpha-trustee-feed`), our one process in the pod:
  - attests the pod to alpha-kms as the **Trustee App**: an App like any other, whose Revision v2
    is registered by the platform organization **and** listed in the platform document's
    `trustee.revisions`;
  - writes the three containers' configuration and keys into an in-guest `emptyDir` before they
    start: the KBS admin API's only identity (an Ed25519 key generated in the TD), the AS's
    token-signing key (the Trustee App's derived key `trustee.as-token`, so both replicas' tokens
    verify at either KBS), the site PCCS and NRAS for the AS;
  - fetches the state alpha-kms generates and installs it through the admin API on loopback;
  - terminates the KBS's public TLS and passes on only `POST /kbs/v0/auth`, `POST /kbs/v0/attest`
    and `GET /kbs/v0/resource/<app>/<type>/<tag>`;
  - serves the KBS's `Vault` resource backend on loopback.
- **alpha-kms** (`services/alpha-kms/src/trustee.rs`): five routes, below, and two tables
  (`migrations/20261012000000_trustee.sql`).
- **`alpha-trustee`** (`crates/alpha-trustee`): what both sides share: the resource contract, the
  reading of Trustee's attestation token (EAR), the policy and reference-value generators, the wire
  bodies.

## Which Trustee mechanism, and why

Trustee v0.21.0 can serve resources from (`kbs/src/plugins/implementations/resource/backend.rs`,
`kbs/docs/resource_storage_backend.md`):

| Mechanism | Per request? | Fits? |
|---|---|---|
| `kvstorage` (memory, LocalFs, LocalJson, Postgres, Redis) | no: values stored in Trustee | a plaintext copy of every resource in Trustee; refused |
| `Aliyun`, `Aws`, `Gcp` | yes | cloud secret managers; not ours |
| `Vault` (KV v1, `vault_kv.rs`, vaultrs 0.8.0) | **yes**: one `GET {vault_url}/v1/{mount}/{repo}/{type}/{tag}` per read | **used**: the feed answers it on loopback |
| `external` plugin (`kbs/docs/ext_plugin.md`, `protos/plugin.proto`) | yes | **no**: served under `/kbs/v0/external/<backend>/…`, not `/kbs/v0/resource/…` where CDH reads, not compiled into the release images (`EXTERNAL_PLUGIN=false` in `kbs/docker/coco-as-grpc/Dockerfile`), and its request carries no attestation claims (field 5 `attestation_context` is reserved) |

No backend or plugin learns which pod asked: the KBS gives them only the path. So the per-request
check with the pod's identity happens in the feed's gate, in front of the KBS, and the backend only
ever answers with the value alpha-kms released for the request in flight (one request at a time,
the value handed over once, for that path only, then dropped).

## A pod's way through

1. **Attestation.** The AA runs the KBS handshake through the gate. The KBS's AS appraises the TD
   (DCAP, the init-data against MRCONFIGID, RVPS reference values) and each GPU (NRAS) and issues a
   token. The gate passes that token back **only after** `POST /v1/trustee/attestations` with the
   token and the init-data the AA sent. alpha-kms:
   - verifies the token before reading any claim (`alpha_trustee::ear::verify_token`): ES256 and
     nothing else (Trustee v0.21.0's AS signs EARs ES256 with a P-256 key only), no `crit`, no
     `kid`, a header `jwk` only if it is that key, the signature under the **Trustee App's
     `trustee.as-token` key, which the KMS derives itself** for the reporting Trustee pod's App
     (exactly as the feed got it from `/v1/keys/derive`), `exp` after now, `iat`/`nbf` not ahead
     by more than a minute. The key is never taken from the token or fetched;
   - reads the token's claims (`alpha_trustee::ear`): every submodule `affirming`, one TDX TD,
     GPUs `gpu0..`;
   - rebuilds the pod's Revision v2 from the init-data, checks that its digest is the token's
     MRCONFIGID, that the Revision is registered, unrevoked and validly signed;
   - applies its own rules to what Trustee found (`trustee::check_claims`): the guest image chosen
     by `kata-tdx/1`'s own rule (`alpha_attest::kata::kata_tdx_reference`, handed every register):
     MRTD and RTMR0..2 one `kata-tdx` reference value **of the Revision's runtime class**, RTMR3
     not compared, as the profile does not (the guest's runtime register; a reference value
     cannot name it, and what the pod runs is bound by MRCONFIGID), `tcb_status` and advisories by
     the document's `policy`, no debug TD, and for GPUs the same decision `/v1/attest` takes
     (`gpu::check_gpus`: count and model of the Revision, distinct devices, CC mode, every NRAS
     claim `nras::claim_report` requires, driver and VBIOS minimums);
   - records the attestation (`trustee_attestations`, by the token's digest, with the token) and audits
     `trustee.attest` with the pod's Revision.
   Refused or unreachable, the pod gets no token.
2. **Resource.** CDH asks `GET /kbs/v0/resource/<app>/<type>/<tag>` with the token. The gate asks
   `POST /v1/trustee/releases` first; alpha-kms releases only if:
   - the token is one a listed Trustee build reported and it has not expired (at most an hour);
   - the stored token still verifies under the reporting Trustee App's key, and its claims still
     pass `check_claims` for the pod's registered Revision **under the platform document as it is
     now**: a reference value, TCB status, advisory or GPU rule withdrawn since admission refuses
     the next read;
   - the pod's Revision is still registered, unrevoked and validly signed: **a revocation refuses
     the next read at once**;
   - the resource is the pod's own App's, never a Trustee App's, never a reserved purpose
     (`trustee.*`, `kms.*`);
   - the App's tenant-signed grant covers it;
   - the feed's installed state is not older than `trustee.max_state_age_secs`.
   It audits `trustee.release` with the resource, the pod's Revision and the Trustee build. Then
   the gate installs the current resource policy again (a restarted KBS would run its built-in
   allow-all), hands the value to its backend and lets the KBS evaluate its own policy over the
   token; the KBS seals the value to the pod's TEE key (`ECDH-ES+A256KW`).

What each type is backed by, at the KMS (`alpha_trustee::resource`), matches the contract of
`docs/encrypted-storage.md`:

| Resource | Released value |
|---|---|
| `secret/<name>` | the App's tenant-signed Secret `<name>`, exactly as `GET /v1/secrets/<name>` |
| `key/<purpose>` | the App's derived key, exactly as `POST /v1/keys/derive` |
| `image-key/<name>` | the tenant's Secret `image-key.<name>`, which must be 32 bytes |
| `sealed-secret-key/<name>` | the tenant's Secret `sealed-secret-key.<name>`, which must be a public P-256 JWK (one with `d` is refused) |

The tenant puts those Secrets with `PUT /v1/secrets` as any other, listing the App. `secret/`
never names a Secret under the other two prefixes, so the three stay apart.

## The tenant's opt-in

`PUT /v1/trustee/grants/{app_id}` (`alpha call trustee-grant`), signed under
`alphacompute/trustee-grant/v1` by a key of the App's organization:

```json
{ "app_id": "…", "resources": [{ "type": "secret", "tag": "db-password" }, { "type": "key", "tag": "*" }], "issued_at": "…" }
```

One per App, replaced only by a later `issued_at`; `[]` opts out. Entries are one of the four
types and a valid tag, or `*` for every tag of the type. Refused: an App without a Revision in the
signer's organization, a Trustee App, reserved purposes, duplicates. Each grant is audited
(`trustee.grant`) and receipted, and its signature and signer's chain are checked again on every
use, so an edited row stops the state rather than admitting anything.

## How the two verifiers are kept in agreement

| Decision | Trustee (generated, `alpha_trustee::policy`) | alpha-kms (authoritative) |
|---|---|---|
| TD genuine, collateral current | AS DCAP (`intel_dcap`), `collateral_expiration_status == "0"` | trusted from Trustee: the quote never reaches the KMS |
| TCB status, advisories, debug | `default_cpu` from the document's `policy` | the same `policy`, re-applied to the token's claims |
| Token | KBS: signed under the AS's certificate (`trusted_certs_paths`) | ES256 under the Trustee App's `trustee.as-token` key, derived by the KMS; re-verified on every release |
| Guest image | `default_cpu`: MRTD and RTMR0..2 one tuple of the RVPS value `alpha_kata_tdx`, generated from the document's `kata-tdx` reference values | `kata-tdx/1`'s own rule (MRTD and RTMR0..2, not RTMR3) for one `kata-tdx` reference value **of the Revision's runtime class**, on every attestation and release |
| Init-data binding | AS checks the init-data the AA sent against MRCONFIGID; `default_cpu` requires it was sent | rebuilds the Revision from the same init-data, checks its MRCONFIGID |
| Revision | resource policy: MRCONFIGID one of the App's admitted Revisions (registered, unrevoked, signed, seen by a Trustee attestation); stale within the refresh interval | registered, unrevoked, signed **now**, on every attestation and release |
| GPUs | `default_gpu`: every claim `nras::claims::REQUIRED` lists, an allowed hardware model, the document's CC-mode claim; resource policy: count and hardware model per Revision | `check_gpus` on the claims, versions included; refused unless `gpu_policy.verifiers` is exactly `[nras]` |
| Resource | resource policy: App = repository, grant covers type and tag | the same, from the signed grant, plus the reserved names |
| Freshness | the feed refreshes every 30 s; past `not_after` it installs deny-all and refuses | refuses a release on state older than `max_state_age_secs` |

Both sides read one release-signed platform document and one database; Trustee never has a rule
the KMS lacks that could admit more, and every release passes the KMS's rules for the exact pod.

## The KBS's TLS certificate

A pod's init-data pins the KBS by URL and certificate (`aa.toml`, `cdh.toml`; the Revision's
`kbs.cert_spki_sha256`). The certificate to pin is the **KMS CA certificate** (`kms_ca_pem`;
its SPKI hash is `kms_ca_spki_sha256`). The feed serves a one-hour leaf alpha-kms issues
(`POST /v1/trustee/kbs-leaf`) only to a listed Trustee build, over that pod's attested key, naming
only `trustee.kbs_hostname` and only for server authentication. An App's Instance leaf from the
same CA names no host, so it never passes for the KBS. The leaf rotates hourly with no new
Revision; only a new KMS CA, which the PRD never plans, would change the pin. Until G0 confirms the
guest's root set (#93's sign-off item: `kbs_protocol` keeps its public roots), the document refuses
a `kbs_hostname` outside `.internal`.

## Fail-closed

- alpha-kms unreachable: no attestation is passed back, no resource is released (503).
- State older than `trustee.max_state_age_secs` (60 to 3600 s): the KBS gets the deny-all policy
  and the gate refuses everything; alpha-kms refuses releases on stale state too.
- A Trustee build delisted from the document, or its Revision revoked: every route refuses, and
  so does every release for a pod it reported.
- A pod admitted after the last state: the gate fetches a new state before the read; if that does
  not admit it, refused.
- The platform document names another NRAS URL than the AS started with: the pod refuses until
  it is rolled.
- No `gpu_policy` Trustee can meet (`verifiers` not exactly `[nras]`, no CC-mode claim, no
  hardware models): no GPU pod is affirming, nor admitted by the KMS.
- `ponytail: G0` items: the KBS image's Vault backend (else the KBS does not start); the AS
  reaching the site PCCS (else no TD is affirming); the guest's TLS client and `X25519MLKEM768`
  (the gate also offers `X25519` until then); the guest's TLS roots (`.internal` only).

## The routes

| Route | Caller | Audit |
|---|---|---|
| `PUT /v1/trustee/grants/{app_id}` | a tenant key (signed, receipted) | `trustee.grant` |
| `POST /v1/trustee/attestations` | a listed Trustee pod (mTLS) | `trustee.attest`, every outcome |
| `POST /v1/trustee/releases` | a listed Trustee pod (mTLS) | `trustee.release`, every outcome |
| `GET /v1/trustee/state` | a listed Trustee pod (mTLS) | `trustee.state`, refusals only |
| `POST /v1/trustee/kbs-leaf` | a listed Trustee pod (mTLS) | `trustee.kbs-leaf`, every outcome |

## Tests

- `crates/alpha-trustee`: the contract, the EAR reading and its refusals, the generated policies
  and reference values (deterministic, the document's TCB policy, every NRAS claim, no GPU without
  a policy Trustee can meet).
- `services/alpha-kms` unit tests (`trustee.rs`): the KMS's rules on Trustee's claims, freshness,
  the released value's form; `certs.rs`: the KBS leaf is no client identity and an Instance leaf
  never passes for the KBS.
- `services/alpha-kms/tests/trustee.rs` (Postgres): a pod's granted resources released and
  audited with its Revision; refusals with their audit rows for an unregistered Revision, another
  pod's init-data, the other class's guest, a non-affirming or expired token, GPUs on a CPU
  Revision, a revoked Revision (at the next release and the next state), an App that has not opted
  in or opted out, another App's resource, reserved purposes, a Trustee App, another
  organization's grant, stale and future state, a Trustee build the document does not list (and
  one delisted after it reported), a tampered grant row; the KBS leaf's SAN, key and EKU.
- `services/alpha-trustee-feed`: the gate between a fake KMS and a fake KBS that behaves as
  Trustee's: tokens withheld unless admitted, nothing reaching the backend that alpha-kms refused,
  stale state withdrawn with deny-all, the admin API and every other path not found, a restarted
  KBS getting the policy back before any read, the backend's one value for one path; the files the
  three containers start with.

Not tested here: Trustee itself. Nothing ran against the upstream images or in a Kata pod; the
first end-to-end run is at G0 with a B300 pod.

## For Ryan Tharp's sign-off

1. **Trust split.** alpha-kms trusts Trustee's attested AS for the cryptographic checks it does
   not repeat: the TDX quote's signature and Intel collateral, the nonce binding to the TEE key,
   the init-data digest against MRCONFIGID, and NRAS's token signatures and nonce. Every policy
   decision is the KMS's.
2. **NRAS keys.** Trustee's NVIDIA verifier trusts the NRAS JWKS it fetches from NVIDIA over web
   PKI at start (`nras_jwks.rs`, a fixed URL), where alpha-kms pins NRAS's keys by `kid` in the
   document. Through Trustee a GPU verdict rests on web PKI. Option: keep GPU pods off Option B
   until a pinned or local verifier is used.
3. **The token-signing key** is the Trustee App's derived key `trustee.as-token`, shared by both
   replicas; anyone with the Trustee App's leaf can derive it. The KMS derives the same key and
   verifies every token's ES256 signature under it before believing a claim, at admission and
   again at each release, and never releases on a token it was not given by a listed Trustee
   build. Pinned by the KMS's own key hierarchy to the Trustee builds the release-signed document
   lists: nothing is fetched, and nothing extra is copied into the document.
4. **One request at a time** through the KBS's backend per Trustee pod: availability, not safety.
5. **TLS** offers `X25519` beside `X25519MLKEM768` until G0; values are sealed to the TEE key
   (P-256) either way.
6. **`kbs_hostname` under `.internal`** until G0 settles the guest's TLS roots.
7. **Two Trustee replicas** (one per zone); the KBS session (handshake) is per replica, tokens
   are not.
8. **Admin API**: no human path. Its key is generated in the TD and never leaves; the ACL allows
   only the policy and reference-value endpoints; the gate does not route it.
9. **Persistent volumes** stay Option A (#86); `key/volume.<name>` is served for a later keyed
   CDH mount and is the same key Option A derives.
10. **When #93 meets this branch**, the Revision v2 gains `kbs`; the KMS could also refuse a pod
    whose Revision names another KBS than `trustee.kbs_hostname` and the KMS CA. Not
    security-relevant (such a pod never reaches this KBS), proposed as a follow-up.
