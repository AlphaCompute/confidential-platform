# Attesting a Kata confidential pod (`kata-tdx/1`)

How `alpha-kms` decides to issue a Revision leaf to a Kata confidential pod on TDX, CPU-only or with NVIDIA confidential GPUs (PRD-02). Clients see no change: the leaf, its one-hour lifetime and its SANs (`urn:alphacompute:revision:sha256:<hash>`) are what they were. The prototype profile (`alphacompute-evidence/1`) is unchanged and both coexist.

`POST /v1/attest` takes either evidence format (`services/alpha-kms/src/instance.rs`): `alphacompute-evidence/1` goes to the prototype `appraise`, `alphacompute-evidence/2` to `kata-tdx/1` in `alpha_attest` (`kata`, `gpu`) and then to the KMS's own checks below. Any other format is `malformed`.

## Identity: init-data and the Revision v2

Kata binds the digest of the pod's init-data into the TD's `MRCONFIGID` when it launches the VM, and the Kata agent policy the pod runs under is the init-data's `policy.rego` entry. The policy pins images by digest and fixes each container's command, environment and mounts, and denies exec and log reads. So the init-data, not the pod spec the host holds, says what may run.

`alpha coco render` adds one entry of ours, `alpha.json`:

```json
{"app_id":"<uuid>","format":"alphacompute-initdata/1","gpu":{"count":8,"model":"B300"},"runtime_class":"kata-qemu-nvidia-gpu-tdx"}
```

The Revision v2 is then a pure function of the init-data bytes:

```json
{"app_id":"<uuid>","format":"alphacompute-coco-revision/1","gpu":{"count":8,"model":"B300"},
 "initdata_sha256":"sha256:<hex>","policy_sha256":"sha256:<hex>","runtime_class":"kata-qemu-nvidia-gpu-tdx"}
```

It is registered in its JCS form, signed by the org key or a passkey exactly like a compose (context `alphacompute/revision/v1`, document `{app_id, compose}` with the Revision v2 text as `compose`), and its hash is SHA-256 over those bytes. The KMS rebuilds it from the verified init-data and looks the hash up in the same `revisions` table.

### Runtime classes

A Revision v2 names one of two runtime classes, both Kata on TDX. The class decides the `gpu` section, in `alpha.json` and in the Revision alike:

| `runtime_class` | Pods | `gpu` |
|---|---|---|
| `kata-qemu-tdx` | CPU-only confidential pods: the KMS, broker, signer, guard, inference front and Corpus supervisor | Absent. Any `gpu` section is refused, even one with `count: 0`, so one pod has exactly one Revision. |
| `kata-qemu-nvidia-gpu-tdx` | Pods with whole B300 GPUs in CC mode (`nvidia.com/pgpu`) | Required: `count` 1 or 8 and an upper-case `model`. A GPU-class Revision without GPUs is refused. |

Any other class is refused at registration and at appraisal (`kata-qemu-nvidia-gpu-snp` waits for the `kata-snp/1` profile). A CPU-only pod's entries:

```json
{"app_id":"<uuid>","format":"alphacompute-initdata/1","runtime_class":"kata-qemu-tdx"}
{"app_id":"<uuid>","format":"alphacompute-coco-revision/1","initdata_sha256":"sha256:<hex>","policy_sha256":"sha256:<hex>","runtime_class":"kata-qemu-tdx"}
```

`MRCONFIGID` holds the init-data digest under the algorithm the document declares, zero-padded to 48 bytes; `alpha coco render` declares `sha384`, which fills it. This is open question Q10 until a golden vector from a B300 pod proves it at M1; `alpha_core::coco::InitData::mrconfigid` is the one place to change if Kata binds it differently.

## Evidence (`alphacompute-evidence/2`)

```json
{
  "format": "alphacompute-evidence/2",
  "cpu": {"kind": "tdx", "quote": "<base64url>", "event_log": [ ... ]},
  "gpus": [{"arch": "BLACKWELL", "evidence": "<base64url>", "certificate": "<base64url>"}],
  "initdata": "<base64url of the exact init-data bytes>",
  "runtime_class": "kata-qemu-nvidia-gpu-tdx"
}
```

`event_log` (the CCEL boot events) is optional; when sent, RTMR0..2 must replay from it. `runtime_class` is the pod's own claim: a class no Revision v2 may name is refused, and any other claim is refused unless it equals the measured init-data's. `kind: "snp"` is refused until the `kata-snp/1` profile exists.

A pod on `kata-qemu-tdx` sends no GPU evidence (`gpus` empty or absent). If it sends any, the appraisal refuses it once the TD checks have passed, without calling a GPU backend, and it refuses a GPU that a backend verified for such a pod the same way: GPU evidence from a CPU pod is refused, never ignored. The KMS refuses it the same way.

The quote's `report_data` binds the runtime key and the KMS nonce exactly as for the prototype (`SHA-256(SPKI ‖ nonce)`, then `SHA-256(xwing)` or zeros). Two encodings are accepted: the 64 bytes themselves (configfs-tsm), or the 64 ASCII bytes of lowercase hex `SHA-256(report_data)`, which is how runtime data passes through the CoCo attestation agent's REST API. Both need the same preimage.

Every GPU report is bound to `SHA-256("alphacompute/gpu-nonce/v1" ‖ report_data)`.

In the pod, `alpha-runtime` (`alpha_tsm::coco`) takes the quote from the CoCo attestation agent's REST API (`GET /aa/evidence`, `ALPHACOMPUTE_QUOTE_SOURCE=coco-aa`) or from configfs-tsm (`coco-tsm`). A pod on `kata-qemu-tdx` asks for no GPU report. On the GPU class, GPU reports always come from the attestation agent: `GET /aa/additional-evidence` with the GPU nonce as the runtime data, sent raw (`encoding=base64`), returns `{"nvidia": {"device_evidence_list": [{"arch", "evidence", "certificate"}, …]}}` from the agent's NVIDIA attester, which asks every confidential GPU for a report over the first 32 bytes of the runtime data through NVIDIA's attestation SDK. guest-components v0.21.0 has that attester (`nvidia-attester`) and endpoint; Kata 4.0.0's guest init starts the NVIDIA-attester build of the agent when a GPU is passed through. NVSwitch entries (`arch: LS10`) are left out of the GPU count and are not appraised yet. Nothing the agent returns is trusted: the KMS's GPU backend verifies every report and its nonce. To confirm at M-B on the pinned stack: that the endpoint is enabled in NVIDIA's guest image (Q11) and that the agent's NVIDIA attester runs in GPU pods.

## Appraisal steps

In the plan's order (PRD-02 R5). Every step is mandatory; the order only decides which reason is named when evidence has several faults.

1. DCAP verification and the TCB policy (unchanged, `verify_quote`).
2. If an event log was sent, it replays to the quoted RTMR0..2.
3. The evidence's `runtime_class` is a class a Revision v2 may name (`kata-qemu-tdx` or `kata-qemu-nvidia-gpu-tdx`). Any other is refused before a reference value is looked up.
4. `MRTD` and `RTMR0..2` match a reference value of kind `kata-tdx` captured for that runtime class. A value for the other class, or one that names no class, never matches. The same registers may be listed under both classes; the value for the pod's class is the one chosen. Provided the two guests' captured registers differ (confirmed when they are captured, see below), a TD booted from the NVIDIA guest image therefore cannot pass as a CPU pod and skip step 10's GPU checks, and the CPU guest cannot pass as a GPU pod. Where they are the same, step 7 still holds the claim to the class of the measured init-data. RTMR3 is not compared: it is the guest's runtime register, extended from inside the TD after boot, so no captured value holds it and a reference value cannot name one; what the pod runs is bound by MRCONFIGID (steps 5 to 7). The rule is `kata::kata_tdx_reference`, which alpha-kms's Trustee path (`docs/trustee.md`) uses too.
5. `MRCONFIGID` is the digest of the init-data sent.
6. The init-data parses, has `policy.rego` and a valid `alpha.json`: a supported runtime class, with the `gpu` section that class requires.
7. The evidence's `runtime_class` is the init-data's.
8. `report_data` binds this runtime key and nonce, last of the TD checks.
9. The Revision v2 hash is the leaf's Revision; for a KMS node it must be in `kms_revisions`.
10. GPUs, by the runtime class:
    - `kata-qemu-nvidia-gpu-tdx`: the evidence has exactly `gpu.count` (1 or 8) entries; every backend the `gpu_policy` lists verified every one of them, over this nonce, in CC mode, of the Revision's model, an allowed model, at or above the minimum driver and VBIOS versions. A failure in any backend fails the attestation. The backends (NRAS is a network call) run only after steps 1 to 9 have passed and after the checks that need no backend (a `gpu_policy` exists, lists a verifier and allows the model, one evidence entry per GPU), so evidence that fails earlier costs no verifier call (`alpha_attest::appraise_any`).
    - `kata-qemu-tdx`: no GPU evidence, and no GPU verified by any backend. No backend is called and `gpu_policy` is not consulted, so a document without one still attests CPU pods. This is the only class whose GPU checks are skipped.

The KMS then requires, after `kata::appraise_kata_tdx` (steps 1 to 10, GPU backends included):

11. The Revision v2 hash is registered. If not, the refusal (`attestation_unknown`) names the init-data's policy digest, so a policy edited after registration is identified as such.
12. The Revision is unrevoked and validly signed by its organization's key or passkey, as for a compose (`revision_revoked`, `signature_invalid`).
13. A Revision v2 is attested only through evidence v2 and a compose only through evidence v1, so a prototype CVM whose `app-compose` were a Revision v2's bytes gets no leaf for it. The registered Revision v2's runtime class, init-data and policy digests are the appraised ones, and the GPUs verified are exactly its count, every one of its model (`attestation_failed`; the hash already binds these, so this holds the leaf to the stored row as well).

The leaf is then issued as for a compose: the same one-hour lifetime and the SAN `urn:alphacompute:revision:sha256:<hash>`. Every attestation writes one `attest` audit row with the SHA-256 of the evidence: on success the attestation result (its `coco` included), on a refusal `{"code", "message"}` with the reason the first failing step names. The KMS's tests (`services/alpha-kms/tests/kata.rs`) run these steps over synthetic quotes through `instance::attest_verified`, which no route reaches, until B300 Kata captures exist at M1; the route itself always runs DCAP first.

## What the result records

`AttestationResult.coco` (absent for the prototype profile) carries the profile, `initdata_sha256`, `policy_sha256`, `runtime_class`, every verified GPU (`index`, `device_id`, `model`, driver and VBIOS versions, `cc_mode`, `nonce`; none for a CPU-class pod) and `gpu_verifiers` (also empty for a CPU-class pod): one `{"verifier", "token_sha256"}` per backend the `gpu_policy` lists, naming who vouched for the GPUs and the digest of the signed result it verified. `device_id` is the device's identity as the backend verified it (NRAS's `ueid`); two GPUs of one pod may not share it, so eight copies of one GPU's report cannot pass for eight GPUs.

## Platform document additions

All optional, so documents already signed still parse and keep their meaning:

```json
"reference_values": [
  {"name": "nvidia-uvm-tdx/b300x8", "kind": "kata-tdx", "runtime_class": "kata-qemu-nvidia-gpu-tdx",
   "values": {"mrtd": "sha384:…", "rtmr0": "sha384:…", "rtmr1": "sha384:…", "rtmr2": "sha384:…"}},
  {"name": "kata-tdx/cpu-4c-8g", "kind": "kata-tdx", "runtime_class": "kata-qemu-tdx",
   "values": {"mrtd": "sha384:…", "rtmr0": "sha384:…", "rtmr1": "sha384:…", "rtmr2": "sha384:…"}}
],
"gpu_policy": {
  "allowed_models": ["B300"],
  "min_driver_version": "570.124.06",
  "min_vbios_version": "97.00.82.00.01",
  "verifiers": ["nras"],
  "nras_url": "https://nras.attestation.nvidia.com",
  "hwmodels": {"<NRAS hwmodel string for B300>": "B300"},
  "nras_keys": {"<kid>": {"kty": "EC", "crv": "P-384", "x": "<base64url>", "y": "<base64url>"}},
  "nras_cc_mode": {"pointer": "<per-GPU claim confirmed at G0>", "equals": "<its CC-on value>"}
}
```

The document, its `policy`, its reference values and `gpu_policy` refuse fields they do not know, so `alpha sign` refuses a misspelled field (a reference value's `runtime_class`, say) rather than signing it to be ignored. The attestation result goes the other way: `coco` and its GPU entries accept fields they do not know, so runtimes keep renewing across a KMS upgrade that adds one. A reference value without `kind` is `prototype-tdx` and never matches Kata evidence (and vice versa). A `kata-tdx` value must name the `runtime_class` whose guest image it was captured from; one without it matches no pod (documents signed before Kata have no `kata-tdx` values). Each class is captured from its own guest image, for every VM size its pods use, and the capture confirms that the CPU guest's registers differ from the NVIDIA guest's. `verifiers` takes `nras`, `local` (after Dec 1) and `fortanix-ccm` (D1); every listed backend must pass. `hwmodels` maps NRAS's `hwmodel` claim to the model names above; a GPU whose string is not listed is refused, so the B300 string is added from the first capture rather than guessed. `nras_keys` pins NRAS's signing keys by `kid`, copied from NVIDIA's JWKS when the document is prepared: an NRAS token whose `kid` is not pinned, or that names none, is refused, and with no pinned key the `nras` backend refuses every GPU before calling NRAS. The backend never fetches NRAS's JWKS, so trust in a GPU verdict rests on the release signature, not on web-PKI TLS; when NRAS rotates its key, a new platform document pins the new one.

## GPU backends

- `nras` (`alpha_attest::gpu::nras`): posts every GPU's report and certificate chain with the nonce, verifies the overall EAT and each per-GPU EAT (ES384 under the key `gpu_policy.nras_keys` pins for the token's `kid`, issuer = `nras_url`, unexpired), ties each per-GPU token to the overall token's `submods` digest, and requires the overall result and the nonce. For every GPU it requires, by name (NVIDIA's GPU claims version 3.0, listed in `nras::claims::REQUIRED`): `measres: success`, secure boot, debug disabled, the architecture check, the report parsed, its signature verified, its nonce matching and its FWID matching the certificate chain; for the attestation report's, the driver RIM's and the VBIOS RIM's certificate chains, `x-nvidia-cert-status: valid` and `x-nvidia-cert-ocsp-status: good` (and the OCSP nonce and response checks true when sent), so a revoked GPU or RIM certificate is refused by this backend whatever NRAS's overall result says; the driver and VBIOS RIM signatures and version matches; the `ueid`, `hwmodel`, driver and VBIOS versions; and the CC-mode claim that `gpu_policy.nras_cc_mode` names. Any missing claim refuses. A call NRAS does not answer (no connection, a timeout, `429`, `408` or a `5xx`) is retried with a doubling backoff and jitter, three calls within 40 s by default (`nras::Retry`), then the attestation fails closed (Q12); an answer NRAS gave is never retried.
- `fortanix-ccm` (`alpha_attest::gpu::ccm`): configured like any backend and refuses every GPU until Fortanix answers F8 with an API.
- `local`: after Dec 1.

`alpha-kms` always runs the `nras` backend and runs `fortanix-ccm` when `ALPHACOMPUTE_FORTANIX_CCM_URL` names an `https://` endpoint (`alpha_kms::gpu_backends`). A backend the `gpu_policy` lists that the node does not run (`local`, or `fortanix-ccm` without its URL) refuses every GPU pod with `gpu verifier … is not configured`.

## G0 check: NRAS claim names on a B300

NVIDIA publishes no claim named for CC mode (GPU claims 3.0; 4.0 adds `x-nvidia-attester-claims` with opaque values a RIM marks), so the claim that proves CC mode is not compiled in. `gpu_policy.nras_cc_mode` names it as a JSON pointer into the per-GPU claims and the value it must hold, for example `{"pointer": "/x-nvidia-attester-claims/<name>", "equals": 1}`. Until a release-signed document sets it, the `nras` backend refuses every GPU (fail closed), before it calls NRAS.

At G0, on the first B300 in CC mode:

1. Collect the GPU evidence in a Kata pod and post it to NRAS (`/v3/attest/gpu`) with any nonce; save the raw reply.
2. Write the candidate `gpu_policy` (JSON) with the B300's `hwmodel` string in `hwmodels` and the chosen `nras_cc_mode`.
3. Run `ALPHA_NRAS_REPLY=reply.json ALPHA_GPU_POLICY=gpu_policy.json cargo test -p alpha-attest --lib -- --ignored g0_nras_reply_has_every_claim_this_backend_requires --nocapture`. It prints every token's claims and fails with one line per required claim the reply lacks or that does not hold (`nras::claim_report`); without `ALPHA_GPU_POLICY` it also lists the `hwmodel` and CC-mode entries still to be chosen.
4. Repeat with a GPU whose CC mode is off and check that the chosen claim then does not hold. Record the choice in the security review (deliverable 8) before it is signed into the platform document.

If a required claim name differs on the B300, `nras::claims::REQUIRED` is the one place to change.

## Malicious-host core suite

`services/alpha-kms/tests/malicious_host.rs` (PRD-02 deliverable 7) runs what a hostile host can do to a Kata pod's attestation through the KMS, on Postgres 18 in CI's db-tests job (step `malicious-host core suite`). Each case attests over the quote a TD launched as the case describes would produce. Every case is refused with its reason, an `attest` audit row records exactly that refusal, no leaf is issued, and where the TD side fails no GPU backend is called.

| The host | Refused with |
|---|---|
| swaps or edits the init-data after launch | `attestation_failed`: MRCONFIGID is not the digest of the init-data sent |
| replays an exchange after its nonce expired, or uses a nonce another KMS minted | `nonce_invalid`: nonce is too old, or does not verify |
| presents a quote over other `report_data`: an earlier nonce, or its own runtime key | `attestation_failed`: report_data is not bound to this key and nonce |
| drops or adds a GPU | `attestation_failed`: `<n>` GPUs attested, the Revision expects 8 (before any backend call) |
| presents one GPU's report twice, or a GPU of another model | `attestation_failed`: device … is reported for another GPU of this pod too; model … is not the Revision's |
| presents GPU evidence bound to another nonce | `attestation_failed`: gpu `<i>`: report is not over this nonce |
| passes a GPU in DevTools mode or with CC off | `policy_denied`: gpu `<i>`: not in CC mode |
| uses a revoked Revision | `revision_revoked` |
| serves an older, still release-signed platform document | the reload is refused with a denied `platform.reload` audit row and the newer document stays in force, so a guest image it withdrew stays refused |
| claims a runtime class no Revision v2 may name, or the CPU class for a GPU pod | `attestation_failed`: runtime class … is not supported; `attestation_unknown`: no kata-tdx reference value … and runtime class kata-qemu-tdx |
| launches the pod with a policy of its own (MRCONFIGID consistent) | `attestation_unknown`: the Revision v2 of this init-data (policy …) is not registered |

The GPU backend in the suite reports each GPU as its report describes it. The `nras` backend reports a GPU whose CC-mode claim holds anything but the CC-on value (`OFF`, `DEVTOOLS`) as not in CC mode (`gpu::nras` tests). A nonce is stateless and valid for five minutes, so within that window one pod may attest twice with one nonce; the leaf certifies a runtime key only the pod holds, so replaying a fresh exchange gains the host nothing. The appraisal-only cases, a guest image without a reference value and a downgraded TCB among them, are `alpha_attest` tests.

## A KMS node on Kata

`alpha-kms` itself runs as a Kata pod on the verifier pool (PRD-05), on the CPU class `kata-qemu-tdx`. With `ALPHACOMPUTE_QUOTE_SOURCE=coco-aa` (or `coco-tsm`) it reads the init-data it booted with from `/run/alpha-pod/cc_init_data` and its Revision is the Revision v2 that init-data stands for (`alpha_kms::NodeGuest`); init-data on any other class is refused at start. It quotes through the same CoCo source as `alpha-runtime` (`alpha_tsm::coco::Source`, no GPU evidence) with `report_data` = `SHA-256(SPKI ‖ nonce) ‖ SHA-256(xwing)`, so the X-Wing key custodians seal to is bound exactly as on a prototype node. Its leaf names that Revision v2, so clients pin it in `ALPHACOMPUTE_KMS_REVISIONS` like any KMS build.

A node is admitted by `alpha_attest::node`, the one appraisal both the serving node (before `join`) and a custodian's `alpha bootstrap` / `alpha unseal` run:

1. Prototype evidence: `appraise` as before. Kata evidence: steps 1 to 9 above with the X-Wing key bound, so its Revision v2 hash must be in `kms_revisions`.
2. A Kata node's init-data names `kata-qemu-tdx`; a node on the GPU class is refused (`a KMS node runs on the runtime class kata-qemu-tdx`), and no GPU backend is ever called for a node. Its GPU decision is the CPU class's: no GPU evidence.
3. The `kms_revisions` entry with that hash is listed for the profile the node was appraised under: `"kind": "kata-tdx"` for a Kata build, absent (`prototype-tdx`) for a prototype build. So a prototype CVM whose compose were a Kata build's Revision v2 bytes, or the reverse, is not a node (`attestation_unknown`).

During the migration the platform document lists both builds:

```json
"kms_revisions": [
  {"compose_hash": "sha256:<prototype build>", "build": "kms v…", "source_url": "…"},
  {"compose_hash": "sha256:<Revision v2 of the Kata KMS init-data>", "build": "kms v… (kata)", "source_url": "…", "kind": "kata-tdx"}
]
```

A Kata node then joins a serving prototype node through the existing protocol (`node.join.request`, a nonce from the serving node, `POST /v1/node/join` with its evidence v2 and X-Wing key, the intermediates in the reply), so the CA and every key are kept; each join writes a `node.join` audit row naming the joining node's Revision and, for a Kata node, its `coco` findings. `alpha bootstrap` on a Kata node is production genesis. The KMS's tests run this over synthetic quotes (`services/alpha-kms/tests/kata_node.rs`, through `node::join_verified` and `alpha_cli::node::verify_kata_node`, which no route or command reaches) until B300 Kata captures exist at M1; the join route and the CLI always run DCAP first.

What a custodian verifies before a share leaves their key, for a Kata node: DCAP and the TCB policy; `kata-tdx` reference values for the CPU guest; MRCONFIGID equal to the digest of the init-data the node sent; the Revision v2 rebuilt from that init-data listed as a `kata-tdx` KMS build; the X-Wing key and runtime key bound in `report_data`; the TLS key equal to the attested runtime key. What the KMS pod may run, and that nothing can exec into it or read its logs, is the agent policy inside that init-data, so it is reviewed once, when the build is listed by the release key, and not by the CLI. The CLI prints the node's `profile`, `revision`, `os_image` and `policy_sha256` for the custodian's record.

## What the KMS cannot see

Exec, log reads, file copies and container changes are refused inside the guest by the agent policy. The KMS's part is to make sure that policy is the one the tenant signed. Those cases are run against a live pod by the full malicious-host suite (deliverable 18), not by the core suite.
