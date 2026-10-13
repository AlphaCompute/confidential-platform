# Attesting a Kata confidential pod (`kata-tdx/1`)

How `alpha-kms` decides to issue a Revision leaf to a Kata confidential pod on TDX with NVIDIA confidential GPUs (PRD-02). Clients see no change: the leaf, its one-hour lifetime and its SANs (`urn:alphacompute:revision:sha256:<hash>`) are what they were. The prototype profile (`alphacompute-evidence/1`) is unchanged and both coexist.

> **Status: the KMS does not run this profile yet.** This document describes the appraisal in `alpha_attest` (`appraise_any`, `kata`, `gpu`) and the behaviour the KMS will have once it is wired in (PRD-02 PR 5, not written yet). Today `alpha-kms` still accepts only `alphacompute-evidence/1` and calls the prototype `appraise` (`services/alpha-kms/src/instance.rs`), so a Kata pod's evidence v2 is refused and no Kata pod gets a leaf. Sentences marked *(PR 5)* describe KMS behaviour that is pending.

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

It is registered in its JCS form, signed by the org key or a passkey exactly like a compose (context `alphacompute/revision/v1`, document `{app_id, compose}` with the Revision v2 text as `compose`), and its hash is SHA-256 over those bytes. *(PR 5)* The KMS rebuilds it from the verified init-data and looks the hash up in the same `revisions` table. `gpu` is absent for a CPU-only pod. `gpu.count` is 1 or 8.

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

`event_log` (the CCEL boot events) is optional; when sent, RTMR0..2 must replay from it. `runtime_class` is the pod's own claim and is refused unless it equals the measured init-data's. `kind: "snp"` is refused until the `kata-snp/1` profile exists.

The quote's `report_data` binds the runtime key and the KMS nonce exactly as for the prototype (`SHA-256(SPKI ‖ nonce)`, then `SHA-256(xwing)` or zeros). Two encodings are accepted: the 64 bytes themselves (configfs-tsm), or the 64 ASCII bytes of lowercase hex `SHA-256(report_data)`, which is how runtime data passes through the CoCo attestation agent's REST API. Both need the same preimage.

Every GPU report is bound to `SHA-256("alphacompute/gpu-nonce/v1" ‖ report_data)`.

In the pod, `alpha-runtime` (`alpha_tsm::coco`) takes the quote from the CoCo attestation agent's REST API (`GET /aa/evidence`, `ALPHACOMPUTE_QUOTE_SOURCE=coco-aa`) or from configfs-tsm (`coco-tsm`). GPU reports always come from the attestation agent: `GET /aa/additional-evidence` with the GPU nonce as the runtime data, sent raw (`encoding=base64`), returns `{"nvidia": {"device_evidence_list": [{"arch", "evidence", "certificate"}, …]}}` from the agent's NVIDIA attester, which asks every confidential GPU for a report over the first 32 bytes of the runtime data through NVIDIA's attestation SDK. guest-components v0.21.0 has that attester (`nvidia-attester`) and endpoint; Kata 4.0.0's guest init starts the NVIDIA-attester build of the agent when a GPU is passed through. NVSwitch entries (`arch: LS10`) are left out of the GPU count and are not appraised yet. Nothing the agent returns is trusted: the KMS's GPU backend verifies every report and its nonce. To confirm at M-B on the pinned stack: that the endpoint is enabled in NVIDIA's guest image (Q11) and that the agent's NVIDIA attester runs in GPU pods.

## Guest REST prerequisites and preflight

Kata's default REST feature selection is `resource`, which serves CDH resource
requests but returns HTTP 404, `Attestation Feature Not Enabled`, for `/aa/*`.
The presence of the REST listener or of an NVIDIA GPU does not enable those routes.
For guests whose runtime uses `coco-aa`, and every GPU pod even with `coco-tsm`,
configure the node's Kata runtime with `agent.guest_components_rest_api=all` in
its guest `kernel_params`. Preserve the existing parameters when adding it; a
Kata configuration drop-in is preferred to editing kata-deploy's managed file.
This affects newly launched guests, so recreate a test pod to verify the change.
Do not expose the pod-local service outside the guest.

Before collecting evidence, `alpha-tsm` checks `GET /info` on the pod-local REST
service. It requires `feature` to be `all` or `attestation`, `tee` to be `tdx`,
and, for GPU pods, `additional_tees` to contain `nvidia`. A disabled feature
produces an error naming the Kata startup setting. These are collection
capabilities, not trusted attestation claims; quote and GPU verification remain
the KMS's responsibility. CPU-only `coco-tsm` pods do not need REST access. A
configfs fallback also requires a mounted, accessible TSM report tree inside
the guest; mounting it in a privileged diagnostic container does not establish
that access for the normal runtime container.

Hardware check on 12 October 2026: on a Kata 4.0.0 B300 guest with guest-components
`da8d93f`, both routes were initially feature-disabled. Adding the startup flag
made `/info` advertise TDX and NVIDIA, `/aa/evidence` return a fresh TDX v4 quote
with the requested runtime data, and `/aa/additional-evidence` return one BLACKWELL
report with the requested nonce. A new pod without a kernel-parameter annotation
confirmed the persistent node drop-in. The GPU report signature verified against
its returned leaf public key; chain trust, OCSP, RIM matching, CPU DCAP/TCB,
init-data binding and KMS leaf issuance were not verified by that check.

The policy-generator suite targets Kata 4.1.0. The collection result on 4.0.0 does
not qualify those generated policies on that guest version; match and validate
the guest agent, genpolicy, rules and settings before running the live suite.

## Appraisal steps

In the plan's order (PRD-02 R5). Every step is mandatory; the order only decides which reason is named when evidence has several faults.

1. DCAP verification and the TCB policy (unchanged, `verify_quote`).
2. If an event log was sent, it replays to the quoted RTMR0..2.
3. `MRTD` and `RTMR0..2` match a reference value of kind `kata-tdx` listed for the pod's runtime class (or for any class, when the value names none). The same registers may be listed under several classes; the value for the pod's class is the one chosen.
4. `MRCONFIGID` is the digest of the init-data sent.
5. The init-data parses, has `policy.rego` and a valid `alpha.json`.
6. The evidence's `runtime_class` is the init-data's.
7. `report_data` binds this runtime key and nonce, last of the TD checks.
8. The Revision v2 hash is the leaf's Revision; for a KMS node it must be in `kms_revisions`.
9. GPUs: the evidence has exactly `gpu.count` entries; every backend the `gpu_policy` lists verified every one of them, over this nonce, in CC mode, of the Revision's model, an allowed model, at or above the minimum driver and VBIOS versions. A failure in any backend fails the attestation. The backends (NRAS is a network call) run only after steps 1 to 8 have passed and after the checks that need no backend (a `gpu_policy` exists, lists a verifier and allows the model, one evidence entry per GPU), so evidence that fails earlier costs no verifier call (`alpha_attest::appraise_any`).

*(PR 5)* The KMS then requires the Revision to be registered, unrevoked and validly signed, as today, and refuses a Revision v2 reached through evidence v1 or the reverse. Every refusal is an audit row with its reason. None of this is wired yet: `appraise_any` returns the reasons, but nothing in `alpha-kms` calls it.

## What the result records

`AttestationResult.coco` (absent for the prototype profile) carries the profile, `initdata_sha256`, `policy_sha256`, `runtime_class`, every verified GPU (`index`, `device_id`, `model`, driver and VBIOS versions, `cc_mode`, `nonce`) and `gpu_verifiers`: one `{"verifier", "token_sha256"}` per backend the `gpu_policy` lists, naming who vouched for the GPUs and the digest of the signed result it verified. `device_id` is the device's identity as the backend verified it (NRAS's `ueid`); two GPUs of one pod may not share it, so eight copies of one GPU's report cannot pass for eight GPUs.

## Platform document additions

All optional, so documents already signed still parse and keep their meaning:

```json
"reference_values": [
  {"name": "nvidia-uvm-tdx/b300x8", "kind": "kata-tdx", "runtime_class": "kata-qemu-nvidia-gpu-tdx",
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

The document, its `policy`, its reference values and `gpu_policy` refuse fields they do not know, so `alpha sign` refuses a misspelled field (a reference value's `runtime_class`, say) rather than signing it to be ignored. The attestation result goes the other way: `coco` and its GPU entries accept fields they do not know, so runtimes keep renewing across a KMS upgrade that adds one. A reference value without `kind` is `prototype-tdx` and never matches Kata evidence (and vice versa). `verifiers` takes `nras`, `local` (after Dec 1) and `fortanix-ccm` (D1); every listed backend must pass. `hwmodels` maps NRAS's `hwmodel` claim to the model names above; a GPU whose string is not listed is refused, so the B300 string is added from the first capture rather than guessed. `nras_keys` pins NRAS's signing keys by `kid`, copied from NVIDIA's JWKS when the document is prepared: an NRAS token whose `kid` is not pinned, or that names none, is refused, and with no pinned key the `nras` backend refuses every GPU before calling NRAS. The backend never fetches NRAS's JWKS, so trust in a GPU verdict rests on the release signature, not on web-PKI TLS; when NRAS rotates its key, a new platform document pins the new one.

## GPU backends

- `nras` (`alpha_attest::gpu::nras`): posts every GPU's report and certificate chain with the nonce, verifies the overall EAT and each per-GPU EAT (ES384 under the key `gpu_policy.nras_keys` pins for the token's `kid`, issuer = `nras_url`, unexpired), ties each per-GPU token to the overall token's `submods` digest, and requires the overall result and the nonce. For every GPU it requires, by name (NVIDIA's GPU claims version 3.0, listed in `nras::claims::REQUIRED`): `measres: success`, secure boot, debug disabled, the architecture check, the report parsed, its signature verified, its nonce matching and its FWID matching the certificate chain; for the attestation report's, the driver RIM's and the VBIOS RIM's certificate chains, `x-nvidia-cert-status: valid` and `x-nvidia-cert-ocsp-status: good` (and the OCSP nonce and response checks true when sent), so a revoked GPU or RIM certificate is refused by this backend whatever NRAS's overall result says; the driver and VBIOS RIM signatures and version matches; the `ueid`, `hwmodel`, driver and VBIOS versions; and the CC-mode claim that `gpu_policy.nras_cc_mode` names. Any missing claim refuses. A call NRAS does not answer (no connection, a timeout, `429`, `408` or a `5xx`) is retried with a doubling backoff and jitter, three calls within 40 s by default (`nras::Retry`), then the attestation fails closed (Q12); an answer NRAS gave is never retried.
- `fortanix-ccm` (`alpha_attest::gpu::ccm`): configured like any backend and refuses every GPU until Fortanix answers F8 with an API.
- `local`: after Dec 1.

## G0 check: NRAS claim names on a B300

NVIDIA publishes no claim named for CC mode (GPU claims 3.0; 4.0 adds `x-nvidia-attester-claims` with opaque values a RIM marks), so the claim that proves CC mode is not compiled in. `gpu_policy.nras_cc_mode` names it as a JSON pointer into the per-GPU claims and the value it must hold, for example `{"pointer": "/x-nvidia-attester-claims/<name>", "equals": 1}`. Until a release-signed document sets it, the `nras` backend refuses every GPU (fail closed), before it calls NRAS.

At G0, on the first B300 in CC mode:

1. Collect the GPU evidence in a Kata pod and post it to NRAS (`/v3/attest/gpu`) with any nonce; save the raw reply.
2. Write the candidate `gpu_policy` (JSON) with the B300's `hwmodel` string in `hwmodels` and the chosen `nras_cc_mode`.
3. Run `ALPHA_NRAS_REPLY=reply.json ALPHA_GPU_POLICY=gpu_policy.json cargo test -p alpha-attest --lib -- --ignored g0_nras_reply_has_every_claim_this_backend_requires --nocapture`. It prints every token's claims and fails with one line per required claim the reply lacks or that does not hold (`nras::claim_report`); without `ALPHA_GPU_POLICY` it also lists the `hwmodel` and CC-mode entries still to be chosen.
4. Repeat with a GPU whose CC mode is off and check that the chosen claim then does not hold. Record the choice in the security review (deliverable 8) before it is signed into the platform document.

If a required claim name differs on the B300, `nras::claims::REQUIRED` is the one place to change.

## What the KMS cannot see

Exec, log reads, file copies and container changes are refused inside the guest by the agent policy. The KMS's part is to make sure that policy is the one the tenant signed. Those cases are run against a live pod by the malicious-host suite, not here.
