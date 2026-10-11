# Attesting a Kata confidential pod (`kata-tdx/1`)

How `alpha-kms` decides to issue a Revision leaf to a Kata confidential pod on TDX with NVIDIA confidential GPUs (PRD-02). Clients see no change: the leaf, its one-hour lifetime and its SANs (`urn:alphacompute:revision:sha256:<hash>`) are what they were. The prototype profile (`alphacompute-evidence/1`) is unchanged and both coexist.

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

It is registered in its JCS form, signed by the org key or a passkey exactly like a compose (context `alphacompute/revision/v1`, document `{app_id, compose}` with the Revision v2 text as `compose`), and its hash is SHA-256 over those bytes. The KMS rebuilds it from the verified init-data and looks the hash up in the same `revisions` table. `gpu` is absent for a CPU-only pod. `gpu.count` is 1 or 8.

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

The KMS then requires the Revision to be registered, unrevoked and validly signed, as today. Every refusal is an audit row with its reason.

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
  "nras_url": "https://nras.attestation.nvidia.com"
}
```

The document, its `policy`, its reference values and `gpu_policy` refuse fields they do not know, so `alpha sign` refuses a misspelled field (a reference value's `runtime_class`, say) rather than signing it to be ignored. The attestation result goes the other way: `coco` and its GPU entries accept fields they do not know, so runtimes keep renewing across a KMS upgrade that adds one. A reference value without `kind` is `prototype-tdx` and never matches Kata evidence (and vice versa). `verifiers` takes `nras`, `local` (after Dec 1) and `fortanix-ccm` (D1); every listed backend must pass.

## What the KMS cannot see

Exec, log reads, file copies and container changes are refused inside the guest by the agent policy. The KMS's part is to make sure that policy is the one the tenant signed. Those cases are run against a live pod by the malicious-host suite, not here.
