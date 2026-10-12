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
4. `MRTD` and `RTMR0..2` match a reference value of kind `kata-tdx` captured for that runtime class. A value for the other class, or one that names no class, never matches. The same registers may be listed under both classes; the value for the pod's class is the one chosen. Provided the two guests' captured registers differ (confirmed when they are captured, see below), a TD booted from the NVIDIA guest image therefore cannot pass as a CPU pod and skip step 10's GPU checks, and the CPU guest cannot pass as a GPU pod. Where they are the same, step 7 still holds the claim to the class of the measured init-data.
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

## What the KMS cannot see

Exec, log reads, file copies and container changes are refused inside the guest by the agent policy. The KMS's part is to make sure that policy is the one the tenant signed. Those cases are the full suite's, below.

## Malicious-host full suite

PRD-02 deliverable 18 runs what a hostile host can ask the Kata agent inside a launched pod to do, in two layers.

**Policy layer, in CI** (`crates/alpha-cli/tests/agent_policy.rs`, step `malicious-host full suite (policy)` of the check job). It evaluates genpolicy 4.1.0's policy for two representative pods (`testdata/agent-policy`: a GPU model server on `kata-qemu-nvidia-gpu-tdx`, a CPU App on `kata-qemu-tdx`, both with `alpha-runtime` mounting the init-data at `/run/alpha-pod/cc_init_data`) exactly as the Kata 4.1.0 agent does: regorus at the agent's commit with the agent's engine options, the policy loaded as `set_policy` loads the init-data's, one query `data.agent_policy.<request type>` per call, each request with every field Kata's own types serialize, and the policy state carried from call to call. Every case first launches the pod with the requests a host legitimately sends (sandbox, network, file copies, each container created, started and waited on) and requires each to be allowed, so a policy that refuses too much fails the suite too; a restart, the stop and the sandbox's destruction must be allowed as well.

| The host | Result |
|---|---|
| `kubectl exec` into any container, with or without a terminal, or the container's own command again | refused (`ExecProcessRequest`) |
| `kubectl logs` | refused (`ReadStreamRequest`): the agent answers with the data cleared |
| writes to or closes a container's stdin; asks for diagnostic data | refused |
| copies a file outside its shared directory: the root filesystem a guest pull made, an in-guest volume, the sandbox storage, a `..` traversal, a relative path, a device, a symlink at the top or pointing out or absolute | refused (`CopyFileRequest`) |
| creates a container, after launch or as a restart, with: another image digest; another image under the same image-name annotation; an extra, changed or unset environment variable (`LD_PRELOAD`, a service-link `VLLM_PORT=tcp://…`); an extra bind mount; a service-account token; an in-guest volume swapped for a host-shared directory; a mount moved or made writable; an extra storage; another command or argument; another working directory, user or terminal; privileged capabilities or `CAP_SYS_ADMIN`; `no_new_privileges` or a read-only root flipped; a host device; a hook; a sysctl; `/proc/kcore` unmasked or `/proc/sys` writable; a seccomp profile; the pod's process namespace shared; a string user; a shared mount; a hypervisor annotation; another pod's name; another container's name; an ephemeral debug container | refused (`CreateContainerRequest`) |
| pulls the pause container from a registry instead of unpacking the guest's own | refused |
| gives the model server a second GPU or none, or the GPU to the runtime | refused |
| creates the CPU App in another namespace | refused |
| sets a new policy; updates, pauses or resumes a container; remounts an in-guest volume; reads or sets iptables; lists interfaces or routes; changes `lo` or routes or neighbours through loopback addresses; creates the sandbox with a guest hook, a kernel module or a shared process namespace; adds swap; hot-plugs memory; reseeds the RNG; sets the clock; resizes a volume; reads volume stats or metrics; reconfigures the memory agent; starts tracing | refused |
| signals any container (or an id the pod never had), waits on it, reads its stats, resizes its terminal, removes it, destroys the sandbox, rewrites a file in its shared directory (`resolv.conf`, `hosts`, the downward-API copy of the init-data), creates a container without one of the mounts its spec lists | allowed: availability and host-written files, which the host has anyway. The runtime reaches the KMS and its upstream by address, not by name, and the KMS checks the init-data it is sent against `MRCONFIGID` |

**What the suite found in genpolicy 4.1.0's output, and the Alpha baseline that closes it.** With genpolicy's own rules and settings, the host can:

- run another image. `rules.rego` checks neither the image a guest pull fetches (the `image_guest_pull` storage's `source`, a TODO upstream) nor the `io.kubernetes.cri.image-name` annotation, so any image whose command, environment, user and mounts match the policy runs, with no change to `MRCONFIGID`: its code would hold the pod's runtime key and get the Revision's leaf. The same gap lets the host have the pause container pulled from a registry instead of unpacked from the guest image.
- unset any environment variable the spec sets (only that each variable set is allowed is checked);
- add service-link-shaped variables (`<ANY>_PORT=tcp://…`, `<ANY>_SERVICE_HOST=…`) to any container, and the Azure and `TERM` variables;
- mount a service-account token or an Azure token directory into any container.

The baseline (`testdata/agent-policy/README.md`) is a settings drop-in (`genpolicy-settings.d/30-alpha-baseline.json`: exec, streams, diagnostics and ephemeral remounts denied, file copies only into the shared directory, only `HOSTNAME` and the API server's `KUBERNETES_*` variables beyond the spec's, no token mounts) and a rules patch (`alpha-rules.patch`: the pulled image and the image-name annotation must be the policy's, the pause container must be the guest's own, every variable the policy names must be set). `alpha coco render` and `alpha coco wrap` must generate with both, and give genpolicy the spec without `automountServiceAccountToken`, `enableServiceLinks` and a claim's `readOnly`, which 4.1.0 refuses. The suite also checks that genpolicy's rules alone still have the image and environment gaps, so an upstream fix shows up as a failing test.

**Live layer, at G0 and after** (`scripts/malicious-host-live.sh`, CI job `malicious-host-live`). It does the hostile actions for real against a deployed, attested test App and requires each to be refused: `kubectl exec` (also `-i`), `kubectl logs` (also `--previous`) returning nothing, `kubectl cp` both ways, `kubectl attach`, `kubectl debug`; clones of the App's pod with another image digest, an extra or changed variable, an extra mount, a service-account token, another command, `privileged`, `CAP_SYS_ADMIN`, another user, a `hostPath`, an extra container, each of which must stop at `CreateContainerRequest is blocked by policy` and never be Ready; a clone whose init-data carries a policy of the host's, which runs but whose runtime the KMS refuses (`attestation_unknown`), so it is never Ready and gets no leaf; and, with `MHS_NODE_SHELL`, `crictl exec`, `crictl logs` and `kata-runtime exec` on the node. Without a cluster it says so and exits 0. It never changes the test Deployment and deletes the pods it creates.

To run it at G0:

1. Deploy a test App on each runtime class (`kata-qemu-tdx`, and `kata-qemu-nvidia-gpu-tdx` on a B300 in CC mode), rendered with the baseline, its Revision registered, and wait until its pod is Ready (its runtime attested).
2. `KUBECONFIG=<admin kubeconfig> MHS_NAMESPACE=app-<id> MHS_DEPLOYMENT=app-<id> MHS_NODE_SHELL="ssh root@<node>" scripts/malicious-host-live.sh` (needs `kubectl`, `jq`, `python3`). Every line must read `refused`; the script exits 1 otherwise. `MHS_TIMEOUT` (default 180 s) bounds each wait.
3. Run the policy layer against the real launch too: with the agent's log level at debug (`kernel_params = "agent.log=debug"` in the node's Kata configuration, on a debug node only), the agent writes each request it evaluates to `/tmp/policy.jsonl` in the guest. Put the legitimate launch's `CreateContainerRequest`s next to the fixtures and check the suite's launch builds the same requests; fix the suite where they differ (the PVC volume of the model server, which genpolicy models as a shared-directory bind, and the OCI version containerd sends are the first to confirm).
4. For CI, set the repository variable `LIVE_CLUSTER` (any value), `MHS_NAMESPACE` and `MHS_DEPLOYMENT`, the secret `LIVE_CLUSTER_KUBECONFIG`, and `LIVE_CLUSTER_RUNNER` to a runner label that reaches the API server. Without `LIVE_CLUSTER` the job is skipped.
