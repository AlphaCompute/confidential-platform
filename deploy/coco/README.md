# Platform services on confidential containers (Kata TDX + NVIDIA CC GPUs)

Specs for the PRD-04 pieces that run on our own B300 hardware, rendered and deployed by Rafay
(PRD-03). Variables are envsubst-style `${VARS}`; everything else in a spec is part of its
Revision.

| File | What it is |
|---|---|
| `model-server.yaml` | `alpha-model-server`: stock vLLM on one whole CC-mode GPU (`nvidia.com/pgpu: 1`) in a Kata TDX pod VM, `alpha-runtime` as a native sidecar terminating TLS on 8443, `alpha-weights open` as an init container |
| `seal-weights-job.yaml` | one-off Job of the same App that downloads a model into pod-VM memory and seals it onto the weights volume |
| `models/*.env` | per-model values: the Corpus model and Nemotron Safety Guard |
| `env/alpha-inference.env` | the front with every model ours and the guard on every model |
| `env/alpha-guard.env` | the judge, now also called by the front |

## Bring-up order

1. Register the model-server App and the seal Job's Revision; put `model-server-bearer` for the
   model-server App and for alpha-inference (same value).
2. Create `sealed-weights-<model>` PVCs; run `seal-weights-job.yaml` per model.
3. Deploy `model-server.yaml` per model; register each Revision; put its hash into
   alpha-inference's `MODEL_SERVERS`.
4. Put alpha-inference's `judge-bearer` and set alpha-guard's `inference-bearer` to the same value;
   add alpha-inference's App to alpha-guard's `CALLER_APPS`.
5. Deploy alpha-inference with `env/alpha-inference.env`, then alpha-guard with
   `env/alpha-guard.env`. Confirm in alpha-inference's log:
   `model <id> served by alphacompute revision sha256:...` for both models.
6. Point corpus-supervisor's `INFERENCE_URL`/`INFERENCE_REVISIONS` at this alpha-inference.

## Choices worth knowing

- **vLLM listens on loopback only.** The pod's only way in is the runtime's TLS on 8443, pinned by
  alpha-inference to the KMS CA and the Revision. The bearer is the second lock: today the runtime
  terminates TLS without a client certificate, so pinning callers by App id needs a runtime change
  (follow-up).
- **Weights are opened into pod-VM memory** (`emptyDir: {medium: Memory}`), so size
  `POD_VM_MEMORY_MIB` for the weights, vLLM's host-side overhead and `/dev/shm`.
- **One GPU per pod**, `Recreate` rollouts: no spare GPU is assumed.

## Depends on PRD-02

`alpha-runtime` reads its evidence from the dstack guest agent today. On Kata it needs the TDX
quote from the pod VM and the GPUs' evidence for the KMS to appraise, and the Revision of a pod
must cover the spec, the images by digest and the generated agent policy
(`io.katacontainers.config.agent.policy`). These specs assume both and change no runtime code.
