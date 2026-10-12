# Platform services on confidential containers (Kata TDX + NVIDIA CC GPUs)

Specs for the PRD-04 pieces that run on our own B300 hardware, deployed by Rafay (PRD-03) in the
form PRD-01 admission and the KMS accept: the agent policy and `alpha.json` inside the pod's
init-data (`io.katacontainers.config.hypervisor.cc_init_data`, the only Kata annotation), the
runtime's quote from the CoCo attestation agent (`ALPHACOMPUTE_QUOTE_SOURCE=coco-aa`) and the
init-data mounted for it through the downward API at `/run/alpha-pod/cc_init_data`. The Revision
v2 of a pod is a function of its init-data alone.

| File | What it is |
|---|---|
| `model-server.yaml` | `alpha-model-server`: stock vLLM on one whole CC-mode GPU (`nvidia.com/pgpu: 1`) in a `kata-qemu-nvidia-gpu-tdx` pod VM, `alpha-runtime` as a native sidecar terminating TLS on 8443 for alpha-inference only, `alpha-weights open` as an init container |
| `seal-weights-job.yaml` | one-off Job of the same App that downloads a model into pod-VM memory and seals it, bound to the model, onto the weights volume |
| `render-interim.py` | **interim** renderer, until `alpha coco render` (PRD-02 PR 6) replaces it: values in, init-data built, spec and Revision v2 out |
| `cluster.env` | per-cluster values: the two Apps, images by digest, the KMS pins |
| `models/*.env` | per-model values: the Corpus model and Nemotron Safety Guard |
| `env/alpha-inference.env` | the front with every model ours and the guard on every model |
| `env/alpha-guard.env` | the judge, now also called by the front |

## Rendering (interim)

`render-interim.py` takes a spec, the agent policy and the values files, and prints the spec with
every `${NAME}` filled and the init-data in its annotation; on stderr it prints the Revision v2
document and hash to register and to pin:

```sh
# 1. The input for genpolicy 4.1.0 (pinned container), with an empty init-data annotation:
deploy/coco/render-interim.py deploy/coco/model-server.yaml --for-genpolicy \
  deploy/coco/cluster.env deploy/coco/models/guard.env > guard.genpolicy.yaml
# 2. genpolicy on that file, then the policy review (no exec, no log readback): guard.rego
# 3. The spec to deploy, and its Revision:
deploy/coco/render-interim.py deploy/coco/model-server.yaml guard.rego \
  deploy/coco/cluster.env deploy/coco/models/guard.env > guard.yaml
```

The init-data is a CoCo init-data document (`version = "0.1.0"`, `algorithm = "sha384"`) with
`policy.rego`, the reviewed policy byte for byte, and `alpha.json`,
`{"app_id", "format": "alphacompute-initdata/1", "gpu": {"count": 1, "model": "B300"},
"runtime_class": "kata-qemu-nvidia-gpu-tdx"}`, the GPU count summed from the spec's
`nvidia.com/pgpu` limits. The script refuses a value that is unset, set twice, still a
`<placeholder>`, or holds a quote, backslash, `$` or newline; an App id that is not a lower-case
UUID; and a policy it cannot embed byte for byte (`'''`, a final quote, a carriage return or
another control character). Its output was checked against PRD-02's `alpha_core::coco` and
`alpha_tsm::coco::decode_annotation`: the same init-data, policy digest and Revision v2 hash.
Delete it, and render with `alpha coco render`, once that exists.

## Bring-up order

1. Register the model-server App and the seal Job's Revision; for each model, put
   `model-server-bearer-<model>` for the model-server App and for alpha-inference (same value,
   a different one per model).
2. Create `sealed-weights-<model>` PVCs; render and run `seal-weights-job.yaml` per model; put the
   manifest digest it prints (also `MANIFEST.sha256` on the volume) into `models/<model>.env` as
   `WEIGHTS_MANIFEST_SHA256`: the model server opens only that sealing of that model.
3. Render and deploy `model-server.yaml` per model; register each Revision; put its hash into
   alpha-inference's `MODEL_SERVERS`.
4. Put alpha-inference's `judge-bearer` and set alpha-guard's `inference-bearer` to the same value;
   name alpha-inference's App in alpha-guard's `INFERENCE_APPS` and `CALLER_APPS`.
5. Register alpha-guard with `env/alpha-guard.env` first: it names the front only by App, so its
   Revision does not depend on the front's. Then register alpha-inference with that Revision in
   `GUARD_REVISIONS` (`env/alpha-inference.env`) and deploy both. Confirm in alpha-inference's log:
   `model <id> served by alphacompute revision sha256:...` for both models.
6. Point corpus-supervisor's `INFERENCE_URL`/`INFERENCE_REVISIONS` at this alpha-inference.

## Choices worth knowing

- **The namespace is an Alpha confidential one**, labelled `alphacompute.ai/confidential=true`,
  `alphacompute.ai/attested=true` and `alphacompute.ai/track=alpha`: PRD-01 admission then holds
  every pod to the rules above, and lets it tolerate the Alpha track taint the runtime class adds.
  The pods carry `alphacompute.ai/tenant` and `alphacompute.ai/app` for GPU-hours chargeback.
- **Only alpha-inference gets in.** vLLM listens on loopback only, so the pod's only way in is the
  runtime's TLS on 8443, which alpha-inference pins to the KMS CA and the Revision. In the other
  direction the runtime admits a client only with an Instance leaf of alpha-inference's App
  (`ALPHACOMPUTE_TLS_CALLER_APPS`), so vLLM's routes outside `/v1`, which its API key does not
  cover, are closed to everyone else. Each server's own bearer is the second lock.
- **The runtime reaches vLLM at `127.0.0.1:8000`**, an address: `/etc/hosts` in a pod VM is written
  by the host and not measured.
- **Probes are TCP on 8443.** The kubelet runs them from the node, and the agent policy refuses
  exec, so an HTTP probe of the pod VM's loopback or an exec probe could never pass. 8443 opens
  once the runtime has attested; whether vLLM serves the model is alpha-inference's own check.
- **Weights are opened into pod-VM memory** (`emptyDir: {medium: Memory}`), and the pod VM is
  sized from the containers' limits (`POD_VM_MEMORY_MIB`, `POD_VM_VCPUS`), not from Kata
  annotations, which admission refuses. Size them for the weights, vLLM's host-side overhead and
  `/dev/shm`. Memory and vCPUs are not in the Revision; the reference values carry RTMR0 per
  shape.
- **One GPU per pod**, `Recreate` rollouts: no spare GPU is assumed.

## Depends on PRD-02

The runtime's CoCo evidence source (`ALPHACOMPUTE_QUOTE_SOURCE`, the init-data at
`/run/alpha-pod/cc_init_data`, GPU evidence) and the KMS's Revision v2 appraisal are PRD-02's; the
runtime on this branch still reads the dstack guest agent and ignores the variable. These specs
are written for the PRD-02 runtime, and nothing here has run on Kata, a GPU or the KMS.
