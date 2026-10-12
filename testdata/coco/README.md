# CoCo generator vectors

`alpha coco render` and `alpha coco wrap` (see `docs/coco-generator.md`). All are produced by the
generator itself under `WRITE_VECTORS=1`; `policy.rego` files are genpolicy 4.1.0's real output
under `alpha coco genpolicy-settings`, recorded with `ALPHA_TEST_GENPOLICY` naming the pinned
binary. Public images stand in for `alpha-runtime` and the services so that genpolicy can read
them: `alpine` for the runtime, `nginx` and `busybox` for the services, each pinned by digest.
The KMS pins are those of `testdata/manifest/05-deploy`.

- `wrap/01-gpu` — `compose.yaml` (two services, a secret, a named volume mounted short and long,
  `depends_on`) on the `b300x1` shape in `shape.json`. `output.json` is what `alpha coco wrap`
  prints for App `01994b3e-5c8a-7d3e-9a1b-2c3d4e5f6a7b`; rafay-plugins' `checkCocoWrapped`
  accepts it for `b300x1`. `genpolicy-input.yaml` is the Deployment genpolicy read last,
  `policy.rego` what it printed, and `genpolicy-runs.json` every run by the SHA-256 of its input:
  the first asked for the runtime image's groups, which the second input pins.
- `wrap/02-cpu` — one service on a `kata-qemu-tdx` shape: no GPU in the pod or the Revision.
- `wrap/03-volume` — one service with an encrypted persistent volume (`x-alphacompute-volumes`)
  on a CPU shape, `busybox` standing in for the `alpha-volume` image: the init container, the
  claim under `volume_claims`, and the policy with the two mounts' propagation set.
- `wrap/04-kbs` — Option B: one service on a CPU shape that opts in to the KBS
  (`x-alphacompute-kbs`), takes a sealed secret in its environment and has an encrypted scratch
  volume (`x-alphacompute-scratch`). The KBS is `https://kbs.trustee.alphacompute.internal:8080`
  with `kbs/cert.pem`, as the adapter would pass them. The sealed value names this App's
  `secret/db_password` under `sealed-secret-key/sealing`; its signature is 64 bytes of `0x07`,
  so it is well formed but would not verify in CDH.
- `wrap-refusals/cases.yaml` — one compose per refusal `coco wrap` adds to `compose wrap`'s
  (`testdata/manifest/09-wrap-refusals`), with a substring of the line the customer sees,
  among them a compose that tries to declare a customer DSM.
- `render/01-pod` — `spec.yaml` and `values.env` for `alpha coco render`; `policy.rego` is
  genpolicy's output for the `--for-genpolicy` rendering, `manifest.yaml` the rendered spec and
  `revision.txt` the Revision v2 and its hash.
- `render/02-volume` — `01-pod`'s spec and values rendered with
  `--volume pgdata:20Gi:app:/var/lib/data`: the claim appended as a document, the init
  container and the mount added, and genpolicy's policy for that rendering.
- `render/03-kbs` — `01-pod` with a sealed secret and a disk-backed `emptyDir` on the service,
  rendered with `--kbs-url` and `--kbs-cert` as for `wrap/04-kbs`.
- `kbs/cert.pem` — a self-signed P-256 certificate standing in for Trustee's KBS certificate;
  its SPKI SHA-256 is `4d7e6cc4…99a8`.
