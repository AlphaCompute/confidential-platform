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
- `wrap-refusals/cases.yaml` — one compose per refusal `coco wrap` adds to `compose wrap`'s
  (`testdata/manifest/09-wrap-refusals`), with a substring of the line the customer sees.
- `render/01-pod` — `spec.yaml` and `values.env` for `alpha coco render`; `policy.rego` is
  genpolicy's output for the `--for-genpolicy` rendering, `manifest.yaml` the rendered spec and
  `revision.txt` the Revision v2 and its hash.
