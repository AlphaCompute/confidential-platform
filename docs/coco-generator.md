# The CoCo generator (`alpha coco render`, `alpha coco wrap`)

Both commands produce what a Kata confidential pod is identified by (PRD-02 D4): the pod spec, the init-data that Kata binds into the TD's `MRCONFIGID`, and the Revision v2 derived from that init-data (see [kata-attestation.md](kata-attestation.md)). They differ in their input.

- `alpha coco render` takes a pod-spec template, `KEY=VALUE` files and an agent policy. It serves our own platform services, whose specs live in a repository.
- `alpha coco wrap` takes a customer's docker-compose and a shape, and runs genpolicy itself. It serves the Rafay offers. Its interface is fixed by rafay-plugins' `rafay-integration/coco-gpu.md` ("The `alpha coco wrap` contract"), and the adapter checks the output with `checkCocoWrapped` and `checkPodSpec`.

## Deployment preflight

`wrap` and `render` produce workloads; they do not enable guest services on the
node. Their `coco-aa` runtime needs the Kata guest startup setting
`agent.guest_components_rest_api=all`. Add it to the selected runtime's existing
`kernel_params` through a node configuration drop-in and recreate a test guest.
The default REST feature mode is `resource`, which responds to `/aa/*` with
`Attestation Feature Not Enabled`. Do not add a pod-level `kernel_params`
annotation to bypass node setup: it is outside the workload's allowed annotation
contract and may be rejected by admission.

Before evidence collection, `alpha-tsm` checks the pod-local `/info` response for
attestation feature access, TDX and, for a GPU shape, the NVIDIA attester. This is
a capability check; the KMS still verifies quotes and GPU evidence. A configfs
CPU fallback does not eliminate the GPU REST requirement. Also provision the
KMS endpoints ConfigMap and use matching, qualified guest-agent/genpolicy
versions; successful wrap output alone establishes none of these deployment
prerequisites. See `kata-attestation.md` for the verified B300 startup fix and
remaining hardware checks.

## `alpha coco wrap`

```
alpha coco wrap --app-id <App id> --platform <platform.json> --runtime-image <image@sha256:...> \
    --shape <shape.json> [--no-resolve] <compose file>
```

The adapter runs it with an empty environment and a two-minute limit, with files only. On success it prints one JSON object:

| Key | Value |
|---|---|
| `revision` | the Revision v2 in JCS form, byte for byte `InitData::revision()` of `initdata` |
| `revision_hash` | `sha256:<hex>` of `revision` |
| `initdata` | standard base64 of the init-data TOML (not gzipped; the adapter gzips it for the `cc_init_data` annotation) |
| `pod_spec` | the PodSpec the adapter deploys unchanged |
| `secrets` | the declared Secret names, at most 16 |

A refusal of the compose exits 1 with one line on stderr, `alpha: <reason>`. The reason names the compose's own keys and nothing of ours, so the adapter can show it to the customer. A failure on our side exits 2 and the adapter shows its own message instead. Our side means genpolicy missing or not the pinned binary, its output failing the baseline, or a shape the classes do not allow. An image that genpolicy cannot read from its registry is the customer's, and it exits 1.

The compose is checked first with the same allowlist and the same platform-document verification as `alpha compose wrap`: image resolution (or `--no-resolve`), secrets declared at the top level and listed per service, named volumes only, exactly one published port. `--shape` is `{"runtime_class", "gpu": {"model", "count"}, "cpu", "memory_mib"}`. `kata-qemu-nvidia-gpu-tdx` takes 1 or 8 GPUs. `kata-qemu-tdx` takes no `gpu`.

### The pod

- **`alpha-runtime`** runs as a native sidecar (an init container with `restartPolicy: Always`). It reads the init-data from the `cc_init_data` annotation, which a downward-API volume mounts at `/run/alpha-pod/cc_init_data`. It attests through the CoCo attestation agent (`ALPHACOMPUTE_QUOTE_SOURCE=coco-aa`) and holds the leaf. It writes each declared Secret into a memory-backed volume per declaring service, which that service mounts read-only at `/run/secrets`. It terminates TLS on 8443 and proxies to the published service at `127.0.0.1:<port>`. It uses the loopback address because a name would resolve through `/etc/hosts`, which the host writes. The socket contract (`/run/alpha/runtime.sock`) and the Secret-file contract are those of the CVM.
- **Start order.** The sidecar's startup probe is a TCP check of 8443. In a pod, the runtime opens 8443 only after it has attested and written every declared Secret (`alpha_runtime::Tls::AfterSecrets`). Kubernetes starts the services only after that probe passes, so a service never starts without its Secret files. This is the pod's equivalent of the compose health check. The probe waits up to 24 hours, as the compose does.
- **One container per service**, in the compose's order, with `image` pinned by digest, `entrypoint` as `command`, `command` as `args`, `environment`, named-volume mounts and a numeric `user` (as `runAsUser` and `runAsGroup`). A string command is split on spaces. A command that needs quoting must be written as a list, so that what runs is exactly what the policy pins.
- **Size.** Kata sizes the TD from the containers' limits, and RTMR0's reference value is captured per shape. So the regular containers' CPU and memory limits add up to the shape exactly, with requests equal to limits. The shape is split evenly and the first service takes the remainder. The sidecar sets no limits, so it adds nothing to the TD's size. The published service takes all of the shape's `nvidia.com/pgpu`.
- **Volumes.** Named volumes, the Secret volumes and the socket volume are `emptyDir` with `medium: Memory`, so they live in TD memory. The App's volumes are not persistent. Encrypted persistent volumes are a separate feature (deliverable 25).
- **No service-account token** (`automountServiceAccountToken: false`) and no service links (`enableServiceLinks: false`).
- **KMS endpoints.** `ALPHACOMPUTE_KMS_ENDPOINTS` comes from the namespace's `alpha-kms` ConfigMap (key `endpoints`) and is not measured. The endpoints only say where to connect: the runtime pins the KMS CA's SPKI hash and the KMS Revisions, which are measured. The policy admits the variable only as a list of `https://host[:port]`. *ponytail*: the adapter's manifest does not create this ConfigMap yet. Until the adapter or the PRD-01 blueprint creates it, the runtime container does not start, so the pod fails closed.

Compose keys that cannot hold in a confidential pod are refused, not dropped:

- `healthcheck`: it would need exec, which the policy refuses.
- `working_dir`: genpolicy 4.1.0 refuses `workingDir`. Set `WORKDIR` in the image instead.
- a named `user`: genpolicy pins numeric ids only.
- service or volume names that are not RFC 1123 labels.
- a published container port of 8443.
- more than 16 secrets.

`restart` and `depends_on` are accepted. The pod restarts every container, and containers start in the compose's order.

All services share the pod's network namespace. They reach each other at `127.0.0.1` on their own ports, and two services cannot listen on the same port. A port a service listens on is reachable on the pod IP. The adapter's NetworkPolicy, which admits only 8443, is what keeps it private.

### Agent policy

wrap runs genpolicy 4.1.0 on exactly the pod spec it prints, wrapped in the Deployment the adapter creates (`app-<App id>` in namespace `app-<App id>`; genpolicy pins the sandbox's name and namespace to it). Some things are left out of genpolicy's input. `automountServiceAccountToken`, `enableServiceLinks` and a claim's `readOnly` are fields genpolicy 4.1.0 refuses. The emitted pod spec still sets `automountServiceAccountToken: false`, and the settings admit no token mount. The KMS endpoints variable is also left out, because the policy admits it by pattern.

- **Binary.** genpolicy is `/opt/kata/bin/genpolicy` from kata-containers 4.1.0's `kata-tools-static-4.1.0-amd64.tar.zst` (sha256 `58fd1660…8f30`). Its own sha256 (`c32ad537…aa59`, `coco::policy::GENPOLICY_SHA256`) is checked before every run, and any other file there is refused. The release's `rules.rego` and `genpolicy-settings.json`, which the adapter image ships under `/opt/kata/share/defaults/kata-containers` with the same pins as its Dockerfile, are checked against `coco::policy::RELEASE_FILES` too. genpolicy itself runs with the copies embedded in `alpha`, with the Alpha baseline applied, which are made from exactly those bytes. The image therefore needs no baseline files of its own. It runs in a fresh directory with an empty environment and a 100-second limit. It needs the network: it downloads every image layer to read `/etc/passwd` and `/etc/group`, and it reads the pause image's configuration from `mcr.microsoft.com`. A large image therefore takes a large share of the two minutes.
- **Rules and settings: the Alpha baseline of #82.** The files live in `crates/alpha-cli/src/coco/genpolicy/`. #82's `testdata/agent-policy/` holds the regression tests that evaluate them with regorus against a hostile host.
  - **Rules.** genpolicy 4.1.0's `rules.rego` with `alpha-rules.patch` applied (`alpha-rules.rego`). The patch is vendored byte for byte from #82, and a test applies it again and compares. It adds `allow_guest_pull_image`: the guest pulls exactly the image the policy names, and the pause container comes from the guest image. It also adds `allow_env_complete`: every variable the policy lists is set. Stock genpolicy 4.1.0 checks neither, so a host could otherwise run another image under the same policy or unset a variable.
  - **Settings.** genpolicy's default `genpolicy-settings.json` plus drop-ins that genpolicy applies itself. `30-alpha-baseline.json` is #82's, byte for byte. `40-alpha-kms-endpoints.json` is ours and adds only the KMS endpoints pattern. `50-alpha-hostname.json` narrows the host-set `HOSTNAME` to one lowercase DNS label; it is #82's too, byte for byte.
  - **`HOSTNAME`.** genpolicy lists `HOSTNAME=$(host-name)` in every container, and its rules let the host set a variable that holds `$(host-name)` to anything. Its own `HOSTNAME` pattern, `$(dns_label)`, also admits `.` and `_`. Either way a host could set `HOSTNAME` to a sealed secret copied from a policy and have the agent unseal it into a container that was never given it. render and wrap therefore take genpolicy's entry out of every container's environment (`coco::policy::pin_hostname`), and the `50-` drop-in leaves one lowercase DNS label, which the pod's name is, as the only `HOSTNAME` the host may set. `HOSTNAME=$(sandbox-name)` would not do: the rules match `$(sandbox-name)` as an unanchored pattern, so any value containing the pod's name passes, a sealed secret with the name appended included. #82's suite shows each of these in genpolicy's own output.
  - `alpha coco genpolicy-settings --out <dir>` writes the settings directory and the patched rules, for running genpolicy by hand.
- **Guest-pulled users.** With guest pull, genpolicy refuses a container whose user or groups come from the image, because containerd might not reproduce them. wrap then sets exactly the values genpolicy names and runs it again: the container's `runAsUser` and `runAsGroup`, and the image's supplementary groups as the pod's `supplementalGroups`. These are the image's own values, so the container runs as it would have, and the policy now pins them. Kubernetes has no per-container supplementary groups, so the groups apply to every container in the pod.

### The baseline (PRD-02 P0)

`coco::policy::verify` accepts a policy only as the patched rules above followed by `policy_data`. A policy with genpolicy's unpatched rules is refused by name. Nothing may follow the data, and the rules' own defaults refuse every request the data does not allow. The data must:

| Request | Baseline |
|---|---|
| `ExecProcessRequest` | no allowed commands, no regexes, and no container's `exec_commands` (no exec probes or hooks) |
| `ReadStreamRequest`, `WriteStreamRequest`, `CloseStdinRequest` | refused: no log reads, no stdin |
| `GetDiagnosticDataRequest`, `UpdateEphemeralMountsRequest` | refused |
| `CopyFileRequest` | only `$(sfprefix)`, the per-container shared files (hosts, resolv.conf, the downward-API init-data) |
| `CreateContainerRequest` | only the listed containers, each by image digest (`io.kubernetes.cri.image-name`) with its command, environment and mounts as genpolicy pinned them, and images pulled in the guest (`guest_pull`) |
| host-added environment | only `HOSTNAME` (one lowercase DNS label), the API server's `KUBERNETES_*` and `ALPHACOMPUTE_KMS_ENDPOINTS` (as above), or fewer. Service links, `AZURE_*` and `TERM` are refused. The patched rules also refuse a container that lacks any variable the policy lists. No listed variable may hold `$(host-name)`, `$(node-name)` or `$(pod-uid)`, which the rules fill with any value, and no listed `HOSTNAME` any placeholder |
| token mounts | none: no container in the policy mounts the service-account or Azure token |

wrap also requires that the policy admits exactly the pod's containers and images. `render --policy` holds its input to the same baseline, and requires that the policy admits exactly the containers and images of the rendered spec's pod templates. A policy that edits the rules, or whose data loosens any line above, is refused. It is never repaired.

Known limits, for the security review:

- `kata_config.oci_version` stays genpolicy's 1.1.0, as in #82's fixtures (*ponytail*, G0: confirm on containerd 2.3.x). A wrong value refuses every container, so it fails closed.

## `alpha coco render`

```
alpha coco render --spec pod.yaml --for-genpolicy --env cluster.env > for_genpolicy.yaml
alpha coco genpolicy-settings --out gp
genpolicy -y for_genpolicy.yaml -p gp/rules.rego -j gp -r > policy.rego     # genpolicy 4.1.0
alpha coco render --spec pod.yaml --policy policy.rego --env cluster.env > manifest.yaml
```

The rendered manifest goes to stdout. The digests, the Revision v2 and its hash go to stderr. `--policy` is refused unless it holds the baseline and admits exactly the spec's containers.

## Test vectors

`testdata/coco/` holds them; see its README. `WRITE_VECTORS=1 cargo test -p alpha-cli coco` writes the outputs again. Add `ALPHA_TEST_GENPOLICY=<path to genpolicy 4.1.0>` to run genpolicy again too. The runs need the network, and the binary must have the pinned digest. Without it, the tests replay the recorded genpolicy runs and fail when genpolicy's input would change.
