# The CoCo generator (`alpha coco render`, `alpha coco wrap`)

Both commands produce what a Kata confidential pod is identified by (PRD-02 D4): the pod spec, the init-data that Kata binds into the TD's `MRCONFIGID`, and the Revision v2 derived from that init-data (see [kata-attestation.md](kata-attestation.md)). They differ in their input.

- `alpha coco render` takes a pod-spec template, `KEY=VALUE` files and an agent policy. It serves our own platform services, whose specs live in a repository.
- `alpha coco wrap` takes a customer's docker-compose and a shape, and runs genpolicy itself. It serves the Rafay offers. Its interface is fixed by rafay-plugins' `rafay-integration/coco-gpu.md` ("The `alpha coco wrap` contract"), and the adapter checks the output with `checkCocoWrapped` and `checkPodSpec`.

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

wrap runs genpolicy 4.1.0 on exactly the pod spec it prints, wrapped in the Deployment the adapter creates (`app-<App id>` in namespace `app-<App id>`; genpolicy pins the sandbox's name and namespace to it). Three things are left out of genpolicy's input: `automountServiceAccountToken` and `enableServiceLinks`, which genpolicy 4.1.0 does not take and which only take things away, and the KMS endpoints variable, which the policy admits by pattern.

- **Binary.** genpolicy is `/opt/kata/bin/genpolicy` from kata-containers 4.1.0's `kata-tools-static-4.1.0-amd64.tar.zst` (sha256 `58fd1660…8f30`). Its own sha256 (`c32ad537…aa59`, `coco::policy::GENPOLICY_SHA256`) is checked before every run, and any other file there is refused. It runs in a fresh directory with an empty environment and a 100-second limit. It needs the network: it downloads every image layer to read `/etc/passwd` and `/etc/group`, and it reads the pause image's configuration from `mcr.microsoft.com`. A large image therefore takes a large share of the two minutes.
- **Rules and settings.** The rules are genpolicy 4.1.0's `rules.rego`, vendored byte for byte (`crates/alpha-cli/src/coco/genpolicy/`). The settings are its `genpolicy-settings.json` with the baseline applied by `coco::policy::settings()`. `alpha coco genpolicy-settings --out <dir>` writes both, for running genpolicy by hand.
- **Guest-pulled users.** With guest pull, genpolicy refuses a container whose user or groups come from the image, because containerd might not reproduce them. wrap then sets exactly the values genpolicy names and runs it again: the container's `runAsUser` and `runAsGroup`, and the image's supplementary groups as the pod's `supplementalGroups`. These are the image's own values, so the container runs as it would have, and the policy now pins them. Kubernetes has no per-container supplementary groups, so the groups apply to every container in the pod.

### The baseline (PRD-02 P0)

`coco::policy::verify` accepts a policy only as genpolicy 4.1.0's rules followed by `policy_data`. Nothing may follow the data, and the rules' own defaults refuse every request the data does not allow. The data must:

| Request | Baseline |
|---|---|
| `ExecProcessRequest` | no allowed commands, no regexes, and no container's `exec_commands` (no exec probes or hooks) |
| `ReadStreamRequest`, `WriteStreamRequest`, `CloseStdinRequest` | refused: no log reads, no stdin |
| `GetDiagnosticDataRequest`, `UpdateEphemeralMountsRequest` | refused |
| `CopyFileRequest` | only `$(sfprefix)`, the per-container shared files (hosts, resolv.conf, the downward-API init-data) |
| `CreateContainerRequest` | only the listed containers, each by image digest (`io.kubernetes.cri.image-name`) with its command, environment and mounts as genpolicy pinned them, and images pulled in the guest (`guest_pull`) |
| host-added environment | only `HOSTNAME` and `ALPHACOMPUTE_KMS_ENDPOINTS` (as above). Service links and cloud-identity variables are refused |
| token mounts | none: the service-account and Azure token mounts are removed from the settings |

wrap also requires that the policy admits exactly the pod's containers and images. `render --policy` holds its input to the same baseline, and requires that the policy admits exactly the containers and images of the rendered spec's pod templates. A policy that edits the rules, or whose data loosens any line above, is refused. It is never repaired.

Known limits, for the security review:

- genpolicy's rules check that a container's environment is a subset of the policy's (`allow_env`). A host can therefore leave a listed variable out, but it cannot add or change one. A service should refuse to start without the configuration it needs.
- `kata_config.oci_version` is set to 1.3.0 (*ponytail*, G0: confirm on containerd 2.3.x). A wrong value refuses every container, so it fails closed.

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
