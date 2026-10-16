# The KMS nodes and platform services on Kata

Every KMS node is a Kata TDX pod (`kata-qemu-tdx`) of one rendered StatefulSet, `kms`, so all
nodes share one Revision: the SHA-256 of its pod template's init-data. The trust-zone Postgres is an
ordinary pod on its own node pool and is treated as untrusted storage: what is secret in it is
ciphertext under keys it never sees, and its rows and their freshness are not protected against
whoever runs it. Nothing here is applied by CI: the operator applies these files with `kubectl`.
How a node gets its database password, and why the init-data carries none, is in
[`../README.md`](../README.md#a-node-in-a-kata-pod).

Production's Day 0 comes after three ceremonies: the release signers' keys
([`../signer-keys.md`](../signer-keys.md)), the tagged release rebuilt on a second machine
([`../verify-release.md`](../verify-release.md)), and the dress rehearsal of genesis
([`../rehearsal.md`](../rehearsal.md)).

## Inputs not fixed yet

Each is chosen before the release whose pod spec is signed; the first three are measured, so
changing one is a new Revision.

- `KMS_KATA_ENDPOINTS` (repository variable): both nodes' addresses,
  `https://kms-0.kms.alpha-kms.svc:8443,https://kms-1.kms.alpha-kms.svc:8443`. A node walks this
  list once, at start, to find a peer to join.
- `KMS_KATA_PLATFORM_DOCUMENT_URL` (repository variable): where the signed platform document is
  served, without a cache in front.
- `KMS_KATA_PCCS_URL` (repository variable): the PCCS the nodes fetch collateral from.
- `TRUST_DB_STORAGE_CLASS`, `TRUST_DB_STORAGE_SIZE` (`trust-db.yaml`): the trust-db pool's local
  volume.

## What a release produces

A tag `v*` with `KMS_KATA_ENDPOINTS` set renders `kms-node.yaml` with the pushed `alpha-kms` digest
and the three variables (`envsubst`, then `alpha coco render` with the Kata 4.0.0 genpolicy) and
adds `kata/` to the `alpha-kms-release-manifest` artifact:

- `kms-node.yaml`: the StatefulSet with the init-data in its pod template's
  `io.katacontainers.config.hypervisor.cc_init_data` annotation;
- `init-data.toml`: the init-data bytes, `[data] app_id` and the agent policy;
- `manifest.json`: `image`, `compose_hash` (`sha256:` of `init-data.toml`, the Revision),
  `rules_sha256` and `policy_data_sha256` (the values of the document's `kata_policy`).

With the variables unset, the release renders no Kata pod; neither does a release whose
`alpha-kms` build fails because `crates/alpha-channel/release-keys/prod.pub` does not hold the
production release key yet. Anyone reproduces it on Linux x86_64
from the tag: `envsubst` the template with the same four values, then
`alpha coco render --app-id 01a09f07-8d09-7640-94c1-bbdb74200a1e --kata <opt/kata of
kata-tools-static-4.0.0-amd64.tar.zst> --out out.yaml kms-node.yaml` prints the same `revision`
and `init_data`.

## Signing the Revision

Each release-key holder downloads the artifact, checks that `sha256sum init-data.toml`
is `compose_hash` in `manifest.json`, and reads `init-data.toml`: the image is the release's digest, the four `ALPHACOMPUTE_*` values are the
intended ones and the database URL has no password. The document gets
`{ "compose_hash": "<manifest.json>", "build": "kms <tag>", "source_url": "<the release>" }` in
`kms_revisions[]`, `kata_policy` with the two digests from `manifest.json`, and
`kata_reference_values` for `kata-qemu-tdx` with `gpu: false` at the pod's shape (no resources:
1 vCPU, 2048 MiB). Then `alpha sign --release-key release.key --init-data init-data.toml
document.json`, which refuses an init-data that is not listed or fails the document's
`kata_policy`. Publish it at `KMS_KATA_PLATFORM_DOCUMENT_URL`. On day 0 `kms_ca_pem` is empty.

## Day 0

Before anything: the document above is served, the release's `kata/` is at hand, and the
custodians have run `alpha keygen --custodian` and handed over their public keys. Every step
runs in one shell, where the CLI reads the document and the PCCS from the repository variables
the release rendered with:

```sh
export ALPHACOMPUTE_PLATFORM_DOCUMENT_URL=$(gh variable get KMS_KATA_PLATFORM_DOCUMENT_URL -R AlphaCompute/confidential-platform)
export ALPHACOMPUTE_PCCS_URL=$(gh variable get KMS_KATA_PCCS_URL -R AlphaCompute/confidential-platform)
```

1. **Node pools.** At least as many TDX hosts with the `kata-qemu-tdx` runtime class as there are
   nodes (pod anti-affinity puts each node on its own host), and one host for Postgres. Exclude
   both pools from automatic drains and upgrades. `KMS_HOSTS` holds the TDX hosts' node names,
   space-separated, and `TRUST_DB_HOST` the Postgres host's.

   ```sh
   : "${KMS_HOSTS:?}" "${TRUST_DB_HOST:?}"
   for node in $KMS_HOSTS; do
     kubectl label node "$node" alphacompute.io/pool=kms
     kubectl taint node "$node" alphacompute.io/pool=kms:NoSchedule
   done
   kubectl label node "$TRUST_DB_HOST" alphacompute.io/pool=trust-db
   kubectl taint node "$TRUST_DB_HOST" alphacompute.io/pool=trust-db:NoSchedule
   ```

2. **Postgres.** The owner password stays with the operator. The server certificate is
   self-signed ECDSA (an Ed25519 certificate has no hash for channel binding). The nodes do not
   verify it, but bind their SCRAM login to the TLS connection, so a relay in between fails.

   ```sh
   umask 077   # the password files and tls.key; keep this shell for step 4
   kubectl create namespace alpha-trust-db
   openssl rand -hex 32 > owner-password
   kubectl -n alpha-trust-db create secret generic postgres --from-file=password=owner-password
   openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
     -subj /CN=postgres.alpha-trust-db.svc -keyout tls.key -out tls.crt
   kubectl -n alpha-trust-db create secret tls postgres-tls --cert tls.crt --key tls.key
   : "${TRUST_DB_STORAGE_CLASS:?}" "${TRUST_DB_STORAGE_SIZE:?}" &&
     export TRUST_DB_STORAGE_CLASS TRUST_DB_STORAGE_SIZE &&
     envsubst '$TRUST_DB_STORAGE_CLASS $TRUST_DB_STORAGE_SIZE' < trust-db.yaml | kubectl apply -f -
   kubectl -n alpha-trust-db rollout status statefulset/postgres
   ```

3. **Migrate** with the release's image; the Job must end `Complete`. It creates the `nologin`
   role `alpha_kms` and its grants.

   ```sh
   KMS_IMAGE=$(jq -r .image manifest.json) envsubst '$KMS_IMAGE' < migrate.yaml | kubectl create -f -
   ```

4. **The nodes' login** with a one-time genesis password, sent on stdin so it never sits in a pod
   spec or an argument list:

   ```sh
   openssl rand -hex 32 > genesis-db-password
   printf "create role alpha_kms_node login password '%s' in role alpha_kms;\n" "$(cat genesis-db-password)" \
     | kubectl -n alpha-trust-db exec -i postgres-0 -- psql -X -v ON_ERROR_STOP=1 -U postgres -d alpha
   ```

5. **Namespace, addresses, budget**: `kubectl apply -f kms.yaml`. The headless Service `kms`
   gives each node its name in `KMS_KATA_ENDPOINTS`; the budget keeps one ready node, and a node
   is ready only while it serves.

6. **The nodes**, from the release's `kms-node.yaml` unchanged. `kms-0` comes up sealed; the
   StatefulSet creates `kms-1` only once `kms-0` is ready.

   ```sh
   kubectl apply -f kms-node.yaml
   kubectl -n alpha-kms port-forward pod/kms-0 8443:8443 &
   curl -sk https://localhost:8443/ready   # 503 {"sealed":true}
   ```

7. **Bootstrap** through the port-forward. The CLI appraises the node against the signed document
   (Revision in `kms_revisions`, a class without GPUs, TLS key equal to the attested one) before it
   seals anything; the genesis password travels inside the sealed body, and the node replaces it,
   in the genesis transaction, with a password derived from the root KEK.

   ```sh
   alpha bootstrap --custodians c1.pub c2.pub c3.pub --endpoint https://localhost:8443 \
     --database-password-file genesis-db-password
   ```

   Hand each `share-<n>.json` to its custodian and delete it, then delete `genesis-db-password`
   once the check below shows it is dead. If the CLI gets no answer, do not retry: drop and
   recreate the database (`drop database alpha; create database alpha;` as `postgres`), give the
   role a new genesis password (`alter role alpha_kms_node password …`, as in step 4), migrate and
   bootstrap again after `kubectl -n alpha-kms delete pod kms-0`.

8. **Re-sign the document** with `kms_ca_pem`; `alpha sign --check` prints the CA's SPKI SHA-256
   and the Revisions, the two values a tenant pins.

9. **The other node.** `kms-1` joins `kms-0` on start, which needs the re-signed document. If it
   started before and stays sealed, `kubectl -n alpha-kms delete pod kms-1`; the StatefulSet
   creates it again.

## Verify

The policy refuses `kubectl exec` into a node and leaves `kubectl logs` empty, so the checks go
through the nodes' API and the database.

- Every node pod carries the signed Revision: for each, the hash below equals `compose_hash`.

  ```sh
  for pod in kms-0 kms-1; do
    kubectl -n alpha-kms get pod "$pod" -o jsonpath='{.metadata.annotations.io\.katacontainers\.config\.hypervisor\.cc_init_data}' | base64 -d | gunzip | sha256sum
  done
  ```
- `kubectl -n alpha-kms exec kms-0 -- /alpha-kms` is refused.
- `kubectl -n alpha-kms get statefulset kms` shows `2/2` ready: both nodes serve.
- The genesis password is dead; this login is refused:

  ```sh
  kubectl -n alpha-trust-db exec -i postgres-0 -- sh -c 'IFS= read -r PGPASSWORD; export PGPASSWORD
    exec psql -X "host=localhost dbname=alpha user=alpha_kms_node sslmode=require" -c "select 1"' \
    < genesis-db-password
  ```
- The audit log has the genesis and one join per other node:
  `select ts, action, outcome from audit_log where actor_kind = 'node' order by seq;` as `postgres`
  shows `node.bootstrap ok` and `node.join ok`.
- `alpha sign --check` on the served document lists the Revision and the CA.

## Restart, upgrade, loss

- **Restart.** The StatefulSet recreates a lost node pod; it comes back sealed and joins the
  serving node.
- **Upgrade.** Sign a document listing the old and the new Revision; every tenant App that pins
  the KMS gets a Revision listing both. Then `kubectl apply -f` the new release's `kms-node.yaml`:
  the StatefulSet replaces `kms-1`, waits until it has joined and is ready, then replaces `kms-0`.
  If the new `kms-1` never becomes ready, apply the old file, then
  `kubectl -n alpha-kms delete pod kms-1`: the StatefulSet does not replace a pod that is not ready.
  Drop the old Revision once no tenant pins it.
- **All nodes lost.** Port-forward to `pod/kms-0` as in step 6, and two custodians each export
  the two variables of Day 0 and, with the one share they were handed, run
  `alpha unseal --share share-[1-3].json --key custodian.key --endpoint https://localhost:8443`.
  The root gives the node its database password. `kms-1` then joins
  it; if it was already running sealed, delete its pod.

## What the operator never sees

The root KEK, the shares in the clear (bootstrap writes each sealed to its custodian's key), the
two intermediates (`tenant-kek-root`, the CA key), the derived database password, tenant secrets.
The operator does hold the Postgres owner password, the server key and the volume: ciphertext,
metadata and the audit log, which the owner can rewrite or roll back. The genesis password is
dead at the genesis commit.

## Platform services

`inference.yaml`, `guard.yaml` and `broker.yaml` are Deployments of `kata-qemu-tdx` pods with no
resources, the KMS nodes' shape (1 vCPU, 2048 MiB), whose reference values the document already
lists. `model-server.yaml` is one vLLM model on one GPU of `kata-qemu-nvidia-gpu-tdx`. Every pod
runs `alpha-runtime` beside its service. The three services read their leaf and Secrets from its
socket and terminate their own TLS on 8443. Each template is its App's Revision once rendered: a new value of any input below is a new Revision.

On B300 the GPU class needs two drop-ins in the `qemu-nvidia-gpu-tdx` shim's
`/opt/kata/share/defaults/kata-containers/runtimes/qemu-nvidia-gpu-tdx/config.d/`, both loaded
after kata-deploy's `50-user-overrides.toml`. Each moves the class's reference values.

- `60-guest-driver-595.91.07.toml` boots a guest rebuilt from Kata 4.0.0 with NVIDIA 595.91.07
  instead of the 595.58.03 it ships: the guest driver must be the version of the host's
  `nv-fabricmanager`, 595.91.07. Besides RTMR1 and RTMR2, the class's
  `gpus.reference_values` need an entry captured with this driver: the KMS matches
  `driver_version` exactly and refuses a GPU it has no reference for.

  ```toml
  [hypervisor.qemu]
  kernel = "/opt/kata/share/kata-containers/vmlinuz-6.18.35-200-nvidia-gpu-595.91.07"
  image = "/opt/kata/share/kata-containers/kata-ubuntu-noble-nvidia-gpu-confidential-595.91.07.image"
  kernel_verity_params = "root_hash=9ba122583c10330cfcb9a1de735da913a5f4a40fc9672fcad62f6291c4fad773,salt=6626d68de4dc10001d3b66d8e64a50f704b677b398ecd49d6cc487237f59e2f1,data_blocks=135680,data_block_size=4096,hash_block_size=4096"
  ```

  | `/opt/kata/share/kata-containers/` | SHA-256 |
  |---|---|
  | `vmlinuz-6.18.35-200-nvidia-gpu-595.91.07` | `44d7cdd903e6999ce47415fd6756d2ebe8ce2425422d7dd55d5a5147dacef0d5` |
  | `kata-ubuntu-noble-nvidia-gpu-confidential-595.91.07.image` | `fe709f1e4f71790dd4bd632c8ed2c6fb19cacb5e7fae004687b1fc46808e3d51` |

- `70-visible-cdi-devices.toml`: the runtime container claims no GPU, so without this it sees no
  `/dev/nvidia*`, sends no GPU evidence, and the KMS refuses it. It adds
  `agent.visible_cdi_devices=true` to the guest command line, so it is part of RTMR2.

  ```toml
  [agent.kata]
  visible_cdi_devices = true
  ```

A restart of kata-deploy keeps both files and the guest; `helm uninstall` of kata-deploy deletes
them with the rest of `/opt/kata`.

### Inputs

Each is the operator's, chosen per environment; none has a default.

| Input | Templates | What |
|---|---|---|
| `RUNTIME_IMAGE` | all | the `alpha-runtime` release image by digest |
| `KMS_CA_SPKI_SHA256`, `KMS_REVISIONS` | all | what `alpha sign --check` prints for the served document |
| `KMS_ENDPOINTS` | all | `KMS_KATA_ENDPOINTS` |
| `INFERENCE_APP_ID`, `GUARD_APP_ID`, `BROKER_APP_ID`, `MODEL_APP_ID` | one each | the service's App id |
| `INFERENCE_IMAGE`, `GUARD_IMAGE`, `BROKER_IMAGE` | one each | the service's release image by digest |
| `MODELS`, `MODEL_SERVERS` | inference | `services/alpha-inference/README.md`; `MODEL_SERVERS` is `{}` when RedPill serves every model, and a model server's `url` is `https://<MODEL_NAME>.alpha-models.svc:8443` |
| `UPSTREAM_URL`, `PCCS_URL`, `UPSTREAM_POLICY` | inference | RedPill's settings; with every model on our own servers, delete their three lines before rendering |
| `INFERENCE_REVISIONS`, `GUARD_CALLER_APPS` | guard | the front's registered Revisions; the App ids that may ask for a verdict (`CALLER_APPS`) |
| the six `<PROVIDER>_CLIENT_ID`, `OAUTH_REDIRECT_BASE` | broker | `services/alpha-broker/README.md` |
| `MODEL_NAME` | model-server | the Deployment's name, one DNS label |
| `MODEL_ID` | model-server | the name vLLM serves the model under |
| `MODEL_IMAGE` | model-server | vLLM with the weights, by digest (below) |
| `MODEL_CALLER_APPS` | model-server | the App ids of the front and the guard, comma-separated |
| `MODEL_CPUS`, `MODEL_MEMORY` | model-server | the pod VM's shape; the memory holds the image the guest pulls, vLLM's host side and the KV cache |

### The model image

The weights are not sealed: they are layers of an image whose digest the policy pins, and the
guest's pull checks every layer against it, so a pod runs exactly the weights the digest names.

```dockerfile
FROM vllm/vllm-openai@sha256:<the pinned vLLM release>
COPY <the model's directory> /weights
```

Build and push it to the repository `MODEL_REPOSITORY` names (`registry/path`), and set
`MODEL_IMAGE` to its digest:

```sh
docker build -t "$MODEL_REPOSITORY" . && docker push "$MODEL_REPOSITORY" &&
  MODEL_IMAGE=$(docker inspect --format '{{index .RepoDigests 0}}' "$MODEL_REPOSITORY") &&
  export MODEL_IMAGE
```

### Render, register, set Secrets

Render in this order, since each pins the Revisions of the next one down: model servers, the front, the guard. On Linux x86_64, with
Kata 4.0.0's genpolicy and the id of `admin.key` from `admin-key.json`, the reply that registered
it:

```sh
kata=$PWD/kata-tools && mkdir -p "$kata"
curl -fsSL https://github.com/kata-containers/kata-containers/releases/download/4.0.0/kata-tools-static-4.0.0-amd64.tar.zst \
  | tar --zstd -x -C "$kata"
ADMIN_KEY_ID=$(jq -r .id admin-key.json)
```

then for each template, here the front:

```sh
template=inference.yaml app=$INFERENCE_APP_ID
envsubst "$(grep -o '\${[A-Z0-9_]*}' "$template" | sort -u | tr -d '\n')" < "$template" > in.yaml
alpha coco render --app-id "$app" --kata "$kata/opt/kata" --out "rendered-$template" in.yaml > rendered.json
jq --arg app "$app" '{app_id: $app, init_data, digest: .revision}' rendered.json > revision.json
alpha call register-revision --key admin.key --key-id "$ADMIN_KEY_ID" revision.json
```

`rendered.json`'s `rules_sha256` and `policy_data_sha256` are the document's `kata_policy`, or the
KMS refuses the Revision. The GPU class
needs `kata_reference_values` with `gpu: true` at `MODEL_CPUS` and `MODEL_MEMORY`: RTMR0 is
captured per shape.

Each Secret goes in with `alpha call put-secret` and the payload
`{"name": "<name>", "app_ids": ["<the App id>"]}`, its value read from the file of its name; the
guard's `inference-bearer` is the front's `caller-bearer`, and the broker's `database-url` is
below. The model server has none.

```sh
put_secret() {
  jq -n --arg name "$1" --arg app "$2" '{name: $name, app_ids: [$app]}' > secret.json
  alpha call put-secret --key admin.key --key-id "$ADMIN_KEY_ID" --value "$1" secret.json
}
put_secret redpill-api-key "$INFERENCE_APP_ID"
put_secret caller-bearer "$INFERENCE_APP_ID"
cp caller-bearer inference-bearer
put_secret inference-bearer "$GUARD_APP_ID"
for name in google-client-secret dropbox-client-secret slack-client-secret \
  figma-client-secret hubspot-client-secret connect-bearer; do
  put_secret "$name" "$BROKER_APP_ID"
done
```

### The broker's database

The broker's login role and database on the trust-db, with a password sent on stdin:

```sh
openssl rand -hex 32 > broker-db-password
printf "create role alpha_broker login password '%s';\n" "$(cat broker-db-password)" \
  | kubectl -n alpha-trust-db exec -i postgres-0 -- psql -X -v ON_ERROR_STOP=1 -U postgres -d alpha
echo 'create database alpha_broker owner alpha_broker;' \
  | kubectl -n alpha-trust-db exec -i postgres-0 -- psql -X -v ON_ERROR_STOP=1 -U postgres -d alpha
```

The Secret `database-url` carries that password; the broker applies its migrations when it starts.

```sh
printf 'postgres://alpha_broker:%s@postgres.alpha-trust-db.svc:5432/alpha_broker?sslmode=require&channel_binding=require&require_auth=scram-sha-256' \
  "$(cat broker-db-password)" > database-url
put_secret database-url "$BROKER_APP_ID" && rm broker-db-password database-url
```

### Apply

```sh
kubectl apply -f platform.yaml
kubectl apply -f rendered-inference.yaml -f rendered-guard.yaml -f rendered-broker.yaml
kubectl apply -f rendered-model-server.yaml
kubectl -n alpha-models expose deployment "$MODEL_NAME" --port 8443
```

A pod turns ready once its runtime has attested and its service answers: the front once its
default model passes the gateway check or its model server lists it, the guard and the broker once they reach the front and the
database, a model server once vLLM's `/health` answers. Exposing the broker or the front outside
the cluster is the operator's choice of ingress, in TLS passthrough: each terminates its own TLS.
