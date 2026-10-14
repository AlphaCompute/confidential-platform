# The KMS nodes on Kata: fresh genesis on owned hardware

Every KMS node is a Kata TDX pod (`kata-qemu-tdx`) created from one rendered pod spec, so all
nodes share one Revision: the SHA-256 of the pod's init-data. The trust-zone Postgres is an
ordinary pod on its own node pool and is treated as untrusted storage: what is secret in it is
ciphertext under keys it never sees, and its rows and their freshness are not protected against
whoever runs it. Nothing here is applied by CI: the operator applies these files with `kubectl`.
How a node gets its database password, and why the init-data carries none, is in
[`../README.md`](../README.md#a-node-in-a-kata-pod).

## Inputs not fixed yet

Each is chosen before the release whose pod spec is signed; the first three are measured, so
changing one is a new Revision.

- `KMS_KATA_ENDPOINTS` (repository variable): every node's address,
  `https://kms-1.alpha-kms.svc:8443,…,https://kms-<N>.alpha-kms.svc:8443`. Its length is the number
  of nodes. A node walks this list once, at start, to find a peer to join.
- `KMS_KATA_PLATFORM_DOCUMENT_URL` (repository variable): where the signed platform document is
  served, without a cache in front.
- `KMS_KATA_PCCS_URL` (repository variable): the PCCS the nodes fetch collateral from.
- `KMS_MAX_UNAVAILABLE` (`kms.yaml`): how many node pods a voluntary disruption may take at once;
  fewer than the number of nodes.
- `TRUST_DB_STORAGE_CLASS`, `TRUST_DB_STORAGE_SIZE` (`trust-db.yaml`): the trust-db pool's local
  volume.

## What a release produces

A tag `v*` with `KMS_KATA_ENDPOINTS` set renders `kms-node.yaml` with the pushed `alpha-kms` digest
and the three variables (`envsubst`, then `alpha coco render` with the Kata 4.0.0 genpolicy) and
adds `kata/` to the `alpha-kms-release-manifest` artifact:

- `pod.yaml`: the pod spec with the init-data in its `io.katacontainers.config.hypervisor.cc_init_data`
  annotation; the file every node pod is created from;
- `init-data.toml`: the init-data bytes, `[data] app_id` and the agent policy;
- `manifest.json`: `image`, `compose_hash` (`sha256:` of `init-data.toml`, the Revision),
  `rules_sha256` and `policy_data_sha256` (the values of the document's `kata_policy`).

With the variables unset, the release renders no Kata pod. Anyone reproduces it on Linux x86_64
from the tag: `envsubst` the template with the same four values, then
`alpha coco render --app-id 01a09f07-8d09-7640-94c1-bbdb74200a1e --kata <opt/kata of
kata-tools-static-4.0.0-amd64.tar.zst> --out pod.yaml kms-node.yaml` prints the same `revision`
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
custodians have run `alpha keygen --custodian` and handed over their public keys.

1. **Node pools.** At least as many TDX hosts with the `kata-qemu-tdx` runtime class as there are
   nodes (pod anti-affinity puts each node on its own host), and one host for Postgres. Exclude
   both pools from automatic drains and upgrades.

   ```sh
   kubectl label node <tdx host> alphacompute.io/pool=kms
   kubectl taint node <tdx host> alphacompute.io/pool=kms:NoSchedule
   kubectl label node <db host> alphacompute.io/pool=trust-db
   kubectl taint node <db host> alphacompute.io/pool=trust-db:NoSchedule
   ```

2. **Postgres.** The owner password stays with the operator. The server certificate is
   self-signed; the nodes connect with `sslmode=require` and do not verify it.

   ```sh
   kubectl create namespace alpha-trust-db
   openssl rand -hex 32 > owner-password
   kubectl -n alpha-trust-db create secret generic postgres --from-file=password=owner-password
   openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
     -subj /CN=postgres.alpha-trust-db.svc -keyout tls.key -out tls.crt
   kubectl -n alpha-trust-db create secret tls postgres-tls --cert tls.crt --key tls.key
   envsubst '$TRUST_DB_STORAGE_CLASS $TRUST_DB_STORAGE_SIZE' < trust-db.yaml | kubectl apply -f -
   kubectl -n alpha-trust-db rollout status statefulset/postgres
   ```

3. **Migrate** with the release's image; the Job must end `Complete`. It creates the `nologin`
   role `alpha_kms` and its grants.

   ```sh
   KMS_IMAGE=<manifest.json image> envsubst '$KMS_IMAGE' < migrate.yaml | kubectl create -f -
   ```

4. **The nodes' login** with a one-time genesis password, sent on stdin so it never sits in a pod
   spec or an argument list:

   ```sh
   openssl rand -hex 32 > genesis-db-password
   printf "create role alpha_kms_node login password '%s' in role alpha_kms;\n" "$(cat genesis-db-password)" \
     | kubectl -n alpha-trust-db exec -i postgres-0 -- psql -X -v ON_ERROR_STOP=1 -U postgres -d alpha
   ```

5. **Namespace, budget, addresses**, one Service for each address in `KMS_KATA_ENDPOINTS`:

   ```sh
   envsubst '$KMS_MAX_UNAVAILABLE' < kms.yaml | kubectl apply -f -
   for n in $(seq <number of nodes>); do KMS_NODE=$n envsubst '$KMS_NODE' < kms-service.yaml | kubectl apply -f -; done
   ```

6. **The first node**, from the release's `pod.yaml` unchanged. A label routes `kms-1` to it.
   It comes up sealed.

   ```sh
   pod=$(kubectl create -f pod.yaml -o name)
   kubectl -n alpha-kms label "$pod" alphacompute.io/kms-node=1
   kubectl -n alpha-kms port-forward service/kms-1 8443:8443 &
   curl -sk https://localhost:8443/ready   # 503 {"sealed":true}
   ```

7. **Bootstrap** through the port-forward. The CLI appraises the node against the signed document
   (Revision in `kms_revisions`, a class without GPUs, TLS key equal to the attested one) before it
   seals anything; the genesis password travels inside the sealed body, and the node replaces it,
   in the genesis transaction, with a password derived from the root KEK.

   ```sh
   alpha bootstrap --custodians c1.pub c2.pub c3.pub --endpoint https://localhost:8443 \
     --database-password-file genesis-db-password \
     --platform-document-url <KMS_KATA_PLATFORM_DOCUMENT_URL> --pccs-url <KMS_KATA_PCCS_URL>
   ```

   Hand each `share-<n>.json` to its custodian and delete it, then delete `genesis-db-password`
   once the check below shows it is dead. If the CLI gets no answer, do not retry: drop and
   recreate the database (`drop database alpha; create database alpha;` as `postgres`), give the
   role a new genesis password (`alter role alpha_kms_node password …`, as in step 4), migrate and
   bootstrap again on a new node pod.

8. **Re-sign the document** with `kms_ca_pem`; `alpha sign --check` prints the CA's SPKI SHA-256
   and the Revisions, the two values a tenant pins.

9. **The other nodes**, from the same `pod.yaml`, each labelled with its number. Each joins a
   serving node on start; one created before the first node served is deleted and created again.

   ```sh
   pod=$(kubectl create -f pod.yaml -o name)
   kubectl -n alpha-kms label "$pod" alphacompute.io/kms-node=2
   ```

## Verify

The policy refuses `kubectl exec` into a node and leaves `kubectl logs` empty, so the checks go
through the nodes' API and the database.

- Every node pod carries the signed Revision:
  `kubectl -n alpha-kms get pod <pod> -o jsonpath='{.metadata.annotations.io\.katacontainers\.config\.hypervisor\.cc_init_data}' | base64 -d | gunzip | sha256sum`
  equals `compose_hash`.
- `kubectl -n alpha-kms exec <pod> -- /alpha-kms` is refused.
- `GET /ready` through each `kms-<n>` answers 200 `{"sealed":false}`.
- The genesis password is dead; this login is refused:

  ```sh
  kubectl -n alpha-trust-db exec postgres-0 -- env PGPASSWORD="$(cat genesis-db-password)" \
    psql -X "host=localhost dbname=alpha user=alpha_kms_node sslmode=require" -c 'select 1'
  ```
- The audit log has the genesis and one join per other node:
  `select ts, action, outcome from audit_log where actor_kind = 'node' order by seq;` as `postgres`
  shows `node.bootstrap ok` and `node.join ok`.
- `alpha sign --check` on the served document lists the Revision and the CA.

## Restart, upgrade, loss

- **Restart.** A node pod that is deleted or restarts comes back sealed and joins a serving node.
  Recreate a deleted one from the same `pod.yaml` and label it again.
- **Upgrade.** Sign a document listing the old and the new Revision; every tenant App that pins
  the KMS gets a Revision listing both. Then, one node at a time, create a pod from the new
  release's `pod.yaml`, move the node's label to it, wait for `/ready` 200, delete the old pod.
  Drop the old Revision once no tenant pins it.
- **All nodes lost.** Create one node pod, label it, port-forward, and two custodians each run
  `alpha unseal --share share-<n>.json --key custodian.key --endpoint https://localhost:8443`
  with the same URL options. The root gives the node its database password. The other nodes then
  join it.

## What the operator never sees

The root KEK, the shares in the clear (bootstrap writes each sealed to its custodian's key), the
two intermediates (`tenant-kek-root`, the CA key), the derived database password, tenant secrets.
The operator does hold the Postgres owner password, the server key and the volume: ciphertext,
metadata and the audit log, which the owner can rewrite or roll back. The genesis password is
dead at the genesis commit.
