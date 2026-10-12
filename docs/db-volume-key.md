# M2(a): the database's volume key

#95 sealed every tenant column of the trust-zone Postgres (M2(b), `docs/metadata-encryption.md`), but the host still sees:
- row counts and sizes;
- the compose hashes;
- the blind indexes' grouping;
- the node facts.

M2(a) puts the Postgres data directory on a LUKS2 volume whose key only the KMS holds, and only an attested Postgres pod receives. With it the host sees ciphertext blocks.

Code: `services/alpha-kms/src/db_volume.rs`, the `db-volume` handling in `src/node.rs` and `src/custodians.rs`, the pod's client in `crates/alpha-client/src/db_key.rs`, and `appraise_db_pod` in `crates/alpha-attest/src/node.rs`. Schema: `migrations/20261014000000_db_volume_key.sql`. Tests: `services/alpha-kms/tests/db_volume.rs`.

## The key

`db-volume` is a third intermediate, a random 256-bit key wrapped under the root KEK with AES-256-GCM (aad `db-volume`), like tenant-kek-root and the CA key. Each copy below is the same ciphertext, and only the root KEK opens it:

| Where | Why |
|---|---|
| `intermediate_keys` (`purpose = 'db-volume'`) | Unwrapped beside the others on every unseal while the database is open. A custodian rotation re-wraps it with the rest. |
| Every share file (`db_volume_wrapped`) | A node unsealed while the database is closed has nowhere else to read it from. `alpha bootstrap` writes it, `alpha custodians accept` writes the re-wrapped one, and `alpha unseal` sends it beside the share. |
| The join reply (`db_volume_key`, in the clear inside the attested channel) | A joining node gets it with the other intermediates. |

The key is created:
- by genesis;
- for a database from before this release, by the first unseal that opens it (`db_volume::open_database`), because only a holder of the root KEK can add one. Share files from before then do not carry it; the next custodian rotation hands every custodian one that does.

The key's value never changes, so the LUKS volume is formatted once and never re-keyed. A custodian rotation changes only its wrapping.

## Who receives it

`POST /v1/node/db-key` takes `{nonce, evidence, xwing_pubkey}`:
- `nonce` comes from `POST /v1/node/nonce`, which the Node API answers before the node serves;
- `evidence` must be `alphacompute-evidence/2`.

The node then:
1. Requires the volume key: `sealed` on a sealed node, `not_found` on a serving node whose database has none.
2. Checks the nonce (minted by this node, at most five minutes old).
3. Requires a platform document. While waiting for its database, the document must be no older than the version the unsealing custodians verified the node against.
4. Runs DCAP and the TCB policy, then `kata-tdx/1` on the CPU class (`alpha_attest::node::appraise_db_pod`):
   - the CPU guest's reference value;
   - MRCONFIGID equal to the init-data's digest;
   - `report_data = SHA-256(xwing_pubkey ‖ nonce) ‖ 0³²`. The pod has no runtime key, so its X-Wing key takes that place, and the quote commits to the one key that can open the reply;
   - the Revision v2 rebuilt from the init-data listed in the platform document's `db_revisions` with `"kind": "kata-tdx"`.
5. Answers `{key_hpke}`: the key HPKE-sealed (X-Wing) to `xwing_pubkey` under `alphacompute/db-volume-key/v1`, its aad this node's runtime-key hash.

Every release and refusal writes a `db.key` audit row naming the Revision, its policy digest and the X-Wing key's hash. While the node waits for its database the row is held in memory and appended, sealed, before the node serves, with `held_at`. The queue is bounded (Hacktron ACC-FD-107): at most 1,000 held refusals, past which refusals are only counted (one `audit.held_dropped` row with the count when the node serves), and 1,024 rows in all, past which a release is refused (`rate_limited`) rather than made without its row. Unauthenticated `db-key` calls therefore cannot grow the node's memory while the database is down, nor crowd out a release's row.

`db_revisions` is a new optional field of the release-signed platform document, the same shape as `kms_revisions`:

```json
"db_revisions": [
  { "compose_hash": "sha256:…", "build": "postgres-18-kata", "source_url": "…", "kind": "kata-tdx" }
]
```

The Postgres pod's Revision is deliberately not in the `revisions` table, which lives on the volume this key opens, and not in `kms_revisions`: a Postgres build is not a KMS build, and a KMS build is not a Postgres one.

## Order on a cold start: unseal → db key → database → serve

The KMS's pool connects lazily (`main.rs`), so a node starts and answers the Node API with Postgres down. Its platform document is then kept in memory only and stored at the first tick after the database opens.

1. Two custodians run `alpha unseal`. If the database answers, nothing changes: the node unwraps every intermediate from `intermediate_keys` and serves. If it does not, the node opens the share file's `db_volume_wrapped` with the combined root (it refuses if no share file carried one, or if the root does not open it), and enters `Phase::Unsealed`:
   - it holds the root KEK and the volume key;
   - `/ready` answers 503 `{"sealed": false, "database": "waiting"}`;
   - every route outside `/v1/node/*` is `sealed`.
2. The Postgres pod's init container attests the node and receives the key (below). It opens the volume and Postgres starts.
3. The node tries the database every second. Once it answers, the node unwraps every intermediate under the root it held, checks that the database holds every audit head the custodians' share files remembered (`docs/metadata-encryption.md`, "Rollback of the whole database"), writes the held audit rows and serves, and the root is dropped. If the rows do not open under that root, the node returns to sealed and writes a denied `node.unseal` row. If the database lacks a custodian's head, it was restored from an older copy: the node halts, releases the volume key no more, and writes nothing.

**Genesis** works the same way: the volume key has to exist before the volume it opens. `alpha bootstrap` on a node whose database does not answer:
- makes the root, both intermediates and the volume key;
- returns the shares (every share file carries the wrapped volume key);
- holds the three rows in memory.

Once the database answers, the node writes them (refusing a database that is not empty) and serves.

## The Postgres pod

The pod is a Kata pod on `kata-qemu-tdx`, rendered by `alpha coco render` like the platform services. Its Revision v2 goes into `db_revisions`. Its persistent volume claim is in block mode, and an init container opens it before `postgres` starts:

```yaml
# Template: the trust-zone Postgres on Kata with its data volume under the KMS's db-volume key.
# Render with `alpha coco render`; the Revision v2 it prints goes into the platform document's
# db_revisions with "kind": "kata-tdx". Nothing secret is in this spec: the init-data is public.
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: alpha-postgres
spec:
  serviceName: alpha-postgres
  replicas: 1
  selector:
    matchLabels: { app.kubernetes.io/name: alpha-postgres }
  template:
    metadata:
      labels: { app.kubernetes.io/name: alpha-postgres, alphacompute.ai/tenant: platform }
      annotations:
        io.katacontainers.config.hypervisor.cc_init_data: "${CC_INIT_DATA}"
    spec:
      runtimeClassName: kata-qemu-tdx
      automountServiceAccountToken: false
      enableServiceLinks: false
      nodeSelector: { alphacompute.ai/role: verifier }
      initContainers:
        - name: alpha-volume-pgdata
          image: ${VOLUME_IMAGE}                 # alpha-volume, pinned by digest
          args: ["open-db", "pgdata", "/dev/pgdata", "/run/pgdata"]
          env:
            - { name: ALPHACOMPUTE_QUOTE_SOURCE, value: coco-aa }
            - { name: ALPHACOMPUTE_KMS_ENDPOINTS, value: "${KMS_ENDPOINTS}" }
            - { name: ALPHACOMPUTE_PLATFORM_DOCUMENT_URL, value: "${PLATFORM_DOCUMENT_URL}" }
            - { name: ALPHACOMPUTE_PCCS_URL, value: "${PCCS_URL}" }
          securityContext: { privileged: true }  # device-mapper inside the TD; pinned by the policy
          volumeDevices: [{ name: pgdata, devicePath: /dev/pgdata }]
          volumeMounts: [{ name: opened, mountPath: /run/pgdata, mountPropagation: Bidirectional }]
      containers:
        - name: postgres
          image: ${POSTGRES_IMAGE}               # postgres:18, pinned by digest
          env:
            - { name: PGDATA, value: /run/pgdata/data }
          volumeMounts: [{ name: opened, mountPath: /run/pgdata, mountPropagation: HostToContainer }]
      volumes:
        - name: opened
          emptyDir: { medium: Memory }
  volumeClaimTemplates:
    - metadata: { name: pgdata }
      spec: { accessModes: [ReadWriteOnce], volumeMode: Block, resources: { requests: { storage: 200Gi } } }
```

`alpha-volume open-db <name> <device> <mount dir>` is `alpha-volume open` (#86) with a different key source. Instead of the runtime socket's `keys/derive`, it calls `alpha_client::db_key::fetch` against each `ALPHACOMPUTE_KMS_ENDPOINTS` in turn until one answers:
1. It attests the KMS node over its own nonce, exactly as a custodian's CLI does: `alpha_attest::node`, the node's build in `kms_revisions`, and the TLS key equal to the attested runtime key. A node waiting for its database serves no KMS-CA leaf yet, so this is the only pin there is.
2. It quotes over `report_data(xwing, nonce, None)` through the CoCo source.
3. It opens the reply.

It then formats or opens LUKS2 exactly as `open` does: the header rules, the `av:<name>` label, the cipher and integrity, and never formatting over a header. The mode is one match arm in `services/alpha-volume/src/main.rs` and lands with #86, which this stack does not include. Until then this section is the template, and `db_key::fetch` is its tested client. The agent policy must pin the init container's image, arguments and environment as it does for `alpha-volume-*` (#79's baseline).

## Not decided here

- **D10.** The draft answer (`docs/db-client-auth.md`, `ALPHACOMPUTE_DATABASE_AUTH=client-cert`) derives a database client CA from this key, so a node can connect only once it holds it. The default is unchanged: the node connects with `ALPHACOMPUTE_DATABASE_URL`. The volume key decides who can read the disk; the derived CA, who can connect.
- **Migration of an existing database** onto an encrypted volume is a dump and restore into a fresh pod: an operations step, not code.
