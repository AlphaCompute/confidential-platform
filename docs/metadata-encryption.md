# The trust-zone Postgres as an untrusted store (D4, M2)

`alpha-kms` keeps its state in the trust-zone Postgres, which runs on AlphaCompute's own disks. Secret values were always ciphertext under each organization's `org_key`. Everything around them was not: who the organizations are, their keys and labels, their Apps and composes, their Secrets' names and grants, and an audit log of every call. AlphaCompute's operators must not be able to read any of it. This is M2 option (b), PRD-05 decision D4: app-level encryption of the plaintext columns and the audit log under KMS intermediates. Option (a), a volume key for the database itself, is in `docs/db-volume-key.md`.

Code: `services/alpha-kms/src/store.rs` (keys, blind indexes, sealed rows, the plaintext migration) and `src/audit.rs` (the chain). Schema: `migrations/20261012000000_sealed_metadata.sql`. Tests: `tests/sealed_store.rs`.

## Keys

| Key | Derivation | Used for |
|---|---|---|
| row | HKDF-SHA256(salt `alphacompute-kms/metadata/v1`, ikm tenant-kek-root, info `row`) | AES-256-GCM of each row's `sealed` column |
| index | same, info `index` | HMAC-SHA256 blind indexes |
| audit | same, info `audit` | AES-256-GCM of each audit row, its associated data the chain |

Before the first custodian rotation (epoch 0) the three keys are derived from tenant-kek-root, not wrapped beside it as a third intermediate. Each rotation replaces them: it makes a new data key, derives them from it (same salt and labels, the data key as input) and re-encrypts every row in the same transaction (`docs/custodian-rotation.md`, "What rotates"). The audit log keeps each epoch's rows under that epoch's audit key. Tenant-kek-root is in memory only on a serving node: after custodians unseal it with two shares, after it joins a serving node, or after bootstrap. So the database keys exist exactly when the intermediates do, without changing the join protocol, and an existing database needs no new intermediate, which only a node holding the root KEK could add. Nothing comes from the environment; the `dev-root` build reaches the same keys through its development root KEK.

**Fail closed.**
- A sealed node holds no metadata key. It reads no tenant row, and it writes no audit row about a tenant (`sealed`).
- Every function that reads or writes a tenant row takes the keys as an argument (`store::*`), so there is no code path that touches such a row without them.
- A row whose `sealed` does not open, or opens only under another table or primary key, is refused as `internal`. It is never read around.
- A row still in the clear is refused too: the KMS decides only on values that came out of a sealed blob.

## Column classification

"Clear" means stored as is. The AES-GCM associated data of `sealed` is `alphacompute-kms/row/v1 ‖ table ‖ primary key`, so a blob copied to another row, or to another table, does not open.

### `principal_keys`

| Column | Class | Why |
|---|---|---|
| `id` | clear | Random UUIDv7, the primary key, and what `key_id` in every signature names. It says nothing about who holds the key, beyond the creation time its v7 prefix shares with `created_at`. |
| `org_index` | blind index of `org_id` | The root-key lookup (`where org_index = $1 and anchor_check is not null`) and the one-root-per-organization unique index. |
| `public_key_index` | blind index of `public_key` | `unique`: one SPKI cannot be registered twice, for two organizations. |
| `anchor_check` | clear (already a keyed digest) | HKDF of tenant-kek-root, the organization and its anchor SPKI. It is opaque without the root and marks the root row. |
| `created_at` | clear | When the row was written. The host sees the write anyway. It is not used in any decision. |
| `sealed` | ciphertext | `org_id`, `principal_id`, `public_key`, `document` (label, issued_at), `registered_by_key`, `signature`, `revoked_at`, `revocation_reason`. |
| `org_id`, `principal_id`, `public_key`, `document`, `registered_by_key`, `signature`, `revoked_at`, `revocation_reason` | must be encrypted: null once sealed | Kept nullable only for rows an earlier release wrote. |

The delegation graph (`registered_by_key`) moved into `sealed`, so the host no longer sees who endorsed whom. The check `(registered_by_key is null) = (anchor_check is not null)` was dropped because `anchor_check` alone marks the root.

### `revisions`

| Column | Class | Why |
|---|---|---|
| `compose_hash` | clear | The lookup key of every attestation: the KMS rebuilds the hash from the evidence. It is a SHA-256 over a compose or Revision v2 that names the App's UUID, so it cannot be inverted or guessed. The hash itself is already public: it is in the Instance's leaf, in clients' pins, and in shroud-go's approval requests. |
| `app_index` | blind index of `app_id` | "Does this App have a Revision of another organization?" (registration and put-Secret), and its index. |
| `org_index` | blind index of `org_id` | The same check's `org_index <> $2`. |
| `created_at` | clear | Written once. The authoritative copy, which the chain walk uses as `signed_at`, is inside `sealed`. |
| `sealed` | ciphertext | `app_id`, `org_id`, `compose`, `created_by_key`, `signature`, `created_at`, `revoked_at`. |
| `app_id`, `org_id`, `compose`, `created_by_key`, `signature`, `revoked_at` | must be encrypted: null once sealed | |

A revocation re-seals the row with its `revoked_at`. The host can no longer un-revoke a Revision by clearing a column.

### `secrets`

| Column | Class | Why |
|---|---|---|
| `id` | clear | Random UUIDv7, the primary key, and the associated data of the value's own ciphertext. |
| `name_index` | blind index of `org_id ‖ name` | The Instance read and the put both look a Secret up by organization and name (`unique`). One index of both, because a name is unique only within its organization. A separate organization index would only group Secrets by organization, which no query needs. |
| `ciphertext` | already ciphertext | AES-256-GCM under `org_key`, as before. |
| `sealed` | ciphertext | `org_id`, `name`, `app_ids`, `content_sha256`, `document`, `signed_by_key`, `signature`, `issued_at`. |
| `org_id`, `name`, `app_ids`, `content_sha256`, `document`, `signed_by_key`, `signature`, `issued_at` | must be encrypted: null once sealed | `content_sha256` is the hash of the value: in the clear, a low-entropy Secret would fall to a dictionary. |

The Instance read no longer filters on `app_ids` in SQL. It opens the row and releases only when the signed document grants the App, as it already required.

### `audit_log`

| Column | Class | Why |
|---|---|---|
| `seq` | clear | Order. |
| `ts` | clear, in the chain | The join check's ten-minute window. Timing is visible to the host anyway. It is bound into the link and the AEAD, so it cannot be moved. |
| `sealed` | ciphertext | `{actor_kind, actor, action, org_id, object, outcome, details, evidence_sha256}` of every row a serving node writes. |
| `link` | clear | The chain (below). |
| `actor_kind`, `actor`, `action`, `outcome`, `details` | clear, node facts only | Written only by a node that holds no key yet: `node.join.request`, a refused `node.unseal`, `platform.reload` at start, `node.join` on a sealed node. They name no organization, object or evidence (enforced on write and on verify). An older release's serving node still queries `node.join.request` here. |
| `org_id`, `object`, `evidence_sha256` | must be encrypted: null for every row this release writes | A row of an earlier release is moved into the chain and scrubbed (below). |

### `platform_document`, `intermediate_keys`, `custodian_rotations`

| Column | Class | Why |
|---|---|---|
| `platform_document.*` | clear | The release-signed document is public: it is served at an unauthenticated URL, and every stored copy is re-verified against the release key. |
| `intermediate_keys.wrapped` | already ciphertext | Under the root KEK: tenant-kek-root, the CA key, the database's volume key (`db-volume`) and, after the first custodian rotation, the data key (`data-key`). A rotation re-wraps them under a new root and replaces the data key (`docs/custodian-rotation.md`); tenant-kek-root, the CA key and the volume key keep their values. |
| `intermediate_keys.epoch` | clear | The data key's epoch (the number of rotations), on its row only: the fence every node checks under the chain lock. The wrapped key carries the epoch it trusts. |
| `intermediate_keys.public_part` | clear | The CA certificate, pinned in the platform document. |
| `custodian_rotations.rotation` | clear, its shares already ciphertext | The proposal (the custodians' X-Wing public keys, a spent nonce, the node's key hash), the new shares HPKE-sealed to the custodians, and the node's receipt. No tenant appears in it, and the custodians verify the receipt rather than trust the row. |

### What the host still learns

- Row counts and sizes, and when rows are written.
- Grouping through the blind indexes:
  - how many keys and Revisions each (unnamed) organization has;
  - which Revisions belong to one App;
  - that a Secret was replaced.
- The compose hashes.
- The node facts written before unseal.

No query needs deterministic encryption, so none is used: every lookup is an equality on an HMAC.

## The audit log

Every row a node of this release appends carries:

```
link = SHA-256("alphacompute-kms/audit/v1" ‖ previous link ‖ ts (µs, BE) ‖ form ‖ content)
```

- **Sealed rows.** A serving node writes the content as AES-256-GCM under the audit key, with `"alphacompute-kms/audit/v1" ‖ previous link ‖ ts` as associated data. The content is the JSON of the entry, and `form` is 1.
- **Plaintext rows.** A node without keys writes the JCS of the entry, its columns in the clear, and `form` is 0.
- **Ordering.** Appends take a transaction-scoped advisory lock and read the head under it. Rows are therefore totally ordered across nodes, and each links to the row committed before it. The lock is held to the end of the caller's transaction, which also holds the row the audit row describes.
- **Append-only.** The service role still has no `update` or `delete` on `audit_log`.

`audit::verify` walks the log in `seq` order. It recomputes each link, opens each sealed row with the link before it, and refuses a plaintext row that names more than the node. Each sealed row therefore authenticates everything before it. A row that is changed, inserted, reordered, removed, given another `ts`, or replayed elsewhere breaks the chain at that row or at the next sealed row. `tests/sealed_store.rs` shows each case.

A serving node walks the whole chain on its first maintenance pass after start, then on each platform tick (five minutes) walks the rows appended since. It reports `{"audit_chain": {"verified_through": seq}}` on `/ready`.

**A broken chain halts the node** (Hacktron ACC-FD-103). A node that finds a break:
- refuses every route that releases a key or reads a tenant row (`503 halted`): `Node::intermediates` refuses before the phase is read, and the gate refuses every route outside `/v1/node/*`, `/healthz` and `/ready`;
- answers `/ready` with `503 {"sealed": …, "halted": "audit_chain_broken"}`, a fixed reason; the detail goes only to the log. Peers do not join it, since `try_join` needs a `200`;
- writes nothing further: every append checks the halt first, both before and after taking the chain lock, so no `audit.verify` row, no `denied` row and no maintenance write follows. The node fact it could have written would be appended to a chain it can no longer vouch for;
- stays halted. Recovery is an operator restarting the pod, then a join or a custodian unseal, both of which check the heads below.

A database writer could already stop the KMS by stopping Postgres, so halting gives the host nothing new.

### Rollback of the whole database

The chain alone cannot see the whole database restored from an older copy, or its tail cut back: the copy is internally consistent, and its chain verifies up to an older head. Andrei Pfau's review asked for a detection that holds against the host, who controls Postgres. Without new infrastructure, the only state the host cannot roll back is what the KMS nodes hold in memory and what the custodians hold in their share files. The design uses both.

**The head.** `audit::Head` is a linked row's `(seq, link)`. Its link commits to every row before it, and the service role can never update or delete a linked row. A database that does not hold a head (no row at that `seq`, or one with another link) is therefore not the one in which that head was committed. It was restored from an older copy, cut back, or is another copy.

**Each node's floor (`audit::Watch`, in memory).** The highest head the node has seen committed. It rises with:
- the node's own appends, once their transaction commits (`Appended::committed`; every Control route, bootstrap, the platform reload and the audit import call it after `commit`, and `Node::audit` does so itself);
- the head it reads under the chain lock at each append, which was committed by whoever held the lock before;
- each walk of the chain;
- heads from outside, once the database turns out to hold them (below).

**The check.** Every append, under the chain lock, and every maintenance pass first checks that the database holds the floor. If it does not, the node halts with `audit_chain_rolled_back`. Every route that releases a key or a stored value (attest, secret read, key derivation, join) appends its audit row before it answers, so a restored copy is refused at the first request: the copy's values are never released.

**Heads from outside.**
- **Join.** `JoinReply.audit_head` carries the serving node's floor, its `node.join` row included. The joining node refuses, and halts, if its own database does not hold it. A node pointed at another or an older copy than the node it joins therefore never serves it.
- **Peers.** `GET /v1/node/audit-head` answers a node's floor, also once halted. On every maintenance pass, and before it starts serving, a node reads each `kms_endpoints` peer's head over a channel pinned as a join is: the KMS CA, and a Revision listed in `kms_revisions`, with a 5-second timeout. Its database must hold each head. So a rollback that only one node's writes would reveal, or two nodes pointed at two copies, halts every node within one tick. A halted node keeps renewing its own leaf, so its peers can still read its head.
- **Custodians (cold start).** A custodian's share file already remembers the highest platform-document version they verified. It now also remembers `audit_head`: the head the node served from after the unseal that custodian completed (`UnsealReply.audit_head`), or a later one from `alpha witness --share share.json --endpoint <node>`, which attests a serving node as `unseal` does, reads its head and sends nothing. `alpha unseal` sends it as `UnsealRequest.audit_floor`. The node collects each floor beside its share, and checks them only once the two shares open the database, so a made-up request cannot plant a floor. It halts if the database lacks one. Accepting a restore deliberately (disaster recovery) is explicit: the custodians whose files remember a later head run `alpha unseal --accept-audit-rollback`. That sends no floor, the share file then remembers the restored head, and the command's output records the choice.

**Residual (what this does not catch):**
- **A full cold restart with every node's memory lost** (Hacktron ACC-FD-106), onto a copy taken after the last head that the two unsealing custodians' share files recorded. Only the second custodian of a cold start records a head from the unseal itself; `alpha witness` records later ones. A copy restored after the last recorded head therefore loses everything written since, undetected. How much that is depends on how often custodians witness: the runbook asks two of them to witness at least daily, and after every revocation or Secret change that matters. Closing it needs a counter outside the host's reach: the release-signed platform document carrying a head floor, an external transparency log, or signed heads in KMS receipts that clients present back.
- **Writes after the last head a node saw**, when the host rolls back between a commit and the next time any node reads the head. Each node records its own commits, so this is limited to another node's commits that no node has read yet: at most one maintenance tick of another node's writes, if that node is then stopped before its next pass.
- **Peers the host cuts off.** A peer that does not answer tells nothing. The host can partition nodes so that each serves its own copy, as long as no node joins another and the custodians do not unseal.
- **Rolling back a single row.** Restoring an older sealed blob of one row (for example a Secret's previous value, or a key or Revision before its revocation) while keeping the audit log is not a whole-database rollback. The row's AEAD binds its table and primary key, not a version. The audit chain records the revocation or put, but the row is not checked against it. This is open: binding each row's version to the chain is a follow-up.
- **Between start and the first full walk**, a node checks the heads it knows but has not yet walked the whole chain. A row tampered with in the middle of the log is found on its first maintenance pass, then the node halts.
- **A plaintext node fact** is authenticated only from the next sealed row on. Anyone with write access can append a fake node fact at the head before that.

## Rows an earlier release wrote

Production starts on this schema, but development databases hold plaintext rows, and the M-C migration copies the prototype's database. The migration is expand-only. It adds the indexes and `sealed`, makes the old columns nullable, and adds a one-form check per table: exactly one of `sealed` and the old content.

On entering the serving phase, the order is **unseal → the database's keys → every plaintext row sealed → serve** (`Node::start_serving`). `store::seal_plaintext` takes an advisory lock and, in one transaction:
- seals every `principal_keys`, `revisions` and `secrets` row whose `sealed` is null;
- computes its indexes;
- nulls its plaintext columns.

If it fails, the node stays sealed.

Audit rows without a link are moved into the chain, one transaction per row:
1. A sealed `audit.import` row carries the original (`seq`, `ts`, content).
2. `audit_log_scrub(legacy, imported)` replaces the original's content with `{"imported_as": <seq>}` and the action `audit.imported`. This is a `security definer` function, the only update path the service role has, and it touches only an unlinked row toward a later sealed one.
3. A `node.join.request` younger than the ten-minute join window stays readable until a later pass.

The same pass runs on every platform tick. Rows an older node writes during an upgrade are therefore sealed within five minutes, and refused until then.

**Upgrading:**
- A node of this release seals the rows on its first unseal or join. From then on, a node of an earlier release fails on every tenant row (`internal`).
- Stop the older nodes once the first node of this release serves. Clients that pin both KMS Revisions fail over.
- The change is one-way: there is no path back to plaintext.

## M2(a): a volume key for the Postgres data volume

Built in `docs/db-volume-key.md`: a `db-volume` intermediate under the root KEK, kept in `intermediate_keys` and, wrapped, in every share file; `POST /v1/node/db-key`, which gives it only to an attested Postgres pod whose Revision v2 the platform document lists in `db_revisions`; and the cold-start order unseal → db key → database → serve, with the node unsealed and waiting while the database is closed. The design's open point (a node restarting while Postgres is down has nothing to read the wrapped key from) is answered by the share files.

## D10 (open)

How the Kata KMS node authenticates to Postgres (a KMS-CA client certificate, or a password released after unseal) is Ryan Tharp's open decision. The node still connects with `ALPHACOMPUTE_DATABASE_URL`. `main.rs` marks the seam `ponytail: D10`. Either answer decides who may connect, not who may read: the rows are sealed either way.
