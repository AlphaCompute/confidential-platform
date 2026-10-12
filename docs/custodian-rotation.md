# Replacing custodians: re-share with root rotation

At genesis `alpha bootstrap` splits a random root KEK 2-of-3 among three custodians' X-Wing keys. The root KEK wraps the intermediates in `intermediate_keys` (tenant-kek-root, the KMS CA key and, with M2(a), the database's volume key, `docs/db-volume-key.md`), and everything else derives from tenant-kek-root: every organization's `org_key`, every App's derived keys, and the metadata keys of `docs/metadata-encryption.md`. Until now a departing custodian kept their share. With any other share it would still unseal the root KEK.

Re-splitting the same root KEK would not help: old Shamir shares of an unchanged secret stay valid. `alpha custodians rotate` therefore makes a **new** root KEK inside the serving node, re-wraps the intermediates under it, splits it to the new custodians and forgets both roots. From the commit on, the old shares rebuild a root that unwraps nothing in the database.

A new root alone is not enough either (Andrei Pfau's review, D12 item 2). Two old shares and a copy of `intermediate_keys` taken before the rotation still give the old intermediates, and if those did not change they open everything written later too. Each rotation therefore also makes a new random **data key** and, in the same transaction, re-encrypts under it every row the old keys protected. The old shares and an old copy then open that copy, as of the day it was taken, and nothing written since. What still does not rotate, and what that leaves open, is under "What an old backup with old shares still opens".

Code: `services/alpha-kms/src/custodians.rs` (routes), `src/data_key.rs` and `store::rekey` (the data key), `crates/alpha-cli/src/custodians.rs` (commands), `migrations/20261013000000_custodian_rotations.sql` and `20261013100000_data_key.sql`. Tests: `services/alpha-kms/tests/custodians.rs`, and a Kata node's rotation in `tests/kata_node.rs`.

## Protocol

1. **Proposal.** `alpha custodians propose --custodians n1.pub,n2.pub,n3.pub --endpoint <node>` attests the serving node (the checks `alpha unseal` runs, plus the agent-policy baseline below). It then takes a nonce from the node (`POST /v1/attest/nonce`, valid five minutes) and writes `proposal.json`:

   ```json
   {"format": "alphacompute-custodian-rotation/1", "nonce": "…",
    "kms_node_spki_sha256": "sha256:…", "custodians": ["<x-wing>", "<x-wing>", "<x-wing>"]}
   ```

   The proposal is not secret. It names exactly one node, by its runtime key, and the three new keys in share order. A custodian who stays is simply listed again, and a new set of three is equally possible. The command prints `proposal_sha256` and each new key's SHA-256, which the approvers compare out of band with what the new custodians printed at `keygen`.
2. **Approvals.** Each of two **current** custodians runs `alpha custodians rotate --proposal proposal.json --share share-N.json --key custodian.key --endpoint <node>`. The CLI:
   - attests the node and refuses unless it is the one the proposal names;
   - opens the custodian's share;
   - seals `digest(proposal) ‖ share` to the node's attested X-Wing key under `alphacompute/custodian-approval/v1`, where `digest` is `signing_digest("alphacompute/custodian-rotation/v1", proposal)`.

   This sealed share is the custodians' signature. A custodian's identity is their X-Wing key and their share, and neither can sign, so authority comes from holding a current share. The approval opens only on that node, only under that info string (a captured unseal share is not an approval), and only for that proposal.
3. **Rotation.** The node counts approvals in memory, per proposal digest. Each approval is checked first:
   - the proposal names this node;
   - its nonce is one this node minted less than five minutes ago;
   - its three keys are distinct;
   - the approval opens and covers this proposal.

   A repeated share counts once. A new proposal replaces the pending one. With two distinct shares the node combines them. In **one transaction** it then:
   - takes the audit chain's lock and the seal pass's lock first, so no node commits a route's rows, or seals legacy rows, under the keys this transaction replaces. It refuses if the database's data key is not the one it serves;
   - locks and opens every `intermediate_keys` row under the combined root. Any row that does not open, or a tenant-kek-root or data key other than the one it serves, refuses the rotation (`signature_invalid` / `internal`) and clears the pending approvals;
   - generates a new 256-bit root with the OS RNG and re-seals tenant-kek-root and the CA key under it, with the same AES-256-GCM and purpose AAD as bootstrap;
   - generates a new 256-bit data key, one epoch after the current one, and stores it wrapped under the new root (purpose `data-key`, its epoch also in the clear);
   - re-encrypts every `principal_keys`, `revisions` and `secrets` row under keys derived from the new data key (`store::rekey`): each sealed blob, each blind index, and each Secret's value. The value is opened under its organization's key of the old epoch and sealed under that of the new one. A row still in the clear, or one that does not open, refuses the rotation;
   - splits the new root 2-of-3 (`vsss_rs::Gf256`, as bootstrap does), checks that every pair of shares combines back, and HPKE-seals share *i* to new custodian *i* under the unseal info string and this node's runtime-key AAD. Each new share is therefore an ordinary share file for `alpha unseal`;
   - inserts the `custodian_rotations` row: the proposal, the three sealed shares and the node's receipt. `nonce` is unique, so a nonce rotates once;
   - appends the `custodians.rotate` audit row, the first row sealed under the new epoch's audit key.

   Then it commits, and serves from the new data key. Both roots and all shares are `Zeroizing` and dropped when the call returns. The reply carries the rotation, and the CLI verifies its receipt before writing `rotation.json`.
4. **Acceptance.** Each new custodian runs `alpha custodians accept --rotation rotation.json --key new.key --out share.json --endpoint <node>`. Without `--rotation`, the node's last committed rotation is fetched from `GET /v1/node/custodians/rotation`, which a sealed node answers too. The CLI:
   - attests the node at `--endpoint` and checks the baseline;
   - verifies the receipt under a leaf of the KMS CA the platform document pins, issued to a KMS build the document lists, for route `custodians.rotate` and exactly this proposal, naming exactly these three sealed shares;
   - finds the custodian's key among the three and opens their share;
   - writes `share.json`, refusing to overwrite an existing file.

   The output says whether the attested node is the one that rotated (`rotating_node_attested`). A new share file remembers no KMS audit head, so the new custodian then runs `alpha witness` against a serving node, which records one (`docs/metadata-encryption.md`, "Rollback of the whole database").

The receipt's signed response is `{rotation_id, proposal_sha256, kms_node_spki_sha256, custodians_sha256[3], shares_hpke_sha256[3], approved_by_shares, rewrapped, db_volume_wrapped_sha256, data_key_epoch, rekeyed}`. `rekeyed` counts the rows re-encrypted per table. The rotation carries the database's volume key re-wrapped under the new root (`db_volume_wrapped`, its hash in the receipt, `null` when the database has none), and `accept` writes it into the new share file, so the new custodians can unseal a node while the database is closed. The volume key's value does not change, so the LUKS volume is not re-keyed. `approved_by_shares` holds the Shamir x-coordinates (1–3) of the two shares that approved. The node never learns which person holds which share.

## Atomicity and crash safety

The re-wrap, the re-encryption of every row and the record of the new shares are one Postgres transaction. Before the commit only the old root and the old data key open the database. After it only the new ones do, and the new shares are durable in `custodian_rotations`, sealed to their holders. The node never commits a state that neither opens:
- A failure before the commit leaves every row as it was. `tests/custodians.rs` makes the transaction's last write fail after every row was re-wrapped and re-encrypted; the rows are unchanged byte for byte, the node keeps serving under its old keys, and the old shares still unseal a fresh node.
- The transaction rewrites every tenant row once. It holds the chain lock throughout, so every write route on every node waits for it. Its length grows with the number of keys, Revisions and Secrets: thousands of rows take well under a second. A row locked by another node's transaction can deadlock with it; Postgres then aborts one of the two, and if that is the rotation, nothing changed and the custodians approve again.
- A reply lost after the commit costs nothing. `accept` fetches the rotation from any node, sealed or serving.

## Joined nodes and replication

tenant-kek-root and the CA key do not change, only their wrapping; the data key is replaced. Every node reads and writes the same Postgres.
- A node that joined before the rotation still holds the old data key. It opens none of the re-encrypted rows, and it writes nothing: every route that writes a sealed row appends its audit row in the same transaction, and every append checks, under the chain lock, that the node's data-key epoch is the database's (`sealed`, "it joins again"). Its next maintenance pass (at most five minutes) drops its keys and joins a serving node again. Until then clients fail over to the rotating node. A database whose epoch is *older* than a node's was restored, and halts that node (`docs/metadata-encryption.md`).
- A node that joins later gets tenant-kek-root and the CA key unchanged, and the new data key (`JoinReply.data_key`). A join reply from a node that has not yet joined again does not start a node: its epoch is not the database's.
- A node that restarts and is unsealed reads the re-wrapped rows and the data key. It needs two **new** shares: old shares, or an old and a new share, combine into a root that unwraps nothing (`does not unwrap under this root`).
- A joined node never held a root, but once it has joined again it can run the next rotation, because the approvals rebuild the root from the database's rows.
- Every node must run this release before the first rotation: a node of an earlier release ignores `JoinReply.data_key`, and would serve epoch 0's keys over a re-keyed database.

## What rotates

| Key | Rotates? | Protects |
|---|---|---|
| root KEK | yes, new each rotation | the wrapped intermediates |
| data key (`data-key`, epoch *n*) | yes, new each rotation | through HKDF: the sealed rows (`row`), the blind indexes (`index`), new audit rows (`audit`), Secret values (`secret`, per organization and anchor), channel tickets (`ticket`) |
| tenant-kek-root | **no**, re-wrapped | every App's derived keys (`org_key` → `app_key`, `keys/derive`), `anchor_check`, and before the first rotation (epoch 0) everything the data key now covers |
| CA key | **no**, re-wrapped | every KMS and Instance leaf; tenants pin the CA through the platform document |
| db-volume key (M2(a)) | **no**, re-wrapped | the trust-zone Postgres's LUKS volume (`docs/db-volume-key.md`); re-keying the volume is a Postgres-pod-side protocol not built |
| audit rows already written | **no** | the log is append-only and each sealed row's AEAD is part of the chain. A node keeps every epoch's audit key (the data key carries the earlier ones) to walk the chain from genesis. |

A database from before this release is epoch 0: its keys come from tenant-kek-root, as #95 built them. Its first rotation moves it to epoch 1.

Why tenant-kek-root and the CA stay:
- Rotating tenant-kek-root would change every App's derived keys. Customers' LUKS volumes (`alpha-volume`) and anything else sealed under `keys/derive` would stop opening, and that cannot be done for them. The Secret values no longer depend on it: from epoch 1 their keys come from the data key with the same per-organization derivation, so an App's derived keys and a Secret's key are now separate.
- Rotating the CA would re-issue every leaf and need a re-signed platform document that every tenant re-pins. That is a release, not a custodian ceremony.

## What an old backup with old shares still opens

Take two shares from before a rotation and a copy of the database from before it: a backup, a snapshot, a WAL archive, or dead tuples on the trust-zone disk before `VACUUM FULL`. A single departing custodian holds one share. They need a second old share, from another custodian who kept their old share file, and such a copy. With both, after this change:

**Still opens:**
- **Everything in the copy, as of the day it was taken:** its Secrets' values, its sealed metadata, its blind indexes, its audit rows. Nothing re-encrypts a copy.
- **tenant-kek-root**, and with it **every App's derived keys**, for any App and purpose, now and later: `keys/derive` is deterministic. Anything sealed under them (customers' LUKS volumes, App data) opens for whoever also has its ciphertext, and the host has the disks. This is the residual: closing it needs a new derivation root that customers migrate their volumes to.
- **The CA key**: leaves for any KMS or Instance identity under the pinned CA, until the CA is re-issued through a new platform document. An attacker who can also intercept traffic can pose as a KMS node to a client that pins the CA, for example to read a Secret value an admin puts later.
- **Audit rows sealed before the rotation**, in any copy including the current database: they keep the audit key of their epoch.
- **The database's volume key** (M2(a)): its value does not change, and two old share files carry its old wrapping, so they open it even without a copy of the database. With the volume itself, that shows what the volume hides (row counts, sizes, compose hashes, blind-index grouping), not the sealed rows, which are under the new data key.
- `anchor_check` (a keyed digest; it reveals nothing the copy does not).

**No longer opens** (`tests/custodians.rs`, `an_old_backup_and_old_shares_open_nothing_written_after_the_rotation`):
- any Secret value, sealed row or blind index the database holds after the rotation: those written after it, and those written before it, which the rotation re-encrypted;
- any audit row sealed after the rotation;
- any channel ticket issued after the rotation;
- any `intermediate_keys` row of the current database, the new data key included.

Two **current** shares open all of it, and an App's derived key is the same before and after the rotation.

Keep old shares and old copies out of reach all the same, because of the residual:
- every custodian deletes their old share file once they hold a new one;
- pre-rotation backups and WAL archives are destroyed or kept under the same custody as shares;
- the operator runs `VACUUM FULL intermediate_keys, principal_keys, revisions, secrets` after the ceremony, so the pre-rotation row versions leave the table files.

Replacing all three custodians at once leaves three old shares outside the new custody. The same holds there.

## Agent-policy baseline (D9)

Every `custodians` command checks a Kata node's agent policy before it sends anything to the node. The policy is the one in the init-data the node's quote binds. The check is on by default. `--no-policy-baseline` turns it off, and the output then records `"policy_baseline": "skipped"` (`held` when checked, `none` for a prototype node, which runs no agent policy). The checker is #79/#83's `alpha_core::coco::policy::verify`, which is not in this branch's base. Until it is, the default checker refuses every Kata node, naming the flag. The seam is `alpha_cli::custodians::alpha_baseline`, marked `ponytail: D9`. `alpha bootstrap` and `alpha unseal` are unchanged.

## Audit

- `custodians.approve`: the first approval of a proposal, with `proposal_sha256`.
- `custodians.rotate` `ok`: the signed response, in the rotation's own transaction.
- `custodians.rotate` `denied` / `error`: a refused approval or a failed rotation, with the reason.

Each row is sealed under the audit key of the node's epoch while it serves; `custodians.rotate` `ok` is the first row of the new epoch.

## Fail closed

- A sealed node takes no approval (`sealed`). A node started with a development root KEK refuses to rotate (`policy_denied`).
- One custodian cannot rotate. A second approval with the same share counts once, and a made-up second share combines into no root the database knows (`signature_invalid`).
- A nonce this node did not mint, or minted more than five minutes ago, is refused (`nonce_invalid`), as is a nonce that already rotated. Also refused (`malformed`): a proposal naming another node, a format other than `/1`, a repeated key, or an approval of another proposal.
- Replaying both approvals after a rotation rebuilds the old root, which opens nothing.
- The CLI refuses a rotation whose receipt does not verify against the pinned CA and listed builds, or that names other shares.
