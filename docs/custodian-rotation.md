# Replacing custodians: re-share with root rotation

At genesis `alpha bootstrap` splits a random root KEK 2-of-3 among three custodians' X-Wing keys. The root KEK wraps the intermediates in `intermediate_keys` (tenant-kek-root, the KMS CA key and, with M2(a), the database's volume key, `docs/db-volume-key.md`), and everything else derives from tenant-kek-root: every organization's `org_key`, every App's derived keys, and the metadata keys of `docs/metadata-encryption.md`. Until now a departing custodian kept their share. With any other share it would still unseal the root KEK.

Re-splitting the same root KEK would not help: old Shamir shares of an unchanged secret stay valid. `alpha custodians rotate` therefore makes a **new** root KEK inside the serving node, re-wraps both intermediates under it, splits it to the new custodians and forgets both roots. From the commit on, the old shares rebuild a root that unwraps nothing in the database.

Code: `services/alpha-kms/src/custodians.rs` (routes), `crates/alpha-cli/src/custodians.rs` (commands), `migrations/20261013000000_custodian_rotations.sql`. Tests: `services/alpha-kms/tests/custodians.rs`, and a Kata node's rotation in `tests/kata_node.rs`.

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
   - locks and opens every `intermediate_keys` row under the combined root. Any row that does not open, or a tenant-kek-root other than the one it serves, refuses the rotation (`signature_invalid` / `internal`) and clears the pending approvals;
   - generates a new 256-bit root with the OS RNG and re-seals every row under it, with the same AES-256-GCM and purpose AAD as bootstrap;
   - splits the new root 2-of-3 (`vsss_rs::Gf256`, as bootstrap does), checks that every pair of shares combines back, and HPKE-seals share *i* to new custodian *i* under the unseal info string and this node's runtime-key AAD. Each new share is therefore an ordinary share file for `alpha unseal`;
   - inserts the `custodian_rotations` row: the proposal, the three sealed shares and the node's receipt. `nonce` is unique, so a nonce rotates once;
   - appends a sealed `custodians.rotate` audit row.

   Then it commits. Both roots and all shares are `Zeroizing` and dropped when the call returns. The reply carries the rotation, and the CLI verifies its receipt before writing `rotation.json`.
4. **Acceptance.** Each new custodian runs `alpha custodians accept --rotation rotation.json --key new.key --out share.json --endpoint <node>`. Without `--rotation`, the node's last committed rotation is fetched from `GET /v1/node/custodians/rotation`, which a sealed node answers too. The CLI:
   - attests the node at `--endpoint` and checks the baseline;
   - verifies the receipt under a leaf of the KMS CA the platform document pins, issued to a KMS build the document lists, for route `custodians.rotate` and exactly this proposal, naming exactly these three sealed shares;
   - finds the custodian's key among the three and opens their share;
   - writes `share.json`, refusing to overwrite an existing file.

   The output says whether the attested node is the one that rotated (`rotating_node_attested`).

The receipt's signed response is `{rotation_id, proposal_sha256, kms_node_spki_sha256, custodians_sha256[3], shares_hpke_sha256[3], approved_by_shares, rewrapped, db_volume_wrapped_sha256}`. The rotation carries the database's volume key re-wrapped under the new root (`db_volume_wrapped`, its hash in the receipt, `null` when the database has none), and `accept` writes it into the new share file, so the new custodians can unseal a node while the database is closed. The volume key's value does not change, so the LUKS volume is not re-keyed. `approved_by_shares` holds the Shamir x-coordinates (1–3) of the two shares that approved. The node never learns which person holds which share.

## Atomicity and crash safety

The re-wrap and the record of the new shares are one Postgres transaction. Before the commit only the old root opens the database. After it only the new root does, and the new shares are durable in `custodian_rotations`, sealed to their holders. The node never commits a state that neither root opens:
- A failure before the commit leaves every row as it was. `tests/custodians.rs` makes the transaction's last write fail after every row was re-wrapped; the rows are unchanged byte for byte and the old shares still unseal a fresh node.
- A reply lost after the commit costs nothing. `accept` fetches the rotation from any node, sealed or serving.

## Joined nodes and replication

The intermediates do not change, only their wrapping. Every node reads and writes the same Postgres.
- A node that joined before the rotation keeps serving with the intermediates it holds. It still reads every row and verifies the audit chain across the rotation.
- A node that joins later gets the same intermediates from a serving node.
- A node that restarts and is unsealed reads the re-wrapped rows. It needs two **new** shares: old shares, or an old and a new share, combine into a root that unwraps nothing (`does not unwrap under this root`).
- A joined node never held a root, but it can run the next rotation, because the approvals rebuild the root from the database's rows.

## What does not rotate, and why

**The metadata and audit keys of #95 do not change, and no table is re-sealed.** They derive from tenant-kek-root (`store::MetadataKeys::derive`), which is re-wrapped, not replaced. So every sealed row, blind index, `anchor_check` and audit-chain link stays valid. That matters for the audit log in particular: its rows are append-only for the service role and could not be re-sealed.

Rotating tenant-kek-root as well would change:
- every `org_key`, and so every Secret's ciphertext;
- every App's derived keys. Customers' LUKS volumes (`alpha-volume`) and anything else sealed under `keys/derive` would stop opening, and that cannot be done for them;
- every blind index and `anchor_check`.

Rotating the CA would re-issue every leaf and need a re-signed platform document. Neither is needed for what this rotation is for.

**The residual risk:** old shares opened the old wrapping of the **same** intermediates. Anyone holding two old shares **and** a copy of `intermediate_keys` from before the rotation (a backup, a snapshot, dead tuples on the trust-zone disk before `VACUUM`) still recovers tenant-kek-root. A single departing custodian holds one share. They need a second old share, from another custodian who kept their old share file, and a pre-rotation copy of the database. Keep both out of reach:
- every custodian deletes their old share file once they hold a new one;
- pre-rotation backups of `intermediate_keys` are destroyed or kept under the same custody as shares;
- the operator runs `VACUUM intermediate_keys` after the ceremony.

Replacing all three custodians at once leaves three old shares outside the new custody. The same holds there.

## Agent-policy baseline (D9)

Every `custodians` command checks a Kata node's agent policy before it sends anything to the node. The policy is the one in the init-data the node's quote binds. The check is on by default. `--no-policy-baseline` turns it off, and the output then records `"policy_baseline": "skipped"` (`held` when checked, `none` for a prototype node, which runs no agent policy). The checker is #79/#83's `alpha_core::coco::policy::verify`, which is not in this branch's base. Until it is, the default checker refuses every Kata node, naming the flag. The seam is `alpha_cli::custodians::alpha_baseline`, marked `ponytail: D9`. `alpha bootstrap` and `alpha unseal` are unchanged.

## Audit

- `custodians.approve`: the first approval of a proposal, with `proposal_sha256`.
- `custodians.rotate` `ok`: the signed response, in the rotation's own transaction.
- `custodians.rotate` `denied` / `error`: a refused approval or a failed rotation, with the reason.

Each row is sealed under the audit key while the node serves.

## Fail closed

- A sealed node takes no approval (`sealed`). A node started with a development root KEK refuses to rotate (`policy_denied`).
- One custodian cannot rotate. A second approval with the same share counts once, and a made-up second share combines into no root the database knows (`signature_invalid`).
- A nonce this node did not mint, or minted more than five minutes ago, is refused (`nonce_invalid`), as is a nonce that already rotated. Also refused (`malformed`): a proposal naming another node, a format other than `/1`, a repeated key, or an approval of another proposal.
- Replaying both approvals after a rotation rebuilds the old root, which opens nothing.
- The CLI refuses a rotation whose receipt does not verify against the pinned CA and listed builds, or that names other shares.
