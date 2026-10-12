# Evidence to the customer (PRD-06)

PRD-06 P1: "Evidence to the customer: CCM attestation records and DSM key-release logs reachable
by the customer directly." A customer who uses Fortanix next to the Alpha stack has two sets of
decisions to show an auditor:

- the Alpha KMS's: which Instances it attested, and which Secrets and keys it released to them;
- Fortanix's: which workloads CCM attested, and which keys DSM released.

Neither set goes through AlphaCompute staff. This page says where each one is read.

The Alpha side has code (below). The Fortanix side is the customer's own account, and what it
exposes is Fortanix question F5.

## What the customer reads, and where

| What | Where | Who can read it | Verifiable offline? |
|---|---|---|---|
| The KMS's decisions about the organization's Instances: every `attest`, `secret.get` and `key.derive`, granted or refused, plus every earlier export | `POST /v1/decisions/export` on the KMS (`alpha evidence decisions`) | Any active key of the organization, including a read-only auditor key | Yes: the node's receipt under the KMS CA; `alpha evidence verify-decisions` |
| One Instance's attestation: the request, the KMS receipt and the leaf, with which verifiers attested it (Alpha, NVIDIA, Fortanix) | `GET /v1/evidence-bundle` on the runtime socket (clear claims, #90); the App decides whom to show it | Whoever the App shows it to | Yes: `alpha_client::attestation::verify_bundle` |
| Fresh TDX + GPU evidence of a running pod over a nonce the customer chooses | `GET /v1/evidence` on the runtime socket (I2, #92; off unless the measured config enables it) | Whoever the App shows it to | It is evidence, appraised like the KMS appraises it |
| CCM attestation records | The customer's own CCM account | The customer's CCM users | F5 |
| DSM key-release logs (I1: the EXPORT of each customer key to an Instance leaf) | The customer's own DSM account (its audit log) | The customer's DSM users | F5 |

AlphaCompute neither relays nor stores the last two rows. Under `docs/fortanix-tenancy.md`
(alpha-infra) no AlphaCompute identity is in the customer's account, so we cannot read them
either.

## The KMS's decisions (`POST /v1/decisions/export`)

- **Request.** A body signed under `alphacompute/decisions-export/v1` by any active key of the
  organization. Payload: `{after_seq, limit, issued_at}`, where `limit` is 1 to 500 and
  `issued_at` is within 5 minutes.
- **Who signs it.** A member key (any ordinary key of the organization) or an **auditor key**.
  An auditor key is read-only: it signs the export and nothing else. The KMS refuses it, as
  `forbidden` (403), on every Control write: registering or revoking a Revision, putting a
  Secret, registering or revoking a key. It also cannot register keys of its own. Secrets and
  derived keys go only to attested Instances, never to a principal key of any kind.
- **Answer.** `alphacompute-kms-decisions/1`:
  - `org_id`;
  - `request`, the body exactly as the KMS received it;
  - `rows`, the audit rows in sequence order;
  - `next_after_seq` and `more`;
  - `receipt`, the node's receipt (route `decisions.export`) over all of the above.
- **Each row.** It has `seq`, `ts`, `actor_kind`, `actor` (the Instance's runtime key hash),
  `action`, `object`, `outcome` and `details`.
  - For an `attest` row, `details` is the attestation result. That includes `verifiers`, which
    names who attested it (#90).
  - `evidence_sha256` is the digest of the evidence that was appraised. It is the same digest
    the evidence bundle's request hashes to.
- **Offline check.** `alpha_client::decisions::verify` takes only the answer and the KMS pins
  from the platform document. The receipt is a listed KMS node's under the KMS CA, for this route,
  over exactly the echoed request, and the rows are in order. It returns only what was signed.
- **Audited.** Every export, and every refused export, is itself an audit row. The organization
  sees each time its record was read.

An existing member key registers the customer's auditor key with an ordinary key registration
(`POST /v1/keys`, signed under `alphacompute/principal-key/v1`), with `"kind": "auditor"` in the
payload. The kind sits in the document the registering key signs, so the chain walk re-reads it on
every call and nobody can change it in the database. The registration is audited
(`key.register`, `details.kind`), and so is every export (`decisions.export`, `details.kind`).

```sh
# A member key registers the auditor's key. auditor-key.json is the payload:
#   {"principal_id": "<auditor uuid>", "public_key": "<the auditor key's SPKI, base64url>",
#    "label": "auditor", "kind": "auditor"}
alpha call register-key --key org.key --key-id <uuid> auditor-key.json
# The auditor exports with it:
alpha evidence decisions --key auditor.key --key-id <auditor key id> > decisions-0.json
alpha evidence decisions --key auditor.key --key-id <auditor key id> --after-seq <next_after_seq> > decisions-1.json
# The auditor, with the signed platform document:
alpha evidence verify-decisions --platform platform.signed.json decisions-0.json
```

### What it does not prove yet

- **Completeness.** The receipt proves these rows came from the KMS, not that no row was left
  out. That needs the hash-chained audit log (#95, PRD-05) and the chain position in the
  receipt (Q89).
- **Refusals the KMS could not attribute.** A failed attestation, or a Control call with a bad
  signature, is recorded with no organization, because the KMS never learned whose it was. Such
  a row is in no organization's export (Q89).
- **Fortanix's decisions.** DSM's release of a customer key to an Instance (I1) is decided and
  logged by the customer's DSM. The KMS never sees it.

## The Fortanix side

- **What to point the customer's auditor at.** The CCM attestation records and the DSM audit log
  of their own account. Onboarding (alpha-infra `docs/fortanix-tenancy.md`) should confirm that
  the customer's security admin can read both before the first workload. `docs/fortanix-dsm-keys.md`
  lists "DSM audit logs of key release are readable by the customer directly" as an onboarding
  check.
- **Unknown until F5.** What evidence an end user receives from CCM; whether it can be verified
  without Fortanix online; and how a DSM key-release log entry names the client (the leaf's DNS
  name, its serial, or the DSM App only). The last one decides whether an auditor can line up
  a DSM release with the KMS `attest` row of the same Instance.
- TODO(PRD-06 Q90): once F5 and F8 are answered, add a short "line them up" procedure: KMS `attest`
  row → leaf → DSM log entry for that leaf → CCM record for the same evidence (I2).

## Open questions

Numbered program-wide; the same numbers are in `QUESTION(PRD-06 Qn)` in the code and in the PR.

- **Q87 (Ryan Tharp)** Which audit actions count as decisions. Today: `attest`, `secret.get`,
  `key.derive` and the exports. Proposed: add the organization's own Control rows
  (`revision.register`, `revision.revoke`, `secret.put`, `key.register`, `key.revoke`) in a
  follow-up, because they show who approved what.
- **Q88 (Ryan Tharp, security sign-off)** Who may export. Implemented as proposed, subject to
  sign-off: any active key of the organization. That includes a read-only auditor key kind (above),
  so the customer's auditor holds no key that can register a Revision or put a Secret. Member keys
  keep the export, because a key that can already write can also read.
- **Q89 (Ryan Tharp)** What the export cannot prove: completeness and unattributed refusals.
  - Completeness. Proposed: once the chained audit log (#95) lands, the answer carries each row's
    chain hash and the receipt names the chain head, so a verifier can check that consecutive
    exports join with no gap.
  - Unattributed refusals. Proposed: accept for the pilot and document it. Attributing a refused
    attestation to the organization its evidence *claims* would let anyone write rows into
    another organization's record.
- **Q90 (Fortanix, F5 and F8)** The Fortanix side's records:
  - What do CCM and DSM expose natively to the customer?
  - Can a CCM attestation record be verified offline?
  - Do DSM's key-release log and CCM's record name something an auditor can match to the KMS's
    `attest` row (leaf DNS name or serial, evidence digest, nonce)?
- **Q91 (Christopher Freytes)** Whether the Rafay portal should show the export to the customer.
  Proposed: CLI and API for the pilot; a portal view after it.
