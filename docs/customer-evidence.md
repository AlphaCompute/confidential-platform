# Evidence to the customer (PRD-06, draft)

PRD-06 P1: "Evidence to the customer: CCM attestation records and DSM key-release logs reachable
by the customer directly." A customer who uses Fortanix next to the Alpha stack has two sets of
decisions to show an auditor:

- the Alpha KMS's: which Instances it attested, and which Secrets and keys it released to them;
- Fortanix's: which workloads CCM attested, and which keys DSM released.

Neither set goes through AlphaCompute staff. This page says where each one is read.

**Draft.** The Alpha side has code (below). The Fortanix side is the customer's own account, and
what it exposes is Fortanix question F5.

## What the customer reads, and where

| What | Where | Who can read it | Verifiable offline? |
|---|---|---|---|
| The KMS's decisions about the organization's Instances: every `attest`, `secret.get` and `key.derive`, granted or refused, plus every earlier export | `POST /v1/decisions/export` on the KMS (`alpha evidence decisions`) | Any active key of the organization | Yes: the node's receipt under the KMS CA; `alpha evidence verify-decisions` |
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

```sh
alpha evidence decisions --key org.key --key-id <uuid> > decisions-0.json
alpha evidence decisions --key org.key --key-id <uuid> --after-seq <next_after_seq> > decisions-1.json
# The auditor, with the signed platform document:
alpha evidence verify-decisions --platform platform.signed.json decisions-0.json
```

### What it does not prove yet

- **Completeness.** The receipt proves these rows came from the KMS, not that no row was left
  out. That needs the hash-chained audit log (#95, PRD-05) and the chain position in the
  receipt (Q3).
- **Refusals the KMS could not attribute.** A failed attestation, or a Control call with a bad
  signature, is recorded with no organization, because the KMS never learned whose it was. Such
  a row is in no organization's export (Q4).
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
- TODO(draft): once F5 and F8 are answered, add a short "line them up" procedure: KMS `attest`
  row → leaf → DSM log entry for that leaf → CCM record for the same evidence (I2).

## Open questions

The numbers match `QUESTION(PRD-06 Qn)` in the code and the draft PR.

1. **Q1 (Ryan Tharp)** Which audit actions count as decisions. Today: `attest`, `secret.get`,
   `key.derive` and the exports. Proposed: add the organization's own Control rows
   (`revision.register`, `revision.revoke`, `secret.put`, `key.register`, `key.revoke`) in a
   follow-up, because they show who approved what.
2. **Q2 (Ryan Tharp)** Who may export. Today: any active key of the organization. Proposed: a
   read-only auditor key kind before the pilot. The customer's auditor would then hold no key that
   can register a Revision or put a Secret.
3. **Q3 (Ryan Tharp)** Completeness. Proposed: once the chained audit log (#95) lands, the answer
   carries each row's chain hash and the receipt names the chain head, so a verifier can check
   that consecutive exports join with no gap.
4. **Q4 (Ryan Tharp)** Unattributed refusals. Proposed: accept for the pilot and say so in the
   export's documentation. Attributing a refused attestation to the organization its evidence
   *claims* would let anyone write rows into another organization's record.
5. **Q5 (Fortanix, F5)** What CCM and DSM expose natively to the customer, and whether a CCM
   attestation record can be verified offline.
6. **Q6 (Fortanix, F5 and F8)** Whether DSM's key-release log and CCM's record name something an
   auditor can match to the KMS's `attest` row (leaf DNS name or serial, evidence digest, nonce).
7. **Q7 (Christopher Freytes)** Whether the Rafay portal should show the export to the customer.
   Proposed: CLI and API for the pilot; a portal view after it.
