# Fortanix tenancy check (PRD-06, draft)

**Draft.** This is the tool behind two PRD-06 requirements:

- **P0, customer-controlled tenancy:** "the SKU binds to the customer's own CCM/DSM account;
  AlphaCompute identities have no CCM policy or DSM key-admin rights. Verified at onboarding and
  audited quarterly."
- **P1, separation of duties:** "Rafay admins, infrastructure admins, release-key holders and
  custodians hold no Fortanix admin roles."

The procedure it serves is in alpha-infra: `docs/fortanix-tenancy.md` (onboarding steps 2–3 and
the quarterly audit) and `docs/separation-of-duties.md` (the roster and its roles). The tool
replaces the by-hand reading of the customer's export in those steps. It does not replace step 4,
the refusal test with every credential AlphaCompute holds, because a person can sign in to
Fortanix with an address the roster does not know.

Every Fortanix-specific value it relies on is an **assumption** tied to a Fortanix question (F3
for all of them today). Until Fortanix confirms an assumption, the check cannot pass. A clean run
reports `unconfirmed` and exits 3. No pilot customer can pass onboarding on this tool before F3
is answered. That is intended.

## What it reads

| Input | Shape | Who provides it |
|---|---|---|
| `--account` | `alphacompute-fortanix-account/1`: the owner, the tenancy (`customer`, `customer-exception` or `own`), the DSM and/or CCM endpoint and account id, every credential AlphaCompute holds in the account with its purpose (`workload`, `audit`, `node-agent`), and for `customer-exception` where the written acceptance is kept | The onboarding record |
| `--roster` | `alphacompute-sod-roster/1`: AlphaCompute's email domains, and every person with their roles (`release-key-holder`, `custodian`, `platform-org-key-holder`, `infrastructure-admin`, `rafay-admin`, `fortanix-admin`), every email they might use and any Fortanix user ids | The separation-of-duties owner, from `<roster location>` |
| `--dsm-listing` | `{"users": …, "apps": …, "groups": …}`: the bodies of DSM's `GET /sys/v1/users`, `GET /sys/v1/apps` and `GET /sys/v1/groups` | The customer's security admin (export) |
| `--dsm-login-file` | `{"email", "password"}` of a read-only (ACCOUNTAUDITOR) user the customer created for the check. The tool then reads the three listings itself, TLS 1.3 hybrid only, pinned to `dsm.ca_pem`. `--save-listing-dir` keeps the bytes it read | The customer, if they choose live reads (see Q6) |
| `--ccm-listing` | `alphacompute-ccm-listing/0`, a shape of this draft's own (`users` and `service_principals`, each with `id`, `email`/`name`, `roles`), because CCM's listing API is not known yet (Q5) | The customer's security admin, by hand from CCM |

A customer can make the DSM export with three calls under their own session:

```sh
for r in users apps groups; do
  curl -sf -H "Authorization: Bearer $TOKEN" "$DSM/sys/v1/$r?limit=1000" > "$r.json"
done
jq -n --slurpfile u users.json --slurpfile a apps.json --slurpfile g groups.json \
  '{users: $u[0], apps: $a[0], groups: $g[0]}' > dsm-listing.json
```

(`limit` and paging are assumption `dsm-listing`, Q4.)

## The rules

**Customer account** (`tenancy: customer`):

- A principal is AlphaCompute's if it is a recorded credential, if its email or Fortanix id is on
  the roster, or if its email is in an AlphaCompute domain (subdomains included).
- A recorded credential may hold only what its purpose allows: `workload` (the I1 trusted-CA
  App) key use only; `audit` and `node-agent` read-only only (Q8).
- Any other AlphaCompute principal fails the check, whatever it holds. The rule names the
  heaviest right: `tenancy.alphacompute-admin`, `-key-use` or `-member`. This is stricter than
  "no admin rights", and matches `docs/fortanix-dsm-keys.md`: no AlphaCompute identity is a
  member of the customer's account at all.

**An account AlphaCompute administers** (`customer-exception`, or `own` for our I3 DSM):

- Every principal with an admin right must be a roster person holding `fortanix-admin`
  (`sod.admin-not-a-fortanix-admin`, `sod.admin-not-on-roster`).
- That person holds no other role (`sod.fortanix-admin-holds-another-role`).
- A `customer-exception` without a recorded written acceptance fails.

**The roster itself:** nobody listed as `fortanix-admin` holds another role (`sod.roster`).

**Inputs:** each service the account record names needs exactly one listing; a listing for a
service it does not name fails.

**Classification.** Each role or permission is read as read-only, member, key use or admin. A
value the tool does not know is `unknown` and counts as admin. So does a group entry in a shape it
cannot parse. The tables are in `crates/alpha-dsm/src/tenancy/{dsm,ccm}.rs`, and each grant in the
report names the assumption its classification rests on.

## The report

JSON `alphacompute-fortanix-tenancy-report/1`, or the same as Markdown with `--format markdown`
for the audit file. `--out` always writes the JSON as well. It holds:

- the verdict: `pass`, `fail` or `unconfirmed`; exit status 0, 1 or 3;
- each listing's source and SHA-256;
- the findings, violations first;
- every principal with an admin or key right (so the customer can review their own admins) and
  every AlphaCompute principal;
- the assumptions the result rests on, each with its F-number and whether it is confirmed.

Keep the report and the listings it names in `<onboarding record>`.

## Not done (draft)

- **CCM live read.** It refuses, naming F3 (`ccm::fetch`).
- **DSM login with a second factor.** It refuses; use an export.
- **DSM plugins, quorum approval policies and external-KMS groups.** These can also move or
  release keys, and the listing does not read them (F3).
- **Running it quarterly.** Nothing schedules it. The quarterly review in
  `docs/separation-of-duties.md` runs it by hand.
- **Confirming assumptions.** Each `Assumption` is flipped to `confirmed: true` in a reviewed
  commit that cites Fortanix's answer. A unit test fails while any assumption is confirmed, so
  that commit must also change the test deliberately.

## Open questions

The numbers match `QUESTION(PRD-06 Qn)` in the code and the draft PR.

1. **Q1 (F3)** DSM user roles: are ACCOUNTADMINISTRATOR and GROUPADMINISTRATOR the key-admin
   roles, ACCOUNTAUDITOR and GROUPAUDITOR read-only, and ACCOUNTMEMBER without key rights? How
   do custom roles appear?
2. **Q2 (F3)** DSM App permissions: which ones administer keys, which use them, which only read?
3. **Q3 (F3)** CCM roles: which roles can change attestation policy (approve builds, apps or
   nodes)? Until then ACCOUNT_MEMBER counts as a policy right.
4. **Q4 (F3)** DSM listing: are `/sys/v1/users`, `/apps` and `/groups` with `limit`/`offset` the
   complete listing, and may an ACCOUNTAUDITOR user call them?
5. **Q5 (F3)** CCM listing: what API or export lists CCM users and API principals with roles?
6. **Q6 (Ryan Tharp)** Should AlphaCompute hold a read-only login in a customer's account at all?
   Proposed: no by default. The customer's export is the normal path, as
   `docs/fortanix-tenancy.md` says. A live read only with a time-boxed auditor user the customer
   creates for the check and deletes after, recorded with purpose `audit`.
7. **Q7 (Ryan Tharp)** Recognising AlphaCompute identities: roster emails and ids plus domains.
   A personal address not on the roster is missed, so the refusal test stays mandatory.
8. **Q8 (F4)** What a recorded credential may hold: node agents' needs are F4. Until then
   read-only only.
9. **Q9 (Ryan Tharp, Christopher Freytes)** The roster and account-record formats: keep them in
   these shapes at `<roster location>` and `<onboarding record>`, or adapt the tool to whatever
   the separation-of-duties owner keeps.
