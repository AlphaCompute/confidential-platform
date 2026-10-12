# Fortanix CCM-attested workloads calling Alpha services (PRD-06 I5)

PRD-06 I5: "alpha-kms accepts a CCM attestation as evidence and issues a certificate", so a
workload attested by Fortanix Confidential Computing Manager can call Alpha's broker, guard or
model servers. The constraint is that this must not weaken the KMS. A CCM-attested workload is
not an Alpha Revision: no tenant signed its code, and alpha-kms did not appraise its evidence.
So it gets a leaf of its own kind, and Alpha services treat it as an Alpha identity only where an
organization allow-listed it, and only where the service chose to accept such leaves.

The feature ships disabled. A platform document without `fortanix_ccm` refuses every CCM
attestation, and until Fortanix answers F5 and F8 the CCM appraisal refuses every certificate,
even inside a pinned zone (see "Fail-closed").

## Trust model

A leaf is issued only when every one of these holds, in this order:

1. **The KMS nonce.** The nonce must be the KMS's own, at most 5 minutes old, as for
   `POST /v1/attest`.
2. **A zone AlphaCompute's release pins.** The release-signed platform document names the CCM
   zones whose attestations count:

   ```json
   "fortanix_ccm": { "zone_cas": ["-----BEGIN CERTIFICATE-----\n…"] }
   ```

   This is the zone's Root CA certificate. Per Fortanix's documentation, the zone Root CA signs
   every application certificate and "issues certificates only to enclaves presenting a valid
   attestation" (support.fortanix.com, "What is the structure of Cert Chain?"; "Fortanix
   Confidential Computing Manager Usage Workflow"). If the field is absent or empty, every CCM
   evidence is refused. Nothing is fetched: trust in a zone rests on the release signature, as
   NRAS's keys do.
3. **The CCM evidence verifies** (`alpha_attest::ccm::appraise_ccm`):
   - the workload's CCM certificate chains to one pinned zone Root CA, with webpki checking the
     signatures, the validity at the KMS's clock, the CA constraints, and the client-auth key
     purpose when the certificate lists purposes;
   - the certificate's key signed `signing_digest("alphacompute/ccm-possession/v1",
     {nonce, runtime_pubkey})`, which makes the evidence fresh and names the P-256 key the leaf
     will certify;
   - the certificate names an identity: the attested application and its image (**F5, F8:
     refuses until answered**).
4. **The workload's organization allow-listed that identity in that zone.** The request names an
   `org_id`, and that organization must have a row in `ccm_identities` for exactly this zone and
   identity. The row must be unrevoked, and its stored document must still verify under its
   signer's chain in that organization, re-checked on every attestation as a Revision is. Another
   organization's allow-listing never counts.

Then the KMS issues a one-hour leaf, under its CA, over the requested key, with:

```
alphacompute-ccm://<org id>/<ccm identity id>/<sha256 of the key>
urn:alphacompute:ccm-zone:sha256:<zone Root CA SPKI>
```

The leaf names no Revision. `parse_instance_sans` refuses it, so with no change at all it is
refused by:

- the KMS's `GET /v1/secrets/{name}` and `POST /v1/keys/derive` (`cert_invalid`, tested);
- `alpha-runtime`;
- `alpha_client::Pin`;
- every relying party that reads an Instance leaf.

A service accepts a CCM leaf only by calling `alpha_channel::cert::parse_ccm_sans`, which it does
explicitly and for the organizations and identities it chooses. No service does yet.

The CCM leaf is the PRD's "distinct leaf type/SAN". There are two allow-lists:

- the organization's (`ccm_identities`), without which no leaf is issued;
- the service's own decision to accept `alphacompute-ccm://` leaves at all.

## Routes

- `POST /v1/ccm-identities` (Control, signed, context `alphacompute/ccm-identity/v1`), with
  payload `{name, zone_ca_spki_sha256, identity}`. The signing key's organization allow-lists the
  identity. The route is idempotent per (organization, zone, identity), and registering a revoked
  identity again returns it still revoked. The reply carries a receipt, as every Control success
  does.
- `POST /v1/ccm-identities/{id}/revoke` (Control, context `alphacompute/control/v1`), with payload
  `{id, issued_at}`. No leaf is issued afterwards, and a leaf already issued runs out within its
  hour.
- `POST /v1/attest/ccm`, with body `{runtime_pubkey, nonce, org_id, evidence}`. Here `evidence`
  is `alphacompute-ccm-evidence/1`: `{format, certificate_chain: [base64url DER, workload's
  first], signature: base64url}`. The reply is shaped like `/v1/attest`'s: `certificate_chain`,
  `not_after`, and `attestation_result` (`alphacompute-ccm-attestation-result/1`: organization,
  CCM identity id, zone, certificate digest, key, evidence digest, and
  `verifiers.attested_by = ["fortanix"]` with a `composite` `fortanix-ccm` entry). The reply also
  carries `attestation_receipt`, a KMS receipt with route `attest.ccm`. Every request writes one
  `attest.ccm` audit row with the evidence digest.

## Fail-closed (`ponytail` markers)

- `alpha_attest::ccm::ccm_identity` (**F5, F8**). Fortanix has not published which fields of a
  CCM application certificate name the attested application, its image and its account, or
  whether CCM attests Kata pods (F1). Guessing, the subject CN say, could let one application of
  a zone pass for another. So every certificate is refused there, after the zone, chain,
  validity and possession checks have run. Once Fortanix answers, that one function reads the
  named fields. The tests that drive the rest of the path then run through the route.
- If Fortanix's attestation output turns out to be a signed token rather than the application
  certificate (F5), the pin stays in `fortanix_ccm`: the token's signing keys go beside
  `zone_cas`, as `nras_keys` does for NRAS. `appraise_ccm` then verifies the token instead of the
  chain. The leaf, allow-list and audit steps do not change.
- `alpha-kms` tests the steps after the identity through `ccm::attest_ccm_verified`, which no
  route reaches, as `instance::attest_verified` does for Kata quotes.

## Not done here

- No Alpha service (broker, guard, model servers) accepts CCM leaves yet. Each one opts in with
  `parse_ccm_sans` and its own allow-list, after this design is signed off.
- No CLI writes `POST /v1/ccm-identities` yet. A signed body built with `alpha_client::sign`
  works.
