# How an App pins the KMS (D6)

`alpha-runtime` trusts a KMS node only when the node's chain ends at the pinned KMS CA and its leaf names a KMS Revision it accepts. There are two ways to say which Revisions. The strict pin is the default; the platform pin is opt-in per App.

| | Strict pin (default) | Platform pin (opt-in) |
|---|---|---|
| Measured config | `ALPHACOMPUTE_KMS_CA_SPKI_SHA256`, `ALPHACOMPUTE_KMS_REVISIONS=sha256:…,sha256:…` | `ALPHACOMPUTE_KMS_CA_SPKI_SHA256`, `ALPHACOMPUTE_KMS_REVISIONS=platform:<min version>`, `ALPHACOMPUTE_PLATFORM_DOCUMENT_URL=https://…` |
| Which KMS builds | exactly the listed ones, as the tenant approved them | whichever `kms_revisions` the current release-signed platform document lists |
| A KMS upgrade | a new App Revision, re-approved by the organization (M3) | a new platform document; the App's Revision is unchanged |
| Who decides the KMS's identity | the tenant's passkey approval | the release key, within the CA the tenant pinned |

## The platform pin

`alpha_client::platform::PlatformPin` holds the rules. The runtime uses it like this:
1. **Before each attestation** (the first one and each renewal, about hourly), the runtime fetches the document from the URL. The URL is untrusted: only the signature counts.
2. **It applies the document only if all of these hold:**
   - it verifies under the compiled-in release key, the same `services/alpha-kms/release-key.pub` the KMS uses;
   - its `version` is at or above the measured minimum;
   - its `version` is at or above every version this process has already accepted;
   - it carries `expires_at`, and has not passed it;
   - its `kms_ca_pem` has the pinned CA key, so the document can never move the App to another CA;
   - it lists at least one KMS Revision.
3. **Pinning.** The handshake then accepts a KMS leaf naming any listed Revision. The list matches nothing once its document's `expires_at` passes, for every handshake, not only at the next refresh.
4. **Fresh connections.** Each attestation opens fresh connections. A connection a dropped build opened earlier is never reused across a document change.
5. **Failure.** A refresh that fails keeps the current document until it expires. With no current document, the runtime does not attest. The renewal loop retries.

Opting in: `alpha compose wrap --kms-platform-pin https://…/platform.json` takes the CA from `--platform` and uses that document's `version` as the minimum. A deploy spec's `runtime` takes `kms_platform_pin: {document_url, min_version}` instead of `kms_revisions`; the two are exclusive.

## Revocation and rollback

- **Revoking a build.** A KMS build is revoked by signing a document that no longer lists it.
- **What could readmit it.** Only an older document that still lists it. A stateless runtime cannot remember having seen the newer one, so how old a document it accepts is bounded three ways:
  - **The measured minimum.** It is independent of time. The tenant raises it only with a new Revision.
  - **Monotone within the process.** A running runtime never goes back below a version it accepted.
  - **`expires_at`.** The release process must re-sign the document before it expires. This bound is only as good as the guest's clock, which on TDX the host influences.
- **No deny-list.** It would add nothing here: the document that readmits a dropped build is an older one, and an older one carries no newer deny-list. "Not listed in an acceptable document" is the revocation.
- **The KMS and the custodian CLI** keep their own monotone versions: the `platform_document` row, and the share file's `platform_document_version`.

## What changes in trust

With the platform pin, the release key can add a KMS build to every opted-in App. Such a build may hold the tenant's keys through `join`, because the serving node appraises a joining node against the same document. The strict pin makes each such build a tenant decision instead. Three things are unchanged:
- the CA stays the tenant's pin;
- every KMS build is still appraised (DCAP, reference values, `kind`) before it receives the intermediates;
- the release key already decides the reference values every Instance is appraised against.

The release key's custody and the sign-off of each listed build therefore carry the weight the tenant's approval used to.

One limit holds for both pins: a KMS build that was once listed and unsealed holds the CA key. Dropping it from the document stops honest clients from talking to it. It does not stop that build from minting leaves, which would need a new CA.
