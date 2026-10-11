# Customer keys from a Fortanix DSM (PRD-06, I1)

An App can take its data keys from the customer's own Fortanix Data Security Manager instead of,
or as well as, from the KMS. The Instance attests to the KMS as usual; the KMS issues its
one-hour leaf; `alpha-runtime` then authenticates to the customer's DSM with that leaf and asks
for the keys the Revision declares. The customer's DSM policy decides whether to release them.
AlphaCompute holds no DSM role and no copy of the keys.

## Declaring it in the compose

`ALPHACOMPUTE_DSM` is set on the runtime service. It is part of the compose, so it is measured
and the tenant signs it with the Revision: an operator cannot point an Instance at another DSM,
another App or another CA.

```json
{
  "endpoint": "https://dsm.customer.example",
  "app_id": "<DSM app uuid>",
  "ca_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
  "keys": {
    "records": { "kid": "<security object uuid>" },
    "index":   { "name": "search-index-key" }
  },
  "binding": "revision"
}
```

- `endpoint` must be `https://`.
- `ca_pem` is the CA (or CAs) the DSM's server certificate chains to. Nothing else is trusted,
  including the system roots.
- Each key name is a lowercase path segment, like a Secret name, and maps to a DSM security
  object by `kid` or `name`.
- `binding` is required: `revision` or `app`, the leaf name the customer's DSM App matches (see
  below). There is no value that binds to the KMS CA alone.
- `key_exchange` is optional: `hybrid`, the default, or `classical-allowed` (see "TLS to the
  DSM" below).
- Unknown fields are refused. A malformed value stops the runtime at start, like any other
  config error.

## Reading a key in the App

```
GET /v1/customer-keys/<name>   on the runtime socket
→ 200 {"name", "kid", "obj_type", "value": <base64url>}
```

Or `RuntimeSocket::customer_key(name)` in `alpha-client`.

| Status | Code | Meaning |
|---|---|---|
| 404 | `not_found` | The Revision declares no such key, or no DSM at all. |
| 403 | `dsm_refused` | The DSM answered 401 or 403: its policy does not grant this App the key. |
| 403 | `dsm_unbound` | The leaf does not carry the DNS name `binding` needs, so nothing was sent. |
| 502 | `dsm_unavailable` | The DSM was unreachable or answered something else. |
| 503 | `not_attested` | There is no valid leaf yet. |

A key is cached with the leaf it was fetched under. Each renewal builds a new DSM client from
the new leaf, and the next read asks the DSM again. An Instance whose Revision is revoked stops
renewing, so it loses access to the DSM within the hour. Copies the App already holds in memory
are the App's to drop.

## What the runtime sends

The calls come from the DSM REST API:

1. `POST /sys/v1/session/auth` over mTLS. The client certificate is the Instance's `[leaf, KMS CA]`
   chain, and the DSM App uuid is the basic-auth user. The bearer token is reused until 30 seconds
   before `expires_in`.
2. `POST /crypto/v1/keys/export` with the descriptor (`{"kid": …}` or `{"name": …}`). The
   object's `value` comes back in standard base64. A 401 here drops the token so the next call
   authenticates again.

### TLS to the DSM

TLS to the DSM is TLS 1.3 with the `X25519MLKEM768` hybrid key exchange only, as on every other
hop of the platform. A DSM that cannot do the hybrid gets no handshake, and every read answers
502 `dsm_unavailable`.

PRD-06 question F6 asks Fortanix what its key-release path supports. Until it is answered, a
tenant whose DSM cannot do the hybrid can set `"key_exchange": "classical-allowed"`. Classical
groups and TLS 1.2 are then accepted, with the hybrid still preferred. The setting is part of the
measured compose, so the tenant signs it with the Revision, and nothing else turns it on. F6
decides whether the setting stays.

## What the customer configures in its DSM

The customer's security admin owns all of this, not AlphaCompute.

### The App's credential: the KMS CA and one leaf name, never the CA alone

The KMS CA signs the leaf of every Instance of every organization, and the KMS nodes' own leaves.
The DSM App uuid is not a secret either: it sits in the plaintext compose, which the host and the
signer page show. A DSM App that trusted the KMS CA alone would therefore release this App's keys
to anyone holding any KMS leaf, including another tenant's App or an App that AlphaCompute staff
deploy as an ordinary tenant. That breaks the PRD-06 rule that AlphaCompute never controls key
release, so it is not supported, not even for a pilot.

The DSM App is a trusted-CA App with both:

- the KMS CA as its trusted CA. It comes from the release-signed platform document, and
  `alpha sign --check` prints it;
- one DNS name of the leaf as the subject alternative name it requires:

| `binding` | DNS name the DSM App matches | Who gets the keys |
|---|---|---|
| `revision` | `<hash hex 1-32>.<hash hex 33-64>.<app id>.<org id>.revision.alphacompute.invalid` | Instances of this Revision only. Add the next Revision's name to the DSM App before rolling it out. |
| `app` | `<app id>.<org id>.app.alphacompute.invalid` | Instances of any Revision of this App that the tenant signed. |

The KMS writes both names into every Instance leaf. It derives them from the same ids as the
leaf's two URI SANs, `alphacompute://<org>/<app>/<runtime key sha256>` and
`urn:alphacompute:revision:sha256:<hex>`, so they cannot disagree. They end in `.invalid`, so they
never name a host. The org id, App id and compose hash are the ones the tenant approved. A 401
`dsm_refused` message names the DNS name the leaf presented.

Before it sends anything, `alpha-runtime` checks that the leaf it is about to present carries the
name `binding` asks for, computed from the leaf's own URI SANs. A leaf without it, such as one
from a KMS older than this change, is never presented, and every read answers 403 `dsm_unbound`.
A compose without `binding` stops the runtime at start.

### Open with Fortanix (F8): no pilot until it is answered

Fortanix documents trusted-CA App authentication as matching a DNS name (the default), an IP
address or a directory name. URI SANs are not on that list, which is why the leaf also carries
DNS names. F8 must confirm, on the pilot customer's DSM version:

1. that a trusted-CA App accepts a client certificate when any one of its DNS-name SANs equals
   the configured name, even though the certificate also carries URI SANs and a second DNS name;
2. that one App can list several names, so a new Revision can be added before the old one is
   removed (Fortanix's DSM 5.6 release notes, February 2026, say it can).

If DSM can match only a directory name, the KMS puts the same names in the leaf's subject instead,
a small change in `issue_leaf`. If it can match neither, a per-organization issuing CA is needed
before any pilot. No customer is onboarded until F8 confirms one of these, and trusting the KMS CA
alone is never the fallback.

### Permissions and onboarding checks

- The EXPORT permission on each declared key, for that App only.
- Onboarding checks, from PRD-06 "customer-controlled tenancy", verified at onboarding and
  quarterly:
  - No AlphaCompute identity (Rafay admin, infrastructure admin, release-key holder, custodian)
    is a member of the customer's DSM account or holds an administrative role in it.
  - DSM audit logs of key release are readable by the customer directly.

## Not in this change

- **CCM appraising the same evidence instead of the KMS leaf** (I1's alternative, and I2):
  waits on F8.
- **I5, the KMS accepting a CCM attestation:** waits on F8.
- **I3, release signing and a KMS root wrap in an on-prem DSM:** a release-process change,
  after Ed25519 support in DSM is confirmed.
