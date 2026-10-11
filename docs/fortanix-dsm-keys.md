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
  }
}
```

- `endpoint` must be `https://`.
- `ca_pem` is the CA (or CAs) the DSM's server certificate chains to. Nothing else is trusted,
  including the system roots.
- Each key name is a lowercase path segment, like a Secret name, and maps to a DSM security
  object by `kid` or `name`.
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

TLS to the DSM uses the standard aws-lc-rs provider: TLS 1.2 or 1.3, hybrid ML-KEM key
exchange preferred, classical key exchange accepted. The KMS hops stay hybrid-only. The
customer's DSM sets its own posture, and PRD-06 question F6 settles what we require.

## What the customer configures in its DSM

The customer's security admin owns all of this, not AlphaCompute:

- An App whose credential is certificate based and trusts the AlphaCompute KMS CA (the CA in
  the platform document).
- The leaf carries two URI SANs:
  - `alphacompute://<org>/<app>/<runtime key sha256>`
  - `urn:alphacompute:revision:<compose hash>`

  Binding the DSM App to a specific App or Revision through these is the customer's choice.
  Whether DSM can match on URI SANs is part of Fortanix question F8. Until F8 is answered,
  assume the binding is to the KMS CA only, and scope keys per DSM App.
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
