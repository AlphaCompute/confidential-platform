# Connecting to an App

An App answers at one name, `https://<dstack app id>-443s.<gateway base>`, and the
deploy that started it returns that URL. The TLS certificate it serves is the whole
point: it is issued by the KMS CA to an Instance that attested, and it names what is
running. Verifying it is how a client learns it is talking to the code it expects,
rather than to a host that merely answers at the right address.

## What the certificate says

Two URI SANs, and nothing in the subject:

```
URI:alphacompute://<org id>/<app id>/<sha256 of the runtime public key>
URI:urn:alphacompute:revision:sha256:<compose hash>
```

The second is the one to check: it is the Revision the Instance is running, and it is
the same hash the tenant registered and signed. The certificate lives one hour and the
Instance renews it, so a client that checks the chain and the SANs on every connection
learns within the hour when an App stops being entitled to run.

Both values a client pins — the KMS CA and the Revision — come from the release-signed
platform document, never from the App and never from this API. `alpha sign --check`
prints them.

## TLS 1.3 with a post-quantum hybrid, and nothing else

Every hop of this platform requires the `X25519MLKEM768` key exchange. Clients offer
that group alone, and a server or client without it cannot complete a handshake here.

**This is the first thing to check when a connection fails.** A client that lacks the
hybrid does not get a certificate error: it gets a connection error, which looks exactly
like an Instance that never attested. The two are told apart by asking the endpoint with
a tool that does support it (below).

The support boundary is OpenSSL 3.5, where ML-KEM and the hybrid groups first shipped.
Measured:

| Runtime | OpenSSL | Hybrid |
|---|---|---|
| `alpine:3.22`, `alpine:edge` | 3.5.8 | yes |
| `debian:trixie` | 3.5.7 | yes |
| Node 22, 24, 25 (bundled) | 3.5.x | yes |
| `alpine:3.20`, `alpine:3.21` | 3.3.7 | no |
| Rust with rustls and `aws-lc-rs` | — | yes |

An App's own container is bound by the same rule: whatever serves the Endpoint has to
speak the hybrid, or nothing will reach it.

## Pinning, in Node

The KMS CA is the only root — a public CA proves nothing about what is running — and the
Revision is checked after the handshake, where the certificate is available:

```js
const tls = require("node:tls");

const socket = tls.connect({
  host, port: 443, servername: host,
  ca: [kmsCaPem],
  minVersion: "TLSv1.3",
  checkServerIdentity: (_, cert) => {
    const sans = (cert.subjectaltname || "").split(", ");
    const want = `URI:urn:alphacompute:revision:${revision}`;
    return sans.includes(want)
      ? undefined
      : new Error(`the Instance serves ${sans.join(" ")}, not ${want}`);
  },
}, () => {
  // socket.authorized is true only when the chain ended at the KMS CA.
});
```

Nothing else about the certificate is worth checking: the subject is empty by design, and
the hostname is the provider's, not an identity.

## Asking an endpoint what it is

```
openssl s_client -connect <host>:443 -servername <host> </dev/null 2>/dev/null \
  | openssl x509 -noout -issuer -ext subjectAltName -dates
```

With OpenSSL 3.5 or newer this prints the issuer, the two SANs and the hour the
certificate is good for. An Instance that has not attested serves no certificate at all:
the connection is accepted by the gateway and closes with none, because there is nothing
behind it to forward to.
