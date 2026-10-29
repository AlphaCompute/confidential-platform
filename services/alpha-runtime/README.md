# alpha-runtime

The sidecar inside every Instance. On start it makes a P-256 key in memory (one per Instance
life), asks the KMS for a nonce, quotes `report_data` over its key and the nonce through
the guest agent's socket, sends the quote and the dstack event log to `POST /v1/attest`, and keeps the
one-hour leaf it gets back, renewing it with fresh evidence ten minutes before it expires. If
the KMS answers `revision_revoked` — at the first attestation, a renewal, a secret or a key read — the
process exits with code 78 and the socket disappears. Startup and configuration refusals exit
with 1 and name the check; a drain on SIGTERM exits with 0.

In a Kata TDX pod there is no guest agent socket: the runtime quotes through configfs-tsm
(`/sys/kernel/config/tsm/report`, which the container needs mounted and must run as uid 0 to
write) and sends the quote alone. The KMS reads the Revision, the digest of the pod's init-data,
from the quote's `MRCONFIGID`. The guest does not show a container its init-data, so a pod that
wants `/v1/identity` to serve it mounts its own annotation into the runtime container with the
downward API, at `/run/alpha-init-data/cc_init_data`:

```yaml
volumes:
  - name: init-data
    downwardAPI:
      items:
        - path: cc_init_data
          fieldRef:
            fieldPath: metadata.annotations['io.katacontainers.config.hypervisor.cc_init_data']
# in the alpha-runtime container
volumeMounts:
  - { name: init-data, mountPath: /run/alpha-init-data, readOnly: true }
```

The host writes that file, so the runtime decodes it (`base64(gzip(toml))`, under 1 MiB
inflated) and refuses to attest unless its SHA-256 is the leaf's Revision. Without the file
`/v1/identity` answers `init_data: null`.

On Kata the host writes the environment variables below, and the init-data's agent policy is
what makes them trustworthy: `alpha coco render` pins every variable of every container to its
rendered value, the guest agent refuses to create a container whose environment differs, and the
KMS registers no init-data without that pinned policy. A pod spec not produced by `render` gets no
Revision.

Configuration is three environment variables, a fourth when a service declared a Secret, a
fifth for a wrapped compose or a Kata pod with an Endpoint, and two optional ones for that
Endpoint.
`ALPHACOMPUTE_KMS_CA_SPKI_SHA256` (`sha256:<hex>` of the KMS CA's SubjectPublicKeyInfo) and the
KMS Revisions are in the measured compose on dstack, and in the policy-pinned environment on Kata,
and are all the runtime trusts, with the release key set when the Revisions come from the document: before the first request it refuses a KMS whose chain does not end
at a CA with that key or whose leaf carries no allowed Revision, and moves on to the next entry of
`ALPHACOMPUTE_KMS_ENDPOINTS`. The Revisions are either `ALPHACOMPUTE_KMS_REVISIONS`
(comma-separated `sha256:<hex>`, not empty), so a new KMS build needs a new Revision of the App, or
the `kms_revisions` of the platform document at `ALPHACOMPUTE_PLATFORM_DOCUMENT_URL` (`https://`),
fetched before every attestation and verified under the release key set compiled in (the `dev`
set when `alpha-channel/dev` is on). A document below `ALPHACOMPUTE_PLATFORM_MIN_VERSION` (from 1),
or not above one this process accepted, is not taken; a failed fetch keeps the accepted one, and with
none the attestation fails. The document's `kms_ca_pem` is never read, so no document moves the
App to another CA. Setting both forms, or neither, is refused at start. `ALPHACOMPUTE_SECRETS`,
also measured, is a JSON object of service name to the Secret names it declared, for example
`{"db":["db_password"],"web":["db_password","session_key"]}`, and is absent when nothing is
declared. Every service and Secret name becomes a path segment, so each must be a lowercase key
purpose (`[a-z0-9][a-z0-9._-]{0,63}`); a repeated key or any other shape is refused at start.
`ALPHACOMPUTE_TLS_UPSTREAM`, measured too, is `<service>:<port>`, the published service of a
wrapped compose and its plain container port; the service must be a lowercase key purpose and
the port 1 to 65535, or the runtime exits 1 at start naming the variable. Without it the runtime
opens no TCP port at all. Two more need it and are refused without it:
`ALPHACOMPUTE_TLS_CALLER_APPS`, comma-separated App ids whose Instances alone may open the
Endpoint (unset or empty admits any client), and `ALPHACOMPUTE_TLS_UPSTREAM_READY`, the
upstream's own readiness path such as vLLM's `/health` (a leading `/`, printable ASCII without
spaces, at most 256 bytes).

The socket is `/run/alpha/runtime.sock`, HTTP/1.1 JSON, no authentication (access is the right
to the socket), and comes up only after the first attestation succeeded:

| Route | Reply |
|---|---|
| `GET /v1/identity` | `{app_id, org_id, compose_hash, certificate_chain, tls_private_key, attestation_result, app_compose, init_data}` — the ids and the hash are read from the leaf's SANs, on dstack and on Kata alike; `tls_private_key` is the PKCS#8 DER, base64url; `app_compose` is the Instance's `app-compose.json`, read once at start from the guest agent's `Info` and refused unless its SHA-256 is the leaf's Revision digest, so a service can show a client which compose it runs; `null` on Kata; `init_data` is the Kata pod's init-data TOML under the same rule, `null` on dstack and when the pod does not mount it |
| `GET /v1/secrets/{name}` | the KMS reply for the Secret of that KMS name (a declared Secret's is `<app_id>.<name>`), fetched over mTLS with the leaf and cached until the leaf expires; a KMS error passes through in its envelope with its status |
| `GET /v1/keys/{purpose}` | the KMS reply to `POST /v1/keys/derive` for that purpose, `{key}`, 32 bytes base64url: the App's own key, the same for every Revision of the App; fetched and cached like a secret, up to 64 purposes per leaf, beyond which a key is derived again on every read |
| `GET /healthz` | `{attested, cert_not_after}` |

With no valid leaf (the last renewal failed and the hour is over) the first three answer
`503 not_attested`. A cached secret or key is served until the leaf expires even after its Revision is
revoked; the next call that reaches the KMS is the one that ends the process.

## Secret files

A stock image reads its Secrets as Docker-style files, with no code change. After the first
attestation the runtime writes each declared Secret to `/run/alpha-secrets/<service>/<name>`, the
read-write mount of that service's own tmpfs volume, which the service sees read-only as
`/run/secrets/<name>`; a service that declared nothing has no volume and gets nothing. A declared
`<name>` is read from the KMS as `<app_id>.<name>`, with the App id the runtime attested as
(lowercase, hyphenated): Secrets are unique per organization and name, so two Apps of one
organization declaring the same name would otherwise replace each other's value and grant. The
socket route `GET /v1/secrets/{name}` is unchanged and passes its name to the KMS as it is. Each
name is fetched once per pass through the same per-leaf cache as that route and replaced
atomically: a mode 0444 temp file in the same directory, renamed over the name; a file already
holding the value is left alone. The runtime never creates a directory, so a missing volume shows
up as a logged failure rather than as files in the container layer.

A Secret not stored yet is retried after 2 s, doubling up to 60 s; once every file is written a
pass runs every 60 s, which hits the cache, so a changed value is written after the next renewal
(within the hour). A revoked Revision gets no new file, at birth or later; the files already
written stay until the volume's last container stops.

`alpha-runtime healthcheck` exits 0 only once every declared file exists under
`/run/alpha-secrets`, and 1 otherwise or when `ALPHACOMPUTE_SECRETS` does not parse. It reads that
one variable and nothing else, before configuration, the key, the guest agent or the socket,
because Docker runs it as a second process in the live container. A declaring service's
`depends_on: alpha-runtime: {condition: service_healthy}` waits on it. The socket's four routes
are unchanged.

## TLS for a wrapped compose

A compose wrapped by `alpha compose wrap` publishes the CVM's 443 on `alpha-runtime` as its port
8443, and the published service keeps only its plain port on the compose network. With
`ALPHACOMPUTE_TLS_UPSTREAM` set, the runtime listens on 8443 once the first attestation
succeeded (a bind failure exits 1) and terminates TLS there: TLS 1.3 with `X25519MLKEM768` only,
no client certificate, and the chain of the current attestation, [leaf, KMS CA]. Each accepted
connection then opens a TCP connection to the upstream and copies bytes both ways until either
side closes, so HTTP/1.1, keep-alive, WebSocket upgrades, HTTP/2 by prior knowledge and any other
byte stream pass unchanged. No ALPN protocol is advertised: a browser speaks HTTP/1.1, and a
client that insists on `h2` by ALPN, such as gRPC, is not served.

There is no session resumption (no tickets, no session cache): a resumed session presents no
certificate, and every connection has to prove the current leaf. A renewal swaps the leaf for
new handshakes only; a connection already open keeps going, since nothing after the handshake
depends on the certificate. With no valid leaf (renewal failed past the hour) a handshake fails
instead of serving an expired certificate.

The handshake and the upstream connect are bounded at 10 s each; an upstream that does not
answer closes the client's connection after the handshake and logs one line naming it. There
is no idle timeout, so WebSockets and long polls stay open. No client address is forwarded (no
PROXY protocol, no header): a stock image cannot read PROXY protocol, the proxy does not parse
HTTP, and behind the provider's TLS passthrough the CVM sees the gateway's address anyway. On
SIGTERM the listener closes at once and open connections get at most 10 s to finish; on
`revision_revoked` every proxied connection is closed at once and the process exits 78.

With `ALPHACOMPUTE_TLS_CALLER_APPS` the handshake requires a client certificate chained to the
KMS CA of the first attestation, and a connection is proxied only when its leaf carries an
Instance's SANs naming a listed App; anything else is closed before a byte reaches the upstream.
A KMS node's leaf chains to the same CA but carries no Instance SANs, so it is refused too. The
caller is pinned by App rather than Revision, so a caller that pins this Endpoint's Revision can
still be registered.

With an upstream, the runtime also listens on 8444 in plain HTTP, for the host: a Kata agent
policy refuses exec, and the host has no Instance leaf for a caller-pinned Endpoint. `GET /leaf`
answers with the PEM chain that the Endpoint presents now, leaf first, or 503 while no leaf is
current. The chain is public, because every handshake shows it. The host reads it through the
Kubernetes API server proxy, and checks it against the KMS CA itself.

The same listener also serves `GET /ready`, for a kubelet probe. It answers 200 with an empty
body only while the leaf is current and, when `ALPHACOMPUTE_TLS_UPSTREAM_READY` is set, the
upstream answers `GET <path>` with a 2xx status within 2 s, else 503; nothing of the upstream's
reply is relayed.

## Tests

`cargo test -p alpha-runtime` covers the configuration parser (the secrets and upstream variables'
accepted and refused shapes included), the renewal schedule, the exit-code decision, the atomic 0444 replace of
a secret file and the healthcheck's file check; `tests/healthcheck.rs` runs the built binary's
`healthcheck` with a cleared environment and checks it exits 0 without reaching configuration and
1 for a missing file or an unparsable variable. The end-to-end tests are `services/alpha-kms/tests/runtime.rs` (they need
`DATABASE_URL`): a runtime holding the key of the `phala-0.5.9-1c-2g-keyed` capture, with a
quote source that hands out the captured quote for exactly the `report_data` that CVM quoted
over, attests against the in-process node clocked to the instant the capture's nonce was
minted — so `POST /v1/attest/nonce` returns that nonce and the appraisal is the real one. They
prove the four routes, the refusal of a compose that is not the leaf's Revision, a tenant backend pinning the KMS CA and reading the Revision from the
SAN URI with rustls and webpki alone, the refusal of a listener under another CA or with an
unlisted Revision (and the walk to the next endpoint), the cache expiring with the leaf,
`revision_revoked` ending the runtime with 78, and the secret files: written only into the
directories of declaring services, waiting for a Secret put later, following a renewal, written
by the running runtime, and never written for a revoked Revision. The same file proves the TLS listener: the leaf it serves,
the hybrid group it requires, pass-through, renewal, expiry, revocation, the drain on SIGTERM,
and with a caller pin: the listed App's leaf served, no client certificate refused, and `/ready`.

What only a live CVM proves: the real quote and `Info` from the guest agent's socket, the real
event log from the CCEL table and `/run/log/dstack`, that the registered `compose_hash` equals
the CVM's `compose-hash` event (`docs/kms-spec.md` §7 item 9), and the image running on Phala
Cloud with the three host mounts of `docs/manifest.md`.

## Image

`images/manager/Dockerfile` builds the binary as a static musl executable in a stage with no
network (dependencies are fetched in the stage before) and ships it alone in a `scratch` image;
the base image is pinned by digest and every timestamp comes from `SOURCE_DATE_EPOCH`, so one
commit gives one image digest. `.github/workflows/release.yml` builds it on two fresh runners
with `--no-cache` and pushes it only when the two are the same.
