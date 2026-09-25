# The inner channel

A page in a browser cannot hold a TLS session to an Instance: its requests pass through the
tenant's own backend, which relays them and could read them. The inner channel is how the page
talks to the Instance anyway. The page checks the Instance's KMS certificate, the Revision it
runs and the exact compose that Revision is the hash of, and then exchanges frames that only
that Instance can open. The relay carries ciphertext.

Both ends live in one crate, `crates/alpha-channel`. An Instance links it natively as the
responder. A page loads the same code as wasm, and a tenant's Node server can use the wasm
package as either end. Everything described here is that crate's behaviour; this document is its
wire format.

## Time comes from the caller

Nothing in the crate reads a clock, because in wasm the system clock traps. Every call that
needs the time takes it: `now_ms`, in Unix milliseconds. A page should not trust the device
clock blindly. A good source is the `now` of the last handshake it verified, plus the monotonic
time elapsed since (`performance.now()`), so a skewed clock breaks neither certificate checks
nor signatures.

## What the page checks, in order

**The platform document first.** It is fetched as `{document, signature: {algorithm: "ed25519",
signature}}`. It must verify under the release key compiled into the package, over
`SHA-256("alphacompute/platform/v1" ‖ 0x00 ‖ JCS(document))`, and its `issued_at` must not be
after `now`. Remembering the highest `version` seen, to refuse a rollback, is the caller's job.
Its `kms_ca_pem` is the only root the page accepts. The page takes it from the document, never
from the Instance or from the relay.

**Then the handshake, eight checks.** Keys are derived only after all of them pass:

1. The chain is exactly two certificates, the leaf and then the CA.
2. The CA is byte for byte the platform document's `kms_ca_pem`.
3. The leaf is signed by that CA with ecdsa-with-SHA256, and `notBefore ≤ now < notAfter`.
4. The leaf's first URI SAN, `alphacompute://<org id>/<app id>/<key sha256>`, names the
   organization and the App the page expects.
5. The second URI SAN, `urn:alphacompute:revision:sha256:<hex>`, is in the page's Revision
   allowlist. An empty allowlist accepts nothing.
6. The SHA-256 of the `compose` the Instance sent equals that Revision.
7. The handshake signature is `ecdsa-p256` and verifies under the leaf's P-256 key over the
   document below, which the page rebuilds from what it sent and received.
8. `enc` decapsulates under the page's X-Wing key.

Because of check 6, the page can read the services, images and environment of the App out of the
compose it just hashed, rather than trusting its own bundle for them (`composeServices`).

## Handshake

One round trip.

The client sends a `ClientHello`: a fresh X-Wing key (1216 bytes) and a fresh 32-byte nonce, both
base64url without padding.

```json
{ "v": 1, "kem": "x-wing", "pk": "<base64url>", "nonce": "<base64url>" }
```

The responder answers with a `ServerHello`:

```json
{
  "v": 1,
  "channel": "<base64url, 16 random bytes>",
  "enc": "<base64url HPKE encapsulation>",
  "now": "2026-09-25T12:00:00Z",
  "certificate_chain": ["<leaf PEM>", "<KMS CA PEM>"],
  "compose": "<app-compose.json, the exact bytes the Revision hashes>",
  "signature": { "algorithm": "ecdsa-p256", "signature": "<base64url r‖s>" }
}
```

To produce it, the responder encapsulates to `pk` with HPKE (RFC 9180) in base mode, with the
X-Wing KEM, HKDF-SHA256 and AES-256-GCM, and uses `info = "alphacompute/inner-channel/v1" ‖ 0x00
‖ nonce`, where `nonce` is the client's 32 raw bytes. It signs this document with the leaf's key:

```json
{
  "v": 1,
  "channel": "<as in the ServerHello>",
  "nonce": "<the client's nonce, as sent>",
  "client_pk_sha256": "sha256:<hex of the client's raw X-Wing key>",
  "enc_sha256": "sha256:<hex of the raw encapsulation>",
  "compose_hash": "sha256:<hex>",
  "now": "<as in the ServerHello>"
}
```

The signature is ECDSA P-256 with SHA-256, as 64 bytes `r‖s`, over
`SHA-256("alphacompute/inner-channel/v1" ‖ 0x00 ‖ JCS(document))`. JCS is RFC 8785.

Both ends then export two 32-byte keys from the HPKE context:
`c2s = Export("alphacompute/inner-channel/v1 c2s", 32)` and
`s2c = Export("alphacompute/inner-channel/v1 s2c", 32)`.

## Frames

**Requests** are sealed under `c2s`:

```json
{ "channel": "<id>", "seq": 0, "ct": "<base64url>" }
```

`ct` is AES-256-GCM of the body. The nonce is `seq` (8 bytes, big-endian) followed by 4 zero
bytes. The associated data is `JCS({"channel", "seq", "method", "path"})`, where the responder
fills in the method and path the frame arrived on. A body moved to another route therefore does
not open. `seq` starts at 0 and counts up. The responder opens each `seq` once, in any order, and
spends it only when the frame opens. After 65 536 requests the client opens a new channel.

**A response** to request `seq` is a run of lines, each the base64url of one AES-256-GCM box under
`s2c`. The nonce is `seq` (8 bytes, big-endian) followed by the frame's index (4 bytes,
big-endian, from 0). The associated data is `JCS({"channel", "seq", "frame": index})`. The
plaintext is one flag byte, `0x00` for more or `0x01` for end, followed by the body. Blank lines
carry nothing. The client refuses any line after the end frame, a frame out of order, and a
stream that closes before its end frame.

## Member documents

A member's key is a WebCrypto ECDSA P-256 key generated with `extractable: false`. The page
holds it and wasm never sees its private half. The page gets each document's bytes and digest
from wasm (`signable`), never from its own JSON code, so both ends canonicalise with one
implementation. It signs the digest itself:

```js
const { document, digest } = signable(context, JSON.stringify(fields), nowMs);
const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, memberKey, digest);
```

The digest is `SHA-256(context ‖ 0x00 ‖ JCS(document))`. `signable` fills in `v: 1`, a fresh
32-byte `nonce` (base64url) and `issued_at` (RFC 3339 UTC), and refuses fields that set them.

WebCrypto produces high-S signatures about half the time. Verifiers accept them as they are, so
a signature is malleable, and replay protection keys on the document's `nonce`, never on the
signature bytes.

A signed request travels inside the channel as:

```json
{
  "document": { },
  "member_key": "<base64url SPKI DER>",
  "signature": { "algorithm": "ecdsa-p256", "signature": "<base64url r‖s>" }
}
```

Requests and writes are fresh when `now − 60 s ≤ issued_at ≤ now + 60 s` by the verifier's
clock. Each nonce is accepted once.

| Context | Document |
|---|---|
| `alphacompute/connector-request/v1` | `{"v":1,"op":"connect","provider","nonce","issued_at"}`, `{"v":1,"op":"finish","state","code","nonce","issued_at"}`, `{"v":1,"op":"list","nonce","issued_at"}`, `{"v":1,"op":"disconnect","connection_id","nonce","issued_at"}` |
| `alphacompute/connector-write/v1` | `{"v":1,"connection_id","method","url","body_sha256":"sha256:<hex>","nonce","issued_at"}`, sent beside the body (`bodySha256` computes the field) |
| `alphacompute/connector-grant/v1` | `{"v":1,"aud":"sha256:<hex>","connections":["<uuid>", …],"exp","nonce","issued_at"}` |

Unknown fields are refused in every document.

**A grant** lets one Instance read through the listed connections until `exp`. `aud` is the
SHA-256 of that Instance's leaf SPKI, which the page learned in its handshake. On the wire a grant
is `base64url(JCS(document)) "." base64url(r‖s)`. A verifier hashes the JCS bytes exactly as
received, checks the signature, and only then parses them. Comparing `aud` with the presenting
Instance and `exp` with the time is the verifier's part.

## Error codes

Every export returns an error rather than trapping, and the error's message starts with its code.

| Code | Meaning |
|---|---|
| `platform_signature` | the platform document does not verify, or was issued after `now` |
| `foreign_certificate` | the chain is not a leaf and the platform's KMS CA, the leaf is not that CA's, or it names another organization or App |
| `certificate_expired` | `now` is outside the leaf's validity |
| `unknown_revision` | the leaf's Revision is not in the allowlist |
| `compose_mismatch` | the compose does not hash to the leaf's Revision |
| `handshake_signature` | the handshake signature or the encapsulation does not check out |
| `malformed` | anything that does not parse, including a time that is not one |
| `rng` | the system's randomness failed |
| `seal` | sealing failed |
| `open` | a frame does not open on this channel, sequence number and route, or arrives out of order |
| `replayed` | a request's sequence number was already used |
| `exhausted` | the channel has carried its last request |
| `truncated` | a response ended without its end frame |
| `signature_invalid` | a member signature does not verify under that key, context and document, or names another algorithm |
| `request_stale` | a member document's `issued_at` is more than a minute from `now` |

## The JavaScript surface

`verifyPlatform(signedJson, nowMs)` returns `{version, issued_at, kms_ca_pem}` as JSON.

`new Initiator()` offers `hello()`, then
`finish(serverHelloJson, kmsCaPem, expectedJson, nowMs)`, which returns a `Channel`.
`expectedJson` is `{org_id, app_id, revisions}`. After `finish`, `verified()` returns what was
verified as JSON, with `aud` and `kms_ca_sha256` in hex and the times in RFC 3339.

A `Channel` offers `sealRequest(method, path, body)`, `lastSeq()` and `response(seq)`. The
`ResponseReader` that `response` returns offers `openLine(line)` and `finish()`.

A tenant's server uses `new Responder(chainPem, pkcs8, compose)`. Its `respond(clientHelloJson,
nowMs)` returns the ServerHello, and `channel()` returns a `ServerChannel`, which offers
`openRequest(frameJson, method, path)` and `sealResponse(seq, index, end, body)`.

The rest are functions: `composeServices(compose)`,
`signable(context, fieldsJson, nowMs)`, `bodySha256(bytes)`,
`verifyMemberRequest(context, documentJson, memberKeyB64, signatureJson, nowMs)`, which returns
the member key's SHA-256 in hex, and `verifyGrant(wire, spkiB64)`, which returns the grant as
JSON.

All of these are synchronous, so a page can seal a request inside `pagehide`.

## Building the package

```
crates/alpha-channel/build-web.sh <out-dir>
```

The script writes `alpha_channel.js`, its typings and `alpha_channel_bg.wasm` for
`wasm-bindgen --target web`. It then prints `sha256 <hex> alpha_channel_bg.wasm` and the commit
it was built from. It needs the toolchain in `rust-toolchain.toml`, the `wasm-bindgen` CLI at the
exact version the crate pins (the script refuses any other), and `wasm-opt` from binaryen if one
is on `PATH`. Paths are remapped, so the same commit built with the same tool versions gives the
same hash. A page calls `init()` from the glue; Node calls
`initSync({ module: readFileSync(".../alpha_channel_bg.wasm") })`.

## What this does not protect against

The page is served by the tenant's backend, the very party it verifies. A backend could serve a
page that skips these checks. It cannot do that without publishing code that does: the `.wasm`
and the script around it are delivered to every visitor, and anyone can compare the served
`.wasm` with a rebuild from a public commit. Nothing checks that on the visitor's behalf today.

The channel authenticates the Instance, not the client. Anyone can open a channel. What a
request is allowed to do rests on what travels inside it: a session secret, or a member's
signature.

wasm memory is readable by the page's own scripts. The channel keys live there. The member's
private key does not, because it stays in WebCrypto.
