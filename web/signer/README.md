# signer page

The page an organization opens to claim itself with passkeys, to approve or decline a launch, and
to revoke the launches of an App it deleted.
It runs `alpha-channel` as wasm, verifies the release-signed platform document with the key
compiled into that wasm, and signs only what it has verified itself. It is static: plain
JavaScript in classic scripts, one stylesheet, one font and the wasm, with no host name inside, so the same
bytes can be served from any origin the platform document lists under `signer.origins`. The
passkeys belong to the document's `signer.rp_id`, which is `sign.alphacompute.cc` in production.

## Tickets

Every link carries one `alpha-control` ticket in its fragment, and a person who has a code instead
types it on the bare page, which reads `GET /v1/tickets/by-code/{code}` (`{kind, ticket}`). The
page reads `GET /v1/tickets/{ticket}`, which always answers `kind` (`claim`, `approve` or
`revoke`), `state` (`open`, `done`, `declined` or `expired`), `expires_at`, `server_time`,
`org_id`, `org_name` and `credentials` (`[{credential_id, key_id}]`, the organization's
passkeys). It sends each signed body to `POST /v1/tickets/{ticket}/kms/{op}`, which relays it to
the KMS and returns the KMS's answer and receipt; the page accepts a step only when that receipt
verifies. Errors are `{"error": {"code"}}`; `ticket_not_found`, `ticket_expired`, `ticket_closed`
and `session_refused` are the service's, and any other code is the KMS's.

## Approval

An `approve` ticket adds `app_id`, `title`, `compose_hash`, either `revision` (the Revision's
bytes) or `catalog_template_sha256`, `secrets` and `predecessor` (`{compose_hash, revision}` of
the App's registered Revision it replaces, or `null`). It carries only bodies signed by a key
already in the roster, so the page refuses a ticket of an organization without a passkey. The page
parses the bytes that hash to `compose_hash` and shows every container from that parse: its full
image reference with the digest, and every environment variable with its value. It signs the
same bytes. Text the service wrote, the title and the Secret descriptions, is labelled "From the
requester". When there is a predecessor, whose bytes must hash to its `compose_hash`, the page
first lists what changed and marks each addition: an image, an environment value, a Secret a
container receives, a network opening. The approval then also revokes the predecessor, as its
last step, unless the person ticks "Keep the previous Revision runnable"; the box is unticked by
default, and that default is the page's, not the ticket's.

## Secrets

A launch whose Revision declares Secrets gets one password field per Secret. The service may add a
description of each Secret to the ticket; the page shows it as plain text, and it never changes which
Secrets are asked for. "Generate a random value" fills a field with 32 random bytes as hex. Each value is read
once, sealed with `KmsSecretSealer` to a KMS node that proves itself against the platform
document (`kms/channel`), and put in its own step (`kms/secret`), signed by the same passkey that
made the first signature; the relay sees the value only as the sealed frame. The signed document it
also sees commits to 32 random bytes the page draws for the put and the value, and those bytes travel
only inside the frame, so the document is no test for a guess. At the KMS the Secret is named
`<app_id>.<name>`, so two Apps of one organization that declare the same name keep separate
values. Every put comes before the Revision's registration (`kms/revision`), and the page says
"Approved" only after the receipt of every put, of the registration and of the predecessor's
revocation verified.

## Claim

A ticket alone never adds a key. A `claim` ticket adds `rooted`; for a rooted organization
`principal_id`, the principal of the key to add; and for an organization without a root
`owner_email`, but no principal.
To root the organization the owner first signs in: the page sends the person to the identity
provider that the platform document names in `signer.oidc` (`{authorization_endpoint,
client_id}`), never one a ticket names, with an authorization code request and PKCE; without
`signer.oidc` it offers no root, keeps the verifier in the tab's
`sessionStorage` under the request's `state`, and on the return to the same path posts
`{code, code_verifier, redirect_uri}` to `POST /v1/tickets/{ticket}/session`. `alpha-control`
redeems the code, checks that the ID token is the owner's, and answers `{session, principal_id}`:
`session` is 32 random bytes as base64url, which the tab keeps and sends as the
`Alpha-Claim-Session` header of the `kms/root` relay, and `alpha-control` refuses a root relay
without it. So another holder of the ticket cannot root the organization once the owner has signed
in elsewhere. Only then does the page create a passkey, state "You, `<owner email>`,
are making this passkey the root key of `<organization>`", sign the `org-root-key` document with
it and relay it (`kms/root`). A key added to a rooted organization is signed by one of its
passkeys and relayed as `kms/key`; the page offers a second passkey after a root, and checks each
new passkey with a local assertion.

## Revocation

A `revoke` ticket adds `app_id`, `title` and `revisions`, the compose hashes to revoke. Each
Revision is revoked in its own step, `{compose_hash, issued_at}` signed under the Control context
by the passkey that made the first signature, and relayed as `kms/revoke`. The page says "Revoked"
only after the receipt of every revocation verified. Which Revisions to revoke is the service's
word: a revocation only takes away, and without a listing the KMS signs the page cannot tell that
the list is complete.

## Building

```
web/signer/build.sh web/signer/dist
```

That page carries the production release key and does not build until the key ceremony has
replaced `crates/alpha-channel/release-keys/prod.pub`; `FEATURES=dev web/signer/build.sh …` builds
the dev stand's page with `release-keys/dev.pub`.

It needs the toolchain in `rust-toolchain.toml`, `openssl`, and the `wasm-bindgen` CLI at the
version `crates/alpha-channel` pins (`cargo install wasm-bindgen-cli --version 0.2.128 --locked`).
The output directory must be empty or absent, and receives eight files:

- `index.html`, which loads the stylesheet and both scripts with `integrity="sha256-…"`;
- `alpha_channel-<hex>.js`, the wasm-bindgen glue built for `--target no-modules`;
- `alpha_channel_bg-<hex>.wasm`, which the page script fetches with its integrity;
- `page-<hex>.js` and `style-<hex>.css`;
- `public_sans-<hex>.woff2`, which the page script fetches with its integrity and adds as a
  `FontFace`, because an `@font-face` source cannot carry one;
- `headers`, the response headers the host must send;
- `OFL.txt`, the license of the font, which the host need not serve.

The font is Public Sans Regular (from `fonts/`), under the SIL Open Font License 1.1 in
`fonts/OFL.txt`. Headings use the system's serif faces; no font of unknown license is bundled.

Every `<hex>` is the first 16 hex digits of the file's SHA-256. The script prints
`bundle_sha256 sha256:<hex>`, the SHA-256 of `index.html`, and the commit it was built from.
`index.html` pins both scripts and the stylesheet, and the page script pins the wasm and the font,
so that one hash covers every byte the page runs or draws with.

## Comparing `bundle_sha256`

The platform document names the page it trusts as `signer.bundle_sha256`. To check a served page,
check out the commit it was built from, run the build, and compare the printed `bundle_sha256`
with the document's value and with the SHA-256 of the `index.html` the host serves. The build is
reproducible: paths are remapped and nothing time-dependent is written. It is reproducible per
host, not across hosts: a macOS build gives a different wasm, so rebuild on x86_64 Linux with the
toolchain in `rust-toolchain.toml`, as CI does, to compare with a published `bundle_sha256`.

## Serving

The page lives at `<origin>/claim#<ticket>`, `<origin>/approve#<ticket>`,
`<origin>/revoke#<ticket>` and, for a typed code, `<origin>/`; a host may put all four under one
path prefix, such as `/sign/`. All of them serve the same `index.html`, which picks its mode
from the last path segment; the ticket stays in
the fragment, so it never reaches a server. The identity provider sends an owner back to
`<origin><prefix>/claim` (`<origin>/claim` without a prefix, `<origin>/sign/claim` under `/sign/`),
so that URL is the OIDC client's redirect URI. The assets are served next to the page, with
the types `text/javascript`, `application/wasm`, `text/css` and `font/woff2`, and may be cached forever because
their names change with their content. `platform.json` beside the page is the release-signed platform
document, and `catalog/<64 hex>.json` serves each catalog entry under the SHA-256 of its
bytes. Every response carries each line of `headers` verbatim; the policy there
forbids framing, inline code, string evaluation and any other origin. `connect-src 'self'` holds
only while the document's `api_origin` is the page's own origin; a host whose API lives on another
origin adds it to `connect-src`, or every call fails as unavailable.

## Tests

```
SIGNER_DIST=web/signer/dist node --test web/signer/test/*.test.js
web/signer/test/smoke.sh web/signer/dist
```

The Node tests need Node 22 or later and nothing else. `test/harness.js` loads the built glue,
wasm and page script into one `vm` context with a fake DOM, a virtual clock, a fake alpha-control,
a software passkey, and KMS receipts signed with the test node key in `testdata/channel`, so every
document, digest, request body and receipt check runs through the real wasm. The flows start from
an injected platform view, because the release key compiled into the wasm cannot sign a test
document; the bootstrap tests use the real release-signed `testdata/channel/platform-document.json`.

CI's `signer` job builds the bundle twice, the second time from an empty target directory, fails
unless the two outputs are byte-identical, runs both test commands, writes `bundle_sha256` to the
job summary and uploads the bundle as the artifact `signer-bundle`.

The smoke test serves the bundle with `test/serve.py`, the same routes and headers a host must
give, checks the headers and content types, and loads `/sign/approve` in headless Chrome
(`$CHROME`, or `google-chrome`, `chromium` or the macOS application) through `test/render.py`. The
test platform document verifies but names no signer, so the page must end on "This page is not
served from an AlphaCompute signer address."; with one byte of the page script changed, its
integrity check must stop it before that. The page that ran must also have loaded its font and met no Content Security Policy violation. It prints `SMOKE_OK` when all of this holds.
