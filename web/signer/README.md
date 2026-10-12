# signer page

The page an organization opens to claim itself with passkeys and to approve or decline a launch.
It runs `alpha-channel` as wasm, verifies the release-signed platform document with the key
compiled into that wasm, and signs only what it has verified itself. It is static: plain
JavaScript in classic scripts, one stylesheet, one font and the wasm, with no host name inside, so the same
bytes can be served from any origin the platform document lists under `signer.origins`.

## Secrets

A launch whose compose declares Secrets gets one password field per Secret. Each value is read
once, sealed with `KmsSecretSealer` to a KMS node that proves itself against the platform
document, and put in its own step, signed by the same passkey that made the first signature; the
relay sees the value only as the sealed frame. The signed document it also sees commits to 32
random bytes the page draws for the put and the value, and those bytes travel only inside the
frame, so the document is no test for a guess. At the KMS the Secret is named `<app_id>.<name>`, so two Apps
of one organization that declare the same name keep separate values. Every put comes before the
Revision's registration, because shroud-go refuses puts once a request is approved, and the page
says "Approved" only after the receipt of every put and of the registration verified.

## Revision v2

A launch whose `compose` is a Revision v2 (`format: alphacompute-coco-revision/1`, a Kata
confidential pod) is refused unless `check_registration` would accept it for the request's App, and
is registered like a compose: the passkey signs `{app_id, compose}` with the Revision's exact bytes
as `compose`. The page shows its runtime class and GPUs from the Revision itself. The Revision
holds only digests of the pod's init-data and agent policy, so images and the policy are shown only
when the request also carries `initdata` (standard base64 of the init-data bytes, as `alpha coco
wrap` prints it) and the wasm rebuilds exactly the requested Revision from those bytes; init-data
that does not is refused as a mismatch. The policy summary is read from the Rego
(`alpha_core::agent_policy`): exec or log reads read "denied" only when their rule is
`default … := false` or absent, and the policy can be neither replaced (`SetPolicyRequest`) nor
bypassed (`AllowRequestsFailingPolicy`). The images are those genpolicy's `policy_data` names.
Without `initdata` the page says it cannot show them and offers the approval from the digests.
Secrets are not put from this page for a Revision v2.

## Building

```
web/signer/build.sh web/signer/dist
```

That page carries the production release key and does not build until the key ceremony has
replaced `crates/alpha-channel/release-keys/prod.pub`; `FEATURES=dev web/signer/build.sh …` builds
the dev stand's page with `release-keys/dev.pub`.

It needs the toolchain in `rust-toolchain.toml`, `openssl`, and the `wasm-bindgen` CLI at the
version `crates/alpha-channel` pins (`cargo install wasm-bindgen-cli --version 0.2.128 --locked`).
The output directory must be empty or absent, and receives nine files:

- `index.html`, which loads the stylesheet and both scripts with `integrity="sha256-…"`;
- `alpha_channel-<hex>.js`, the wasm-bindgen glue built for `--target no-modules`;
- `alpha_channel_bg-<hex>.wasm`, which the page script fetches with its integrity;
- `page-<hex>.js` and `style-<hex>.css`;
- `public_sans-<hex>.woff2`, which the page script fetches with its integrity and adds as a
  `FontFace`, because an `@font-face` source cannot carry one;
- `headers`, the response headers the host must send;
- `headers-embed`, the response headers of `/sign/embed` (below), with `@EMBED_ANCESTORS@` for
  the host to fill;
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

The page lives at `<origin>/sign/claim#<ticket>` and `<origin>/sign/approve#<ticket>`. Both paths
serve the same `index.html`, which picks its mode from the last path segment; the ticket stays in
the fragment, so it never reaches a server. The assets are served next to it under `/sign/`, with
the types `text/javascript`, `application/wasm`, `text/css` and `font/woff2`, and may be cached forever because
their names change with their content. `/sign/platform.json` is the release-signed platform
document, and `/sign/catalog/<64 hex>.json` serves each catalog entry under the SHA-256 of its
bytes. Every response under `/sign/` but `/sign/embed` (below) carries each line of `headers` verbatim; the policy there
forbids framing, inline code, string evaluation and any other origin. `connect-src 'self'` holds
only while the document's `api_origin` is the page's own origin; a host whose API lives on another
origin adds it to `connect-src`, or every call fails as unavailable.

On dev, shroud-go serves the page and embeds a copy of this build. It serves `/sign/embed` as
below once that copy ships `headers-embed` (AlphaCompute/shroud-go#467).

## The embed view (PRD-03 S5, draft)

Tenants approve without leaving their Rafay portal, while the approval stays on our origin, where
Rafay, which is not trusted, cannot change what is approved. `<origin>/sign/embed#<ticket>` is the
one view of this page another origin may frame:

- **Only the portals the platform document names.** `signer.embed_ancestors` in the
  release-signed document lists at most eight exact https origins (no wildcard, path or scheme
  source; never a signer origin). Empty, the default, means no page may frame the view. The host
  serves `/sign/embed` with `headers-embed`, replacing `@EMBED_ANCESTORS@` with that list,
  space-separated, or with `'none'` when it is empty. The host reads the list only from a
  document that verifies under the release key, and serves `'none'` rather than a partial list if
  the document does not verify or any entry is not one alpha-core accepts. In Chromium and Safari
  the page also checks `location.ancestorOrigins` against the list and refuses if any page around
  it is not listed; Firefox has no such list, so there the host's `frame-ancestors` is the only
  check.
- **It never signs.** It shows which launch waits (organization, title, App, compose_hash, when
  the link closes) and one button, "Review and approve", which opens `/sign/approve#<ticket>` in
  a new top-level window with `noopener`. The passkey prompt, the full launch view and every
  signature stay on the approval page, under `frame-ancestors 'none'` and its own
  Cross-Origin-Opener-Policy. `headers-embed` denies the frame passkeys altogether
  (`Permissions-Policy: publickey-credentials-get=(), publickey-credentials-create=()`). A framing
  page can at most trick a click into opening that window, where the user still reads the launch
  and confirms with a passkey. The view cannot decline either; a decline is a state change.
- **It only reads.** After approving in the other window, "Check again" shows the request
  decided.

Still open (draft):

- QUESTION(PRD-03 Q75), Rafay: the portal origins, and whether the portal can frame a page of
  another origin at all (an iframe extension point, its `sandbox` flags: the view needs
  `allow-scripts allow-same-origin allow-popups allow-popups-to-escape-sandbox`).
- QUESTION(PRD-03 Q76), Ryan Tharp: security sign-off on framing an approval view.
- QUESTION(PRD-03 Q77), Christopher Freytes and the exec sponsor: whether a window of our own
  meets "tenants never leave their portal", or the passkey prompt must run in the frame
  (`publickey-credentials-get` delegated to the portal; proposed: no).
- QUESTION(PRD-03 Q78), Ryan Tharp: whether Firefox, without `ancestorOrigins`, may rely on
  `frame-ancestors` alone (proposed: yes; it is the browser's own enforcement).
- TODO(draft): the rafay-plugins adapter shows only `approval_url`; how the portal learns the
  embed URL (the same ticket under `/sign/embed`) waits on Q75.
- TODO(draft): if the portal sends `Cross-Origin-Embedder-Policy: require-corp`, the view needs
  `Cross-Origin-Resource-Policy: cross-origin` on `/sign/embed` only.

## Tests

```
SIGNER_DIST=web/signer/dist node --test web/signer/test/*.test.js
web/signer/test/smoke.sh web/signer/dist
```

The Node tests need Node 22 or later and nothing else. `test/harness.js` loads the built glue,
wasm and page script into one `vm` context with a fake DOM, a virtual clock, a fake shroud-go,
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
