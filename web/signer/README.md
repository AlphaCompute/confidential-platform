# signer page

The page an organization opens to claim itself with passkeys and to approve or decline a launch.
It runs `alpha-channel` as wasm, verifies the release-signed platform document with the key
compiled into that wasm, and signs only what it has verified itself. It is static: plain
JavaScript in classic scripts, one stylesheet, three fonts and the wasm, with no host name inside, so the same
bytes can be served from any origin the platform document lists under `signer.origins`.

## Secrets

A launch whose compose declares Secrets gets one password field per Secret. Each value is read
once, sealed with `KmsSecretSealer` to a KMS node that proves itself against the platform
document, and put in its own step, signed by the same passkey that made the first signature; the
relay sees the value only as the sealed frame, but it does see the signed document with the
value's unsalted SHA-256, so a short or guessable value can be found by trying candidates. At the KMS the Secret is named `<app_id>.<name>`, so two Apps
of one organization that declare the same name keep separate values. Every put comes before the
Revision's registration, because shroud-go refuses puts once a request is approved, and the page
says "Approved" only after the receipt of every put and of the registration verified.

## Building

```
web/signer/build.sh web/signer/dist
```

It needs the toolchain in `rust-toolchain.toml`, `openssl`, and the `wasm-bindgen` CLI at the
version `crates/alpha-channel` pins (`cargo install wasm-bindgen-cli --version 0.2.128 --locked`).
The output directory must be empty or absent, and receives ten files:

- `index.html`, which loads the stylesheet and both scripts with `integrity="sha256-…"`;
- `alpha_channel-<hex>.js`, the wasm-bindgen glue built for `--target no-modules`;
- `alpha_channel_bg-<hex>.wasm`, which the page script fetches with its integrity;
- `page-<hex>.js` and `style-<hex>.css`;
- `public_sans_{light,regular,bold}-<hex>.woff2`, which the page script fetches with their
  integrity and adds as `FontFace`s, because an `@font-face` source cannot carry one;
- `headers`, the response headers the host must send;
- `OFL.txt`, the license of the fonts, which the host need not serve.

The fonts are Public Sans (from `fonts/`), under the SIL Open Font License 1.1 in
`fonts/OFL.txt`. Headings use the system's serif faces; no font of unknown license is bundled.

Every `<hex>` is the first 16 hex digits of the file's SHA-256. The script prints
`bundle_sha256 sha256:<hex>`, the SHA-256 of `index.html`, and the commit it was built from.
`index.html` pins both scripts and the stylesheet, and the page script pins the wasm and the fonts,
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
bytes. Every response under `/sign/` carries each line of `headers` verbatim; the policy there
forbids framing, inline code, string evaluation and any other origin. `connect-src 'self'` holds
only while the document's `api_origin` is the page's own origin; a host whose API lives on another
origin adds it to `connect-src`, or every call fails as unavailable.

On dev, shroud-go serves the page and embeds a copy of this build.

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
integrity check must stop it before that. It prints `SMOKE_OK` when both hold.
