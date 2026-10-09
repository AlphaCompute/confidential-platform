# signer page

The page an organization opens to claim itself with passkeys and to approve or decline a launch.
It runs `alpha-channel` as wasm, verifies the release-signed platform document with the key
compiled into that wasm, and signs only what it has verified itself. It is static: plain
JavaScript in classic scripts, one stylesheet and the wasm, with no host name inside, so the same
bytes can be served from any origin the platform document lists under `signer.origins`.

## Building

```
web/signer/build.sh web/signer/dist
```

It needs the toolchain in `rust-toolchain.toml`, `openssl`, and the `wasm-bindgen` CLI at the
version `crates/alpha-channel` pins (`cargo install wasm-bindgen-cli --version 0.2.128 --locked`).
The output directory must be empty or absent, and receives six files:

- `index.html`, which loads the stylesheet and both scripts with `integrity="sha256-…"`;
- `alpha_channel-<hex>.js`, the wasm-bindgen glue built for `--target no-modules`;
- `alpha_channel_bg-<hex>.wasm`, which the page script fetches with its integrity;
- `page-<hex>.js` and `style-<hex>.css`;
- `headers`, the response headers the host must send.

Every `<hex>` is the first 16 hex digits of the file's SHA-256. The script prints
`bundle_sha256 sha256:<hex>`, the SHA-256 of `index.html`, and the commit it was built from.
`index.html` pins both scripts and the stylesheet, and the page script pins the wasm, so that one
hash covers every byte the page runs.

## Comparing `bundle_sha256`

The platform document names the page it trusts as `signer.bundle_sha256`. To check a served page,
check out the commit it was built from, run the build, and compare the printed `bundle_sha256`
with the document's value and with the SHA-256 of the `index.html` the host serves. The build is
reproducible: paths are remapped and nothing time-dependent is written.

## Serving

The page lives at `<origin>/sign/claim#<ticket>` and `<origin>/sign/approve#<ticket>`. Both paths
serve the same `index.html`, which picks its mode from the last path segment; the ticket stays in
the fragment, so it never reaches a server. The assets are served next to it under `/sign/`, with
the types `text/javascript`, `application/wasm` and `text/css`, and may be cached forever because
their names change with their content. `/sign/platform.json` is the release-signed platform
document. Every response under `/sign/` carries each line of `headers` verbatim; the policy there
forbids framing, inline code, string evaluation and any other origin.

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
