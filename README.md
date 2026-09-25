# confidential-platform

Rust workspace for the AlphaCompute trust plane: attestation verifier, key broker, in-CVM runtime and the `alpha` CLI.

- `crates/alpha-channel`: the attested inner channel and the member-signed documents, one implementation for an Instance (native) and a page (wasm, built with `crates/alpha-channel/build-web.sh`).
- `docs/connecting-to-an-app.md`: reaching an App over TLS pinned to the KMS CA and its Revision.
- `docs/inner-channel.md`: the inner channel's wire format, for a page that verifies an App through a relay.
