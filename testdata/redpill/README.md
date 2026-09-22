# RedPill attestation vectors

Golden inputs for `services/alpha-inference`, read by its `upstream.rs` unit tests. Every
file here is a real response captured live against `api.redpill.ai`; nothing is synthesized
or edited into a passing state. `now` in the tests is `captured_at.txt`, so the DCAP
collateral never expires.

## Files

- `report.json` — the full `GET /v1/attestation/report?model=nvidia%2Fnemotron-3.5-lightning&nonce=<nonce.hex>&signing_algo=ecdsa&version=2` response body for the default model, unmodified. `signing_address` and `attestation.evidence.quote` (== the top-level `intel_quote`) are what `services/alpha-inference` reads from it.
- `nonce.hex` — the 32-byte nonce (64 lowercase hex) sent with that request.
- `quote.hex` — `attestation.evidence.quote` alone, for `alpha_attest::verify_quote` and for fetching collateral.
- `collateral.json` — DCAP collateral for `quote.hex`, fetched once with `cargo run -p alpha-attest --example fetch_collateral -- https://pccs.phala.network quote.hex`.
- `captured_at.txt` — the response's `Date` header (RFC 2822), the clock the tests pin `now` to.
- `api.redpill.ai.pem` — the TLS leaf `api.redpill.ai:443` served at capture time; its SubjectPublicKeyInfo is the SPKI `report.json`'s `report_data` binds to.
- `tee.redpill.ai.pem` — the TLS leaf `tee.redpill.ai:443` served at capture time, from the same attested workload keyset. Used only as a *wrong* SPKI in the binding-mismatch test — `report.json`'s report was requested against `api.redpill.ai`, not this host.

## What the golden test proves

`report_data == SHA-256(signing_address_bytes ‖ SHA-256(SPKI(api.redpill.ai.pem))) ‖ nonce`,
independently recomputed from these files and compared byte-for-byte against
`attestation.report_data` in `report.json` — the same check the live spike ran, now pinned
as a regression fixture. The quote inside also verifies with `dcap-qvl` against
`collateral.json`: TCB status `UpToDate`, no advisories.

No RedPill key, caller bearer, or conversation text is in any file here — every request this
data came from was a keyless `GET`.
