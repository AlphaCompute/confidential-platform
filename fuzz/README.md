# Fuzz targets

For the local GPU verifier's parsers (`alpha_attest::gpu::local`, `docs/local-gpu-verifier.md`), which read bytes a pod or an operator supplies. They are part of the external parser review the design calls for. Not run in CI: they need a nightly toolchain and cargo-fuzz.

```sh
cargo install cargo-fuzz
cd fuzz
mkdir -p corpus/spdm && xxd -r -p ../testdata/gpu/nvidia/blackwellAttestationReport.txt > corpus/spdm/blackwell
cargo +nightly fuzz run spdm -- -max_total_time=600
```

| Target | Parser | Seeds |
|---|---|---|
| `spdm` | SPDM 1.1 report, then its opaque data | `testdata/gpu/nvidia/*AttestationReport.txt` (hex; decode first) |
| `opaque` | NVIDIA opaque data and every accessor | the opaque data of those reports |
| `cert_chain` | PEM chain or one DER certificate, extensions, DICE `TcbInfo`, chain checks | `testdata/gpu/nvidia/*CertChain.txt`, `testdata/gpu/certs/*.der` |
| `ocsp` | OCSP response, checked against the Blackwell sample chain | `testdata/gpu/ocsp/*.der` |
| `rim_signed_info` | RIM `SignedInfo` profile | `signed_info` of `testdata/gpu/rim/*.json` (base64; decode first) |
| `rim_document` | canonical SWID document | `document` of `testdata/gpu/rim/*.json` |

On stable, `cargo test -p alpha-attest --test gpu_local_vectors` runs every parser over truncations and bit flips of these inputs on every CI run.
