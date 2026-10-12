# SEV-SNP vector: a Milan report from virtee/sev

The only real SEV-SNP evidence here. We have no SNP hardware, so no report in this directory comes from our own pods or hosts; `kata-snp/1`'s appraisal of a Kata pod's report (HOST_DATA = init-data digest, a launch measurement we captured, our `report_data`) is tested over synthetic verified reports, and a capture from our own SNP pod is `ponytail: snp-capture`.

| File | What | From |
|---|---|---|
| `report.hex` | A version 2 attestation report from an AMD EPYC Milan host, hex | `tests/certs_data/report_milan.hex` of the `sev` crate 8.0.0 (virtee/sev, git `76535be354648a3e4adf00631fdf4941ab51fb88`), Apache-2.0 |
| `vcek.der` | The VCEK that signed it (`Milan-B0`, TCB bl 3, tee 0, snp 8, ucode 115), DER | `tests/certs_data/vcek_milan.der`, same crate and commit |
| `cert_chain.pem` | AMD's Milan ASK then ARK, PEM | `https://kdsintf.amd.com/vcek/v1/Milan/cert_chain`, fetched 2026-10-12; byte-identical to the crate's `tests/certs_data/cert_chain_milan` and to its built-in `src/certs/snp/builtin/milan/{ask,ark}.pem` |
| `crl.der` | AMD's Milan VCEK CRL (CRL number 12, thisUpdate 2026-09-22T07:35:42Z, nextUpdate 2026-11-09T01:00:00Z, nothing revoked), DER | `https://kdsintf.amd.com/vcek/v1/Milan/crl`, fetched 2026-10-12T06:20Z |

SHA-256: `report.hex` 3d956e91…ae7d and `vcek.der` 3bbfb6ee…95e1, both equal to the crate's files.

The report's own content (from its fields): guest policy `0x30000` (SMT allowed, no migration agent, no debug), VMPL 0, platform info SMT enabled, signed by a VCEK, HOST_DATA all zero, `report_data` and the launch measurement of virtee's test guest. So it verifies with `snp_policy.allow_smt: true` and fails `kata-snp/1` after the report checks (no reference value is ours, and HOST_DATA binds no init-data). Tests pin `now` to 2026-10-12T00:00:00Z, inside the CRL's window; the CRL expires on 2026-11-09, which the tests do not depend on since `now` is fixed.

The ARK and ASK are copied into each test's `snp_policy` from `cert_chain.pem`, as a release document pins them, never read from the evidence.
