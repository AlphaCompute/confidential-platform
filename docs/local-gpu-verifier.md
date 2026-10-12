# Local GPU verifier (`local`, option 3)

How `alpha-kms` can appraise NVIDIA GPU evidence itself, with no call to NVIDIA's Remote Attestation Service (NRAS), for Kata pods on `kata-qemu-nvidia-gpu-tdx` (`nvidia-gpu/1`, `docs/kata-attestation.md`). It is a third backend behind the existing `GpuVerifier` seam, next to `nras` and `fortanix-ccm`. Every backend reduces what it verified to the same `VerifiedGpu`, and `alpha_attest::gpu::check_gpus` decides, so the backend that ran never changes what a leaf means.

Status (PRD-02): built after Dec 1. This document replaces the earlier design, which is not in the repository, and closes the three high findings of its review in the sections below. The backend refuses every GPU until a release-signed `gpu_policy` pins everything listed under [Policy](#policy-gpu_policylocal), which needs the B300 capture at G0. It is never enabled by default. NVIDIA must still confirm how the GPU CC capability is licensed (L1) before the local verifier is described as free: running it removes the NRAS call, not necessarily the licence.

## Sources

The formats are taken from NVIDIA's open-source verifiers and the public specifications, at these versions:

| Source | Version | Used for |
|---|---|---|
| NVIDIA attestation SDK (`NVIDIA/attestation-sdk`, `nv-attestation-sdk-cpp`) | release 2026.10.02, commit `11b2bfeb42a1158aa08744603ecb239ccb3d2265` | Local verifier logic (`src/gpu/verify.cpp`, `src/gpu/evidence.cpp`), SPDM parsers (`src/spdm/`), opaque data (`src/gpu/spdm/gpu_opaque_data_parser.cpp`), RIM parsing (`src/rim.cpp`), OCSP (`src/nv_ocsp.cpp`, `src/nv_x509.cpp`), DICE `TcbInfo` (`src/dice_tcb_info.cpp`), Blackwell and Hopper sample evidence (`unit-tests/testdata/sample_attestation_data/gpu/`) |
| NVIDIA nvtrust (`NVIDIA/nvtrust`) | commit `858ada9a17f58c482f578414ea2455498fa51e17` (2026-08-31; pins the SDK at `0c1be386…`, 2026.03.02) | `guest_tools/gpu_verifiers/local_gpu_verifier` (the Python local verifier: Hopper samples only), its RIM schemas, the device and RIM root certificates, sample RIMs |
| CoCo guest-components | v0.21.0, commit `da8d93f2797088a5f0636c8c1eeb31da73784fe8` | How the attestation agent's NVIDIA attester packages evidence (`attestation-agent/attester/src/nvidia/mod.rs`) |
| DMTF DSP0274 (SPDM) | 1.1.x; 1.2.x §15 for why 1.2 is not accepted | `GET_MEASUREMENTS` / `MEASUREMENTS`, measurement blocks, the signature over the exchange |
| TCG DICE Attestation Architecture | 1.1 | `DiceTcbInfo`, `OperationalFlags` |
| RFC 5280, RFC 6960 | | Certificate path checks, OCSP |
| W3C XML Signature 1.1, Canonical XML 1.1; ISO/IEC 19770-2:2015; TCG RIM Information Model 1.01 | | The SWID RIMs and their enveloped signature |
| NVIDIA RIM service, OCSP service | observed 2026-10-12 (`https://rim.attestation.nvidia.com/v1/rim/<id>`, `/v1/rim/ids`; `https://ocsp.ndis.nvidia.com`) | Refreshing the RIM cache offline. No URL is compiled in; `gpu_policy` names the OCSP endpoint if one may be called |

## What the pod sends

Unchanged from `alphacompute-evidence/2`: one `{"arch", "evidence", "certificate"}` per GPU, from the attestation agent's NVIDIA attester (`GET /aa/additional-evidence`), which calls NVIDIA's SDK (`GpuEvidenceSource::from_nvml().collect(nonce)`). `evidence` is the SPDM report: the 37-byte `GET_MEASUREMENTS` request (version `0x11`, `Param1 = 0x01` signature requested, `Param2 = 0xFF` every block, our 32-byte nonce, slot) followed by the GPU's `MEASUREMENTS` response (blocks, the GPU's nonce, NVIDIA opaque data, a 96-byte ECDSA P-384 signature). `certificate` is the device certificate chain as PEM text. The nonce is `gpu_nonce(report_data)`, so every GPU report is bound to the TD quote. `arch` is the pod's word and never selects a parser.

## Trust chain

```text
gpu_policy (release-signed platform document)
 ├─ local.device_roots ──pins──▶ NVIDIA Device Identity CA (self-signed)
 │                                └▶ NVIDIA GB1xx Identity ─▶ Provisioner ICA ─▶ <chip> A01 GSP BROM (per GPU; CN = hwmodel)
 │                                                                              └▶ <chip> A01 GSP FMC LF (leaf)
 │                                                                                  ├ TcbInfo FWID (certified firmware identity)
 │                                                                                  └ signs the SPDM report over our nonce
 ├─ local.rim_roots ────pins──▶ NVIDIA CoRIM signing Root CA ─▶ Reference Value GB1XX CA ─▶ L3 ─▶ RIM L4 Signer
 │                                                                                                 └ signs driver and VBIOS RIMs
 ├─ local.rims ─────────pins──▶ the SHA-384 digest of every RIM the verifier may use
 ├─ local.fwids, local.cc_mode, hwmodels, allowed_models, min versions
 └─ local.ocsp_max_age_secs, local.ocsp_url, local.accept_certificate_hold
OCSP (NVIDIA responders, delegated by each issuer) ─▶ every non-root certificate the decision rests on
```

No NVIDIA key, root, URL or measurement is compiled in. The roots are in the policy as exact DER, so NVIDIA rotating one is a new platform document, and nothing is trusted on a fetch over web-PKI TLS.

## Appraisal, per GPU

Before any GPU is looked at, the backend refuses (`attestation_unknown`, naming the field, "G0 check") if `gpu_policy.local` is absent or lacks any of `device_roots`, `rim_roots`, `rims`, `fwids`, `cc_mode` or `ocsp_max_age_secs`. Then, for each GPU in order, the first failure refuses the pod:

1. **Chain.** The PEM chain parses (at most 8 certificates, 64 KiB), every certificate is strict DER, issued by the next (ECDSA with the issuer's P-384 key, names chained, CA and key-usage constraints, path length), valid now, has no critical extension the verifier does not process, and the last one is byte-for-byte a `device_roots` entry.
2. **Hardware model.** The common name of certificate 1 (the per-GPU `BROM` certificate, NVIDIA's `hwmodel`) is in `gpu_policy.hwmodels`, which maps it to a model name (`B300`). The chip is its first word (`GB100`). Only a `GSP` responder is appraised: an `FSP` chain (Blackwell's other responder, which sends no opaque data) is refused.
3. **Revocation.** Certificates 1 to n−2 (the leaf is issued by the device itself) each have a fresh `good` OCSP response; see [OCSP](#ocsp).
4. **Certified firmware identity.** The leaf's DICE `TcbInfo` (OID 2.23.133.5.4.1.1) parses and its first FWID is SHA-384. Its `debug`, `notSecure` and `recovery` operational flags are read for step 9.
5. **Report.** The report parses as one SPDM 1.1 exchange (64 KiB at most, at most 1 KiB per block, every block in the DMTF format, no duplicate index, nothing after the opaque data but the signature); its signature verifies under the leaf key; the request nonce is ours.
6. **Opaque data.** It parses (legacy or `NVDAOD` format, version ≤ 2, no field twice). The reported FWID equals the certificate's, and the FWID is in `local.fwids`. `FEATURE_FLAG` is read for step 9.
7. **RIMs, selected by measurement.** From the RIM cache, only RIMs that verify (signature, chain to `rim_roots`, OCSP, pinned in `local.rims`) and whose signed `PlatformModel` is the chip are candidates. The driver RIM and the VBIOS RIM are the candidates whose every active golden measurement matches the GPU's block of the same index (block = index + 1), with NVIDIA's one exception: index 35 is skipped when the signed NVDEC0 status is `0x55` (disabled) and compared when it is `0xAA`; any other status refuses. Exactly one driver version and one VBIOS version must match; their active indices must not overlap; a block the GPU reports that neither RIM lists refuses. Minimum-SVN records in the RIMs are compared with the opaque fields they name.
8. **Versions.** The GPU's driver and VBIOS versions are the matched RIMs' signed `colloquialVersion`s. The versions in the opaque data must equal them; a GPU whose firmware reports another version than the one it measures as refuses.
9. **CC mode.** The GPU is in CC mode only if the signed indicator `local.cc_mode` names holds one of its production values, no DICE `debug`, `notSecure` or `recovery` flag is set, and `FEATURE_FLAG` is not `ppcie` (protected PCIe, where the GPU's own CC mode is off). Otherwise it is reported with `cc_mode: false`, and `check_gpus` refuses it exactly as it refuses one from NRAS: `policy_denied`, "gpu `<i>`: not in CC mode". An indicator missing from the report refuses outright.
10. **Distinct devices.** `device_id` is the leaf certificate's serial number in decimal (NVIDIA's `ueid`); `check_gpus` refuses two GPUs of one pod with the same one.

The verdict's `token_sha256` is SHA-256 over `alphacompute/gpu-local/v1`, then for every GPU its report, its chain and the digests of its two RIMs, each length-prefixed, so the attestation result names exactly what was appraised.

## Finding 1: firmware identity not appraised

*The review: the earlier design took the firmware's identity from what the firmware says about itself.* NVIDIA's own local verifier builds the RIM IDs from the version strings in the opaque data (`get_driver_rim_id`, `get_vbios_rim_id`), fetches those RIMs, and checks that the RIM's version equals the reported one (`verify.cpp`). The opaque data is inside the signed response, but it is written by the GPU firmware being appraised (GSP-RM), so a firmware that misreports its version picks its own reference values; and the FWID in the device certificate is only compared with the FWID in the report, never with a known-good value.

How this design closes it:

- **RIM selection by measurement, not by name.** No RIM is looked up by a reported version. Every pinned RIM for the certified chip is tried, and the one whose golden values the GPU's signed measurements match is the one that applies (step 7). A GPU that matches no pinned RIM, or two of different versions, is refused.
- **Versions come from the signed RIM.** `driver_version` and `vbios_version` in the result, and therefore the policy's minimum versions, are the matched RIMs' signed versions (step 8). The self-reported strings must agree with them or the GPU is refused.
- **The certified FWID is appraised.** The SHA-384 FWID in the leaf's `TcbInfo` is certified by the device's `BROM` key, which NVIDIA's provisioning CA certified. It must equal the report's and be one the release pins in `local.fwids` (step 6), so a GPU booting firmware outside what the release accepted is refused even if its later measurements match.
- **Kind and chip from signed content.** Whether a RIM is a driver or a VBIOS RIM is read from the format of its signed version, and the chip from its signed `PlatformModel` matched against the certified hardware model, not from the RIM's unsigned ID.

Negative tests: a GPU whose opaque driver version differs from the RIM it matches; a GPU that matches no pinned RIM; a RIM that matches but is not pinned; two pinned RIMs of different versions that both match; an FWID not in `local.fwids`; an FWID that differs between certificate and report.

## Finding 2: a devtools-mode GPU able to pass

*The review: a GPU in CC DevTools mode (or with CC off) could pass.* Nothing in NVIDIA's published claims or the local verifier decides CC mode from signed evidence: the SDK checks CC and PPCIe mode through NVML in the guest (`nvml_client.cpp`, `ccFeature`; `devToolsMode` is read and not checked), which is the host-controlled driver's word, and NRAS publishes no CC-mode claim (which is why `gpu_policy.nras_cc_mode` exists). A devtools GPU still produces a correctly signed report, and its measurements can match a RIM.

How this design closes it:

- **CC mode is decided only from signed evidence, by a rule the release pins.** `local.cc_mode` names a signed indicator (a measurement block, or an opaque field) and the values that mean production CC mode. Until a release-signed document sets it, the backend refuses every GPU. The indicator is chosen at G0 by capturing the same B300 in `on` and in `devtools` mode and diffing the two signed reports (`ponytail: G0-gpu-capture`); the choice is recorded in the security review before it is signed.
- **Only production RIMs count.** The signed content of a RIM does not say whether a driver RIM is the CC one: `NV_GPU_CC_DRIVER_GB100_580.159.03` and `NV_GPU_BMSAI_DRIVER_GB100_620.06` carry the same `Meta` fields. `local.rims` pins every acceptable RIM by its signed digest, so a non-CC or debug RIM in the cache is never a candidate.
- **Other signed debug state counts too.** A DICE `debug`, `notSecure` or `recovery` flag in the leaf's `TcbInfo`, or a `FEATURE_FLAG` of `ppcie`, makes the GPU not in CC mode whatever the indicator says (step 9).
- **Same refusal as NRAS.** A GPU whose indicator does not hold is `cc_mode: false`, refused by `check_gpus` with `policy_denied`, "not in CC mode", exactly as the `nras` backend reports a DevTools GPU.

Negative tests: devtools (indicator with its devtools value), CC off, a policy with no `cc_mode`, a DICE debug flag set, PPCIe mode, a debug-only RIM present in the cache but not pinned.

## Finding 3: Blackwell evidence refused

*The review: the earlier design parsed Hopper evidence only, so B300 evidence could never pass.* Blackwell differs from Hopper in exactly the places such a parser hard-codes:

| | Hopper (GH100) | Blackwell (GB100, GB110) |
|---|---|---|
| FWID in the leaf certificate | TCG `CompositeDeviceID` at 2.23.133.5.4.1 | TCG DICE `TcbInfo` at 2.23.133.5.4.1.1 (vendor, model `GB100 A01 GSP`, version, SVN, FWIDs, operational flags) |
| Device chain | `GH100 A01 GSP BROM` ← `NVIDIA GH100 Provisioner ICA 1` ← `NVIDIA GH100 Identity` | `GB100 A01 GSP BROM` ← `NVIDIA GB100 Provisioner ICA 00000` ← `NVIDIA GB100 Identity` (same root, `NVIDIA Device Identity CA`) |
| Driver RIM | `NV_GPU_DRIVER_GH100_<v>` | `NV_GPU_CC_DRIVER_<chip>_<v>`, chip from opaque `CHIP_INFO` (`GB100`, `GB110`) |
| RIM signing chain | `… Reference Value GH100 CA` | `… Reference Value GB1XX CA 001` ← `L3 GB100-CC 001` |
| Opaque data | legacy TLV | legacy TLV, or `NVDAOD` header with value types (newer firmware) |
| Second responder | — | FSP (`GB100 A01 FSP BROM`), typed raw blocks, no opaque data, CoRIM |

How this design closes it: the verifier is written for Blackwell from NVIDIA's Blackwell sample evidence. It parses `TcbInfo` at 2.23.133.5.4.1.1, both opaque encodings, any chain length up to 8 ending at the pinned root, and selects RIMs without ID strings, so the `CC_DRIVER` naming and the chip in it do not matter. The parse path is chosen by the certificate, never by the self-reported `arch`. NVIDIA's Blackwell sample report and chain verify end to end in the tests (chain to the pinned root, `TcbInfo` FWID equal to the report's, SPDM signature, nonce, opaque data); its VBIOS RIM (`NV_GPU_VBIOS_G525_0220_886_970088000F`, from the RIM service) matches all 19 of its active measurements, checked during development and not committed (licence). Hopper is refused with a reason that names the Hopper FWID format; adding it is a separate parser, not in scope.

What is validated only against the documented format, because no B300 capture exists until G0: the B300's chip string (`GB110` has CC driver RIMs on the RIM service; that it is the B300 is not confirmed), its `hwmodel`, whether its leaf carries `TcbInfo` the same way, its opaque data version, the measurement indices its driver and VBIOS RIMs cover, and the CC-mode indicator. Each B300 test is marked `ponytail: G0-gpu-capture` and is re-pinned with the capture.

## Policy (`gpu_policy.local`)

Release-signed in the platform document, refusing unknown fields like the rest of `gpu_policy`:

```json
"gpu_policy": {
  "allowed_models": ["B300"],
  "min_driver_version": "580.159.03",
  "min_vbios_version": "97.00.88.00.0F",
  "verifiers": ["local"],
  "hwmodels": {"<BROM certificate CN of the B300, from G0>": "B300"},
  "local": {
    "device_roots": ["<base64 DER of NVIDIA Device Identity CA>"],
    "rim_roots": ["<base64 DER of NVIDIA CoRIM signing Root CA>"],
    "rims": {"sha384:<hex DigestValue>": "NV_GPU_CC_DRIVER_<chip>_<version>",
             "sha384:<hex DigestValue>": "NV_GPU_VBIOS_<project>_<sku>_<chip sku>_<version>"},
    "fwids": ["sha384:<hex>"],
    "cc_mode": {"source": "measurement", "index": "<SPDM block, from G0>", "values": ["<hex>"]},
    "ocsp_max_age_secs": 86400,
    "ocsp_url": "https://ocsp.ndis.nvidia.com",
    "accept_certificate_hold": false
  }
}
```

- `device_roots`, `rim_roots`: the only roots, as DER. NVIDIA's are in nvtrust (`certs/verifier_device_root.pem`, SHA-256 fingerprint `10:2B:F6:59:…:7B:48`; `certs/verifier_RIM_root.pem`); the release copies them in after checking them against NVIDIA's documentation.
- `rims`: every RIM the verifier may use, by the SHA-384 its signature covers; the value is the RIM's ID, for people. A RIM in the cache but not here is ignored.
- `fwids`: the certified FMC firmware IDs the release accepts, captured at G0 from a GPU whose measurements matched NVIDIA's RIMs, and added for each firmware update the release accepts.
- `cc_mode`: `source` is `measurement` (an SPDM block index) or `opaque` (an opaque field type); `values` the signed values that mean production CC mode.
- `ocsp_max_age_secs`: required, at most 7 days. NVIDIA's responders answer with a one-day `nextUpdate`; NVIDIA's terms (L1) ask for attestation results refreshed at least every 24 hours, which hourly leaves satisfy.
- `ocsp_url`: optional. When set, the KMS may query exactly this endpoint at appraisal time for a status the cache lacks; when absent, the verifier uses cached responses only and makes no network call.
- `accept_certificate_hold`: default `false`. NVIDIA's RIM service serves RIMs whose `RIM L4 Signer` is on `certificateHold` (the GB100 VBIOS RIM above, on hold since 2025-06-26, observed 2026-10-12); a release that must accept such RIMs says so here, per document.

## RIM cache

The KMS never canonicalises XML, and never fetches a RIM. The cache is a JSON file the operator refreshes offline and the KMS reads at start (`ALPHACOMPUTE_GPU_RIM_CACHE`; the `local` backend runs only when it is set, and a cache the node cannot read stops it at start):

```json
{"format": "alphacompute-gpu-rim-cache/1",
 "rims": [{"id": "NV_GPU_CC_DRIVER_GB110_595.58.03", "signed_info": "<b64>", "document": "<b64>",
           "signature": "<b64 r‖s>", "certificates": ["<b64 DER>", "..."]}],
 "ocsp": ["<b64 DER OCSPResponse>", "..."]}
```

- **Signed content only.** Each RIM entry is NVIDIA's signature, its signing chain and the two byte strings XML-DSig's processing produces: the canonical `SignedInfo` (the signed bytes) and the canonical document after the enveloped-signature transform (the bytes `DigestValue` is over). The KMS verifies the signature over the first, checks that SHA-384 of the second is the signed `DigestValue` and that the digest is pinned in `local.rims`, and only then parses the second, with a strict, bounded XML reader (`roxmltree`, DTDs off, node limit). The `SignedInfo` must be NVIDIA's profile exactly (Canonical XML 1.1, ECDSA SHA-384, one reference to the whole document with the enveloped-signature transform, SHA-384).
- **Canonicalisation stays out of the trusted path.** `testdata/gpu/tools/canonicalize.py` (lxml and `cryptography`) produces an entry from a RIM file or a RIM service reply and checks it before writing; a wrong canonicalisation can only produce an entry that fails. No XML-DSig canonicaliser is hand-written.
- **Freshness.** The OCSP responses for the RIM signing chains, and for the device CAs, are in the cache; each must be younger than `ocsp_max_age_secs` and not past its `nextUpdate`. A stale cache refuses every GPU, so the refresh runs at least daily.
- **Expired signers.** A RIM whose signing certificate has expired is refused; the refresh takes the RIM service's current copy.
- **Refresh.** `deploy/gpu-rims/refresh.py --rim-service <url> --ocsp <url> --rim <id>… [--device-chain <pem>…] --out <file>`: for each RIM ID the release pins, it fetches the RIM, makes its entry with `canonicalize.py`, and fetches OCSP for each certificate of its signing chain but the root; for each device chain given, OCSP for its CAs. It writes the file atomically; the KMS reads it at start. `cargo test -p alpha-attest --test gpu_local_vectors -- --ignored g0_rim_cache` (with `ALPHA_GPU_RIM_CACHE`) checks a cache against NVIDIA's roots and prints each RIM's digest to pin. Run 2026-10-12 against NVIDIA's services for `NV_GPU_CC_DRIVER_GB110_595.58.03`, the whole path verified in Rust (chain, live OCSP, signature, digest, 19 active measurements).

## OCSP

- Device chain: certificates 1 to n−2 (the `BROM` certificate, the provisioner ICA, the chip identity CA). The `BROM` certificate is per GPU, so its status comes from the policy's `ocsp_url` at appraisal time, or from responses staged in the cache for the GPUs a node has.
- RIM signing chain: every certificate but the root.
- A response counts only if it is signed by the issuer or by a responder certificate that issuer issued with `id-kp-OCSPSigning` (both kinds are NVIDIA's), names the certificate by a SHA-256 or SHA-384 `CertID`, is no older than `ocsp_max_age_secs`, is not past `nextUpdate`, and says `good`. `revoked` (any reason; `certificateHold` only as above) and `unknown` refuse; no response refuses.
- An online query carries a nonce derived from the GPU nonce and the certificate's serial, so it is fresh for each appraisal, and a response that does not echo it is not used. Each query has 5 s, all of an appraisal's queries 20 s; a status still missing then refuses (fail closed). Reliable responses are kept in memory, at most 1024, until they reach the maximum age.

## Result and refusal reasons

The backend returns the same `GpuVerdict` as `nras` (`index`, `device_id`, `model`, `driver_version`, `vbios_version`, `cc_mode`, `nonce`) and refuses with the same codes:

| Case | Code | Reason |
|---|---|---|
| `gpu_policy.local` absent or incomplete | `attestation_unknown` | `gpu_policy.local.<field> … (G0 check)`, before any GPU is parsed |
| Bad chain, signature, nonce, measurements, RIM, OCSP | `attestation_failed` | `local: GPU-<i>: <what>` |
| `hwmodel` not in `hwmodels` | `attestation_failed` | `hwmodel "<cn>" is not in gpu_policy.hwmodels` |
| CC-mode indicator not production | `policy_denied` (by `check_gpus`) | `gpu <i>: not in CC mode` |
| Driver or VBIOS below the minimum | `policy_denied` (by `check_gpus`) | `gpu <i>: driver version … is below …` |
| Wrong count, duplicate device, wrong model | as for every backend (`check_gpus`) | |

## Parsers, limits and external review

All parsers take attacker-controlled bytes (the report and chain from the pod; the cache from the operator). The workspace lints deny `unwrap`, `expect`, `panic`, indexing and unchecked arithmetic outside tests, and every parser bounds its input before allocating:

| Parser | Module | Bounds |
|---|---|---|
| SPDM 1.1 report | `gpu::local::spdm` | report ≤ 64 KiB, block value ≤ 1 KiB, ≤ 255 blocks, exact lengths |
| NVIDIA opaque data | `gpu::local::opaque` | ≤ 128 fields, no duplicates, version ≤ 2 |
| PEM chain, X.509, DICE `TcbInfo` | `gpu::local::cert` (`x509-cert`, `der`) | PEM ≤ 64 KiB, ≤ 8 certificates, certificate ≤ 8 KiB |
| OCSP response | `gpu::local::ocsp` (`x509-ocsp`) | ≤ 16 KiB |
| RIM `SignedInfo` and document | `gpu::local::rim` (`roxmltree`) | `SignedInfo` ≤ 8 KiB, document ≤ 512 KiB, ≤ 20 000 nodes, ≤ 1024 resources, ≤ 16 alternatives |

Each has a cargo-fuzz target under `fuzz/` (`spdm`, `opaque`, `cert_chain`, `ocsp`, `rim_signed_info`, `rim_document`), seeded from `testdata/gpu`; they need nightly and are not run in CI. On stable, `alpha-attest`'s `gpu_local_vectors` test runs every parser over truncations and bit flips of NVIDIA's real inputs in every CI run. The review re-estimates the build at 30–36 days plus an external review of these parsers; the list for that review is in the pull requests.

Where this verifier is stricter than NVIDIA's: certificate validity is checked (the SDK verifies chains with `X509_V_FLAG_NO_CHECK_TIME`); a duplicated opaque field or measurement index refuses (the SDK keeps the last); a block length that does not match its value refuses (the SDK ignores the excess); SPDM versions other than 1.1 refuse; a block no RIM lists refuses; OCSP is required for every non-root certificate, with a maximum age.

## Test vectors

`testdata/gpu` (provenance and SHA-256 in its README): NVIDIA's Blackwell, Blackwell FSP and Hopper sample reports and chains, the device and RIM roots, two NVIDIA-signed RIMs and their canonical entries (Apache-2.0, from the SDK and nvtrust), and live OCSP responses for the Blackwell device chain and for a Blackwell RIM signing chain (one of them `certificateHold`), fetched 2026-10-12. End-to-end backend tests build a synthetic PKI, RIMs and reports in the test, since no NVIDIA RIM pair matches a published report. The B300 tests use the documented format and are marked `ponytail: G0-gpu-capture`.

## G0 checklist (`ponytail: G0-gpu-capture`)

On the first B300 in CC mode, in a Kata pod:

1. Save the evidence (`/aa/additional-evidence`) for a known nonce, with CC `on`, then the same GPU with CC `devtools`, then CC `off` if a report can be collected.
2. Record the `BROM` CN (`hwmodels`), the leaf's `TcbInfo` (model, FWID, flags), the opaque data version and fields, and which blocks differ between `on` and `devtools` (`cc_mode`).
3. Fetch the RIMs the GPU's driver and VBIOS correspond to, build the cache, and check that every active measurement matches and no block is unlisted.
4. Replace the documented-format B300 tests with the capture and pin the values above in a release-signed `gpu_policy`.
