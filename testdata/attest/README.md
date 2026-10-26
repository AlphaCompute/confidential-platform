# Attestation vectors

Golden inputs for `crates/alpha-attest`, read by `crates/alpha-attest/tests/vectors.rs`. Every quote here was produced by a real Phala Cloud CVM; nothing is synthesized or edited into a passing state. `now` in the tests is the capture time, so the DCAP collateral never expires.

## Captures

Four CVMs on node `prod5` (US-WEST-1, dstack host v0.6.0), each deployed on 2026-09-14 and deleted right after its capture:

- `phala-dev-0.5.9` — `tdx.small` (1 vCPU, 2 GB), OS image `dstack-dev-0.5.9` (the image `phala deploy` picks by default; `is_dev` means SSH and dev tooling in the guest, the TD debug bit is clear);
- `phala-0.5.9-4c-8g` — `tdx.large` (4 vCPU, 8 GB), OS image `dstack-0.5.9`, deployed with `--image dstack-0.5.9 --no-dev-os`;
- `phala-dev-0.5.9-keyed` and `phala-0.5.9-1c-2g-keyed` — both `tdx.small`, the dev and the production image, captured with the current kit: the nonce is the HMAC shape `alpha-kms` issues over the test key `capture/nonce_key.hex`, the X-Wing key derives from `capture/xwing_seed.hex`, and the P-256 private key is kept (`runtime.key.pem`, `runtime.key.pkcs8.der`; a throwaway, the CVM is gone). They also hold the raw CCEL table (`ccel.bin`) and `runtime_events.log`, which `alpha-tsm`'s test rebuilds into `event_log.json`. The KMS db tests act as these CVMs.

Between the images, `mrtd` and `rtmr1` are identical; `rtmr0` differs with the CVM shape and `rtmr2` with the image, so a reference value is one row per image and shape, as `docs/kms-spec.md` §4.3 says. The procedure:

1. `capture/in-cvm.sh` is the script that runs inside the CVM; `capture/prepare.py <dir>` writes `<dir>/docker-compose.yml` with the script base64-embedded in the `command` of an `alpine:3.20` container, the nonce and X-Wing key in `environment`, and `/var/run/dstack.sock`, `/run/log/dstack` and the CCEL table mounted; it also writes `<dir>/nonce.bin`. The two older captures were made by an earlier kit (random nonce, random X-Wing bytes, key deleted; `git log capture/`).
2. Deploy: `phala deploy -n attest-capture-dev -c <dir>/docker-compose.yml -t tdx.small --wait` for a dev capture, `… --image dstack-0.5.9 --no-dev-os` for a production one (the `phala` CLI, `npx phala@latest`, with `PHALA_CLOUD_API_KEY` set). The nonce is only fresh for five minutes of the KMS clock, so the tests pin the clock to `captured_at`.
3. Inside the CVM the script generates a P-256 key (`openssl ecparam -name prime256v1 -genkey`), exports its SPKI DER (`runtime_spki.der`) and computes `report_data` as `docs/kms-spec.md` §4.1 says: `[0..32] = SHA-256(SPKI_DER ‖ nonce)`, `[32..64]` all zero for the Instance-shaped quote and `SHA-256(node_xwing_pubkey)` for the node-shaped one. For each shape it calls `GET /GetQuote?report_data=0x<128 hex>` on the dstack socket, stores the quote (`quote.<shape>.hex`, hex as the guest agent returns it) and the event log from the same response (`event_log.json`, identical for both shapes since the CVM did not change between calls), records `date -u` (`captured_at.txt`), saves `/Info` (`info.json`, from which `app-compose.json` is the `tcb_info.app_compose` string; its SHA-256 is the measured `compose-hash` event), copies the CCEL table and `runtime_events.log`, and serves the directory on port 8080.
4. Fetch the files through the dstack gateway, `https://<app_id>-8080.dstack-pha-prod5.phala.network/`.
5. Collateral, from a laptop against Phala's PCCS: `cargo run -p alpha-attest --example fetch_collateral -- https://pccs.phala.network <dir>/quote.instance.hex > <dir>/collateral.json`. The two quotes share one platform, so one collateral serves both.
6. `phala cvms delete --cvm-id <uuid> --force`.

Each capture's `platform-document.json` is the platform document for it: one reference value, named after the image and shape (`dstack-dev-0.5.9/1c-2g`, `dstack-0.5.9/4c-8g`, `dstack-0.5.9/1c-2g`), holding the quoted `mrtd`, `rtmr0`, `rtmr1`, `rtmr2`, the policy `UpToDate | SWHardeningNeeded` with no tolerated advisories, an empty `kms_ca_pem` (no KMS CA exists yet) and the capture's compose hash as the only KMS Revision. It is unsigned: the release-key signature is checked by the reader of the document, not by `alpha-attest`.

## Vectors

Each directory has an `expected.json` naming the capture and the quote shape (`instance` or `node`), plus either the expected `Appraised` or the expected error code and a fragment of its message. Any other file in the directory overrides the file of the same name in the capture.

| Directory | Overrides | Expects |
|---|---|---|
| `01-instance` | — | `Appraised` for the Instance-shaped quote |
| `02-node` | — | `Appraised` for the node-shaped quote, `compose_hash` found in `kms_revisions` |
| `03-wrong-report-data` | `nonce.bin` with one bit flipped | `attestation_failed`, `report_data` |
| `04-tampered-event-log` | `event_log.json` with the `app-id` payload zeroed | `attestation_failed`, RTMR replay |
| `05-unknown-image` | `platform-document.json` whose reference value has another `rtmr0` | `attestation_unknown`, no reference value |
| `06-unknown-kms-revision` | `platform-document.json` with empty `kms_revisions` | `attestation_unknown`, KMS revision |
| `07-prod-instance` | — (capture `phala-0.5.9-4c-8g`) | `Appraised` for the production image, Instance-shaped |
| `08-prod-node` | — (capture `phala-0.5.9-4c-8g`) | `Appraised` for the production image, node-shaped |
| `09-keyed-instance` | — (capture `phala-0.5.9-1c-2g-keyed`) | `Appraised` for the keyed production capture, Instance-shaped |
| `10-keyed-node` | — (capture `phala-0.5.9-1c-2g-keyed`) | `Appraised` for the keyed production capture, node-shaped |

The debug-bit and TCB-status/advisory policy checks cannot be produced as real quotes (Phala Cloud does not hand out debug TDs or out-of-date platforms on request), so they are unit tests in `crates/alpha-attest/src/lib.rs` over synthetic report attributes and status strings, not vectors here. The expired-collateral and wrong-format cases are unit tests over the real capture with a shifted `now` and a changed `format`, respectively.

## Kata on owned hardware

`b300-kata-4.0.0` holds quotes from Kata 4.0.0 pods on our B300 host, taken through configfs-tsm, read by `crates/alpha-attest/tests/kata.rs`, the Kata unit tests in `crates/alpha-attest/src/lib.rs` and `services/alpha-kms/tests/kata.rs`. Every pod ran the same OVMF, the same QEMU and the kernel and rootfs bundle of 2026-10-12; a CPU pod is 1 vCPU and 2048 MiB unless said otherwise:

- `p1-sha256.quote.bin` — a `kata-qemu-tdx` pod booted with the init-data `t1-sha256.toml` in its `io.katacontainers.config.hypervisor.cc_init_data` annotation; `MRCONFIGID` is `SHA-256(t1-sha256.toml)` followed by 16 zero bytes, `report_data` all zero;
- `p0-none.quote.bin` — the same pod without the annotation; `MRCONFIGID` is all zero, and RTMR0 differs from `p1` because the init-data disk is gone from the ACPI tables;
- `r10-debug-console.quote.bin` — a `kata-qemu-tdx` pod with `agent.debug_console agent.debug_console_vport=1026` added through the `kernel_params` annotation; only RTMR2 differs from `p1`;
- `r14-2c-4096.quote.bin` — a `kata-qemu-tdx` pod of 2 vCPUs and 4096 MiB; only RTMR0 differs;
- `g1b-gpu.quote.bin` — a `kata-qemu-nvidia-gpu-tdx` pod with one B300 passed through; RTMR0, RTMR1 (another kernel) and RTMR2 (another cmdline and rootfs) differ, `report_data` is not zero;
- `k3-app.quote.bin` — a `kata-qemu-tdx` pod booted with the init-data `k3-app.toml`, which names its App in `[data] app_id` and carries in `[data] "policy.rego"` the Kata agent policy genpolicy generated for the pod spec `k3-pod.yaml`, as the KMS requires of a Revision. The pod runs unprivileged as uid 0 with no capabilities and a hostPath of `/sys/kernel/config`, and quotes over `report_data(runtime_spki.der, nonce.bin, None)`: `runtime_spki.der` is the P-256 key whose scalar is `0x4b` repeated 32 times, and `nonce.bin` is what a KMS with `capture/nonce_key.hex` mints at `captured_at.txt`, so a node clocked there accepts it at age zero. The policy refuses `kubectl exec` and leaves `kubectl logs` empty, so the pod serves its quote on port 8080 and the quote was read over the pod network. Taken the same day, verified with the same collateral; registers other than `MRCONFIGID` equal `p1`'s.

`r10`, `r14` and `g1b` booted with a sha384 init-data that `alpha_core::InitData` refuses, so their `MRCONFIGID` matches no Revision; the tests only use them where the refusal comes earlier, from the reference values.

`platform-document.json` is unsigned and lists two classes: `kata-qemu-tdx` with the quoted MRTD, RTMR1 and RTMR2 and the RTMR0 of five shapes captured with init-data (1 vCPU at 2048, 3072 and 4096 MiB; 2 and 4 vCPUs at 2048 MiB), deliberately without the 2-vCPU, 4096-MiB shape of `r14`; and `kata-qemu-nvidia-gpu-tdx` with the registers of `g1b`. Each class says whether it passes GPUs through (`gpu`). `kata_policy` pins the policy in `k3-app.toml`: `rules_sha256` is the SHA-256 of the rules file, the Kata 4.0.0 `rules.rego` with our patch for image digests, environment completeness and the hostname, and `data_sha256` the SHA-256 of the JCS of its `policy_data` without `containers`.

The policy came from the Kata 4.0.0 release `genpolicy` (`kata-tools-static-4.0.0-amd64.tar.zst`), run as `genpolicy -s -u -j <settings> -p <rules> -y k3-pod.yaml -r`, with that release's `genpolicy-settings.json` and drop-ins that set the OCI version to `1.3.0` (containerd 2.3), the pause image to `registry.k8s.io/pause:3.10.2`, the allowed host environment to the `KUBERNETES_*` service variables, and no service-account token mounts; `ReadStreamRequest` stays false. The init-data is `algorithm`, `version`, `[data]`, `"app_id"`, then `"policy.rego"` as a TOML multi-line literal string holding genpolicy's output byte for byte.

`collateral.json` is Intel's, fetched once for the first five quotes (they share one platform) from the PCS with `cargo run -p alpha-attest --example fetch_collateral -- https://api.trustedservices.intel.com <quote.hex>`, after the hex quote was written with `xxd -p <quote> | tr -d '\n'`. `captured_at.txt` is the time the fetch finished, and the tests verify at that time.

`b300-kata-kbs` holds one KBS handshake of the guest's attestation agent, read by `services/alpha-kms/tests/kbs.rs`. A `kata-qemu-tdx` pod (1 vCPU, 2048 MiB, Kata 4.0.0 on the B300 host, 2026-10-26) booted with an init-data that `alpha coco render` wrote for its pod spec, plus the registry credential template of `alpha_core::registry_auth("regcred", kms_ca_pem)`. A stand-in KBS answered at `kms.alpha-kms.svc:8443` with a certificate under that CA, through a DNS stand-in the pod named in `dnsConfig`. The stand-in answered `/kbs/v0/auth` with the nonce a KMS mints at `captured_at.txt` when its tenant-kek-root is `tenant_kek_root.hex`, and it refused the attestation after it recorded the request:

- `attest.json` — the agent's `POST /kbs/v0/attest` body byte for byte: the init-data, the nonce and TEE key, and the TDX quote with its CCEL. The additional evidence is empty;
- `platform-document.json` — the Kata reference values and agent policy of the stand's platform document v7, and `kms_ca_pem`, the CA of the stand-in;
- `collateral.json` — Intel's collateral for the quote, fetched from the PCS before `captured_at.txt`.

## GPU evidence on owned hardware

`b300-gpu-595.58.03` holds the evidence of two B300 GPUs (driver 595.58.03, VBIOS 97.10.52.00.17), each passed through to its own `kata-qemu-nvidia-gpu-tdx` pod, read by `crates/alpha-attest/tests/gpu.rs`. Each was taken inside the pod with NVML's `nvmlDeviceGetConfComputeGpuAttestationReport` over a verifier challenge:

- `g1b.spdm.bin`, `g2b.spdm.bin` — the SPDM 1.1 GET_MEASUREMENTS request and signed response, the challenge at offset 4. `g1b` is the evidence whose SHA-256 is the second half of `b300-kata-4.0.0/g1b-gpu.quote.bin`'s `report_data`, the challenge its first half; the capture predates the length prefix the binding now puts before each evidence, so the tests bind it anew. `g1b` reports zero in measurement block 62, `g2b` the other value the driver RIM allows;
- `g1b.certchain.pem`, `g2b.certchain.pem` — each device's certificate chain as NVML returns it, leaf first, ending in the NVIDIA Device Identity CA (SHA-256 `102bf659…0b167b48`, the root NVIDIA publishes and its local verifier pins);
- `gpu-reference.json` — reference values for that model and firmware: every block the signed driver RIM `NV_GPU_CC_DRIVER_GB110_595.58.03` marks active, with all its alternatives, and blocks 2–5, 7, 9, 12–14 and 18–21, which the driver RIM does not cover and NVIDIA publishes no VBIOS RIM for, as three GPUs of that server reported them identically; the leaf FWID `c4c76fa6…0202e3deec`, the same on all four GPUs of that server, and `feature_flag` 1, the value of a single GPU passed through.

`b300-gpu-595.91.07` holds one B300 GPU (driver 595.91.07, VBIOS 97.10.7e.00.03) passed through to a `kata-qemu-nvidia-gpu-tdx` pod, with the two RIMs NVIDIA signs for that firmware, read by `crates/alpha-attest/tests/gpu.rs`:

- `spdm.bin`, `certchain.pem` — the device's evidence and certificate chain as NVML returned them in the pod, taken as for `b300-gpu-595.58.03`;
- `NV_GPU_CC_DRIVER_GB110_595.91.07.xml`, `NV_GPU_VBIOS_G540_0216_887_97107E0003.xml` — the RIMs, the base64-decoded `rim` of `https://rim.attestation.nvidia.com/v1/rim/<name>`, byte for byte. Each is signed by its own `RIM L4 Signer`, under the NVIDIA CoRIM signing Root CA (SHA-256 `12977b51…a41df5d1`, the root NVIDIA's local verifier pins as `verifier_RIM_root.pem`);
- `gpu-reference.json` — the reference `alpha coco gpu-reference` must print for them, written independently with lxml: the identity, FWID and `feature_flag` the GPU reports, and for every block either RIM marks active (block = RIM index + 1) all its alternatives. The driver RIM covers blocks 15, 41, 42, 46–51, 53–57, 59–62 and 64, the VBIOS RIM 1–14 and 17–21; the GPU reports every other block as zero.
- `ocsp/driver-rim-signer.der`, `ocsp/rim-l3.der`, `ocsp/rim-ca.der`, `ocsp/vbios-rim-signer.der` — the `OCSPResponse` NVIDIA's responder (`https://ocsp.ndis.nvidia.com/`) returned on 2026-10-19 at 10:06 UTC for the driver RIM's `RIM L4 Signer`, the `Reference Value L3 GB110-CC 001`, the `Reference Value GB1XX CA 001` and the VBIOS RIM's `RIM L4 Signer`, each to the request `OcspQuery::request` encodes with the nonce of 32 bytes `0x5a`. Each is `good`, echoes that nonce, is current for 24 hours and carries the delegated responder that signed it.
- `ocsp/brom.der`, `ocsp/provisioner-ica.der`, `ocsp/identity.der` — the responder's answers, captured the same way at 10:07 UTC, for the device chain's `GB110 A01 GSP BROM` (the certificate unique to this GPU), `NVIDIA GB110 Provisioner ICA 00000` and `NVIDIA GB100 Identity`. The leaf names no responder and the root is pinned, so these three are all a device chain has to answer for.
