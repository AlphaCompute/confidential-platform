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
