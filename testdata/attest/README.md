# Attestation vectors

Golden inputs for `crates/alpha-attest`, read by `crates/alpha-attest/tests/vectors.rs`. Every quote here was produced by a real Phala Cloud CVM; nothing is synthesized or edited into a passing state. `now` in the tests is the capture time, so the DCAP collateral never expires.

## Capture `phala-dev-0.5.9`

One CVM, `tdx.small` (1 vCPU, 2 GB), node `prod5` (US-WEST-1, dstack host v0.6.0), OS image `dstack-dev-0.5.9`, deployed on 2026-09-14 and deleted right after the capture. Reproduce it with the kit in `capture/`:

1. `capture/in-cvm.sh` is the script that runs inside the CVM; `capture/docker-compose.yml` carries it base64-embedded in the `command` of an `alpine:3.20` container with `/var/run/dstack.sock` and `/run/log/dstack` mounted. If the script changes, regenerate the compose line with `base64 < in-cvm.sh | tr -d '\n'`.
2. Deploy: `phala deploy -n attest-capture -c capture/docker-compose.yml -t tdx.small --wait` (the `phala` CLI, `npx phala@latest`, with `PHALA_CLOUD_API_KEY` set).
3. Inside the CVM the script generates a P-256 key (`openssl ecparam -name prime256v1 -genkey`), exports its SPKI DER (`runtime_spki.der`), draws 32 random bytes (`nonce.bin`) and 1216 random bytes standing in for a KMS node's X-Wing SPKI (`node_xwing_spki.der`), and computes `report_data` as `docs/kms-spec.md` §4.1 says: `[0..32] = SHA-256(SPKI_DER ‖ nonce)`, `[32..64]` all zero for the Instance-shaped quote and `SHA-256(node_xwing_spki)` for the node-shaped one. For each shape it calls `GET /GetQuote?report_data=0x<128 hex>` on the dstack socket, stores the quote (`quote.<shape>.hex`, hex as the guest agent returns it) and the event log from the same response (`event_log.json`, identical for both shapes since the CVM did not change between calls), records `date -u` (`captured_at.txt`), saves `/Info` (`info.json`, from which `app-compose.json` is the `tcb_info.app_compose` string; its SHA-256 is the measured `compose-hash` event), deletes the private key and serves the directory on port 8080.
4. Fetch the files through the dstack gateway, `https://<app_id>-8080.dstack-pha-prod5.phala.network/`.
5. Collateral, from a laptop against Phala's PCCS: `cargo run -p alpha-attest --example fetch_collateral -- https://pccs.phala.network phala-dev-0.5.9/quote.instance.hex > phala-dev-0.5.9/collateral.json`. The two quotes share one platform, so one collateral serves both.
6. `phala cvms delete --cvm-id <uuid> --force`.

`platform-document.json` is the platform document for this capture: one reference value named `dstack-dev-0.5.9/1c-2g` holding the quoted `mrtd`, `rtmr0`, `rtmr1`, `rtmr2`, the policy `UpToDate | SWHardeningNeeded` with no tolerated advisories, an empty `kms_ca_pem` (no KMS CA exists yet) and the capture's compose hash as the only KMS Revision. It is unsigned: the release-key signature is checked by the reader of the document, not by `alpha-attest`.

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

The debug-bit and TCB-status/advisory policy checks cannot be produced as real quotes (Phala Cloud does not hand out debug TDs or out-of-date platforms on request), so they are unit tests in `crates/alpha-attest/src/lib.rs` over synthetic report attributes and status strings, not vectors here. The expired-collateral and wrong-format cases are unit tests over the real capture with a shifted `now` and a changed `format`, respectively.
