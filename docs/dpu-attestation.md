# NIC/DPU evidence for composite attestation (`nvidia-dpu/1`)

PRD-02 P2, item 17: a Kata pod's attestation can also cover the NVIDIA BlueField DPUs (or ConnectX NICs) of its host, next to its CPU TEE (`kata-tdx/1`, `kata-snp/1`) and GPUs (`nvidia-gpu/1`). This document records what NVIDIA publishes about BlueField-3 attestation, what `alpha-attest` and `alpha-kms` verify of it today, what they do not, and where the code stops at a refusing seam.

Status: the appraisal is built and fails closed. No pod can send DPU evidence yet (no collector, `ponytail: dpu-collect`), no release document has a `dpu_policy` with NVIDIA's roots and reference values, and nothing ran against a BlueField. A Revision that expects a DPU therefore gets no leaf until those exist.

## What NVIDIA publishes (read 2026-10-12)

- **Transport: the DPU's BMC, Redfish over SPDM.** The BlueField BMC runs SPDM over MCTP to the DPU and exposes it through the DMTF Redfish `ComponentIntegrity` schema ([BlueField BMC: DPU BMC SPDM attestation via Redfish](https://networking-docs.nvidia.com/bluefieldbmc/2510/dpu-bmc-spdm-attestation-via-redfish)):
  - `GET /redfish/v1/ComponentIntegrity` lists the targets: `Bluefield_DPU_IRoT` (Arm and NIC measurements, held by the PSC) and `Bluefield_ERoT` (the BMC's own).
  - `POST /redfish/v1/ComponentIntegrity/<id>/Actions/ComponentIntegrity.SPDMGetSignedMeasurements` with `{"SlotId": 0, "MeasurementIndices": [...], "Nonce": "<64 hex>"}` starts a task. Only slot 0 (NVIDIA's chain) is supported.
  - `GET .../ComponentIntegrity.SPDMGetSignedMeasurements/data` returns `{"HashingAlgorithm": "TPM_ALG_SHA_512", "SignedMeasurements": "<base64>", "SigningAlgorithm": "TPM_ALG_ECDSA_ECC_NIST_P384", "Version": "1.1.0"}`.
  - `GET /redfish/v1/Chassis/<id>/Certificates/CertChain` returns the slot 0 chain.
- **The signed blob's format is DMTF's, not NVIDIA's.** The Redfish `ComponentIntegrity` schema (v1.2.1, `SPDMGetSignedMeasurementsResponse.SignedMeasurements`) defines it: for SPDM 1.0 and 1.1, "a concatenation of SPDM `GET_MEASUREMENTS` requests and responses exchanged between the SPDM Requester and the SPDM Responder. The last `MEASUREMENTS` response shall contain a signature generated over the `L2` string". For 1.2 the VCA messages come first. The message layouts are DSP0274.
- **SPDM on NVIDIA devices** ([SPDM DSP0274](https://networking-docs.nvidia.com/dpunicattestation/spdm-dsp0274)): SPDM 1.1 for measurements; `CERT_CAP`, `CHAL_CAP`, `MEAS_CAP = 2` (signed measurements); SHA-384 and ECC NIST P-384. BlueField's BMC reports `TPM_ALG_SHA_512` as the hashing algorithm.
- **Certificate chain** ([BlueField-3 certificates](https://networking-docs.nvidia.com/dpunicattestation/bluefield-3-certificates)): a DICE chain in SPDM slot 0. L1–L3 ship in the image, L4 is provisioned in production (write-protected), L5 and L6 are generated at boot. The L6 leaf's key signs SPDM measurements. FWIDs sit in X.509 extension `2.23.133.5.4.1` (NVIDIA notes this OID is registered for TCG-DICE-TCBINFO): FWID-0 on L5 (hardware configuration and first mutable firmware), FWID-1 on L6 (runtime firmware). The page names no root CA and no distribution point for it.
- **Measurements** ([BlueField-3 measurements](https://networking-docs.nvidia.com/dpunicattestation/bluefield-3-measurements)), all DMTF: 1 firmware version (`0x83`, 4 bytes), 2 PSC firmware, 3 NIC firmware, 4 Arm firmware (`0x01`, SHA-512); 5–10 instance-specific rollback counters and security configuration (`0x02`, SHA-512, not in CoRIM); 11 the PCI device identity (`0x81`, 50 bytes).
- **Reference values: CoRIM** ([CoRIM](https://networking-docs.nvidia.com/dpunicattestation/concise-reference-integrity-manifest-corim), [NVIDIA RIM service](https://networking-docs.nvidia.com/dpunicattestation/nvidia-rim-service)): CBOR CoRIMs, COSE-signed, following draft-ietf-rats-corim 0.6 ("may change"), served by `https://rim.attestation.nvidia.com/v1/rim/<id>` (`{"id", "rim": <base64 CoRIM>, "sha256", ...}`). The published examples are ConnectX ids; the BlueField-3 id scheme and the CoRIM signing root are on pages we could not read in full.

Not published, as far as we found: the root certificate(s) BlueField-3 chains end at and how to obtain them out of band; a revocation service (OCSP or CRL) for BlueField device certificates; NRAS or another NVIDIA verifier for BlueField; the BlueField-3 CoRIM ids and their COSE signing key; how a pod (rather than the host's administrator) reaches the BMC.

## What is built

Evidence v2 gains an optional `nic` array, one entry per DPU, which is the Redfish answer as is:

```json
"nic": [{
  "spdm_version": "1.1.0",
  "hashing_algorithm": "TPM_ALG_SHA_512",
  "signing_algorithm": "TPM_ALG_ECDSA_ECC_NIST_P384",
  "signed_measurements": "<base64url of SignedMeasurements>",
  "certificate_chain": "<PEM, the slot 0 chain>"
}]
```

The nonce sent in the Redfish request is `SHA-256("alphacompute/dpu-nonce/v1" ‖ report_data)`, bound to the CPU evidence exactly as the GPU nonce is (`alpha_attest::dpu::dpu_nonce`).

**Revision v2.** `alpha.json` and the Revision v2 take an optional `"dpu": {"count": 1..8, "model": "BLUEFIELD-3"}` on any runtime class. Absent, the Revision's bytes and hash are what they were.

**Platform document.** An optional `dpu_policy`, shaped like `gpu_policy`:

```json
"dpu_policy": {
  "models": {"BLUEFIELD-3": {
    "roots_pem": ["<NVIDIA's root, PEM, copied out of band when the document is prepared>"],
    "measurements": {"2": ["01<sha512 hex>"], "3": ["01<sha512 hex>"], "4": ["01<sha512 hex>"]},
    "accept_unchecked_revocation": false
  }},
  "verifiers": ["local"]
}
```

`measurements` maps a measurement index to the DMTF values allowed for it (value type byte, then the value, hex), transcribed from NVIDIA's CoRIM for the firmware releases we allow. Every field refuses unknown keys.

**The appraisal** (`alpha_attest::dpu`, the same seam as the GPU's): after the CPU checks pass, the profile runs the checks that need no backend (a `dpu_policy` exists, lists a verifier and knows the Revision's model, one `nic` entry per expected DPU) together with the GPU's, then the backends, then the pure decision `dpu::check_dpus`: every listed backend verified exactly the Revision's DPUs, each index once, no two the same device, over this nonce, of the Revision's model. A pod whose Revision expects no DPU and sends DPU evidence is refused, never ignored. `alpha-kms` then holds the registered Revision's `dpu` count and model against what was verified (`check_platform`), and the result's `coco.dpus` records each DPU's device id, model, every measurement and `revocation_checked`.

**The local backend** (`alpha_attest::dpu::spdm::LocalDpu`) verifies, per DPU:

1. `dpu_policy` pins at least one root and one reference measurement for the model (else `policy_denied`).
2. SPDM 1.1 only (`1.2` and later: `attestation_unknown`, `ponytail: dpu-spdm-1.2`); ECDSA P-384 signing; SHA-384 or SHA-512 hashing.
3. The transcript parses strictly as DSP0274 1.1 `GET_MEASUREMENTS`/`MEASUREMENTS` pairs: version 1.1 throughout, only the last request asks for a signature, nothing after its signature, DMTF measurement blocks whose sizes agree, no index twice.
4. The signed request carried our DPU nonce, for slot 0.
5. The chain (PEM, root first as SPDM orders it, or leaf first) ends at a pinned root: its first certificate is the root or is signed by it. Every link is ECDSA P-384 with SHA-384 with matching issuer names, and every certificate is valid now.
6. The signature (r‖s, P-384) verifies under the leaf's key over the hash of every transcript byte before it.
7. Every measurement index the policy lists is in the transcript with an allowed value (else `policy_denied`); indices not listed are recorded, not judged.
8. The device id is SHA-256 of the DeviceID (L4) certificate's public key, the certificate below the two boot-generated aliases (`ponytail: dpu-capture`: its position is read from NVIDIA's description, not from a chain).
9. Revocation is not checked: unless the model's `accept_unchecked_revocation` is set, the DPU is refused (`ponytail: dpu-ocsp`). When set, the result says `revocation_checked: false`.

## What is not verified, and why

- **That the DPU is the pod's host's.** SPDM proves that a genuine device in a measured state answered our nonce, not where it is plugged in. A hostile host can relay the nonce to a healthy BlueField elsewhere. Pinning the expected device per node would need a node inventory the KMS does not have. Until then, a DPU result says "a BlueField-3 with these measurements exists and answered", which is weaker than the GPU's (whose report comes from inside the pod VM). `ponytail: dpu-binding`.
- **Revocation** of the DeviceID and alias certificates: no public BlueField source. `ponytail: dpu-ocsp`.
- **CoRIMs.** Reference values are pinned in the release-signed document, transcribed by whoever prepares it. Parsing CBOR/COSE CoRIMs from NVIDIA's RIM service (draft 0.6, signing root not read) is not built. `ponytail: dpu-corim`.
- **The FWID extensions** on L5 and L6 are not read: measurement indices 2–4 already cover the firmware. Their OID deviation is noted above.
- **SPDM 1.2** transcripts (VCA prefix, signing context) are refused.
- **ERoT** (the BMC's own measurements, `Bluefield_ERoT`) is not requested or appraised.
- **ConnectX NICs** use the same Redfish and SPDM shape but have their own chains and measurement tables; a `dpu_policy` model for them is a document change, not tested.

## Collection (not built, `ponytail: dpu-collect`)

The pod cannot reach the DPU's BMC today, and the BMC's credentials must not be in a measured pod. The evidence is signed over our nonce, so the collector need not be trusted. The design: `alpha-runtime` derives the DPU nonce from its `report_data` and asks a host-side collector (a DaemonSet with BMC credentials, outside the TEE) for the Redfish answer for that nonce. The collector POSTs `SPDMGetSignedMeasurements` with `MeasurementIndices: [255]`, polls the task, reads `/data` and the `CertChain`, and returns them unchanged. Until it exists, `alpha_tsm::coco::Source` refuses to build evidence for a Revision that expects a DPU, so no pod sends a partial attestation.

## Needs hardware

On a BlueField-3 behind its BMC: a captured `SignedMeasurements` and `CertChain` for a known nonce, to confirm the DMTF blob layout, the root-first order, the DeviceID position, SHA-512 with P-384, and the measurement values; NVIDIA's root obtained out of band and checked; and reference values from the matching CoRIM.
