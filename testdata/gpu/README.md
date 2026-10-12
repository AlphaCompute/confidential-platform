# GPU evidence vectors (local GPU verifier)

Inputs for `crates/alpha-attest/tests/gpu_local_vectors.rs` and the seeds of the fuzz targets under `fuzz/`. Nothing here is edited into a passing state: every file is NVIDIA's, byte for byte, or derived from one by the command given. `docs/local-gpu-verifier.md` explains what each proves. Their SHA-256 are listed below and in `testdata/SHA256SUMS`, which CI checks.

No B300 capture exists yet; it is made at G0 on the real server and added here (`ponytail: G0-gpu-capture`). The Blackwell files are NVIDIA's GB100 samples.

## `nvidia/`: NVIDIA's published samples (Apache-2.0, `nvidia/LICENSE`)

Copied unchanged from:

- NVIDIA attestation SDK, `NVIDIA/attestation-sdk` release 2026.10.02, commit `11b2bfeb42a1158aa08744603ecb239ccb3d2265`, directory `nv-attestation-sdk-cpp/unit-tests/testdata/sample_attestation_data/gpu/`: `blackwellAttestationReport.txt`, `blackwellCertChain.txt`, `blackwellFspAttestationReport.txt`, `blackwellFspCertChain.txt`, `hopperAttestationReport.txt`, `hopperCertChain.txt`; and from `nv-attestation-sdk-cpp/unit-tests/testdata/`: `NV_GPU_DRIVER_GH100_550.144.03.xml`, `incorrect_signature_driver_rim.xml`. `LICENSE` is that repository's.
- NVIDIA nvtrust, commit `858ada9a17f58c482f578414ea2455498fa51e17`, directory `guest_tools/gpu_verifiers/local_gpu_verifier/src/verifier/`: `certs/verifier_device_root.pem` (`NVIDIA Device Identity CA`), `certs/verifier_RIM_root.pem` (`NVIDIA CoRIM signing Root CA`), `samples/1010_0200_882_96005E0001_PROD.swidtag`.

The reports are hex text of the SPDM exchange; the chains are PEM. What they contain, as the tests check:

| File | Contents |
|---|---|
| `blackwellAttestationReport.txt` + `blackwellCertChain.txt` | GB100 GSP report over nonce `931d8dd0…64dfcb`, 64 blocks, legacy opaque data (driver `575.32`, VBIOS `97.00.88.00.0F`, NVDEC0 disabled, FWID `d090cab1…f77502`); chain `GB100 A01 GSP FMC LF` → `GB100 A01 GSP BROM` → `NVIDIA GB100 Provisioner ICA 00000` → `NVIDIA GB100 Identity` → `NVIDIA Device Identity CA`; the leaf's `TcbInfo` (2.23.133.5.4.1.1) has the same FWID |
| `blackwellFsp*` | the FSP responder: typed raw blocks, no opaque data |
| `hopper*` | GH100 report (driver `535.86.09`, VBIOS `96.00.5E.00.01`); its leaf has the Hopper `CompositeDeviceID` at 2.23.133.5.4.1 |
| `1010_0200_882_96005E0001_PROD.swidtag` | the VBIOS RIM of that Hopper report: its 12 active measurements match the report |
| `NV_GPU_DRIVER_GH100_550.144.03.xml` | an NVIDIA-signed driver RIM (signer valid 2024-12-30 to 2026-12-30) |
| `incorrect_signature_driver_rim.xml` | NVIDIA's negative sample: a driver RIM whose signature does not verify |

## `rim/`: canonical RIM entries (derived)

The entries the verifier's RIM cache holds, made from the two signed RIMs above by

```sh
python3 -I tools/canonicalize.py nvidia/1010_0200_882_96005E0001_PROD.swidtag NV_GPU_VBIOS_1010_0200_882_96005E0001 > rim/NV_GPU_VBIOS_1010_0200_882_96005E0001.json
python3 -I tools/canonicalize.py nvidia/NV_GPU_DRIVER_GH100_550.144.03.xml NV_GPU_DRIVER_GH100_550.144.03 > rim/NV_GPU_DRIVER_GH100_550.144.03.json
```

with lxml 5.2.1 and cryptography 41.0.7. `canonicalize.py` checks the signature and the digest before it writes, as the verifier does after it reads.

## `ocsp/` and `certs/`: from NVIDIA's services (fetched 2026-10-12)

OCSP responses from `https://ocsp.ndis.nvidia.com`, fetched 2026-10-12 04:26–04:29 UTC with OpenSSL 3.0.13 (`openssl ocsp -sha384 -issuer <issuer> -cert <cert> -url https://ocsp.ndis.nvidia.com -respout <file>`), each valid one day:

| File | Certificate (issuer) | Status | Signed by |
|---|---|---|---|
| `blackwell-brom.der` | `GB100 A01 GSP BROM` of `blackwellCertChain.txt` (Provisioner ICA) | good | `NVIDIA OCSP Responder L3 GB100 ICA 00000` |
| `blackwell-provisioner-ica.der` | `NVIDIA GB100 Provisioner ICA 00000` (GB100 Identity) | good | delegated responder |
| `blackwell-identity.der` | `NVIDIA GB100 Identity` (Device Identity CA) | good | delegated responder |
| `rim-gb100-cc-signer.der` | `RIM L4 Signer` of `certs/rim-gb100-cc-0.der` | revoked, `certificateHold` since 2025-06-26 | `NVIDIA OCSP Responder L3 Reference Value GB100-CC 001` (ECDSA SHA-256) |
| `rim-gb100-cc-l3.der` | `NVIDIA Reference Value L3 GB100-CC 001` | good | delegated responder (ECDSA SHA-256) |
| `rim-gb1xx-ca.der` | `NVIDIA Reference Value GB1XX CA 001` | good | `NVIDIA OCSP Responder L1 CoRIM Root` |

`certs/rim-gb100-cc-{0,1,2,3}.der` are the signing chain (`RIM L4 Signer` → `L3 GB100-CC 001` → `GB1XX CA 001` → `NVIDIA CoRIM signing Root CA`) taken from the `ds:X509Certificate` elements of `NV_GPU_VBIOS_G525_0220_886_970088000F` as NVIDIA's RIM service returned it on 2026-10-12 (`https://rim.attestation.nvidia.com/v1/rim/NV_GPU_VBIOS_G525_0220_886_970088000F`, reply `sha256` field `1ffe5b51…d3df50`). That RIM is the VBIOS RIM of the Blackwell sample report (all 19 active measurements match); the RIM itself is not committed, since the RIM service's terms do not say it may be redistributed.

## SHA-256

```text
b88d08fce148079f77be3ebd34af8802e979d7352dbde031de46c337a33c478f  certs/rim-gb100-cc-0.der
1fe5417cfd73b925740e045cc74a95fc1ae8bba520f6894b02b7f33ea5542364  certs/rim-gb100-cc-1.der
d0f29af9034b45f7ac5fb2131c35dfc7df90b8ee0178c543a6d928a7c0254a54  certs/rim-gb100-cc-2.der
12977b5115acb0381179279fffeb5a8c4d264971ebb32298023a465fa41df5d1  certs/rim-gb100-cc-3.der
7e8ea28e7961a9ef83b87ca5c5685312014eae871977b720ae08553aa917bc50  nvidia/1010_0200_882_96005E0001_PROD.swidtag
82d36972a71088e8d4a4793313e64e18340c60de08e3175a58360a277c962a33  nvidia/LICENSE
585ccd55e3d9420d693f82f4a1aa0b7506f126ba2ab9344ec67e244fde0c6305  nvidia/NV_GPU_DRIVER_GH100_550.144.03.xml
94a532d25ee95354c8294d5c9d8f257af7d11c9dbcda6089978ac5579cfd3381  nvidia/blackwellAttestationReport.txt
e7f4f73380aabac5d0e43f69a3c6ae4913a55dc0d376372c764632c25e91dfc1  nvidia/blackwellCertChain.txt
e2e3f12b0ad193df0a9d6b21a4c71301aa4c1a5ca1de96ec66ef52b172d3092f  nvidia/blackwellFspAttestationReport.txt
a4e2ae8ca67464a65a17693da5f2818ee547be9300584ae70c430eca9f333212  nvidia/blackwellFspCertChain.txt
2b9616df9a77f2f32ef470028c030364e9fb734f465ca334d028527db4b509df  nvidia/hopperAttestationReport.txt
a9073b181991e32accb2283f51e567a7b7ee4a532c3ebcc26fc5bdf6b5bdff07  nvidia/hopperCertChain.txt
4f894d00df1298e6fe0e59059fba4bfa8ff8666685c315ce3678b1342b13158f  nvidia/incorrect_signature_driver_rim.xml
afe8d01ab79b451fc6401a00bd8d3cba283e67339bd902e14bb41171eacb99d1  nvidia/verifier_RIM_root.pem
6e6e91e84068cb7de2c715ca73d6df168a16b23d96a895b42e553b297a471bfc  nvidia/verifier_device_root.pem
53c97740f5578e15c22defde13debbcf624b15abd9ad38a9bd0de60db96ac6a0  ocsp/blackwell-brom.der
45fd08d0c12fd6166a42da62de72ab5eb08bc92eb1fafba2bb1ad27a75f1a13f  ocsp/blackwell-identity.der
3e8e751fb10e570f1c04e722d617393c799f9e43e5d8b4a91ba3c3585f48b81c  ocsp/blackwell-provisioner-ica.der
f720daaab827a7474b04b166d930c972c16309686d1bdf17ad6bb66d27024c1f  ocsp/rim-gb100-cc-l3.der
a06b8580c1954ad17b5d7c70c5634b3564c718ffbb0c08f1d09f1d5858fffc04  ocsp/rim-gb100-cc-signer.der
83f5ae8377e1b14cc13c9acbb09b293b8dd72455ab17f997d838e94b1b230100  ocsp/rim-gb1xx-ca.der
ea0deb297646ac3b8fe4c83ffe024204d7dadf9863d5eb46d18fa377c62b7e3d  rim/NV_GPU_DRIVER_GH100_550.144.03.json
06cba12ca69624d2f90a488c64eb533871f639e15328903295cbf9a0ee094c54  rim/NV_GPU_VBIOS_1010_0200_882_96005E0001.json
f66ebd7a297074489abcc2d5afe988a723d93dada06aa6ac9edc86f96bc63689  tools/canonicalize.py
```
