# Which verifiers attested a workload (PRD-06 clear claims)

PRD-06 asks that every SKU and evidence bundle state which verifiers attested it: Alpha,
Fortanix, or both. In confidential-platform the statement is made by `alpha-kms` from its own
appraisal and signed by the KMS node that issued the leaf. Nothing in it comes from the workload,
so a pod cannot claim a verifier that did not run.

## The claim: `attestation_result.verifiers`

Every attestation result now carries `verifiers` (`alpha_attest::Verifiers`,
`alphacompute-verifiers/1`):

```json
"verifiers": {
  "format": "alphacompute-verifiers/1",
  "attested_by": ["alpha", "nvidia", "fortanix"],
  "cpu": [{"verifier": "alpha-kms-dcap", "profile": "kata-tdx/1"}],
  "gpu": [
    {"verifier": "nras", "token_sha256": "sha256:…"},
    {"verifier": "fortanix-ccm", "token_sha256": "sha256:…"}
  ]
}
```

- `cpu`: `alpha-kms-dcap` is the only CPU verifier. alpha-kms verifies the TDX quote with DCAP
  over Intel's collateral, then runs the profile: `kata-tdx/1` for a Kata pod, or
  `alphacompute-evidence/1` for a prototype CVM.
- `gpu`: one entry per backend that the release-signed `gpu_policy` listed. Every listed backend
  must verify every GPU (see `kata-attestation.md`, "GPU backends"). `token_sha256` is the digest
  of the signed result that backend verified. The list is empty, and omitted, for a pod without
  GPUs.
- `attested_by`: every party whose verifier appraised some of the evidence, once each, in the
  order `alpha`, `nvidia`, `fortanix`:
  - `alpha`: alpha-kms (CPU, and the `local` GPU verifier after Dec 1);
  - `nvidia`: NVIDIA's hosted NRAS vouched for the GPUs, and alpha-kms applied policy to its
    signed verdict;
  - `fortanix`: Fortanix CCM vouched for the GPUs (D1's `fortanix-ccm` backend, which fails closed
    until F8).

  "Alpha, Fortanix, or both" reads off `attested_by`. NVIDIA is named as well, because its
  verdict comes from a third party.

The same `verifiers` object is in the `attest` audit row, whose details are the result, and in
the runtime's `/v1/identity` `attestation_result`. A result from a KMS older than this change has
no `verifiers`. Readers must treat that as "not stated", never as "Alpha only".

## The evidence bundle

The reply's `attestation_result` is not signed. The KMS now also returns `attestation_receipt`:
a KMS receipt (`alpha_channel::receipt`, route `attest`, context `alphacompute/kms-receipt/v1`).
The KMS node signs it with the key of its own leaf, and it covers:

- `request_sha256`: the SHA-256 of the canonical attest request, which includes the TDX quote,
  the init-data and every GPU report;
- `response.attestation_result`: the result, `verifiers` included;
- `response.certificate_sha256`: the SHA-256 of the leaf's DER;
- `response.not_after`: the leaf's expiry.

`alpha-runtime` keeps the request it sent, and serves the whole bundle on its socket at
`GET /v1/evidence-bundle`:

```json
{"format": "alphacompute-evidence-bundle/1",
 "request": {"runtime_pubkey": "…", "nonce": "…", "evidence": {…}},
 "receipt": {"document": {…}, "signature": {…}, "certificate_chain": ["<KMS node leaf>"]},
 "certificate_chain": ["<Instance leaf>", "<KMS CA>"]}
```

The route answers 404 if the KMS sent no receipt, and `503 not_attested` with no valid leaf. A
workload can publish this bundle to its auditors. `alpha_client::attestation::verify_bundle`
checks it offline, against only the KMS CA and the KMS Revisions from the release-signed
platform document:

1. The receipt verifies under a KMS node leaf. That leaf must be issued by the pinned CA, valid
   at `issued_at`, and name a listed KMS Revision.
2. The receipt is for route `attest` and for exactly this request.
3. The Instance leaf is the one the receipt names, was issued by the CA at `verified_at`, and
   names the result's organization, App and Revision.
4. The request's key, the leaf's key and the result's `runtime_pubkey_sha256` are the same key.
5. The evidence in the request hashes to the result's `evidence_sha256`, so the raw evidence in
   the bundle is the evidence that was appraised. A second verifier, Fortanix CCM included
   (PRD-06 I2), can appraise that evidence again.
6. The result names its verifiers.

What it returns (`VerifiedAttestation`: the result, its `verifiers`, the leaf and `not_after`)
is read from the signed receipt, never from the bundle's unsigned fields.

## For `alpha verify` (PRD-02, PR #78)

`alpha verify --attestation-result` checks the unsigned `attestation_result` for agreement with
the leaf. Once this lands under it, the verify report should:

- show `verifiers.attested_by`, and the `cpu` and `gpu` entries, in its CPU and GPU sections;
- take an evidence bundle (`--evidence-bundle F`) and check it with `verify_bundle`. Its
  verifiers, and the rest of the result, then count as signed by the KMS, not merely as
  agreeing with the leaf.

## Why not an X.509 extension on the leaf

A leaf extension would put the claim in the TLS handshake itself. We did not add one, for two
reasons:

- AlphaCompute has no registered OID arc. The registration-free arc (`2.25.<UUID>`) needs a
  128-bit arc, and `rcgen` encodes arcs as `u64`.
- A third URI SAN would break every runtime and client that requires exactly two
  (`parse_instance_sans`).

The receipt carries the same claim, signed by the same KMS, and stays verifiable after the
one-hour leaf expires. If an arc is registered later, the extension can be added beside the
receipt.

## SKUs

SKU metadata lives in the Rafay templates (`rafay-plugins`), not in this repository. The
vocabulary there should be `attested_by` as above: `["alpha"]`, `["alpha", "nvidia"]` or
`["alpha", "fortanix"]` for an Alpha offer, depending on its `gpu_policy`, and `["fortanix"]`
for a Fortanix-attested SKU. A SKU's claim is a product statement. The evidence bundle is the
per-workload proof.
