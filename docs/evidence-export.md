# Exporting a pod's evidence to a second verifier (PRD-06 I2)

PRD-06 I2 asks for one evidence set that both alpha-kms and Fortanix CCM appraise: one TDX
quote and one GPU report per pod, an Alpha certificate and a Fortanix attestation record, and no
second workload or node. `alpha-runtime` already collects that evidence for alpha-kms. This
change lets it hand the same evidence to a second verifier, bound to that verifier's nonce.

## Off unless the measured configuration turns it on

`ALPHACOMPUTE_EVIDENCE_EXPORT=alphacompute-evidence-export/1` turns the route on.

- Unset, `GET /v1/evidence` answers `404 not_found`.
- Any other value stops the runtime at start (exit 1, naming the variable). A typo can therefore
  never leave the route silently on or off.

The variable is measured the same way the runtime's other `ALPHACOMPUTE_*` settings are:

- On the prototype CVM path it is in the measured compose.
- On a Kata pod the host writes the container's environment, so the value counts only if the
  pod's agent policy (in the measured init-data) pins it. This is the same rule as
  `ALPHACOMPUTE_QUOTE_SOURCE` and `ALPHACOMPUTE_DSM`. Under the agent-policy baseline of the
  `alpha coco` generators (#79, #83, `docs/coco-generator.md` there), genpolicy pins every
  variable the pod spec sets on a container. `allow_env_regex` lets the host add only
  `HOSTNAME`, `KUBERNETES_*` and `ALPHACOMPUTE_KMS_ENDPOINTS`, so a host can neither add this
  variable nor change it, and with #82's `allow_env_complete` it cannot drop it either.

If a host did turn the route on, it would gain little. Evidence is not secret, the socket is
reachable only inside the pod, and an export can never be used as an attestation to alpha-kms
(below). The switch exists so that the tenant, not the host, decides whether its pod serves
evidence on request.

## The route

`GET /v1/evidence?nonce=<32 bytes base64url>[&format=alphacompute|fortanix-ccm]` on the
runtime socket answers with `alphacompute-evidence-export/1` (`alpha_attest::export`):

```json
{"format": "alphacompute-evidence-export/1",
 "nonce": "<the caller's nonce>",
 "runtime_pubkey": "<the runtime's P-256 SPKI, base64url>",
 "evidence": {"format": "alphacompute-evidence/2", "cpu": {…}, "gpus": […], "initdata": "…", "runtime_class": "…"},
 "certificate_chain": ["<the runtime's current Alpha leaf>", "<KMS CA>"]}
```

`evidence` is exactly what the runtime sends alpha-kms: the TDX quote, every GPU's SPDM report
and certificate chain, the init-data and the runtime class. On a prototype CVM it is
`alphacompute-evidence/1`. The certificate chain is present once the runtime holds a leaf. It is
unsigned by the export, so check it against a pinned KMS CA. It lets the second verifier tie the
pod it appraised to the Alpha identity the pod serves under.

Exports run one at a time, because each one asks the guest for a quote and for every GPU's
report.

## The binding

The quote's `report_data` is the KMS's layout over a derived nonce:

```
export_nonce = SHA-256("alphacompute/evidence-export/v1" ‖ 0x00 ‖ caller nonce)
report_data  = SHA-256(runtime SPKI ‖ export_nonce) ‖ 32 zero bytes
gpu nonce    = SHA-256("alphacompute/gpu-nonce/v1" ‖ report_data)   (unchanged)
```

- A second verifier runs the KMS's own rules unchanged: `kata::appraise_any` (or `appraise` for
  v1) over `EvidenceExport::binding(caller nonce)`, which refuses an export made for another nonce
  and returns the derived nonce and the key.
- The derived nonce is a hash, never an HMAC nonce alpha-kms minted. So an export can never be
  replayed to alpha-kms as an attestation, whatever nonce the caller passes.
- A test (`kata::tests::an_exported_quote_appraises_over_the_derived_nonce_only`) shows that an
  exported quote appraises over the derived nonce and is refused over the raw one.

## Fortanix CCM (F8)

Whether CCM can appraise evidence collected by alpha-runtime, and in what request format, is
Fortanix's answer to F8 (due 2026-10-30). `format=fortanix-ccm` goes through
`alpha_attest::export::ccm_input`, the adapter seam. Until F8 is answered, it answers
`501 not_implemented`, naming F8 (`ponytail: F8`). The `alphacompute` format is the documented
format meanwhile, and a pilot can hand it to Fortanix as is.

The F8 question has three parts:

1. Does CCM accept a raw TDX quote and NVIDIA SPDM reports produced outside its own agent?
2. If so, can it take our nonce, or the derived `report_data`, as the freshness value?
3. What request and response format does it use?

## Clear claims

The export carries no verdict. A Fortanix record of the appraisal is Fortanix's to sign (F5).
The Alpha side of the same pod is its evidence bundle (`docs/clear-claims.md`), whose `verifiers`
say who attested it for Alpha.
