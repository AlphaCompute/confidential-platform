//! The evidence bundle (PRD-06 clear claims): what one attestation was, in a form a relying party
//! or an auditor can check offline against a pinned KMS CA. It holds the attest request exactly as
//! the KMS parsed it (the TDX quote and every GPU report), the leaf the KMS issued, and the KMS
//! node's receipt over both and over the attestation result, which names the verifiers that
//! attested the workload. Everything this module returns is read from the signed receipt, never
//! from the bundle's unsigned fields.

use std::time::SystemTime;

use alpha_attest::ccm::CcmAppraised;
use alpha_attest::{AttestationResult, Verdict, Verifiers};
use alpha_channel::cert::{parse_ccm_sans, parse_instance_sans, pem_to_der, spki_of, uri_sans, verify_leaf};
use alpha_channel::receipt::{self, ATTEST_CCM_ROUTE, ATTEST_ROUTE, Expected};
use alpha_channel::sha256_label;
use alpha_core::{CcmIdentityId, ComposeHash, OrgId};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::Error;

pub const BUNDLE_FORMAT: &str = "alphacompute-evidence-bundle/1";
pub const CCM_BUNDLE_FORMAT: &str = "alphacompute-ccm-evidence-bundle/1";

/// `alphacompute-evidence-bundle/1`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceBundle {
    pub format: String,
    /// The `POST /v1/attest` body: `runtime_pubkey`, `nonce` and `evidence`.
    pub request: Value,
    /// The reply's `attestation_receipt`.
    pub receipt: Value,
    /// The reply's `[leaf, KMS CA]`.
    pub certificate_chain: Vec<String>,
}

/// What a bundle proves, all of it from the KMS's signature.
#[derive(Clone, Debug)]
pub struct VerifiedAttestation {
    pub result: AttestationResult,
    pub verifiers: Verifiers,
    pub leaf_der: Vec<u8>,
    pub not_after: String,
}

fn invalid(m: impl Into<String>) -> Error {
    Error::Invalid(m.into())
}

/// Checks a bundle against the KMS CA and the KMS Revisions the caller pins (from the
/// release-signed platform document): the receipt is a KMS node's signature over this request,
/// the leaf is the one it names and was issued by that CA to the request's key for the result's
/// Revision, and the evidence is the evidence the result was appraised from.
pub fn verify_bundle(
    bundle_json: &[u8],
    kms_ca_pem: &str,
    kms_revisions: &[ComposeHash],
) -> Result<VerifiedAttestation, Error> {
    let bundle: EvidenceBundle = alpha_core::parse(bundle_json)
        .and_then(serde_json::from_value)
        .map_err(|e| invalid(format!("evidence bundle: {e}")))?;
    if bundle.format != BUNDLE_FORMAT {
        return Err(invalid(format!(
            "evidence bundle format {:?}",
            bundle.format
        )));
    }
    let receipt_json =
        serde_json::to_vec(&bundle.receipt).map_err(|e| invalid(format!("receipt: {e}")))?;
    let expected = Expected {
        route: ATTEST_ROUTE.into(),
        request_sha256: receipt::request_sha256(&bundle.request)?,
        response: Map::new(),
    };
    let signed = receipt::verify(&receipt_json, kms_ca_pem, kms_revisions, &expected)?;
    #[derive(Deserialize)]
    struct Signed {
        attestation_result: AttestationResult,
        certificate_sha256: String,
        not_after: String,
    }
    let signed: Signed =
        serde_json::from_value(signed).map_err(|e| invalid(format!("signed response: {e}")))?;
    let result = signed.attestation_result;

    let [leaf_pem, _] = bundle.certificate_chain.as_slice() else {
        return Err(invalid("certificate_chain is not [leaf, ca]"));
    };
    let leaf = pem_to_der(leaf_pem)?;
    if sha256_label(&leaf) != signed.certificate_sha256 {
        return Err(invalid("the leaf is not the one the receipt names"));
    }
    let verified_at = chrono::DateTime::parse_from_rfc3339(&result.verified_at)
        .map_err(|e| invalid(format!("verified_at: {e}")))?;
    let issued = SystemTime::from(verified_at);
    verify_leaf(&leaf, &pem_to_der(kms_ca_pem)?, issued)?;
    let sans = parse_instance_sans(&uri_sans(&leaf)?)?;
    let runtime_pubkey = bundle
        .request
        .get("runtime_pubkey")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("request: runtime_pubkey"))?;
    let spki = crate::decode("runtime_pubkey", runtime_pubkey)?;
    if spki_of(&leaf)? != spki
        || sha256_label(&spki) != result.runtime_pubkey_sha256
        || format!("sha256:{}", sans.runtime_pubkey_sha256_hex) != result.runtime_pubkey_sha256
    {
        return Err(invalid(
            "the leaf, the request and the result name different runtime keys",
        ));
    }
    if (sans.org_id, sans.app_id, sans.compose_hash)
        != (
            result.revision.org_id,
            result.revision.app_id,
            result.revision.compose_hash,
        )
    {
        return Err(invalid("the leaf names another Revision than the result"));
    }
    let evidence = bundle
        .request
        .get("evidence")
        .ok_or_else(|| invalid("request: evidence"))?;
    let evidence = alpha_core::jcs(evidence).map_err(|e| invalid(format!("evidence: {e}")))?;
    if sha256_label(&evidence) != result.evidence_sha256 {
        return Err(invalid(
            "the evidence is not the evidence the result was appraised from",
        ));
    }
    let verifiers = result.verifiers.clone().ok_or_else(|| {
        invalid("the result names no verifiers: the KMS that issued it predates clear claims")
    })?;
    Ok(VerifiedAttestation {
        result,
        verifiers,
        leaf_der: leaf,
        not_after: signed.not_after,
    })
}

/// `alphacompute-ccm-evidence-bundle/1`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CcmEvidenceBundle {
    pub format: String,
    /// The `POST /v1/attest/ccm` body: `runtime_pubkey`, `nonce`, `org_id` and `evidence`.
    pub request: Value,
    /// The reply's `attestation_receipt`.
    pub receipt: Value,
    /// The reply's `[leaf, KMS CA]`.
    pub certificate_chain: Vec<String>,
}

/// The CCM attestation result as signed by the KMS node into the receipt.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CcmAttestationResult {
    pub format: String,
    pub verdict: Verdict,
    pub org_id: OrgId,
    pub ccm_identity_id: CcmIdentityId,
    pub ccm: CcmAppraised,
    pub runtime_pubkey_sha256: String,
    pub evidence_sha256: String,
    pub verified_at: String,
    pub policy_version: u64,
    pub verifiers: Verifiers,
}

/// What a CCM bundle proves, all of it from the KMS's signature.
#[derive(Clone, Debug)]
pub struct VerifiedCcmAttestation {
    pub result: CcmAttestationResult,
    pub leaf_der: Vec<u8>,
    pub not_after: String,
}

/// Checks a CCM bundle against the KMS CA and the KMS Revisions the caller pins: the receipt is a
/// KMS node's signature over this CCM attest request, the leaf is the one it names and was issued
/// by that CA to the request's key for the allow-listed CCM identity, and the evidence is the
/// evidence the result was appraised from.
pub fn verify_ccm_bundle(
    bundle_json: &[u8],
    kms_ca_pem: &str,
    kms_revisions: &[ComposeHash],
) -> Result<VerifiedCcmAttestation, Error> {
    let bundle: CcmEvidenceBundle = alpha_core::parse(bundle_json)
        .and_then(serde_json::from_value)
        .map_err(|e| invalid(format!("CCM evidence bundle: {e}")))?;
    if bundle.format != CCM_BUNDLE_FORMAT {
        return Err(invalid(format!(
            "CCM evidence bundle format {:?}",
            bundle.format
        )));
    }
    let receipt_json =
        serde_json::to_vec(&bundle.receipt).map_err(|e| invalid(format!("receipt: {e}")))?;
    let expected = Expected {
        route: ATTEST_CCM_ROUTE.into(),
        request_sha256: receipt::request_sha256(&bundle.request)?,
        response: Map::new(),
    };
    let signed = receipt::verify(&receipt_json, kms_ca_pem, kms_revisions, &expected)?;
    #[derive(Deserialize)]
    struct Signed {
        attestation_result: CcmAttestationResult,
        certificate_sha256: String,
        not_after: String,
    }
    let signed: Signed =
        serde_json::from_value(signed).map_err(|e| invalid(format!("signed response: {e}")))?;
    let result = signed.attestation_result;

    let [leaf_pem, _] = bundle.certificate_chain.as_slice() else {
        return Err(invalid("certificate_chain is not [leaf, ca]"));
    };
    let leaf = pem_to_der(leaf_pem)?;
    if sha256_label(&leaf) != signed.certificate_sha256 {
        return Err(invalid("the leaf is not the one the receipt names"));
    }
    let verified_at = chrono::DateTime::parse_from_rfc3339(&result.verified_at)
        .map_err(|e| invalid(format!("verified_at: {e}")))?;
    let issued = SystemTime::from(verified_at);
    verify_leaf(&leaf, &pem_to_der(kms_ca_pem)?, issued)?;
    let sans = parse_ccm_sans(&uri_sans(&leaf)?)?;
    let runtime_pubkey = bundle
        .request
        .get("runtime_pubkey")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("request: runtime_pubkey"))?;
    let spki = crate::decode("runtime_pubkey", runtime_pubkey)?;
    if spki_of(&leaf)? != spki
        || sha256_label(&spki) != result.runtime_pubkey_sha256
        || format!("sha256:{}", sans.runtime_pubkey_sha256_hex) != result.runtime_pubkey_sha256
    {
        return Err(invalid(
            "the leaf, the request and the result name different runtime keys",
        ));
    }
    if (sans.org_id, sans.ccm_identity_id) != (result.org_id, result.ccm_identity_id) {
        return Err(invalid("the leaf names another CCM identity than the result"));
    }
    let evidence = bundle
        .request
        .get("evidence")
        .ok_or_else(|| invalid("request: evidence"))?;
    let evidence = alpha_core::jcs(evidence).map_err(|e| invalid(format!("evidence: {e}")))?;
    if sha256_label(&evidence) != result.evidence_sha256 {
        return Err(invalid(
            "the evidence is not the evidence the result was appraised from",
        ));
    }
    Ok(VerifiedCcmAttestation {
        result,
        leaf_der: leaf,
        not_after: signed.not_after,
    })
}
