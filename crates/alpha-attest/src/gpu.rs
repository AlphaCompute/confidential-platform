//! GPU evidence (`nvidia-gpu/1`): what a confidential pod sends for every passed-through GPU, the
//! platform document's GPU policy, and the seam between them.
//!
//! The cryptographic verification of a GPU report (NVIDIA's certificate chain and revocation, the
//! driver and VBIOS RIMs, the SPDM signature, the nonce) is done by a [`GpuVerifier`] backend:
//! NVIDIA's (NRAS, or later the local verifier) or Fortanix CCM (D1, hybrid). Every backend
//! reduces what it verified to the same [`VerifiedGpu`] claims, and [`check_gpus`] applies the
//! platform document's policy and the Revision's GPU shape to them. That last step is pure and is
//! the one that decides, so which backend ran never changes what a leaf means.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use alpha_core::coco::GpuShape;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{AppraisalError, base64url};

/// One GPU's evidence as collected in the guest: the SPDM attestation report and the device's
/// certificate chain, both as the NVIDIA attestation SDK hands them out.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GpuEvidence {
    /// NVIDIA's architecture token, e.g. `BLACKWELL`.
    pub arch: String,
    #[serde(with = "base64url")]
    pub evidence: Vec<u8>,
    #[serde(with = "base64url")]
    pub certificate: Vec<u8>,
}

/// Which backend verifies GPU evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GpuVerifierKind {
    /// NVIDIA Remote Attestation Service.
    Nras,
    /// NVIDIA's verifier run by the KMS with cached RIMs and OCSP (after Dec 1).
    Local,
    /// Fortanix Confidential Computing Manager (D1; awaits F1, F2, F8, F9).
    FortanixCcm,
}

/// The platform document's `gpu_policy`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GpuPolicy {
    /// Model names a Revision may expect, e.g. `["B300"]`.
    pub allowed_models: Vec<String>,
    /// Dotted versions; a GPU below either is refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_driver_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_vbios_version: Option<String>,
    /// Every backend listed must verify every GPU; the first listed supplies the reported claims.
    pub verifiers: Vec<GpuVerifierKind>,
    /// NRAS's base URL; NVIDIA's public service when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nras_url: Option<String>,
}

/// What a backend proved about one GPU, after its own cryptographic checks passed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedGpu {
    /// Position in the evidence's `gpus`.
    pub index: u32,
    /// Normalized to the policy's model names, e.g. `B300`.
    pub model: String,
    pub driver_version: String,
    pub vbios_version: String,
    pub cc_mode: bool,
    /// The nonce the verified report was over.
    #[serde(with = "hex::serde")]
    pub nonce: [u8; 32],
}

/// One backend's result over all of a pod's GPUs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GpuAppraisal {
    pub verifier: GpuVerifierKind,
    pub gpus: Vec<VerifiedGpu>,
}

/// The 32-byte nonce every GPU report is bound to: SHA-256 of the quote's `report_data`, so a GPU
/// report is over the same runtime key and KMS nonce (and, for a node, X-Wing key) as the TD.
pub fn gpu_nonce(report_data: &[u8; 64]) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"alphacompute/gpu-nonce/v1")
        .chain_update(report_data)
        .finalize()
        .into()
}

pub type GpuFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Vec<VerifiedGpu>, AppraisalError>> + Send + 'a>>;

/// A GPU verifier backend. It must fail rather than return a GPU it could not fully verify;
/// [`check_gpus`] then applies policy to what it returns.
pub trait GpuVerifier: Send + Sync {
    fn kind(&self) -> GpuVerifierKind;
    fn verify<'a>(
        &'a self,
        gpus: &'a [GpuEvidence],
        nonce: &'a [u8; 32],
        policy: &'a GpuPolicy,
    ) -> GpuFuture<'a>;
}

/// Runs every backend the policy lists, failing closed on a listed backend that is not
/// configured or that fails.
pub async fn verify_gpus(
    backends: &[Arc<dyn GpuVerifier>],
    gpus: &[GpuEvidence],
    nonce: &[u8; 32],
    policy: &GpuPolicy,
) -> Result<Vec<GpuAppraisal>, AppraisalError> {
    let mut out = Vec::with_capacity(policy.verifiers.len());
    for kind in &policy.verifiers {
        let backend = backends.iter().find(|b| b.kind() == *kind).ok_or_else(|| {
            AppraisalError::Unknown(format!("gpu verifier {kind:?} is not configured"))
        })?;
        out.push(GpuAppraisal {
            verifier: *kind,
            gpus: backend.verify(gpus, nonce, policy).await?,
        });
    }
    Ok(out)
}

/// The decision over the backends' results: the Revision's GPU shape, the policy, and the nonce.
/// `expected` is the Revision's `gpu`; `evidence_count` is how many GPUs the pod sent evidence for.
pub fn check_gpus(
    policy: Option<&GpuPolicy>,
    expected: Option<&GpuShape>,
    evidence_count: usize,
    appraisals: &[GpuAppraisal],
    nonce: &[u8; 32],
) -> Result<Vec<VerifiedGpu>, AppraisalError> {
    use AppraisalError::*;

    let Some(shape) = expected else {
        if evidence_count != 0 {
            return Err(Failed(format!(
                "{evidence_count} GPU evidence entries for a Revision that expects no GPU"
            )));
        }
        return Ok(Vec::new());
    };
    let policy = policy.ok_or_else(|| Unknown("the platform document has no gpu_policy".into()))?;
    if policy.verifiers.is_empty() {
        return Err(PolicyDenied("gpu_policy lists no verifier".into()));
    }
    if !policy.allowed_models.contains(&shape.model) {
        return Err(PolicyDenied(format!(
            "gpu model {} is not allowed",
            shape.model
        )));
    }
    let count = usize::try_from(shape.count).map_err(|_| Failed("gpu count".into()))?;
    if evidence_count != count {
        return Err(Failed(format!(
            "{evidence_count} GPUs attested, the Revision expects {}",
            shape.count
        )));
    }
    for kind in &policy.verifiers {
        let appraisal = appraisals
            .iter()
            .find(|a| a.verifier == *kind)
            .ok_or_else(|| Failed(format!("gpu verifier {kind:?} did not run")))?;
        if appraisal.gpus.len() != count {
            return Err(Failed(format!(
                "gpu verifier {kind:?} verified {} GPUs, the Revision expects {}",
                appraisal.gpus.len(),
                shape.count
            )));
        }
        let mut seen = vec![false; count];
        for gpu in &appraisal.gpus {
            let slot = usize::try_from(gpu.index)
                .ok()
                .and_then(|i| seen.get_mut(i))
                .ok_or_else(|| Failed(format!("gpu index {} is out of range", gpu.index)))?;
            if std::mem::replace(slot, true) {
                return Err(Failed(format!("gpu index {} verified twice", gpu.index)));
            }
            check_gpu(policy, shape, gpu, nonce)?;
        }
    }
    let first = policy
        .verifiers
        .first()
        .ok_or_else(|| Failed("no verifier".into()))?;
    let mut gpus = appraisals
        .iter()
        .find(|a| a.verifier == *first)
        .map(|a| a.gpus.clone())
        .unwrap_or_default();
    gpus.sort_by_key(|g| g.index);
    Ok(gpus)
}

fn check_gpu(
    policy: &GpuPolicy,
    shape: &GpuShape,
    gpu: &VerifiedGpu,
    nonce: &[u8; 32],
) -> Result<(), AppraisalError> {
    use AppraisalError::*;
    let i = gpu.index;
    if gpu.nonce != *nonce {
        return Err(Failed(format!("gpu {i}: report is not over this nonce")));
    }
    if !gpu.cc_mode {
        return Err(PolicyDenied(format!("gpu {i}: not in CC mode")));
    }
    if gpu.model != shape.model {
        return Err(Failed(format!(
            "gpu {i}: model {} is not the Revision's {}",
            gpu.model, shape.model
        )));
    }
    for (what, have, min) in [
        ("driver", &gpu.driver_version, &policy.min_driver_version),
        ("vbios", &gpu.vbios_version, &policy.min_vbios_version),
    ] {
        if let Some(min) = min
            && !at_least(have, min).ok_or_else(|| {
                Failed(format!(
                    "gpu {i}: {what} version {have:?} or {min:?} does not parse"
                ))
            })?
        {
            return Err(PolicyDenied(format!(
                "gpu {i}: {what} version {have} is below {min}"
            )));
        }
    }
    Ok(())
}

/// `have >= min` over dot-separated segments read as hexadecimal (VBIOS versions are hex pairs;
/// for digit-only driver segments the order is the decimal order), a missing segment being zero.
fn at_least(have: &str, min: &str) -> Option<bool> {
    let parse = |v: &str| -> Option<Vec<u64>> {
        v.split('.')
            .map(|s| {
                (!s.is_empty() && s.len() <= 8)
                    .then(|| u64::from_str_radix(s, 16).ok())
                    .flatten()
            })
            .collect()
    };
    let (have, min) = (parse(have)?, parse(min)?);
    let len = have.len().max(min.len());
    let at = |v: &[u64], i: usize| v.get(i).copied().unwrap_or(0);
    for i in 0..len {
        match at(&have, i).cmp(&at(&min, i)) {
            std::cmp::Ordering::Greater => return Some(true),
            std::cmp::Ordering::Less => return Some(false),
            std::cmp::Ordering::Equal => {}
        }
    }
    Some(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONCE: [u8; 32] = [7; 32];

    fn policy() -> GpuPolicy {
        GpuPolicy {
            allowed_models: vec!["B300".into()],
            min_driver_version: Some("570.124.06".into()),
            min_vbios_version: Some("97.00.82.00.01".into()),
            verifiers: vec![GpuVerifierKind::Nras],
            nras_url: None,
        }
    }

    fn gpu(index: u32) -> VerifiedGpu {
        VerifiedGpu {
            index,
            model: "B300".into(),
            driver_version: "575.51.03".into(),
            vbios_version: "97.00.9a.00.01".into(),
            cc_mode: true,
            nonce: NONCE,
        }
    }

    fn shape(count: u32) -> GpuShape {
        GpuShape {
            count,
            model: "B300".into(),
        }
    }

    fn nras(gpus: Vec<VerifiedGpu>) -> Vec<GpuAppraisal> {
        vec![GpuAppraisal {
            verifier: GpuVerifierKind::Nras,
            gpus,
        }]
    }

    fn denied(
        expected: Option<GpuShape>,
        evidence: usize,
        appraisals: Vec<GpuAppraisal>,
    ) -> (String, String) {
        let e = check_gpus(
            Some(&policy()),
            expected.as_ref(),
            evidence,
            &appraisals,
            &NONCE,
        )
        .unwrap_err();
        (e.code().to_owned(), e.to_string())
    }

    #[test]
    fn eight_verified_gpus_pass_in_index_order() {
        let mut gpus: Vec<_> = (0..8).map(gpu).collect();
        gpus.reverse();
        let out = check_gpus(Some(&policy()), Some(&shape(8)), 8, &nras(gpus), &NONCE).unwrap();
        assert_eq!(
            out.iter().map(|g| g.index).collect::<Vec<_>>(),
            (0..8).collect::<Vec<_>>()
        );
        assert!(check_gpus(None, None, 0, &[], &NONCE).unwrap().is_empty());
    }

    #[test]
    fn malicious_host_gpu_cases_are_refused() {
        let cc_off = VerifiedGpu {
            cc_mode: false,
            ..gpu(0)
        };
        let stale = VerifiedGpu {
            nonce: [8; 32],
            ..gpu(0)
        };
        let h100 = VerifiedGpu {
            model: "H100".into(),
            ..gpu(0)
        };
        let old_driver = VerifiedGpu {
            driver_version: "550.90.07".into(),
            ..gpu(0)
        };
        let old_vbios = VerifiedGpu {
            vbios_version: "96.00.ff.00.01".into(),
            ..gpu(0)
        };
        for (case, (code, reason)) in [
            (
                "not in CC mode",
                denied(Some(shape(1)), 1, nras(vec![cc_off])),
            ),
            ("stale nonce", denied(Some(shape(1)), 1, nras(vec![stale]))),
            ("wrong model", denied(Some(shape(1)), 1, nras(vec![h100]))),
            (
                "old driver",
                denied(Some(shape(1)), 1, nras(vec![old_driver])),
            ),
            (
                "old vbios",
                denied(Some(shape(1)), 1, nras(vec![old_vbios])),
            ),
            (
                "fewer GPUs than the Revision",
                denied(Some(shape(8)), 1, nras(vec![gpu(0)])),
            ),
            (
                "more GPUs than verified",
                denied(Some(shape(8)), 8, nras(vec![gpu(0)])),
            ),
            (
                "same GPU twice",
                denied(Some(shape(1)), 1, nras(vec![gpu(0), gpu(0)])),
            ),
            (
                "index out of range",
                denied(Some(shape(1)), 1, nras(vec![gpu(3)])),
            ),
            ("GPU on a CPU Revision", denied(None, 1, vec![])),
            ("verifier did not run", denied(Some(shape(1)), 1, vec![])),
        ] {
            assert!(
                matches!(code.as_str(), "attestation_failed" | "policy_denied"),
                "{case}: {code} {reason}"
            );
        }
        let (code, reason) = denied(Some(shape(1)), 1, nras(vec![cc_off_gpu()]));
        assert_eq!(
            (code.as_str(), reason.contains("CC mode")),
            ("policy_denied", true)
        );
    }

    fn cc_off_gpu() -> VerifiedGpu {
        VerifiedGpu {
            cc_mode: false,
            ..gpu(0)
        }
    }

    #[test]
    fn policy_gates_models_and_requires_every_listed_verifier() {
        let mut both = policy();
        both.verifiers.push(GpuVerifierKind::FortanixCcm);
        let error =
            check_gpus(Some(&both), Some(&shape(1)), 1, &nras(vec![gpu(0)]), &NONCE).unwrap_err();
        assert!(error.to_string().contains("FortanixCcm"), "{error}");

        let mut appraisals = nras(vec![gpu(0)]);
        appraisals.push(GpuAppraisal {
            verifier: GpuVerifierKind::FortanixCcm,
            gpus: vec![gpu(0)],
        });
        assert!(check_gpus(Some(&both), Some(&shape(1)), 1, &appraisals, &NONCE).is_ok());

        let h100 = GpuShape {
            count: 1,
            model: "H100".into(),
        };
        let error = check_gpus(Some(&policy()), Some(&h100), 1, &[], &NONCE).unwrap_err();
        assert_eq!(error.code(), "policy_denied");
        let error = check_gpus(None, Some(&shape(1)), 1, &[], &NONCE).unwrap_err();
        assert_eq!(error.code(), "attestation_unknown");
    }

    #[test]
    fn versions_compare_by_segment() {
        assert_eq!(at_least("570.124.06", "570.124.06"), Some(true));
        assert_eq!(at_least("570.124.6", "570.124.06"), Some(true));
        assert_eq!(at_least("575.1", "570.124.06"), Some(true));
        assert_eq!(at_least("570.86", "570.124"), Some(false));
        assert_eq!(at_least("1000", "999"), Some(true));
        assert_eq!(at_least("97.00.9a", "97.00.82"), Some(true));
        assert_eq!(at_least("570", "570.0.1"), Some(false));
        assert_eq!(at_least("57x", "570"), None);
        assert_eq!(at_least("", "570"), None);
    }

    #[test]
    fn gpu_nonce_binds_the_whole_report_data() {
        let mut rd = [0u8; 64];
        let a = gpu_nonce(&rd);
        rd[63] = 1;
        assert_ne!(a, gpu_nonce(&rd));
    }

    struct Fixed(GpuVerifierKind, Result<Vec<VerifiedGpu>, String>);

    impl GpuVerifier for Fixed {
        fn kind(&self) -> GpuVerifierKind {
            self.0
        }
        fn verify<'a>(
            &'a self,
            _: &'a [GpuEvidence],
            _: &'a [u8; 32],
            _: &'a GpuPolicy,
        ) -> GpuFuture<'a> {
            let out = self.1.clone().map_err(AppraisalError::Failed);
            Box::pin(async move { out })
        }
    }

    #[tokio::test]
    async fn verify_gpus_runs_listed_backends_and_fails_closed() {
        let ok: Arc<dyn GpuVerifier> = Arc::new(Fixed(GpuVerifierKind::Nras, Ok(vec![gpu(0)])));
        let out = verify_gpus(std::slice::from_ref(&ok), &[], &NONCE, &policy())
            .await
            .unwrap();
        assert_eq!(out, nras(vec![gpu(0)]));

        let error = verify_gpus(&[], &[], &NONCE, &policy()).await.unwrap_err();
        assert_eq!(error.code(), "attestation_unknown");

        let failing: Arc<dyn GpuVerifier> =
            Arc::new(Fixed(GpuVerifierKind::Nras, Err("nras is down".into())));
        let error = verify_gpus(&[failing], &[], &NONCE, &policy())
            .await
            .unwrap_err();
        assert!(error.to_string().contains("nras is down"));
    }
}
