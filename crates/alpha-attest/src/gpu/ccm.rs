//! The Fortanix Confidential Computing Manager backend (D1, hybrid). Its API for appraising
//! alpha-runtime's GPU evidence, and whether CCM covers B300 and Kata pods on GPU Operator nodes,
//! are vendor questions F1, F2 and F8, due 2026-10-30. Until they are answered this backend is
//! configured like any other and refuses every GPU, so a `gpu_policy` that lists `fortanix-ccm`
//! fails closed rather than silently skipping it.

use super::{GpuEvidence, GpuFuture, GpuPolicy, GpuVerifier, GpuVerifierKind};
use crate::AppraisalError;

pub struct FortanixCcm {
    /// The CCM endpoint the KMS will call once F8 settles the API.
    pub endpoint: String,
}

impl GpuVerifier for FortanixCcm {
    fn kind(&self) -> GpuVerifierKind {
        GpuVerifierKind::FortanixCcm
    }

    fn verify<'a>(
        &'a self,
        _gpus: &'a [GpuEvidence],
        _nonce: &'a [u8; 32],
        _policy: &'a GpuPolicy,
    ) -> GpuFuture<'a> {
        let endpoint = self.endpoint.clone();
        Box::pin(async move {
            Err(AppraisalError::Unknown(format!(
                "fortanix-ccm GPU verification at {endpoint} is not available yet (F8)"
            )))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn refuses_until_the_api_exists() {
        let ccm = FortanixCcm {
            endpoint: "https://ccm.example".into(),
        };
        let policy = GpuPolicy {
            allowed_models: vec![],
            min_driver_version: None,
            min_vbios_version: None,
            verifiers: vec![GpuVerifierKind::FortanixCcm],
            nras_url: None,
            hwmodels: Default::default(),
            nras_keys: Default::default(),
            nras_cc_mode: None,
        };
        let error = ccm.verify(&[], &[0; 32], &policy).await.unwrap_err();
        assert_eq!(error.code(), "attestation_unknown");
    }
}
