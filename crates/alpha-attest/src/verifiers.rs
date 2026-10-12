//! Clear claims (PRD-06 P1): which verifiers attested a workload, stated in every attestation
//! result. The KMS derives it from its own appraisal ([`Verifiers::of`]); nothing in it comes from
//! the workload, so a pod cannot claim a verifier that did not run.

use serde::{Deserialize, Serialize};

use crate::gpu::{GpuVerifierKind, GpuVouch};
use crate::{Appraised, EVIDENCE_FORMAT};

pub const VERIFIERS_FORMAT: &str = "alphacompute-verifiers/1";

/// Whose verifier appraised some of the evidence. PRD-06 asks for "Alpha, Fortanix, or both";
/// NVIDIA is named too when its hosted service (NRAS) vouched for the GPUs, because that is a
/// third party's verdict that alpha-kms only applied policy to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Party {
    Alpha,
    Nvidia,
    Fortanix,
}

/// Which verifier appraised the CPU evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CpuVerifierKind {
    /// alpha-kms itself: DCAP over Intel's collateral, then the profile's checks.
    AlphaKmsDcap,
}

impl CpuVerifierKind {
    pub fn party(self) -> Party {
        match self {
            Self::AlphaKmsDcap => Party::Alpha,
        }
    }
}

impl GpuVerifierKind {
    pub fn party(self) -> Party {
        match self {
            Self::Nras => Party::Nvidia,
            Self::Local => Party::Alpha,
            Self::FortanixCcm => Party::Fortanix,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CpuVouch {
    pub verifier: CpuVerifierKind,
    /// The appraisal profile: `kata-tdx/1`, or `alphacompute-evidence/1` for a prototype CVM.
    pub profile: String,
}

/// `alphacompute-verifiers/1`. Part of the attestation result, so it accepts fields it does not
/// know, as the rest of the result does.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verifiers {
    pub format: String,
    /// Every party below, once each, in [`Party`] order.
    pub attested_by: Vec<Party>,
    pub cpu: Vec<CpuVouch>,
    /// Every GPU backend the `gpu_policy` listed, each of which verified every GPU. Empty for a
    /// pod without GPUs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gpu: Vec<GpuVouch>,
}

impl Verifiers {
    /// What the KMS's own appraisal ran: alpha-kms's DCAP path for the CPU (the only CPU
    /// verifier there is), and the GPU backends that vouched, as `check_gpus` recorded them.
    pub fn of(appraised: &Appraised) -> Self {
        let profile = appraised
            .coco
            .as_ref()
            .map_or(EVIDENCE_FORMAT, |c| c.profile.as_str());
        let gpu = appraised
            .coco
            .as_ref()
            .map(|c| c.gpu_verifiers.clone())
            .unwrap_or_default();
        Self::new(
            vec![CpuVouch {
                verifier: CpuVerifierKind::AlphaKmsDcap,
                profile: profile.to_owned(),
            }],
            gpu,
        )
    }

    pub fn new(cpu: Vec<CpuVouch>, gpu: Vec<GpuVouch>) -> Self {
        let mut attested_by: Vec<Party> = cpu
            .iter()
            .map(|c| c.verifier.party())
            .chain(gpu.iter().map(|g| g.verifier.party()))
            .collect();
        attested_by.sort();
        attested_by.dedup();
        Self {
            format: VERIFIERS_FORMAT.into(),
            attested_by,
            cpu,
            gpu,
        }
    }

    pub fn attested_by(&self, party: Party) -> bool {
        self.attested_by.contains(&party)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::{CocoAppraised, Measured, Measurement};

    fn appraised(coco: Option<CocoAppraised>) -> Appraised {
        let m = Measurement([1; 48]);
        Appraised {
            measured: Measured {
                mrtd: m,
                rtmr0: m,
                rtmr1: m,
                rtmr2: m,
                rtmr3: m,
                mrconfigid: None,
            },
            tcb_status: "UpToDate".into(),
            advisories: vec![],
            os_image: "image".into(),
            compose_hash: alpha_core::compose_hash("{}"),
            runtime_pubkey_sha256: String::new(),
            evidence_sha256: String::new(),
            policy_version: 1,
            coco,
        }
    }

    fn pod(gpu_verifiers: Vec<GpuVouch>) -> CocoAppraised {
        CocoAppraised {
            profile: "kata-tdx/1".into(),
            initdata_sha256: alpha_core::compose_hash("i"),
            policy_sha256: alpha_core::compose_hash("p"),
            runtime_class: "kata-qemu-nvidia-gpu-tdx".into(),
            gpus: vec![],
            gpu_verifiers,
        }
    }

    fn vouch(verifier: GpuVerifierKind) -> GpuVouch {
        GpuVouch {
            verifier,
            token_sha256: format!("sha256:{}", "ab".repeat(32)),
        }
    }

    #[test]
    fn the_claims_name_exactly_the_verifiers_the_appraisal_ran() {
        let prototype = Verifiers::of(&appraised(None));
        assert_eq!(
            json!(prototype),
            json!({
                "format": "alphacompute-verifiers/1",
                "attested_by": ["alpha"],
                "cpu": [{ "verifier": "alpha-kms-dcap", "profile": "alphacompute-evidence/1" }],
            })
        );

        let cpu_pod = Verifiers::of(&appraised(Some(pod(vec![]))));
        assert_eq!(cpu_pod.attested_by, [Party::Alpha]);
        assert_eq!(cpu_pod.cpu[0].profile, "kata-tdx/1");
        assert!(cpu_pod.gpu.is_empty());

        let nras = Verifiers::of(&appraised(Some(pod(vec![vouch(GpuVerifierKind::Nras)]))));
        assert_eq!(nras.attested_by, [Party::Alpha, Party::Nvidia]);
        assert!(!nras.attested_by(Party::Fortanix));

        let both = Verifiers::of(&appraised(Some(pod(vec![
            vouch(GpuVerifierKind::FortanixCcm),
            vouch(GpuVerifierKind::Nras),
        ]))));
        assert_eq!(
            both.attested_by,
            [Party::Alpha, Party::Nvidia, Party::Fortanix]
        );
        assert_eq!(both.gpu[0].verifier, GpuVerifierKind::FortanixCcm);

        let local = Verifiers::of(&appraised(Some(pod(vec![vouch(GpuVerifierKind::Local)]))));
        assert_eq!(local.attested_by, [Party::Alpha]);
    }

    #[test]
    fn a_result_from_a_newer_kms_still_parses() {
        let parsed: Verifiers = serde_json::from_value(json!({
            "format": "alphacompute-verifiers/1",
            "attested_by": ["alpha"],
            "cpu": [{ "verifier": "alpha-kms-dcap", "profile": "kata-tdx/1", "later": 1 }],
            "later": true,
        }))
        .unwrap();
        assert!(parsed.attested_by(Party::Alpha));
    }
}
