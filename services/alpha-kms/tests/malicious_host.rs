//! The malicious-host core suite (PRD-02 deliverable 7) against a real Postgres (`DATABASE_URL`;
//! skipped without it, run by CI's db-tests job). The host controls everything outside the TD: the
//! init-data it launches the pod with, the evidence on the wire, the GPUs it passes through, the
//! platform document it serves and the timing. Each case is refused by the KMS with its named
//! reason, an `attest` audit row records exactly that refusal, and no leaf is issued; where the TD
//! side fails, no GPU backend is called. Pods attest over synthetic quotes (`common::kata`), each
//! the quote a TD launched as the case describes would produce. Exec, log reads and container
//! changes are refused inside the guest by the agent policy; the full suite runs those against a
//! live pod.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use alpha_attest::gpu::gpu_nonce;
use alpha_attest::{EvidenceV2, VerifiedQuote};
use alpha_core::coco::{CPU_RUNTIME_CLASS, GPU_RUNTIME_CLASS};
use alpha_core::{AppId, KeyId, context};
use alpha_kms::error::ApiError;
use alpha_kms::instance::{self, AttestRequest};
use alpha_kms::{platform, rfc3339};
use common::kata::*;
use common::*;
use ed25519_dalek::SigningKey;
use reqwest::StatusCode;
use serde_json::{Value, json};

/// A KMS under [`kata_document`] with an eight-B300 pod's Revision v2 registered, which the honest
/// pod attests to.
struct Suite {
    h: Harness,
    gpu: Arc<FakeGpu>,
    pod: Pod,
    admin: (KeyId, SigningKey),
}

async fn suite() -> Option<Suite> {
    let gpu = FakeGpu::new();
    let h = kata_harness(&gpu).await?;
    let admin = h.register_key(&h.root, 41).await;
    let pod = Pod::gpu(AppId::mint(), 8);
    pod.register(&h, &admin).await;
    pod.attest(&h).await.unwrap();
    Some(Suite { h, gpu, pod, admin })
}

impl Suite {
    /// Attests and reports how many GPU backend calls the attempt made.
    async fn attest(
        &self,
        request: &AttestRequest,
        quote: VerifiedQuote,
    ) -> (Result<Value, ApiError>, usize) {
        let before = self.gpu.calls();
        let result = attest(&self.h, request, quote).await;
        (result, self.gpu.calls() - before)
    }

    /// `pod` with a fresh nonce, its evidence, and the quote its own TD produces.
    async fn attest_pod(&self, pod: &Pod) -> (Result<Value, ApiError>, usize) {
        let nonce = fresh_nonce(&self.h);
        self.attest(
            &pod.request(&nonce, pod.evidence(&nonce)),
            pod.quote(&nonce),
        )
        .await
    }

    /// The honest pod's evidence for `nonce`, edited by the host.
    fn evidence(&self, nonce: &[u8; 32], edit: impl FnOnce(&mut EvidenceV2)) -> EvidenceV2 {
        let mut evidence = self.pod.evidence(nonce);
        edit(&mut evidence);
        evidence
    }

    async fn refused(&self, result: Result<Value, ApiError>, code: &str, reason: &str) {
        refused(&self.h, result, code, reason).await;
    }
}

const EXEC_ALLOWED: &str =
    "package agent_policy\ndefault ExecProcessRequest := true\ndefault ReadStreamRequest := true\n";

#[tokio::test]
async fn init_data_swapped_or_edited_after_launch_is_refused() {
    let Some(s) = suite().await else {
        return;
    };
    let nonce = fresh_nonce(&s.h);
    // The TD booted with the registered init-data; the host sends another one beside its quote.
    let edited = initdata(s.pod.app, GPU_RUNTIME_CLASS, Some(8), EXEC_ALLOWED);
    let other_app = initdata(AppId::mint(), GPU_RUNTIME_CLASS, Some(8), POLICY);
    for initdata in [edited, other_app] {
        let evidence = s.evidence(&nonce, |e| e.initdata = initdata.into_bytes());
        let (result, calls) = s
            .attest(&s.pod.request(&nonce, evidence), s.pod.quote(&nonce))
            .await;
        s.refused(
            result,
            "attestation_failed",
            "MRCONFIGID is not the digest of the init-data sent",
        )
        .await;
        assert_eq!(calls, 0);
    }
}

#[tokio::test]
async fn a_replayed_or_foreign_nonce_is_refused() {
    let Some(s) = suite().await else {
        return;
    };
    // A whole exchange recorded earlier, nonce, evidence and quote, played back after the nonce
    // expired; and one over a nonce another KMS minted.
    let stale = instance::mint_nonce(
        &s.h.node.nonce_key,
        s.h.now() - instance::NONCE_MAX_AGE - Duration::from_secs(1),
    )
    .unwrap();
    let foreign = instance::mint_nonce(&[0x55; 32], s.h.now()).unwrap();
    for (nonce, reason) in [
        (stale, "nonce is too old"),
        (foreign, "nonce does not verify"),
    ] {
        let (result, calls) = s
            .attest(
                &s.pod.request(&nonce, s.pod.evidence(&nonce)),
                s.pod.quote(&nonce),
            )
            .await;
        s.refused(result, "nonce_invalid", reason).await;
        assert_eq!(calls, 0);
    }
}

#[tokio::test]
async fn a_quote_over_other_report_data_is_refused() {
    let Some(s) = suite().await else {
        return;
    };
    let nonce = fresh_nonce(&s.h);
    let earlier =
        instance::mint_nonce(&s.h.node.nonce_key, s.h.now() - Duration::from_secs(60)).unwrap();
    let mut host = s.pod.clone();
    host.key = p256::ecdsa::SigningKey::from_bytes((&[0x66u8; 32]).into()).unwrap();
    let cases = [
        // A quote replayed from an earlier attestation of this pod, under a fresh nonce.
        (
            s.pod.request(&nonce, s.pod.evidence(&nonce)),
            s.pod.quote(&earlier),
        ),
        // The pod's fresh quote and evidence under the host's own runtime key.
        (
            host.request(&nonce, s.pod.evidence(&nonce)),
            s.pod.quote(&nonce),
        ),
    ];
    for (request, quote) in cases {
        let (result, calls) = s.attest(&request, quote).await;
        s.refused(
            result,
            "attestation_failed",
            "report_data is not bound to this key and nonce",
        )
        .await;
        assert_eq!(calls, 0);
    }
}

#[tokio::test]
async fn a_dropped_added_duplicated_or_other_model_gpu_is_refused() {
    let Some(s) = suite().await else {
        return;
    };
    let mut dropped = s.pod.clone();
    dropped.gpus.pop();
    let (result, calls) = s.attest_pod(&dropped).await;
    s.refused(
        result,
        "attestation_failed",
        "7 GPUs attested, the Revision expects 8",
    )
    .await;
    assert_eq!(calls, 0, "counted before any backend call");

    let mut added = s.pod.clone();
    added.gpus.push(Gpu::b300(8));
    let (result, calls) = s.attest_pod(&added).await;
    s.refused(
        result,
        "attestation_failed",
        "9 GPUs attested, the Revision expects 8",
    )
    .await;
    assert_eq!(calls, 0);

    // One GPU's report presented twice in place of another GPU.
    let mut duplicated = s.pod.clone();
    duplicated.gpus[7] = duplicated.gpus[0].clone();
    let (result, _) = s.attest_pod(&duplicated).await;
    s.refused(
        result,
        "attestation_failed",
        "gpu 7: device ueid-0 is reported for another GPU of this pod too",
    )
    .await;

    let mut other_model = s.pod.clone();
    other_model.gpus[6].model = "H100".into();
    let (result, _) = s.attest_pod(&other_model).await;
    s.refused(
        result,
        "attestation_failed",
        "gpu 6: model H100 is not the Revision's B300",
    )
    .await;
}

#[tokio::test]
async fn gpu_evidence_bound_to_another_nonce_is_refused() {
    let Some(s) = suite().await else {
        return;
    };
    let earlier =
        instance::mint_nonce(&s.h.node.nonce_key, s.h.now() - Duration::from_secs(60)).unwrap();
    let mut replayed = s.pod.clone();
    replayed.gpus[2].nonce = Some(gpu_nonce(&s.pod.report_data(&earlier)));
    let (result, calls) = s.attest_pod(&replayed).await;
    s.refused(
        result,
        "attestation_failed",
        "gpu 2: report is not over this nonce",
    )
    .await;
    assert_eq!(calls, 1);
}

#[tokio::test]
async fn a_devtools_mode_or_cc_off_gpu_is_refused() {
    let Some(s) = suite().await else {
        return;
    };
    for mode in ["devtools", "off"] {
        let mut pod = s.pod.clone();
        pod.gpus[4].mode = mode.into();
        let (result, _) = s.attest_pod(&pod).await;
        s.refused(result, "policy_denied", "gpu 4: not in CC mode")
            .await;
    }
}

#[tokio::test]
async fn a_revoked_revision_gets_no_leaf() {
    let Some(s) = suite().await else {
        return;
    };
    let hash = s.pod.hash();
    let revoke = s.h.signed(
        context::CONTROL,
        json!({ "compose_hash": hash, "issued_at": rfc3339(s.h.now()) }),
        &s.admin,
    );
    let (status, reply) =
        s.h.post(&format!("/v1/revisions/{hash}/revoke"), revoke)
            .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let (result, _) = s.attest_pod(&s.pod).await;
    s.refused(result, "revision_revoked", "revision is revoked")
        .await;
}

#[tokio::test]
async fn a_rolled_back_platform_document_is_refused_and_the_newer_one_kept() {
    let Some(s) = suite().await else {
        return;
    };
    // Version 3 withdraws the GPU guest image the pod booted from in favour of a new one.
    let mut newer = kata_document(3);
    for value in newer["reference_values"].as_array_mut().unwrap() {
        if value["runtime_class"] == GPU_RUNTIME_CLASS {
            *value = reference_value(
                "nvidia-uvm-tdx/b300x8-2",
                GPU_RUNTIME_CLASS,
                [m(21), m(22), m(23), m(24)],
            );
        }
    }
    publish(&s.h, newer).await;
    let withdrawn = "no kata-tdx reference value for mrtd";
    let (result, calls) = s.attest_pod(&s.pod).await;
    s.refused(result, "attestation_unknown", withdrawn).await;
    assert_eq!(calls, 0);

    // The host serves version 2 again: release-signed, so it verifies, but it is older.
    s.h.release.set(kata_document(2));
    let error = platform::reload(&s.h.node).await.unwrap_err();
    assert!(
        error.message.contains("version 2 is below the stored 3"),
        "{}",
        error.message
    );
    let (_, outcome, details) = s.h.audit("platform.reload").await.pop().unwrap();
    assert_eq!(outcome, "denied");
    assert_eq!(
        details,
        json!({ "version": 2, "stored": 3, "message": error.message })
    );
    assert_eq!(s.h.node.platform_document().unwrap().version, 3);
    let (result, _) = s.attest_pod(&s.pod).await;
    s.refused(result, "attestation_unknown", withdrawn).await;
}

#[tokio::test]
async fn an_unknown_runtime_class_or_a_policy_hash_mismatch_is_refused() {
    let Some(s) = suite().await else {
        return;
    };
    let nonce = fresh_nonce(&s.h);
    // A class no Revision v2 may name; an SEV-SNP class claimed by a TD; and the CPU class claimed
    // by the GPU pod to skip its GPU checks, which its NVIDIA guest's registers do not match.
    for (class, code, reason) in [
        (
            "kata-qemu-nvidia-gpu-sev",
            "attestation_failed",
            "runtime class \"kata-qemu-nvidia-gpu-sev\" is not supported".to_owned(),
        ),
        (
            "kata-qemu-nvidia-gpu-snp",
            "attestation_failed",
            "runtime class kata-qemu-nvidia-gpu-snp does not run on Tdx".to_owned(),
        ),
        (
            CPU_RUNTIME_CLASS,
            "attestation_unknown",
            format!("and runtime class {CPU_RUNTIME_CLASS}"),
        ),
    ] {
        let evidence = s.evidence(&nonce, |e| e.runtime_class = class.into());
        let (result, calls) = s
            .attest(&s.pod.request(&nonce, evidence), s.pod.quote(&nonce))
            .await;
        s.refused(result, code, &reason).await;
        assert_eq!(calls, 0);
    }

    // The host launches the TD with a policy of its own, consistently: MRCONFIGID matches, but the
    // Revision v2 that init-data stands for is not the registered one.
    let mut launched = s.pod.clone();
    launched.initdata = initdata(s.pod.app, GPU_RUNTIME_CLASS, Some(8), EXEC_ALLOWED);
    let (result, _) = s.attest_pod(&launched).await;
    s.refused(
        result,
        "attestation_unknown",
        &format!(
            "the Revision v2 of this init-data (policy {}) is not registered",
            launched.revision().policy_sha256
        ),
    )
    .await;
}
