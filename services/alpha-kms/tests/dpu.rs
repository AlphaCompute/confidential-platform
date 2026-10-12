//! NIC/DPU composite attestation (`nvidia-dpu/1`, PRD-02 P2) against a real Postgres
//! (`DATABASE_URL`; skipped without it). Pods present synthetic DPU transcripts that `FakeDpu`
//! reports as they describe themselves, so the KMS's own decisions are what refuse; the SPDM
//! verifier itself is `alpha_attest::dpu` tests (no BlueField capture exists,
//! `ponytail: dpu-capture`).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use alpha_core::AppId;
use common::kata::*;

#[tokio::test]
async fn a_pod_whose_revision_expects_a_dpu_gets_a_leaf_only_with_it() {
    let gpu = FakeGpu::new();
    let Some(h) = kata_harness(&gpu).await else {
        return;
    };
    let admin = h.register_key(&h.root, 51).await;
    let pod = Pod::gpu(AppId::mint(), 8).with_dpus(1);
    assert_eq!(pod.revision().dpu.unwrap().model, DPU_MODEL);
    pod.register(&h, &admin).await;

    let reply = pod.attest(&h).await.unwrap();
    let coco = &reply["attestation_result"]["coco"];
    assert_eq!(coco["gpus"].as_array().unwrap().len(), 8);
    assert_eq!(coco["dpus"].as_array().unwrap().len(), 1);
    assert_eq!(coco["dpus"][0]["model"], DPU_MODEL);
    assert_eq!(coco["dpus"][0]["revocation_checked"], false);
    assert_eq!(gpu.calls(), 1);

    // The host drops the DPU evidence: refused before any GPU backend runs.
    let mut dropped = pod.clone();
    dropped.dpus.clear();
    refused(
        &h,
        dropped.attest(&h).await,
        "attestation_failed",
        "0 DPUs attested, the Revision expects 1",
    )
    .await;
    assert_eq!(gpu.calls(), 1);
    // A transcript over another nonce (replayed from an earlier attestation).
    let mut replayed = pod.clone();
    replayed.dpus[0].nonce = Some([7; 32]);
    refused(
        &h,
        replayed.attest(&h).await,
        "attestation_failed",
        "dpu 0: transcript is not over this nonce",
    )
    .await;
    // Another device model than the Revision's.
    let mut other = pod.clone();
    other.dpus[0].model = "CONNECTX-7".into();
    refused(
        &h,
        other.attest(&h).await,
        "attestation_failed",
        "model CONNECTX-7 is not the Revision's",
    )
    .await;

    // No dpu_policy in the document: no Revision expecting a DPU attests.
    let mut doc = kata_document(3);
    doc.as_object_mut().unwrap().remove("dpu_policy");
    publish(&h, doc).await;
    refused(
        &h,
        pod.attest(&h).await,
        "attestation_unknown",
        "the platform document has no dpu_policy",
    )
    .await;
}

#[tokio::test]
async fn dpu_evidence_from_a_pod_that_expects_none_is_refused() {
    let gpu = FakeGpu::new();
    let Some(h) = kata_harness(&gpu).await else {
        return;
    };
    let admin = h.register_key(&h.root, 52).await;
    let cpu = Pod::cpu(AppId::mint());
    cpu.register(&h, &admin).await;
    let mut extra = cpu.clone();
    extra.dpus = Pod::cpu(cpu.app).with_dpus(1).dpus;
    refused(
        &h,
        extra.attest(&h).await,
        "attestation_failed",
        "NIC/DPU evidence from a pod whose Revision expects no DPU",
    )
    .await;
    let reply = cpu.attest(&h).await.unwrap();
    assert!(reply["attestation_result"]["coco"].get("dpus").is_none());

    // The same App's Revision with a DPU is another Revision: registering one does not let the
    // other attest.
    let with = Pod::cpu(cpu.app).with_dpus(1);
    assert_ne!(with.hash(), cpu.hash());
    refused(
        &h,
        with.attest(&h).await,
        "attestation_unknown",
        "is not registered",
    )
    .await;
}
