//! A Kata confidential pod's attestation (`kata-tdx/1`, PRD-02) against a real Postgres
//! (`DATABASE_URL`; skipped without it): Revision v2 registration, the leaf naming it, the GPU
//! backends, and an audit row for every refusal. Pods attest over synthetic quotes (see
//! `common::kata`); the route's DCAP step is checked for evidence v2 with a quote that fails it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use std::sync::Arc;

use alpha_attest::{GpuVerifier, GpuVerifierKind, Party};
use alpha_client::attestation::verify_bundle;
use alpha_core::coco::{CPU_RUNTIME_CLASS, GPU_RUNTIME_CLASS};
use alpha_core::{AppId, context};
use alpha_kms::{certs, rfc3339};
use common::kata::*;
use common::*;
use reqwest::StatusCode;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[tokio::test]
async fn a_revision_v2_registers_and_its_gpu_pod_gets_a_leaf_naming_it() {
    let gpu = FakeGpu::new();
    let Some(h) = kata_harness(&gpu).await else {
        return;
    };
    let admin = h.register_key(&h.root, 31).await;
    let pod = Pod::gpu(AppId::mint(), 8);
    let body = pod.registration(&h, &admin);
    for _ in 0..2 {
        let (status, reply) = h.post("/v1/revisions", body.clone()).await;
        assert_eq!(status, StatusCode::OK, "{reply}");
        verified(
            &h,
            &reply,
            "revision.register",
            &body,
            json!({ "compose_hash": pod.hash(), "org_id": h.org }),
        );
    }

    let reply = pod.attest(&h).await.unwrap();
    let result = &reply["attestation_result"];
    assert_eq!(result["verdict"], "verified");
    assert_eq!(
        result["revision"],
        json!({ "compose_hash": pod.hash(), "app_id": pod.app, "org_id": h.org })
    );
    assert_eq!(result["os_image"], "nvidia-uvm-tdx/b300x8");
    let coco = &result["coco"];
    assert_eq!(coco["profile"], "kata-tdx/1");
    assert_eq!(coco["runtime_class"], GPU_RUNTIME_CLASS);
    assert_eq!(coco["policy_sha256"], json!(pod.revision().policy_sha256));
    assert_eq!(coco["gpus"].as_array().unwrap().len(), 8);
    assert!(
        coco["gpus"]
            .as_array()
            .unwrap()
            .iter()
            .all(|g| g["model"] == "B300" && g["cc_mode"] == true)
    );
    assert_eq!(
        coco["gpu_verifiers"],
        json!([{ "verifier": "nras", "token_sha256": format!("sha256:{}", "ab".repeat(32)) }])
    );
    assert_eq!(gpu.calls(), 1);
    assert_eq!(reply["certificate_chain"][1], json!(h.ca_pem));
    let runtime = hex::encode(Sha256::digest(pod.spki()));
    assert_eq!(
        leaf_sans(&reply),
        [
            format!("alphacompute://{}/{}/{runtime}", h.org, pod.app),
            format!("urn:alphacompute:revision:{}", pod.hash()),
        ]
    );
    let (_, outcome, details) = h.audit("attest").await.pop().unwrap();
    assert_eq!(outcome, "ok");
    assert_eq!(&details, result);
}

#[tokio::test]
async fn a_cpu_pod_gets_a_leaf_without_any_gpu_backend_or_gpu_policy() {
    let gpu = FakeGpu::new();
    let Some(h) = kata_harness(&gpu).await else {
        return;
    };
    let admin = h.register_key(&h.root, 32).await;
    let cpu = Pod::cpu(AppId::mint());
    cpu.register(&h, &admin).await;
    let gpu_pod = Pod::gpu(AppId::mint(), 1);
    gpu_pod.register(&h, &admin).await;
    let mut doc = kata_document(3);
    doc.as_object_mut().unwrap().remove("gpu_policy");
    publish(&h, doc).await;

    let reply = cpu.attest(&h).await.unwrap();
    let result = &reply["attestation_result"];
    assert_eq!(result["os_image"], "kata-tdx/cpu-4c-8g");
    assert_eq!(result["coco"]["runtime_class"], CPU_RUNTIME_CLASS);
    assert!(result["coco"].get("gpus").is_none());
    assert!(result["coco"].get("gpu_verifiers").is_none());
    assert_eq!(
        leaf_sans(&reply)[1],
        format!("urn:alphacompute:revision:{}", cpu.hash())
    );

    refused(
        &h,
        gpu_pod.attest(&h).await,
        "attestation_unknown",
        "the platform document has no gpu_policy",
    )
    .await;
    assert_eq!(gpu.calls(), 0);
}

#[tokio::test]
async fn evidence_v2_through_the_route_is_dcap_verified_and_audited() {
    let gpu = FakeGpu::new();
    let Some(h) = kata_harness(&gpu).await else {
        return;
    };
    let admin = h.register_key(&h.root, 33).await;
    let pod = Pod::gpu(AppId::mint(), 8);
    pod.register(&h, &admin).await;
    let nonce = fresh_nonce(&h);
    let body = |evidence: serde_json::Value| json!({ "runtime_pubkey": b64(&pod.spki()), "nonce": b64(&nonce), "evidence": evidence });

    let mut evidence = json!(pod.evidence(&nonce));
    let (status, reply) = h.post("/v1/attest", body(evidence.clone())).await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::FORBIDDEN, "attestation_failed"),
        "{reply}"
    );
    assert!(reply["error"]["message"].as_str().unwrap().contains("dcap"));
    evidence["cpu"]["kind"] = json!("snp");
    let (status, reply) = h.post("/v1/attest", body(evidence.clone())).await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::FORBIDDEN, "attestation_unknown"),
        "{reply}"
    );
    assert!(
        reply["error"]["message"]
            .as_str()
            .unwrap()
            .contains("no kata-snp/1 profile")
    );
    let rows = h.audit("attest").await;
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|(_, outcome, _)| outcome == "denied"));
    let with_evidence: i64 = sqlx::query_scalar(
        "select count(*) from audit_log where action = 'attest' and evidence_sha256 is not null",
    )
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert_eq!(with_evidence, 2);

    evidence["format"] = json!("alphacompute-evidence/3");
    let (status, reply) = h.post("/v1/attest", body(evidence)).await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::BAD_REQUEST, "malformed")
    );
    assert_eq!(gpu.calls(), 0);
}

#[tokio::test]
async fn a_kata_pod_whose_revision_or_gpu_backends_do_not_pass_is_refused_and_audited() {
    let gpu = FakeGpu::new();
    let Some(h) = kata_harness(&gpu).await else {
        return;
    };
    let admin = h.register_key(&h.root, 34).await;
    let pod = Pod::gpu(AppId::mint(), 8);

    refused(
        &h,
        pod.attest(&h).await,
        "attestation_unknown",
        &format!(
            "the Revision v2 of this init-data (policy {}) is not registered",
            pod.revision().policy_sha256
        ),
    )
    .await;
    let hash = pod.register(&h, &admin).await;

    // A backend the gpu_policy lists must run here: `local` never does, Fortanix CCM refuses
    // until F8.
    let mut doc = kata_document(3);
    doc["gpu_policy"]["verifiers"] = json!(["local"]);
    publish(&h, doc).await;
    refused(
        &h,
        pod.attest(&h).await,
        "attestation_unknown",
        "gpu verifier Local is not configured",
    )
    .await;
    let mut doc = kata_document(4);
    doc["gpu_policy"]["verifiers"] = json!(["nras", "fortanix-ccm"]);
    publish(&h, doc).await;
    refused(
        &h,
        pod.attest(&h).await,
        "attestation_unknown",
        "fortanix-ccm GPU verification at https://ccm.example is not available yet (F8)",
    )
    .await;
    publish(&h, kata_document(5)).await;
    pod.attest(&h).await.unwrap();

    // A TD check and a GPU check, each with its reason.
    let mut swapped = pod.clone();
    swapped.initdata = initdata(
        pod.app,
        GPU_RUNTIME_CLASS,
        Some(8),
        "package agent_policy\n",
    );
    let nonce = fresh_nonce(&h);
    let calls = gpu.calls();
    refused(
        &h,
        attest(
            &h,
            &swapped.request(&nonce, swapped.evidence(&nonce)),
            pod.quote(&nonce),
        )
        .await,
        "attestation_failed",
        "MRCONFIGID is not the digest of the init-data sent",
    )
    .await;
    assert_eq!(gpu.calls(), calls, "no GPU backend runs for a failed TD");
    let mut devtools = pod.clone();
    devtools.gpus[5].mode = "devtools".into();
    refused(
        &h,
        devtools.attest(&h).await,
        "policy_denied",
        "gpu 5: not in CC mode",
    )
    .await;

    let revoke = h.signed(
        context::CONTROL,
        json!({ "compose_hash": hash, "issued_at": rfc3339(h.now()) }),
        &admin,
    );
    let (status, reply) = h
        .post(&format!("/v1/revisions/{hash}/revoke"), revoke)
        .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    refused(
        &h,
        pod.attest(&h).await,
        "revision_revoked",
        "revision is revoked",
    )
    .await;
}

/// PRD-06 clear claims: every leaf comes with the KMS's signed statement of which verifiers
/// attested the workload, derived from its own appraisal, and an evidence bundle carrying it
/// verifies offline against the pinned KMS CA and nothing else.
#[tokio::test]
async fn every_leaf_comes_with_a_signed_statement_of_the_verifiers_that_attested_it() {
    let gpu = FakeGpu::new();
    let ccm = FakeGpu::of(GpuVerifierKind::FortanixCcm);
    let now = captured_at(KEYED);
    let backends: Vec<Arc<dyn GpuVerifier>> = vec![gpu.clone(), ccm.clone()];
    let Some(h) = harness_with(Arc::new(move || now), backends).await else {
        return;
    };
    publish(&h, kata_document(2)).await;
    let admin = h.register_key(&h.root, 33).await;
    let pod = Pod::gpu(AppId::mint(), 8);
    pod.register(&h, &admin).await;
    let cpu = Pod::cpu(AppId::mint());
    cpu.register(&h, &admin).await;
    let kms = [h.node.compose_hash];

    // NRAS alone: Alpha appraised the TD, NVIDIA's service vouched for the GPUs.
    let bundle = pod.bundle(&h).await;
    let verified = verify_bundle(&serde_json::to_vec(&bundle).unwrap(), &h.ca_pem, &kms).unwrap();
    assert_eq!(
        json!(verified.verifiers),
        json!({
            "format": "alphacompute-verifiers/1",
            "attested_by": ["alpha", "nvidia"],
            "cpu": [{ "verifier": "alpha-kms-dcap", "profile": "kata-tdx/1" }],
            "gpu": [{ "verifier": "nras", "token_sha256": format!("sha256:{}", "ab".repeat(32)) }],
        })
    );
    assert!(!verified.verifiers.attested_by(Party::Fortanix));
    assert_eq!(verified.result.revision.compose_hash, pod.hash());
    // The audit row records the same claims as the signed result.
    let (_, outcome, details) = h.audit("attest").await.pop().unwrap();
    assert_eq!(outcome, "ok");
    assert_eq!(details["verifiers"], json!(verified.verifiers));

    // A gpu_policy listing both backends: Fortanix CCM is named beside NVIDIA's.
    let mut doc = kata_document(3);
    doc["gpu_policy"]["verifiers"] = json!(["nras", "fortanix-ccm"]);
    publish(&h, doc).await;
    let both = pod.bundle(&h).await;
    let verified = verify_bundle(&serde_json::to_vec(&both).unwrap(), &h.ca_pem, &kms).unwrap();
    assert_eq!(
        verified.verifiers.attested_by,
        [Party::Alpha, Party::Nvidia, Party::Fortanix]
    );
    assert_eq!(
        verified.verifiers.gpu[1].token_sha256,
        format!("sha256:{}", "cc".repeat(32))
    );
    assert_eq!((gpu.calls(), ccm.calls()), (2, 1));

    // A CPU pod: Alpha alone, and no GPU entry.
    let alone = cpu.bundle(&h).await;
    let verified = verify_bundle(&serde_json::to_vec(&alone).unwrap(), &h.ca_pem, &kms).unwrap();
    assert_eq!(json!(verified.verifiers.attested_by), json!(["alpha"]));
    assert!(verified.verifiers.gpu.is_empty());

    // Nothing in a bundle can be changed without the check failing.
    let refused = |bundle: &Value, ca: &str, kms: &[alpha_core::ComposeHash]| {
        verify_bundle(&serde_json::to_vec(bundle).unwrap(), ca, kms)
            .unwrap_err()
            .to_string()
    };
    let mut claimed = bundle.clone();
    claimed["receipt"]["document"]["response"]["attestation_result"]["verifiers"]["attested_by"] =
        json!(["alpha", "fortanix"]);
    assert!(refused(&claimed, &h.ca_pem, &kms).contains("does not verify"));
    let mut other_evidence = bundle.clone();
    other_evidence["request"] = alone["request"].clone();
    assert!(refused(&other_evidence, &h.ca_pem, &kms).contains("another request"));
    let mut other_leaf = bundle.clone();
    other_leaf["certificate_chain"] = both["certificate_chain"].clone();
    assert!(refused(&other_leaf, &h.ca_pem, &kms).contains("not the one the receipt names"));
    let other_node = alpha_core::compose_hash("another KMS revision");
    assert!(refused(&bundle, &h.ca_pem, &[other_node]).contains("not in the allowlist"));
    let (_, other_ca) = certs::new_ca(h.now()).unwrap();
    assert!(!refused(&bundle, &certs::pem(&other_ca), &kms).is_empty());
    let mut unsigned = bundle.clone();
    unsigned["receipt"] = Value::Null;
    assert!(!refused(&unsigned, &h.ca_pem, &kms).is_empty());
}
