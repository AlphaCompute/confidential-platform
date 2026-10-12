//! A Kata confidential pod on SEV-SNP (`kata-snp/1`, PRD-02 P2) against a real Postgres
//! (`DATABASE_URL`; skipped without it). The route verifies virtee's real Milan report under AMD's
//! pinned chain and real CRL, then refuses it at the checks that are ours (it is not a guest of
//! ours); SNP pods of ours attest over synthetic verified reports (see `common::kata`), since we
//! have no SNP hardware (`ponytail: snp-capture`).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use alpha_core::AppId;
use alpha_core::coco::{SNP_CPU_RUNTIME_CLASS, SNP_GPU_RUNTIME_CLASS};
use common::kata::*;
use common::*;
use reqwest::StatusCode;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// virtee's Milan report as an SNP pod of `pod`'s would send it, with its VCEK.
fn virtee_evidence(pod: &Pod, nonce: &[u8; 32]) -> Value {
    let report = hex::decode(text("snp-virtee-milan", "report.hex").trim()).unwrap();
    let mut evidence = json!(pod.evidence(nonce));
    evidence["cpu"]["quote"] = json!(b64(&report));
    evidence["cpu"]["vek"] = json!(b64(&read("snp-virtee-milan", "vcek.der")));
    evidence
}

#[tokio::test]
async fn an_snp_report_through_the_route_is_verified_to_amds_pinned_chain_and_audited() {
    // 2026-10-12T00:00:00Z, inside AMD's CRL window.
    let now = UNIX_EPOCH + Duration::from_secs(1_791_763_200);
    let gpu = FakeGpu::new();
    let Some(h) = harness_with(Arc::new(move || now), vec![gpu.clone()]).await else {
        return;
    };
    let admin = h.register_key(&h.root, 41).await;
    let pod = Pod::snp_cpu(AppId::mint());
    pod.register(&h, &admin).await;
    let nonce = fresh_nonce(&h);
    let body = |evidence: Value| json!({ "runtime_pubkey": b64(&pod.spki()), "nonce": b64(&nonce), "evidence": evidence });
    let refused_with = |reply: &Value, status: StatusCode, code: &str, reason: &str| {
        assert_eq!(status, StatusCode::FORBIDDEN, "{reply}");
        assert_eq!(reply["error"]["code"], code, "{reply}");
        let message = reply["error"]["message"].as_str().unwrap();
        assert!(message.contains(reason), "{message}");
    };

    // No snp_policy in the document: no SNP pod can attest.
    publish(&h, kata_document(3)).await;
    let (status, reply) = h
        .post("/v1/attest", body(virtee_evidence(&pod, &nonce)))
        .await;
    refused_with(&reply, status, "attestation_unknown", "no snp_policy");

    // With AMD's Milan chain pinned, the report verifies and the profile's own checks refuse it:
    // virtee's guest measurement is no reference value of ours.
    let mut doc = kata_document(4);
    doc["snp_policy"] = snp_policy();
    publish(&h, doc.clone()).await;
    let (status, reply) = h
        .post("/v1/attest", body(virtee_evidence(&pod, &nonce)))
        .await;
    refused_with(
        &reply,
        status,
        "attestation_unknown",
        "no kata-snp reference value for measurement sha384:7a1e5c26",
    );
    // Listed, it reaches HOST_DATA, which binds no init-data of ours.
    let measurement = "sha384:7a1e5c266c0108dbc9bb94fa926951320940915d0aafb42464bd88b579ea158d3e1a0dc39b2c60bd95b9c480cd81841f";
    doc["version"] = json!(5);
    doc["reference_values"]
        .as_array_mut()
        .unwrap()
        .push(json!({ "name": "virtee-test-guest", "kind": "kata-snp",
                      "runtime_class": SNP_CPU_RUNTIME_CLASS, "values": { "measurement": measurement } }));
    publish(&h, doc.clone()).await;
    let (status, reply) = h
        .post("/v1/attest", body(virtee_evidence(&pod, &nonce)))
        .await;
    refused_with(
        &reply,
        status,
        "attestation_failed",
        "HOST_DATA is not the digest of the init-data sent",
    );

    // One changed byte of the report, a host that SMT the policy forbids, a VCEK left out of a
    // version 2 report, and a KDS that does not serve the product's CRL.
    let mut tampered = virtee_evidence(&pod, &nonce);
    let mut report = hex::decode(text("snp-virtee-milan", "report.hex").trim()).unwrap();
    report[0x50] ^= 1;
    tampered["cpu"]["quote"] = json!(b64(&report));
    let (status, reply) = h.post("/v1/attest", body(tampered)).await;
    refused_with(
        &reply,
        status,
        "attestation_failed",
        "signature does not verify",
    );
    let mut no_smt = doc.clone();
    no_smt["version"] = json!(6);
    no_smt["snp_policy"]["allow_smt"] = json!(false);
    publish(&h, no_smt).await;
    let (status, reply) = h
        .post("/v1/attest", body(virtee_evidence(&pod, &nonce)))
        .await;
    refused_with(&reply, status, "policy_denied", "SMT enabled");
    let mut no_vcek = virtee_evidence(&pod, &nonce);
    no_vcek["cpu"].as_object_mut().unwrap().remove("vek");
    let (status, reply) = h.post("/v1/attest", body(no_vcek)).await;
    refused_with(&reply, status, "attestation_failed", "must carry its VCEK");
    let mut elsewhere = doc;
    elsewhere["version"] = json!(7);
    elsewhere["snp_policy"]["kds_url"] = json!("https://kds.example/other");
    publish(&h, elsewhere).await;
    let (status, reply) = h
        .post("/v1/attest", body(virtee_evidence(&pod, &nonce)))
        .await;
    refused_with(&reply, status, "attestation_failed", "status 404");

    let rows = h.audit("attest").await;
    assert_eq!(rows.len(), 7);
    assert!(rows.iter().all(|(_, outcome, _)| outcome == "denied"));
    assert_eq!(gpu.calls(), 0);
}

#[tokio::test]
async fn snp_pods_get_a_leaf_naming_their_revision_v2() {
    let gpu = FakeGpu::new();
    let Some(h) = kata_harness(&gpu).await else {
        return;
    };
    let admin = h.register_key(&h.root, 42).await;

    let cpu = Pod::snp_cpu(AppId::mint());
    cpu.register(&h, &admin).await;
    let reply = cpu.attest(&h).await.unwrap();
    let result = &reply["attestation_result"];
    assert_eq!(result["verdict"], "verified");
    assert_eq!(result["os_image"], "kata-snp/cpu-4c-8g");
    assert_eq!(result["tcb_status"], "AtOrAboveMinimum");
    assert!(result.get("measured").is_none(), "{result}");
    let coco = &result["coco"];
    assert_eq!(coco["profile"], "kata-snp/1");
    assert_eq!(coco["runtime_class"], SNP_CPU_RUNTIME_CLASS);
    assert_eq!(coco["snp"]["signing_key"], "vcek");
    assert_eq!(
        coco["snp"]["measurement"],
        json!(snp_measurement(SNP_CPU_RUNTIME_CLASS))
    );
    assert!(coco.get("gpus").is_none());
    let runtime = hex::encode(Sha256::digest(cpu.spki()));
    assert_eq!(
        leaf_sans(&reply),
        [
            format!("alphacompute://{}/{}/{runtime}", h.org, cpu.app),
            format!("urn:alphacompute:revision:{}", cpu.hash()),
        ]
    );
    let (_, outcome, details) = h.audit("attest").await.pop().unwrap();
    assert_eq!(outcome, "ok");
    assert_eq!(&details, result);
    assert_eq!(gpu.calls(), 0);

    let gpus = Pod::snp_gpu(AppId::mint(), 8);
    gpus.register(&h, &admin).await;
    let reply = gpus.attest(&h).await.unwrap();
    let coco = &reply["attestation_result"]["coco"];
    assert_eq!(coco["profile"], "kata-snp/1");
    assert_eq!(coco["runtime_class"], SNP_GPU_RUNTIME_CLASS);
    assert_eq!(coco["gpus"].as_array().unwrap().len(), 8);
    assert_eq!(gpu.calls(), 1);
}

#[tokio::test]
async fn snp_pods_are_refused_as_tdx_pods_are_and_audited() {
    let gpu = FakeGpu::new();
    let Some(h) = kata_harness(&gpu).await else {
        return;
    };
    let admin = h.register_key(&h.root, 43).await;
    let pod = Pod::snp_gpu(AppId::mint(), 8);

    // Not registered; the TDX pod of the same App is another Revision.
    let tdx = Pod {
        app: pod.app,
        ..Pod::gpu(pod.app, 8)
    };
    tdx.register(&h, &admin).await;
    refused(
        &h,
        pod.attest(&h).await,
        "attestation_unknown",
        "the Revision v2 of this init-data",
    )
    .await;
    pod.register(&h, &admin).await;
    pod.attest(&h).await.unwrap();

    // The host swaps the init-data after launch: HOST_DATA holds the launched one's digest.
    let nonce = fresh_nonce(&h);
    let mut swapped = pod.clone();
    swapped.initdata = initdata(
        pod.app,
        SNP_GPU_RUNTIME_CLASS,
        Some(8),
        "package agent_policy\n",
    );
    let calls = gpu.calls();
    refused(
        &h,
        attest(
            &h,
            &swapped.request(&nonce, swapped.evidence(&nonce)),
            pod.verified(&nonce),
        )
        .await,
        "attestation_failed",
        "HOST_DATA is not the digest of the init-data sent",
    )
    .await;
    assert_eq!(gpu.calls(), calls, "no GPU backend runs for a failed guest");

    // A TDX quote presented for the SNP pod's evidence, and the reverse.
    refused(
        &h,
        attest(
            &h,
            &pod.request(&nonce, pod.evidence(&nonce)),
            tdx.quote(&nonce),
        )
        .await,
        "attestation_failed",
        "the evidence is Snp",
    )
    .await;
    refused(
        &h,
        attest(
            &h,
            &tdx.request(&nonce, tdx.evidence(&nonce)),
            pod.verified(&nonce),
        )
        .await,
        "attestation_failed",
        "the evidence is Tdx",
    )
    .await;

    // A GPU in DevTools mode on SNP, as on TDX.
    let mut devtools = pod.clone();
    devtools.gpus[2].mode = "devtools".into();
    refused(
        &h,
        devtools.attest(&h).await,
        "policy_denied",
        "gpu 2: not in CC mode",
    )
    .await;
}
