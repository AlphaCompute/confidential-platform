//! Revisions of Kata init-data, and leaves for the Kata TDX pods that boot with them, against a
//! quote taken on our B300 over a fixed runtime key and a nonce of the test nonce key.
//! Also: Revision v2 registration with synthetic quotes (see `common::kata`), GPU backends, and
//! an audit row for every refusal.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use alpha_attest::KATA_EVIDENCE_FORMAT;
use alpha_core::coco::{CPU_RUNTIME_CLASS, GPU_RUNTIME_CLASS};
use alpha_core::{AppId, ComposeHash, InitData, KeyId, compose_hash, context};
use alpha_kms::{certs, platform, rfc3339};
use common::kata::{
    FakeGpu, Gpu, Pod, attest as kata_attest, fresh_nonce, initdata, kata_document,
    kata_harness as kata_gpu_harness, leaf_sans, publish, refused,
};
use common::*;
use ed25519_dalek::SigningKey;
use reqwest::StatusCode;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// The App `k3-app.toml` names in its `[data]`.
fn kata_app() -> AppId {
    "0199e000-0000-7000-8000-00000000a11d".parse().unwrap()
}

fn k3() -> String {
    text(KATA, "k3-app.toml")
}

fn k3_digest() -> ComposeHash {
    InitData::parse(k3()).unwrap().digest()
}

fn registration(app: AppId, init_data: &str, digest: ComposeHash) -> Value {
    json!({ "app_id": app, "init_data": init_data, "digest": digest })
}

async fn register(h: &Harness, signer: &(KeyId, SigningKey)) -> (StatusCode, Value) {
    h.post(
        "/v1/revisions",
        h.signed(
            context::REVISION,
            registration(kata_app(), &k3(), k3_digest()),
            signer,
        ),
    )
    .await
}

fn attest_body(quote: &str, spki: &[u8]) -> Value {
    json!({
        "runtime_pubkey": b64(spki),
        "nonce": b64(&read(KATA, "nonce.bin")),
        "evidence": { "format": KATA_EVIDENCE_FORMAT, "quote": b64(&read(KATA, quote)) },
    })
}

async fn attest(h: &Harness, quote: &str) -> (StatusCode, Value) {
    h.post(
        "/v1/attest",
        attest_body(quote, &read(KATA, "runtime_spki.der")),
    )
    .await
}

/// Serves the `change`d document as its next version.
async fn republish(h: &Harness, change: impl FnOnce(&mut Value)) {
    let mut document = h.release.document.read().unwrap().clone();
    document["version"] = json!(document["version"].as_u64().unwrap() + 1);
    change(&mut document);
    h.release.set(document);
    platform::reload(&h.node).await.unwrap();
}

#[tokio::test]
async fn an_init_data_revision_is_registered_as_signed() {
    let Some(h) = kata_harness().await else {
        return;
    };
    let admin = h.register_key(&h.root, 31).await;
    let app = kata_app();

    let (status, reply) = register(&h, &admin).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["compose_hash"], json!(k3_digest()));
    assert_eq!(reply["app_id"], json!(app));
    assert_eq!(reply["org_id"], json!(h.org));
    let digest = k3_digest();
    let row = sqlx::query!(
        "select compose, init_data from revisions where compose_hash = $1",
        digest.as_bytes().as_slice()
    )
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert_eq!((row.compose, row.init_data), (None, Some(k3())));

    let t1 = text(KATA, "t1-sha256.toml");
    let another_app = k3().replace("a11d", "a11e");
    let no_policy = k3().replace("\"policy.rego\"", "\"policy.txt\"");
    let read_stream = k3().replace(
        "\"ReadStreamRequest\": false",
        "\"ReadStreamRequest\": true",
    );
    let refusals = [
        (
            registration(app, "not toml", compose_hash("not toml")),
            "TOML",
        ),
        (
            registration(app, &another_app, compose_hash(&another_app)),
            "app_id",
        ),
        (registration(app, &t1, compose_hash(&t1)), "app_id"),
        (registration(app, &k3(), compose_hash(&t1)), "digest"),
        (
            registration(app, &no_policy, compose_hash(&no_policy)),
            "policy.rego",
        ),
        (
            registration(app, &read_stream, compose_hash(&read_stream)),
            "pinned data",
        ),
        (
            json!({ "app_id": app, "init_data": k3(), "digest": k3_digest(), "compose": "{}" }),
            "unknown field",
        ),
    ];
    for (payload, fragment) in refusals {
        let (status, reply) = h
            .post(
                "/v1/revisions",
                h.signed(context::REVISION, payload, &admin),
            )
            .await;
        assert_eq!(
            (status, code(&reply)),
            (StatusCode::BAD_REQUEST, "malformed")
        );
        assert!(
            reply["error"]["message"]
                .as_str()
                .unwrap()
                .contains(fragment),
            "{reply}"
        );
    }

    let tampered = k3().replace("version = ", "version  = ");
    let mut unsigned = h.signed(
        context::REVISION,
        registration(app, &k3(), k3_digest()),
        &admin,
    );
    unsigned["payload"]["init_data"] = json!(tampered);
    unsigned["payload"]["digest"] = json!(compose_hash(&tampered));
    let (status, reply) = h.post("/v1/revisions", unsigned).await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::BAD_REQUEST, "signature_invalid")
    );
}

#[tokio::test]
async fn no_init_data_registers_while_the_document_pins_no_agent_policy() {
    let Some(h) = kata_harness().await else {
        return;
    };
    let admin = h.register_key(&h.root, 33).await;
    republish(&h, |d| {
        d.as_object_mut().unwrap().remove("kata_policy");
    })
    .await;
    let (status, reply) = register(&h, &admin).await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::FORBIDDEN, "policy_denied"),
        "{reply}"
    );
}

#[tokio::test]
async fn a_kata_pod_gets_a_leaf_naming_the_revision_in_its_mrconfigid() {
    let Some(h) = kata_harness().await else {
        return;
    };
    let admin = h.register_key(&h.root, 32).await;
    let app = kata_app();

    let (status, reply) = attest(&h, "k3-app.quote.bin").await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::FORBIDDEN, "attestation_unknown"),
        "{reply}"
    );
    assert!(
        reply["error"]["message"]
            .as_str()
            .unwrap()
            .contains(&k3_digest().to_string())
    );

    let (status, reply) = register(&h, &admin).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let (status, reply) = attest(&h, "k3-app.quote.bin").await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let result = &reply["attestation_result"];
    assert_eq!(result["verdict"], "verified");
    assert_eq!(result["os_image"], "kata-qemu-tdx");
    assert_eq!(
        result["revision"],
        json!({ "compose_hash": k3_digest(), "app_id": app, "org_id": h.org })
    );
    let runtime_sha = alpha_kms::keys::sha256_hex(&read(KATA, "runtime_spki.der"));
    assert_eq!(
        result["runtime_pubkey_sha256"],
        format!("sha256:{runtime_sha}")
    );
    assert_eq!(reply["not_after"], rfc3339(h.now() + certs::LEAF_TTL));
    let leaf =
        <rustls::pki_types::CertificateDer as rustls::pki_types::pem::PemObject>::from_pem_slice(
            reply["certificate_chain"][0].as_str().unwrap().as_bytes(),
        )
        .unwrap();
    assert_eq!(
        certs::uri_sans(&leaf).unwrap(),
        [
            format!("alphacompute://{}/{app}/{runtime_sha}", h.org),
            format!("urn:alphacompute:revision:{}", k3_digest()),
        ]
    );
    let audited = h.audit("attest").await;
    assert!(
        audited
            .iter()
            .any(|(_, o, d)| o == "ok" && d["os_image"] == "kata-qemu-tdx")
    );

    // The runtime key the quote binds is the P-256 scalar 0x4b repeated.
    let (status, put) = h
        .put_secret("model-key", &[app], b"for the pod", h.now(), &admin)
        .await;
    assert_eq!(status, StatusCode::OK, "{put}");
    let key_pem = {
        use p256::pkcs8::EncodePrivateKey;
        p256::SecretKey::from_bytes(&[0x4b; 32].into())
            .unwrap()
            .to_pkcs8_pem(Default::default())
            .unwrap()
    };
    let pod = client_with(&format!(
        "{}{}",
        key_pem.as_str(),
        reply["certificate_chain"][0].as_str().unwrap()
    ));
    let (status, secret) = send(pod.get(format!("{}/v1/secrets/model-key", h.url))).await;
    assert_eq!(status, StatusCode::OK, "{secret}");
    assert_eq!(secret["value"], json!(b64(b"for the pod")));

    let other = p256::SecretKey::from_bytes(&[0x4c; 32].into()).unwrap();
    let other_spki = {
        use p256::pkcs8::EncodePublicKey;
        other.public_key().to_public_key_der().unwrap().into_vec()
    };
    let (status, reply) = h
        .post("/v1/attest", attest_body("k3-app.quote.bin", &other_spki))
        .await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::FORBIDDEN, "attestation_failed")
    );
    assert!(
        reply["error"]["message"]
            .as_str()
            .unwrap()
            .contains("report_data")
    );

    let mut dstack = attest_body("k3-app.quote.bin", &read(KATA, "runtime_spki.der"));
    dstack["evidence"]["event_log"] = json!([]);
    let (status, reply) = h.post("/v1/attest", dstack).await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::BAD_REQUEST, "malformed"),
        "{reply}"
    );
}

#[tokio::test]
async fn a_class_passing_gpus_through_gets_no_leaf() {
    let Some(h) = kata_harness().await else {
        return;
    };
    let admin = h.register_key(&h.root, 34).await;
    register(&h, &admin).await;
    republish(&h, |d| d["kata_reference_values"][0]["gpu"] = json!(true)).await;
    let (status, reply) = attest(&h, "k3-app.quote.bin").await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::FORBIDDEN, "policy_denied")
    );
    assert!(
        reply["error"]["message"].as_str().unwrap().contains("GPU"),
        "{reply}"
    );
}

#[tokio::test]
async fn a_revoked_init_data_revision_gets_no_leaf() {
    let Some(h) = kata_harness().await else {
        return;
    };
    let admin = h.register_key(&h.root, 35).await;
    register(&h, &admin).await;
    let payload = json!({ "compose_hash": k3_digest(), "issued_at": rfc3339(h.now()) });
    let (status, reply) = h
        .post(
            &format!("/v1/revisions/{}/revoke", k3_digest()),
            h.signed(context::CONTROL, payload, &admin),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let (status, reply) = attest(&h, "k3-app.quote.bin").await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::CONFLICT, "revision_revoked")
    );
}

#[tokio::test]
async fn a_compose_revision_is_not_an_init_data_one() {
    let Some(h) = kata_harness().await else {
        return;
    };
    let admin = h.register_key(&h.root, 36).await;
    let app = kata_app();
    let document = json!({ "app_id": app, "compose": k3() });
    let signature = h.signed(context::REVISION, document, &admin)["signature"].clone();
    let hash = h
        .insert_signed_revision(h.org, app, k3(), admin.0, signature)
        .await;
    assert_eq!(hash, k3_digest());
    let (status, reply) = attest(&h, "k3-app.quote.bin").await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::FORBIDDEN, "attestation_unknown")
    );
}

async fn attest_after_republishing(h: &Harness, change: impl FnOnce(&mut Value)) -> Value {
    let admin = h.register_key(&h.root, 37).await;
    let (status, reply) = register(h, &admin).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    republish(h, change).await;
    let (status, reply) = attest(h, "k3-app.quote.bin").await;
    assert_eq!(
        (status, code(&reply)),
        (StatusCode::FORBIDDEN, "policy_denied"),
        "{reply}"
    );
    reply
}

#[tokio::test]
async fn a_revision_registered_under_another_pin_gets_no_leaf() {
    let Some(h) = kata_harness().await else {
        return;
    };
    let reply = attest_after_republishing(&h, |d| {
        d["kata_policy"]["rules_sha256"] = json!(compose_hash("other rules"));
    })
    .await;
    assert!(
        reply["error"]["message"]
            .as_str()
            .unwrap()
            .contains("pinned rules"),
        "{reply}"
    );
}

#[tokio::test]
async fn no_leaf_is_issued_while_the_document_pins_no_agent_policy() {
    let Some(h) = kata_harness().await else {
        return;
    };
    let reply = attest_after_republishing(&h, |d| {
        d.as_object_mut().unwrap().remove("kata_policy");
    })
    .await;
    assert!(
        reply["error"]["message"]
            .as_str()
            .unwrap()
            .contains("pins no Kata agent policy"),
        "{reply}"
    );
}

#[tokio::test]
async fn a_revision_v2_registers_and_its_gpu_pod_gets_a_leaf_naming_it() {
    let gpu = FakeGpu::new();
    let Some(h) = kata_gpu_harness(&gpu).await else {
        return;
    };
    let admin = h.register_key(&h.root, 51).await;
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
    let Some(h) = kata_gpu_harness(&gpu).await else {
        return;
    };
    let admin = h.register_key(&h.root, 52).await;
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
    let Some(h) = kata_gpu_harness(&gpu).await else {
        return;
    };
    let admin = h.register_key(&h.root, 53).await;
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
    let Some(h) = kata_gpu_harness(&gpu).await else {
        return;
    };
    let admin = h.register_key(&h.root, 54).await;
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
        kata_attest(
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
