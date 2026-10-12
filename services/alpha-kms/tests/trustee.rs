//! Option B (PRD-02 deliverable 26) against a real Postgres (`DATABASE_URL`; skipped without
//! it): a Trustee pod, itself an attested Kata pod over a synthetic quote, reports the KBS
//! attestations of tenant pods and asks for their resources (`docs/trustee.md`). Every refusal the
//! design promises is here with its audit row: an unregistered, foreign or revoked Revision, an
//! App that has not opted in, another App's resource, stale state, a Trustee build the platform
//! document does not list, and the platform's own keys.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alpha_core::coco::{GPU_RUNTIME_CLASS, InitData};
use alpha_core::{AppId, KeyId, OrgId, context};
use alpha_kms::rfc3339;
use alpha_trustee::ear::sample::{payload, token};
use alpha_trustee::ear::token_sha256;
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use common::kata::*;
use common::*;
use ed25519_dalek::SigningKey;
use p256::pkcs8::EncodePrivateKey;
use reqwest::StatusCode;
use serde_json::{Value, json};

const KBS_HOST: &str = "kbs.trustee.internal";

struct Trustee {
    h: Harness,
    admin: (KeyId, SigningKey),
    /// The Trustee pod and an HTTPS client holding its leaf.
    pod: Pod,
    client: reqwest::Client,
}

fn hex48(m: alpha_attest::Measurement) -> String {
    hex::encode(m.0)
}

/// The platform document with a GPU policy Trustee can meet and `trustee` listing `builds`.
fn document(version: u64, builds: &[alpha_core::ComposeHash], max_age: u32) -> Value {
    let mut doc = kata_document(version);
    doc["gpu_policy"]["hwmodels"] = json!({ "GB110 A01 GSP BROM": "B300" });
    doc["gpu_policy"]["nras_cc_mode"] =
        json!({ "pointer": "/x-nvidia-gpu-cc-mode", "equals": "on" });
    doc["trustee"] = json!({
        "revisions": builds.iter().map(|b| json!({ "compose_hash": b, "build": "trustee v0.21.0",
                                                    "source_url": "https://example/trustee" }))
                           .collect::<Vec<_>>(),
        "kbs_hostname": KBS_HOST,
        "max_state_age_secs": max_age,
    });
    doc
}

/// A client holding `pod`'s leaf, after it attested.
async fn leaf_client(h: &Harness, pod: &Pod) -> reqwest::Client {
    let reply = pod.attest(h).await.unwrap();
    let leaf = reply["certificate_chain"][0].as_str().unwrap();
    let key = pem::encode(&pem::Pem::new(
        "PRIVATE KEY",
        pod.key.to_pkcs8_der().unwrap().as_bytes(),
    ));
    client_with(&format!("{key}{leaf}"))
}

async fn trustee() -> Option<Trustee> {
    let gpu = FakeGpu::new();
    let h = kata_harness(&gpu).await?;
    let admin = h.register_key(&h.root, 41).await;
    let pod = Pod {
        key: p256::ecdsa::SigningKey::from_bytes((&[11u8; 32]).into()).unwrap(),
        ..Pod::cpu(AppId::mint())
    };
    pod.register(&h, &admin).await;
    publish(&h, document(3, &[pod.hash()], 300)).await;
    let client = leaf_client(&h, &pod).await;
    Some(Trustee {
        h,
        admin,
        pod,
        client,
    })
}

impl Trustee {
    async fn call(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut request = self.client.request(method, format!("{}{path}", self.h.url));
        if let Some(body) = body {
            request = request.json(&body);
        }
        send(request).await
    }

    async fn attest(&self, token: &str, initdata: &str) -> (StatusCode, Value) {
        let body = json!({ "token": token, "initdata": BASE64_URL_SAFE_NO_PAD.encode(initdata) });
        self.call(
            reqwest::Method::POST,
            "/v1/trustee/attestations",
            Some(body),
        )
        .await
    }

    async fn release(
        &self,
        token: &str,
        resource: &str,
        generated_at: SystemTime,
    ) -> (StatusCode, Value) {
        let body = json!({
            "token_sha256": format!("sha256:{}", hex::encode(token_sha256(token))),
            "resource": resource,
            "state_generated_at": rfc3339(generated_at),
        });
        self.call(reqwest::Method::POST, "/v1/trustee/releases", Some(body))
            .await
    }

    async fn state(&self) -> (StatusCode, Value) {
        self.call(reqwest::Method::GET, "/v1/trustee/state", None)
            .await
    }

    async fn grant(&self, app: AppId, resources: Value, at: SystemTime) -> (StatusCode, Value) {
        grant(&self.h, &self.admin, app, resources, at).await
    }
}

async fn grant(
    h: &Harness,
    signer: &(KeyId, SigningKey),
    app: AppId,
    resources: Value,
    at: SystemTime,
) -> (StatusCode, Value) {
    let body = h.signed(
        context::TRUSTEE_GRANT,
        json!({ "app_id": app, "resources": resources, "issued_at": rfc3339(at) }),
        signer,
    );
    h.call(
        reqwest::Method::PUT,
        &format!("/v1/trustee/grants/{app}"),
        body,
    )
    .await
}

/// The token Trustee's KBS issues for `pod`: its class's registers, its init-data's MRCONFIGID,
/// one NVIDIA submodule per GPU claim set.
fn pod_token(h: &Harness, pod: &Pod, gpus: &[Value]) -> String {
    let [mrtd, rtmr0, rtmr1, rtmr2] = registers(&pod.runtime_class);
    let (mrtd, rtmr0, rtmr1, rtmr2) = (hex48(mrtd), hex48(rtmr0), hex48(rtmr1), hex48(rtmr2));
    let mrconfigid = hex::encode(
        InitData::parse(pod.initdata.as_bytes())
            .unwrap()
            .mrconfigid(),
    );
    let exp = h.now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 300;
    token(&payload(
        [&mrtd, &rtmr0, &rtmr1, &rtmr2, &hex48(m(5))],
        &mrconfigid,
        gpus,
        exp,
    ))
}

/// One B300's NRAS claims, every claim the KMS's NRAS backend requires holding.
fn b300(ueid: &str) -> Value {
    let mut c = json!({ "hwmodel": "GB110 A01 GSP BROM", "ueid": ueid,
                        "x-nvidia-gpu-driver-version": "595.58.03",
                        "x-nvidia-gpu-vbios-version": "97.00.9a.00.01",
                        "x-nvidia-gpu-cc-mode": "on" });
    for (pointer, expect) in alpha_attest::gpu::nras::claims::REQUIRED {
        let value = match expect {
            alpha_attest::gpu::nras::claims::Expect::Text(t) => json!(t),
            _ => json!(true),
        };
        let segments: Vec<&str> = pointer.trim_start_matches('/').split('/').collect();
        let mut at = &mut c;
        for (i, s) in segments.iter().enumerate() {
            if i + 1 == segments.len() {
                at[*s] = value.clone();
            } else {
                if at.get(*s).is_none() {
                    at[*s] = json!({});
                }
                at = &mut at[*s];
            }
        }
    }
    c
}

/// The last audit row of `action`: its outcome and details.
async fn last(h: &Harness, action: &str) -> (String, Value) {
    let (_, outcome, details) = h.audit(action).await.pop().unwrap();
    (outcome, details)
}

async fn refused_with(
    h: &Harness,
    action: &str,
    (status, reply): (StatusCode, Value),
    code: &str,
    reason: &str,
) {
    assert_ne!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["error"]["code"], code, "{reply}");
    let message = reply["error"]["message"].as_str().unwrap();
    assert!(message.contains(reason), "{reason}: {message}");
    let (outcome, details) = last(h, action).await;
    assert_eq!(outcome, "denied");
    assert_eq!(details["code"], code);
}

fn jwk() -> Value {
    json!({ "kty": "EC", "crv": "P-256", "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0" })
}

#[tokio::test]
async fn a_pod_trustee_attested_gets_exactly_its_granted_resources_each_release_audited() {
    let Some(t) = trustee().await else {
        return;
    };
    let h = &t.h;
    let app = AppId::mint();
    let pod = Pod::cpu(app);
    let hash = pod.register(h, &t.admin).await;
    let at = h.now();
    for (name, value) in [
        ("db", b"hunter2".to_vec()),
        ("image-key.base", vec![7u8; 32]),
        ("sealed-secret-key.signing", jwk().to_string().into_bytes()),
    ] {
        let (status, reply) = h.put_secret(name, &[app], &value, at, &t.admin).await;
        assert_eq!(status, StatusCode::OK, "{reply}");
    }
    let (status, reply) = t
        .grant(
            app,
            json!([{ "type": "secret", "tag": "db" }, { "type": "key", "tag": "*" },
                   { "type": "image-key", "tag": "base" }, { "type": "sealed-secret-key", "tag": "signing" }]),
            at,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    verified(
        h,
        &reply,
        "trustee.grant",
        &h.signed(
            context::TRUSTEE_GRANT,
            json!({ "app_id": app, "resources": [{ "type": "secret", "tag": "db" }, { "type": "key", "tag": "*" },
                   { "type": "image-key", "tag": "base" }, { "type": "sealed-secret-key", "tag": "signing" }],
                   "issued_at": rfc3339(at) }),
            &t.admin,
        ),
        json!({ "app_id": app, "org_id": h.org }),
    );

    let tok = pod_token(h, &pod, &[]);
    let (status, admitted) = t.attest(&tok, &pod.initdata).await;
    assert_eq!(status, StatusCode::OK, "{admitted}");
    assert_eq!(admitted["revision"], json!(hash));
    assert_eq!(admitted["app_id"], json!(app));
    let mrconfigid = hex::encode(
        InitData::parse(pod.initdata.as_bytes())
            .unwrap()
            .mrconfigid(),
    );
    assert_eq!(admitted["mrconfigid"], json!(mrconfigid));
    let (outcome, details) = last(h, "trustee.attest").await;
    assert_eq!(outcome, "ok");
    assert_eq!(details["trustee_revision"], json!(t.pod.hash()));
    // Reported again (the KBS hands an attested session its old token): the same answer.
    let (status, again) = t.attest(&tok, &pod.initdata).await;
    assert_eq!(status, StatusCode::OK, "{again}");

    let (status, state) = t.state().await;
    assert_eq!(status, StatusCode::OK, "{state}");
    assert_eq!(
        state["admitted"],
        json!([{ "app_id": app, "mrconfigid": mrconfigid }])
    );
    assert_eq!(state["platform_version"], 3);
    assert!(
        state["resource_policy"]
            .as_str()
            .unwrap()
            .contains(&mrconfigid)
    );
    let generated =
        chrono::DateTime::parse_from_rfc3339(state["generated_at"].as_str().unwrap()).unwrap();
    let not_after =
        chrono::DateTime::parse_from_rfc3339(state["not_after"].as_str().unwrap()).unwrap();
    assert_eq!((not_after - generated).num_seconds(), 300);
    assert!(
        state["attestation_policies"]["default_cpu"]
            .as_str()
            .unwrap()
            .contains("alpha_kata_tdx")
    );
    assert!(
        state["reference_values"]
            .as_str()
            .unwrap()
            .contains("\"type\":\"sample\"")
    );

    let now = h.now();
    let value = |reply: &Value| {
        BASE64_URL_SAFE_NO_PAD
            .decode(reply["value"].as_str().unwrap())
            .unwrap()
    };
    let (status, reply) = t
        .release(&tok, &format!("kbs:///{app}/secret/db"), now)
        .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(value(&reply), b"hunter2");
    assert_eq!(reply["mrconfigid"], json!(mrconfigid));
    let (outcome, details) = last(h, "trustee.release").await;
    assert_eq!(outcome, "ok");
    assert_eq!(
        details["revision"],
        json!(hash),
        "audited with the pod's Revision"
    );
    assert_eq!(details["trustee_revision"], json!(t.pod.hash()));

    let (status, reply) = t
        .release(&tok, &format!("kbs:///{app}/key/volume.data"), now)
        .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(
        value(&reply),
        h.app_key(app, "volume.data"),
        "the key /v1/keys/derive gives the App"
    );
    let (status, reply) = t
        .release(&tok, &format!("kbs:///{app}/image-key/base"), now)
        .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(value(&reply), [7u8; 32]);
    let (status, reply) = t
        .release(
            &tok,
            &format!("kbs:///{app}/sealed-secret-key/signing"),
            now,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(
        serde_json::from_slice::<Value>(&value(&reply)).unwrap(),
        jwk()
    );

    // Not granted, not the pod's App, not a resource of the contract.
    refused_with(
        h,
        "trustee.release",
        t.release(&tok, &format!("kbs:///{app}/secret/other"), now)
            .await,
        "policy_denied",
        "grant does not cover",
    )
    .await;
    let other = AppId::mint();
    refused_with(
        h,
        "trustee.release",
        t.release(&tok, &format!("kbs:///{other}/secret/db"), now)
            .await,
        "not_found",
        "no such resource for this pod",
    )
    .await;
    refused_with(
        h,
        "trustee.release",
        t.release(&tok, &format!("kbs:///{app}/secret/image-key.base"), now)
            .await,
        "malformed",
        "not a valid name",
    )
    .await;
    refused_with(
        h,
        "trustee.release",
        t.release(&tok, &format!("kbs:///{app}/key/trustee.as-token"), now)
            .await,
        "malformed",
        "not a valid name",
    )
    .await;
    // A token nobody reported.
    let forged = token(&json!({ "submods": {} }));
    refused_with(
        h,
        "trustee.release",
        t.release(&forged, &format!("kbs:///{app}/secret/db"), now)
            .await,
        "attestation_unknown",
        "no admitted attestation",
    )
    .await;
}

#[tokio::test]
async fn trustee_admits_no_pod_the_kms_would_not() {
    let Some(t) = trustee().await else {
        return;
    };
    let h = &t.h;
    let app = AppId::mint();
    let pod = Pod::cpu(app);
    // Not registered: the init-data's Revision v2 is unknown here.
    refused_with(
        h,
        "trustee.attest",
        t.attest(&pod_token(h, &pod, &[]), &pod.initdata).await,
        "attestation_unknown",
        "is not registered",
    )
    .await;
    pod.register(h, &t.admin).await;
    // Another pod's init-data beside this pod's token.
    let other = Pod::cpu(AppId::mint());
    other.register(h, &t.admin).await;
    refused_with(
        h,
        "trustee.attest",
        t.attest(&pod_token(h, &pod, &[]), &other.initdata).await,
        "attestation_failed",
        "MRCONFIGID is not the digest",
    )
    .await;
    // The GPU guest's registers for a CPU Revision.
    let mut as_gpu = pod.clone();
    as_gpu.runtime_class = GPU_RUNTIME_CLASS.into();
    refused_with(
        h,
        "trustee.attest",
        t.attest(&pod_token(h, &as_gpu, &[]), &pod.initdata).await,
        "attestation_unknown",
        "no kata-tdx reference value",
    )
    .await;
    // A token Trustee marked anything but affirming, and one already expired.
    let mut warned: Value = alpha_trustee::ear::token_payload(&pod_token(h, &pod, &[])).unwrap();
    warned["submods"]["cpu0"]["ear.status"] = json!("warning");
    refused_with(
        h,
        "trustee.attest",
        t.attest(&token(&warned), &pod.initdata).await,
        "attestation_failed",
        "not affirming",
    )
    .await;
    let mut expired = alpha_trustee::ear::token_payload(&pod_token(h, &pod, &[])).unwrap();
    expired["exp"] = json!(h.now().duration_since(UNIX_EPOCH).unwrap().as_secs());
    refused_with(
        h,
        "trustee.attest",
        t.attest(&token(&expired), &pod.initdata).await,
        "attestation_failed",
        "expired",
    )
    .await;
    // GPUs on a CPU Revision.
    refused_with(
        h,
        "trustee.attest",
        t.attest(&pod_token(h, &pod, &[b300("u0")]), &pod.initdata)
            .await,
        "attestation_failed",
        "runs none",
    )
    .await;

    // A GPU pod: exactly its eight B300s, each with every claim the KMS requires.
    let gpu_pod = Pod::gpu(app, 8);
    gpu_pod.register(h, &t.admin).await;
    let eight: Vec<Value> = (0..8).map(|i| b300(&format!("u{i}"))).collect();
    let (status, reply) = t
        .attest(&pod_token(h, &gpu_pod, &eight), &gpu_pod.initdata)
        .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    refused_with(
        h,
        "trustee.attest",
        t.attest(&pod_token(h, &gpu_pod, &eight[..7]), &gpu_pod.initdata)
            .await,
        "attestation_failed",
        "7",
    )
    .await;
    let mut off = eight.clone();
    off[4]["x-nvidia-gpu-cc-mode"] = json!("off");
    refused_with(
        h,
        "trustee.attest",
        t.attest(&pod_token(h, &gpu_pod, &off), &gpu_pod.initdata)
            .await,
        "attestation_failed",
        "gpu 4",
    )
    .await;
}

#[tokio::test]
async fn a_revocation_reaches_trustee_at_the_next_release_and_the_next_state() {
    let Some(t) = trustee().await else {
        return;
    };
    let h = &t.h;
    let app = AppId::mint();
    let pod = Pod::cpu(app);
    let hash = pod.register(h, &t.admin).await;
    h.put_secret("db", &[app], b"v", h.now(), &t.admin).await;
    let (status, reply) = t
        .grant(app, json!([{ "type": "secret", "tag": "*" }]), h.now())
        .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let tok = pod_token(h, &pod, &[]);
    assert_eq!(t.attest(&tok, &pod.initdata).await.0, StatusCode::OK);
    let (_, state) = t.state().await;
    assert_eq!(state["admitted"].as_array().unwrap().len(), 1);
    let resource = format!("kbs:///{app}/secret/db");
    assert_eq!(t.release(&tok, &resource, h.now()).await.0, StatusCode::OK);

    let revoke = h.signed(
        context::CONTROL,
        json!({ "compose_hash": hash, "issued_at": rfc3339(h.now()) }),
        &t.admin,
    );
    let (status, reply) = h
        .post(&format!("/v1/revisions/{hash}/revoke"), revoke)
        .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    // The token Trustee holds still verifies at its KBS; the KMS refuses it at once.
    refused_with(
        h,
        "trustee.release",
        t.release(&tok, &resource, h.now()).await,
        "revision_revoked",
        "revision is revoked",
    )
    .await;
    refused_with(
        h,
        "trustee.attest",
        t.attest(&pod_token(h, &pod, &[]), &pod.initdata).await,
        "revision_revoked",
        "revision is revoked",
    )
    .await;
    let (_, state) = t.state().await;
    assert_eq!(state["admitted"], json!([]));
    assert!(
        !state["resource_policy"]
            .as_str()
            .unwrap()
            .contains(&hex::encode(
                InitData::parse(pod.initdata.as_bytes())
                    .unwrap()
                    .mrconfigid()
            ))
    );
}

#[tokio::test]
async fn an_app_releases_nothing_through_trustee_until_its_tenant_opts_in() {
    let Some(t) = trustee().await else {
        return;
    };
    let h = &t.h;
    let app = AppId::mint();
    let pod = Pod::cpu(app);
    pod.register(h, &t.admin).await;
    h.put_secret("db", &[app], b"v", h.now(), &t.admin).await;
    let tok = pod_token(h, &pod, &[]);
    assert_eq!(t.attest(&tok, &pod.initdata).await.0, StatusCode::OK);
    let resource = format!("kbs:///{app}/secret/db");
    refused_with(
        h,
        "trustee.release",
        t.release(&tok, &resource, h.now()).await,
        "policy_denied",
        "grant does not cover",
    )
    .await;
    let (_, state) = t.state().await;
    assert_eq!(state["admitted"], json!([]), "no grant, not in the policy");

    let t1 = h.now();
    let (status, _) = t
        .grant(app, json!([{ "type": "secret", "tag": "db" }]), t1)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(t.release(&tok, &resource, h.now()).await.0, StatusCode::OK);
    // Opting out is a later, empty grant; an older one is refused.
    refused_with(
        h,
        "trustee.grant",
        t.grant(app, json!([]), t1).await,
        "already_exists",
        "later issued_at",
    )
    .await;
    let t2 = t1 + Duration::from_secs(1);
    let (status, reply) = t.grant(app, json!([]), t2).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    refused_with(
        h,
        "trustee.release",
        t.release(&tok, &resource, h.now()).await,
        "policy_denied",
        "grant does not cover",
    )
    .await;
}

#[tokio::test]
async fn a_grant_is_its_own_organizations_scoped_to_option_b_and_never_a_trustee_apps() {
    let Some(t) = trustee().await else {
        return;
    };
    let h = &t.h;
    let app = AppId::mint();
    let now = h.now();
    // No Revision of the App here yet.
    refused_with(
        h,
        "trustee.grant",
        t.grant(app, json!([{ "type": "secret", "tag": "*" }]), now)
            .await,
        "not_found",
        "register a Revision",
    )
    .await;
    Pod::cpu(app).register(h, &t.admin).await;
    for (resources, reason) in [
        (json!([{ "type": "token", "tag": "*" }]), "unknown variant"),
        (
            json!([{ "type": "key", "tag": "kms.root" }]),
            "not a valid name",
        ),
        (
            json!([{ "type": "key", "tag": "trustee.as-token" }]),
            "not a valid name",
        ),
        (
            json!([{ "type": "secret", "tag": "*" }, { "type": "secret", "tag": "*" }]),
            "listed twice",
        ),
    ] {
        refused_with(
            h,
            "trustee.grant",
            t.grant(app, resources, now).await,
            "malformed",
            reason,
        )
        .await;
    }
    // The Trustee pod's own App: its keys never leave through Trustee.
    refused_with(
        h,
        "trustee.grant",
        t.grant(t.pod.app, json!([{ "type": "key", "tag": "*" }]), now)
            .await,
        "policy_denied",
        "Trustee App",
    )
    .await;
    // Another organization cannot grant this App's resources.
    let org = OrgId::mint();
    let root = SigningKey::from_bytes(&[77u8; 32]);
    let (status, reply) = h
        .post("/v1/keys", root_key_registration(org, &root, h.now()))
        .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let foreign = (
        reply["id"].as_str().unwrap().parse::<KeyId>().unwrap(),
        root,
    );
    refused_with(
        h,
        "trustee.grant",
        grant(
            h,
            &foreign,
            app,
            json!([{ "type": "secret", "tag": "*" }]),
            now,
        )
        .await,
        "not_found",
        "no such app in this organization",
    )
    .await;
}

#[tokio::test]
async fn trustee_acting_on_stale_state_releases_nothing() {
    let Some(t) = trustee().await else {
        return;
    };
    let h = &t.h;
    let app = AppId::mint();
    let pod = Pod::cpu(app);
    pod.register(h, &t.admin).await;
    h.put_secret("db", &[app], b"v", h.now(), &t.admin).await;
    t.grant(app, json!([{ "type": "secret", "tag": "db" }]), h.now())
        .await;
    let tok = pod_token(h, &pod, &[]);
    assert_eq!(t.attest(&tok, &pod.initdata).await.0, StatusCode::OK);
    let resource = format!("kbs:///{app}/secret/db");
    let now = h.now();
    assert_eq!(
        t.release(&tok, &resource, now - Duration::from_secs(300))
            .await
            .0,
        StatusCode::OK
    );
    refused_with(
        h,
        "trustee.release",
        t.release(&tok, &resource, now - Duration::from_secs(301))
            .await,
        "policy_denied",
        "more than trustee.max_state_age_secs",
    )
    .await;
    refused_with(
        h,
        "trustee.release",
        t.release(&tok, &resource, now + Duration::from_secs(120))
            .await,
        "policy_denied",
        "future",
    )
    .await;
}

#[tokio::test]
async fn a_trustee_build_the_document_does_not_list_gets_nothing() {
    let Some(t) = trustee().await else {
        return;
    };
    let h = &t.h;
    // A pod of another App, registered and attested like any, but no Trustee build.
    let rogue = Pod {
        key: p256::ecdsa::SigningKey::from_bytes((&[12u8; 32]).into()).unwrap(),
        ..Pod::cpu(AppId::mint())
    };
    rogue.register(h, &t.admin).await;
    let rogue_client = leaf_client(h, &rogue).await;
    let app = AppId::mint();
    let pod = Pod::cpu(app);
    pod.register(h, &t.admin).await;
    let tok = pod_token(h, &pod, &[]);
    let body = json!({ "token": tok, "initdata": BASE64_URL_SAFE_NO_PAD.encode(&pod.initdata) });
    for (path, body) in [
        ("/v1/trustee/attestations", Some(body)),
        ("/v1/trustee/kbs-leaf", Some(json!({}))),
    ] {
        let mut request = rogue_client.post(format!("{}{path}", h.url));
        if let Some(body) = body {
            request = request.json(&body);
        }
        let (status, reply) = send(request).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}: {reply}");
        assert!(
            reply["error"]["message"]
                .as_str()
                .unwrap()
                .contains("not a Trustee build")
        );
    }
    let (status, _) = send(rogue_client.get(format!("{}/v1/trustee/state", h.url))).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (outcome, details) = last(h, "trustee.state").await;
    assert_eq!(
        (outcome.as_str(), details["code"].as_str()),
        ("denied", Some("attestation_unknown"))
    );
    // No client certificate at all.
    let (status, _) = h
        .post(
            "/v1/trustee/attestations",
            json!({ "token": "x", "initdata": "" }),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Delisting the real Trustee build stops it, and what it reported, at once.
    h.put_secret("db", &[app], b"v", h.now(), &t.admin).await;
    t.grant(app, json!([{ "type": "secret", "tag": "db" }]), h.now())
        .await;
    assert_eq!(t.attest(&tok, &pod.initdata).await.0, StatusCode::OK);
    publish(h, document(4, &[], 300)).await;
    refused_with(
        h,
        "trustee.release",
        t.release(&tok, &format!("kbs:///{app}/secret/db"), h.now())
            .await,
        "attestation_unknown",
        "not a Trustee build",
    )
    .await;
    let mut no_trustee = document(5, &[], 300);
    no_trustee.as_object_mut().unwrap().remove("trustee");
    publish(h, no_trustee).await;
    refused_with(
        h,
        "trustee.state",
        t.state().await,
        "attestation_unknown",
        "lists no Trustee",
    )
    .await;
}

#[tokio::test]
async fn the_kbs_leaf_is_over_trustees_own_key_and_names_only_the_kbs() {
    let Some(t) = trustee().await else {
        return;
    };
    let (status, reply) = t
        .call(
            reqwest::Method::POST,
            "/v1/trustee/kbs-leaf",
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["certificate_chain"][1], json!(t.h.ca_pem));
    let pem = reply["certificate_chain"][0].as_str().unwrap();
    let der =
        <rustls::pki_types::CertificateDer as rustls::pki_types::pem::PemObject>::from_pem_slice(
            pem.as_bytes(),
        )
        .unwrap();
    let (_, cert) = x509_parser::parse_x509_certificate(&der).unwrap();
    let sans = cert.subject_alternative_name().unwrap().unwrap();
    assert_eq!(
        format!("{:?}", sans.value.general_names),
        format!("[DNSName({KBS_HOST:?})]")
    );
    assert_eq!(cert.public_key().raw, t.pod.spki().as_slice());
    let eku = cert.extended_key_usage().unwrap().unwrap().value;
    assert!(eku.server_auth && !eku.client_auth);
    let (outcome, details) = last(&t.h, "trustee.kbs-leaf").await;
    assert_eq!(outcome, "ok");
    assert_eq!(details["dns_name"], KBS_HOST);
}

#[tokio::test]
async fn the_policy_never_admits_a_trustee_app_and_a_tampered_grant_stops_the_state() {
    let Some(t) = trustee().await else {
        return;
    };
    let h = &t.h;
    // The Trustee pod attested through a Trustee, with a validly signed grant written past the
    // route's refusal: still not in the policy, and nothing of it released.
    let tok = pod_token(h, &t.pod, &[]);
    assert_eq!(t.attest(&tok, &t.pod.initdata).await.0, StatusCode::OK);
    let at = h.now();
    let document = json!({ "app_id": t.pod.app, "resources": [{ "type": "key", "tag": "*" }],
                           "issued_at": rfc3339(at) });
    let signed = h.signed(context::TRUSTEE_GRANT, document.clone(), &t.admin);
    sqlx::query("insert into trustee_grants (app_id, org_id, resources, document, signed_by_key, signature, issued_at) values ($1, $2, $3, $4, $5, $6, $7)")
        .bind(uuid::Uuid::from(t.pod.app))
        .bind(uuid::Uuid::from(h.org))
        .bind(&document["resources"])
        .bind(&document)
        .bind(uuid::Uuid::from(t.admin.0))
        .bind(&signed["signature"])
        .bind(chrono::DateTime::<chrono::Utc>::from(at))
        .execute(&h.pool)
        .await
        .unwrap();
    let (status, state) = t.state().await;
    assert_eq!(status, StatusCode::OK, "{state}");
    assert_eq!(state["admitted"], json!([]));
    refused_with(
        h,
        "trustee.release",
        t.release(&tok, &format!("kbs:///{}/key/volume.x", t.pod.app), h.now())
            .await,
        "policy_denied",
        "Trustee App",
    )
    .await;
    // A grant row edited in the database no longer verifies, and the state refuses rather than
    // admit anything on it.
    sqlx::query("update trustee_grants set document = jsonb_set(document, '{resources,0,tag}', '\"volume.x\"')")
        .execute(&h.pool)
        .await
        .unwrap();
    refused_with(h, "trustee.state", t.state().await, "signature_invalid", "").await;
}
