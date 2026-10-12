//! The KBS facade (`alpha-kbs`, PRD-02 P1) against a real Postgres (`DATABASE_URL`; skipped
//! without it): a Kata pod attests over KBS protocol 0.4.0 through `kata-tdx/1` and the Revision v2
//! checks, every attempt audited, and fetches only its own App's resources, sealed to the TEE key
//! its quote bound. Pods attest over synthetic quotes through `kbs::attest_verified`, as
//! `tests/kata.rs` does through `instance::attest_verified`; the route's DCAP step is checked with
//! a quote that fails it. The JWE tests at the end need no database.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use alpha_core::AppId;
use alpha_core::context;
use alpha_kms::kbs::{jwe, token};
use alpha_kms::rfc3339;
use base64::Engine;
use base64::prelude::{BASE64_STANDARD, BASE64_URL_SAFE_NO_PAD};
use common::kata::{FakeGpu, Gpu, Pod, kata_harness};
use common::kbs::*;
use common::*;
use reqwest::StatusCode;
use serde_json::{Value, json};

fn kind(reply: &Value) -> &str {
    reply["type"]
        .as_str()
        .unwrap_or_default()
        .rsplit('/')
        .next()
        .unwrap_or_default()
}

#[tokio::test]
async fn a_gpu_pod_attests_over_the_kbs_protocol_and_gets_its_apps_resources_sealed_to_its_key() {
    let gpu = FakeGpu::new();
    let Some(h) = kbs_harness(&gpu).await else {
        return;
    };
    let admin = h.register_key(&h.root, 41).await;
    let pod = KbsPod::new(Pod::gpu(AppId::mint(), 8), 61);
    let hash = pod.pod.register(&h, &admin).await;
    let app = pod.pod.app;
    let (status, reply) = h
        .put_secret("registry.auth", &[app], b"{\"auths\":{}}", h.now(), &admin)
        .await;
    assert_eq!(status, StatusCode::OK, "{reply}");

    let token = pod.attest(&h).await.unwrap();
    assert_eq!(gpu.calls(), 1);
    let (_, outcome, result) = h.audit("kbs.attest").await.pop().unwrap();
    assert_eq!(outcome, "ok");
    assert_eq!(result["verdict"], "verified");
    assert_eq!(
        result["revision"],
        json!({ "compose_hash": hash, "app_id": app, "org_id": h.org })
    );
    assert_eq!(result["coco"]["profile"], "kata-tdx/1");
    assert_eq!(result["coco"]["gpus"].as_array().unwrap().len(), 8);
    let key_sha256 = hex::encode(pod.tee_key().sha256().unwrap());
    assert_eq!(
        result["runtime_pubkey_sha256"],
        format!("sha256:{key_sha256}")
    );

    // The guest reads only `exp`; the KMS reads the rest.
    let claims: Value = serde_json::from_slice(
        &BASE64_URL_SAFE_NO_PAD
            .decode(token.split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap();
    let now = h.now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    assert_eq!(claims["exp"], now + 3600);
    assert_eq!(claims["tee-pubkey"], json!(pod.tee_key()));

    let (status, sealed) = get(&h, Some(&token), &format!("{app}/secret/registry.auth")).await;
    assert_eq!(status, StatusCode::OK, "{sealed}");
    assert_eq!(open(&sealed, &pod.tee).unwrap(), b"{\"auths\":{}}");
    assert!(
        open(&sealed, &tee_secret(62)).is_none(),
        "only the TEE key opens it"
    );

    let (status, sealed) = get(&h, Some(&token), &format!("{app}/key/volume.data")).await;
    assert_eq!(status, StatusCode::OK, "{sealed}");
    assert_eq!(
        open(&sealed, &pod.tee).unwrap(),
        h.app_key(app, "volume.data"),
        "the key POST /v1/keys/derive returns for the purpose"
    );

    let rows = h.audit("kbs.resource").await;
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|(_, outcome, _)| outcome == "ok"));
    let objects: Vec<(String, String, Option<uuid::Uuid>)> = sqlx::query_as(
        "select actor, object, org_id from audit_log where action = 'kbs.resource' order by seq",
    )
    .fetch_all(&h.pool)
    .await
    .unwrap();
    assert_eq!(
        objects,
        [
            (
                key_sha256.clone(),
                format!("resource:{app}/secret/registry.auth"),
                Some(h.org.into())
            ),
            (
                key_sha256,
                format!("resource:{app}/key/volume.data"),
                Some(h.org.into())
            ),
        ]
    );
}

#[tokio::test]
async fn a_cpu_pod_attests_without_device_evidence() {
    let gpu = FakeGpu::new();
    let Some(h) = kbs_harness(&gpu).await else {
        return;
    };
    let admin = h.register_key(&h.root, 42).await;
    let pod = KbsPod::new(Pod::cpu(AppId::mint()), 63);
    pod.pod.register(&h, &admin).await;
    let token = pod.attest(&h).await.unwrap();
    assert_eq!(gpu.calls(), 0);
    let (status, sealed) = get(&h, Some(&token), &format!("{}/key/db", pod.pod.app)).await;
    assert_eq!(status, StatusCode::OK, "{sealed}");
    assert_eq!(
        open(&sealed, &pod.tee).unwrap(),
        h.app_key(pod.pod.app, "db")
    );

    // GPU evidence from a CPU-class pod is refused, never ignored, even bound into its quote.
    let mut with_gpu = KbsPod::new(Pod::cpu(pod.pod.app), 63);
    with_gpu.pod.gpus.push(Gpu::b300(0));
    refused(
        &h,
        with_gpu.attest(&h).await,
        "attestation_failed",
        "which runs no GPU",
    )
    .await;
    assert_eq!(gpu.calls(), 0);
}

/// The host, or another pod, against the handshake: every case refused with its reason in a
/// `kbs.attest` audit row, and no token.
#[tokio::test]
async fn a_hostile_attestation_is_refused_and_audited() {
    let gpu = FakeGpu::new();
    let Some(h) = kbs_harness(&gpu).await else {
        return;
    };
    let admin = h.register_key(&h.root, 43).await;
    let pod = KbsPod::new(Pod::gpu(AppId::mint(), 8), 64);

    // Not registered yet.
    refused(
        &h,
        pod.attest(&h).await,
        "attestation_unknown",
        "is not registered",
    )
    .await;
    let hash = pod.pod.register(&h, &admin).await;
    let calls = gpu.calls();

    // Wrong nonce: one another KMS minted, one expired, one not a nonce at all.
    let foreign =
        BASE64_STANDARD.encode(alpha_kms::instance::mint_nonce(&[9; 32], h.now()).unwrap());
    refused(
        &h,
        pod.exchange(&foreign).attest(&h).await,
        "nonce_invalid",
        "does not verify",
    )
    .await;
    let stale = BASE64_STANDARD.encode(
        alpha_kms::instance::mint_nonce(
            &h.node.nonce_key,
            h.now() - std::time::Duration::from_secs(301),
        )
        .unwrap(),
    );
    refused(
        &h,
        pod.exchange(&stale).attest(&h).await,
        "nonce_invalid",
        "too old",
    )
    .await;
    refused(
        &h,
        pod.exchange("test_nonce").attest(&h).await,
        "nonce_invalid",
        "not one this KMS issued",
    )
    .await;

    // A quote over another challenge, replayed with this one.
    let nonce = KbsPod::nonce(&h);
    let earlier = pod.exchange(&BASE64_STANDARD.encode([1u8; 32]));
    let mut replay = pod.exchange(&nonce);
    replay.quote = earlier.quote;
    refused(
        &h,
        replay.attest(&h).await,
        "attestation_failed",
        "report_data is not bound to this key and nonce",
    )
    .await;

    // The tee-pubkey is not the one the quote bound: the host swaps in its own.
    let mut swapped = pod.exchange(&nonce);
    swapped.body["runtime-data"]["tee-pubkey"] = json!(tee_key(&tee_secret(66)));
    refused(
        &h,
        swapped.attest(&h).await,
        "attestation_failed",
        "report_data is not bound to this key and nonce",
    )
    .await;

    // GPU evidence edited after the quote bound it.
    let mut edited = pod.exchange(&nonce);
    let additional = edited.body["tee-evidence"]["additional_evidence"]
        .as_str()
        .unwrap()
        .to_owned();
    edited.body["tee-evidence"]["additional_evidence"] = json!(format!("{additional} "));
    refused(
        &h,
        edited.attest(&h).await,
        "attestation_failed",
        "report_data is not bound",
    )
    .await;

    // Another pod's init-data under this pod's MRCONFIGID.
    let mut other_initdata = pod.exchange(&nonce);
    other_initdata.body["init-data"]["body"] = json!(Pod::gpu(AppId::mint(), 8).initdata);
    refused(
        &h,
        other_initdata.attest(&h).await,
        "attestation_failed",
        "MRCONFIGID is not the digest of the init-data sent",
    )
    .await;

    // No init-data, an RSA TEE key, a body that is not an Attestation.
    let mut no_initdata = pod.exchange(&nonce);
    no_initdata.body["init-data"] = Value::Null;
    refused(
        &h,
        no_initdata.attest(&h).await,
        "attestation_failed",
        "no init-data",
    )
    .await;
    let mut rsa = pod.exchange(&nonce);
    rsa.body["runtime-data"]["tee-pubkey"] =
        json!({ "kty": "RSA", "alg": "RSA-OAEP-256", "n": "AQAB", "e": "AQAB" });
    refused(&h, rsa.attest(&h).await, "malformed", "tee-pubkey").await;
    refused(
        &h,
        alpha_kms::kbs::attest_verified(
            &h.node,
            b"{\"runtime-data\":1}",
            pod.exchange(&nonce).quote,
        )
        .await,
        "malformed",
        "Attestation",
    )
    .await;
    assert_eq!(gpu.calls(), calls, "no GPU backend runs for a failed TD");
    // GPU reports over another nonce, bound into a fresh quote.
    let mut stale_gpus = KbsPod::new(Pod::gpu(pod.pod.app, 8), 64);
    stale_gpus.pod.gpus[2].nonce = Some([7; 32]);
    refused(
        &h,
        stale_gpus.exchange(&nonce).attest(&h).await,
        "attestation_failed",
        "gpu 2: report is not over this nonce",
    )
    .await;

    // A revoked Revision.
    let token = pod.attest(&h).await.unwrap();
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
    // Its earlier token releases nothing more: 401, so the client attests again and is refused.
    denied(
        &h,
        Some(&token),
        &format!("{}/key/volume.data", pod.pod.app),
        StatusCode::UNAUTHORIZED,
        "PolicyDeny",
        "revision_revoked",
    )
    .await;
    let rows: i64 =
        sqlx::query_scalar("select count(*) from audit_log where action = 'kbs.attest'")
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert_eq!(rows, 14, "one row per attempt");
}

/// Deny by default: only the token's own App's resources, only the two types, only names the
/// KMS could hold; and only a token this KMS issued, unexpired, unedited.
#[tokio::test]
async fn a_resource_is_released_only_to_its_apps_pod_with_a_valid_token() {
    let gpu = FakeGpu::new();
    let Some(h) = kbs_harness(&gpu).await else {
        return;
    };
    let admin = h.register_key(&h.root, 44).await;
    let pod = KbsPod::new(Pod::cpu(AppId::mint()), 67);
    let other = KbsPod::new(Pod::cpu(AppId::mint()), 68);
    pod.pod.register(&h, &admin).await;
    other.pod.register(&h, &admin).await;
    let (app, other_app) = (pod.pod.app, other.pod.app);
    for (name, apps) in [("mine", vec![app]), ("theirs", vec![other_app])] {
        let (status, reply) = h.put_secret(name, &apps, b"value", h.now(), &admin).await;
        assert_eq!(status, StatusCode::OK, "{reply}");
    }
    let token = pod.attest(&h).await.unwrap();
    let (status, _) = get(&h, Some(&token), &format!("{app}/secret/mine")).await;
    assert_eq!(status, StatusCode::OK);

    // Another pod's App: by its repository, or its secret named under ours.
    for path in [
        format!("{other_app}/secret/theirs"),
        format!("{other_app}/key/volume.data"),
        format!("{app}/secret/theirs"),
    ] {
        denied(
            &h,
            Some(&token),
            &path,
            StatusCode::NOT_FOUND,
            "ResourceNotFound",
            "not_found",
        )
        .await;
    }
    // Unknown resources: another type, a name the KMS cannot hold, upstream's `default`.
    for path in [
        format!("{app}/secret/missing"),
        format!("{app}/cert/leaf"),
        format!("{app}/key/UPPER"),
        "default/key/1".to_owned(),
    ] {
        denied(
            &h,
            Some(&token),
            &path,
            StatusCode::NOT_FOUND,
            "ResourceNotFound",
            "not_found",
        )
        .await;
    }
    let refused_names: i64 = sqlx::query_scalar(
        "select count(*) from audit_log where action = 'kbs.resource' and object is null",
    )
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert_eq!(refused_names, 3, "a refused name is not written to the log");

    // Tokens: none, one past `exp`, one with its claims edited, one from another root, `alg: none`.
    let path = format!("{app}/secret/mine");
    denied(
        &h,
        None,
        &path,
        StatusCode::UNAUTHORIZED,
        "TokenNotFound",
        "token_missing",
    )
    .await;
    let keys = h.node.intermediates().unwrap();
    let key = token::token_key(&keys.tenant_kek_root).unwrap();
    let mut claims = token::verify(
        &key,
        &token,
        h.now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
    )
    .unwrap();
    claims.exp = claims.iat;
    let expired = token::issue(&key, &claims).unwrap();
    let mut parts: Vec<String> = token.split('.').map(str::to_owned).collect();
    let mut edited_claims: Value =
        serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(&parts[1]).unwrap()).unwrap();
    edited_claims["revision"]["app_id"] = json!(other_app);
    parts[1] = BASE64_URL_SAFE_NO_PAD.encode(edited_claims.to_string());
    let edited = parts.join(".");
    let foreign = token::issue(&token::token_key(&[3; 32]).unwrap(), &claims).unwrap();
    let none = format!(
        "{}.{}.",
        BASE64_URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#),
        token.split('.').nth(1).unwrap()
    );
    for bad in [expired, edited, foreign, none] {
        denied(
            &h,
            Some(&bad),
            &path,
            StatusCode::UNAUTHORIZED,
            "TokenVerifierError",
            "token_invalid",
        )
        .await;
    }

    // A replayed token gets a response only the TEE key its quote bound opens.
    let (status, sealed) = get(&h, Some(&token), &path).await;
    assert_eq!(status, StatusCode::OK);
    assert!(open(&sealed, &other.tee).is_none());
    assert_eq!(open(&sealed, &pod.tee).unwrap(), b"value");

    // The agent's own client presents the session cookie instead.
    let (status, sealed) = send(
        client()
            .get(format!("{}/kbs/v0/resource/{path}", h.url))
            .header("cookie", format!("kbs-session-id={token}")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{sealed}");
    assert_eq!(open(&sealed, &pod.tee).unwrap(), b"value");
}

/// The routes: `/auth` as the agent calls it, the facade off without a hostname, no route to
/// write or administer a resource, and the node's leaf naming the hostname for a client that
/// trusts only the KMS CA, as CDH does with `kbs_cert`.
#[tokio::test]
async fn the_kbs_routes_serve_attested_pods_only() {
    let gpu = FakeGpu::new();
    // The wall clock, so the client accepts the node's one-hour leaf.
    let Some(h) = kbs_harness_with_clock(&gpu, Arc::new(SystemTime::now)).await else {
        return;
    };
    let addr = h.url.trim_start_matches("https://").to_owned();
    let ca = reqwest::Certificate::from_pem(h.ca_pem.as_bytes()).unwrap();
    let cdh = reqwest::Client::builder()
        .tls_certs_only([ca])
        .resolve(HOSTNAME, addr.parse().unwrap())
        .build()
        .unwrap();
    let port = addr.rsplit(':').next().unwrap();
    let base = format!("https://{HOSTNAME}:{port}/kbs/v0");
    let request = json!({ "version": "0.4.0", "tee": "tdx",
                          "extra-params": { "supported-hash-algorithms": ["sha256", "sha384", "sha512", "sm3"] } });
    let (status, challenge) = send(cdh.post(format!("{base}/auth")).json(&request)).await;
    assert_eq!(status, StatusCode::OK, "{challenge}");
    assert_eq!(
        challenge["extra-params"],
        json!({ "selected-hash-algorithm": "sha384" })
    );
    let nonce: [u8; 32] = BASE64_STANDARD
        .decode(challenge["nonce"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    alpha_kms::instance::check_nonce(&h.node.nonce_key, &nonce, h.now()).unwrap();

    for (field, value, reason) in [
        (
            "version",
            json!("0.3.0"),
            "KBS Client Protocol Version Mismatch",
        ),
        ("tee", json!("snp"), "only tdx"),
        (
            "extra-params",
            json!({ "supported-hash-algorithms": ["sha256"] }),
            "sha384",
        ),
    ] {
        let mut bad = request.clone();
        bad[field] = value;
        let (status, reply) = send(cdh.post(format!("{base}/auth")).json(&bad)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{reply}");
        assert!(
            reply["detail"].as_str().unwrap().contains(reason),
            "{reply}"
        );
    }

    // Through the route, the synthetic quote fails DCAP, and the refusal is audited.
    let admin = h.register_key(&h.root, 45).await;
    let pod = KbsPod::new(Pod::gpu(AppId::mint(), 1), 69);
    pod.pod.register(&h, &admin).await;
    let exchange = pod.exchange(challenge["nonce"].as_str().unwrap());
    let (status, reply) = send(cdh.post(format!("{base}/attest")).json(&exchange.body)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{reply}");
    assert_eq!(kind(&reply), "AttestationError");
    assert!(
        reply["detail"].as_str().unwrap().contains("dcap"),
        "{reply}"
    );
    let (_, outcome, details) = h.audit("kbs.attest").await.pop().unwrap();
    assert_eq!(
        (outcome.as_str(), &details["code"]),
        ("denied", &json!("attestation_failed"))
    );
    assert_eq!(gpu.calls(), 0);

    // A token's route answers with the cookie too.
    let token = pod.attest(&h).await.unwrap();
    let (status, _) = send(
        cdh.get(format!("{base}/resource/{}/key/x", pod.pod.app))
            .bearer_auth(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // No route writes or deletes a resource; Trustee's admin API does not exist.
    let resource = format!("{base}/resource/{}/key/x", pod.pod.app);
    for (request, expected) in [
        (
            cdh.post(&resource).bearer_auth(&token).body("x"),
            StatusCode::METHOD_NOT_ALLOWED,
        ),
        (
            cdh.put(&resource).bearer_auth(&token).body("x"),
            StatusCode::METHOD_NOT_ALLOWED,
        ),
        (
            cdh.delete(&resource).bearer_auth(&token),
            StatusCode::METHOD_NOT_ALLOWED,
        ),
        (
            cdh.post(format!("{base}/resource-policy")).body("{}"),
            StatusCode::NOT_FOUND,
        ),
        (
            cdh.post(format!("{base}/attestation-policy")).body("{}"),
            StatusCode::NOT_FOUND,
        ),
        (
            cdh.get(format!("{base}/reference-value/x")),
            StatusCode::NOT_FOUND,
        ),
    ] {
        let (status, reply) = send(request).await;
        assert_eq!(status, expected, "{reply}");
    }
}

#[tokio::test]
async fn without_a_hostname_the_facade_refuses_everything() {
    let gpu = FakeGpu::new();
    let Some(h) = kata_harness(&gpu).await else {
        return;
    };
    let leaf = h.node.server_cert.leaf_der().unwrap();
    let (_, cert) = x509_parser::parse_x509_certificate(&leaf).unwrap();
    let san = cert.subject_alternative_name().unwrap().unwrap();
    assert!(
        san.value
            .general_names
            .iter()
            .all(|n| matches!(n, x509_parser::extensions::GeneralName::URI(_))),
        "no DNS name without a hostname"
    );
    let admin = h.register_key(&h.root, 46).await;
    let pod = KbsPod::new(Pod::cpu(AppId::mint()), 70);
    pod.pod.register(&h, &admin).await;
    let (status, reply) = h
        .post(
            "/kbs/v0/auth",
            json!({ "version": "0.4.0", "tee": "tdx", "extra-params": "" }),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{reply}");
    assert!(reply["detail"].as_str().unwrap().contains("kbs_disabled"));
    let error = pod.attest(&h).await.unwrap_err();
    assert_eq!(error.code, "kbs_disabled");
    let (status, _) = get(&h, Some("a.b.c"), &format!("{}/key/x", pod.pod.app)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(h.audit("kbs.attest").await.is_empty());
}

#[tokio::test]
async fn the_nodes_leaf_names_the_kbs_hostname() {
    let gpu = FakeGpu::new();
    let Some(h) = kbs_harness(&gpu).await else {
        return;
    };
    let leaf = h.node.server_cert.leaf_der().unwrap();
    let (_, cert) = x509_parser::parse_x509_certificate(&leaf).unwrap();
    let names: Vec<String> = cert
        .subject_alternative_name()
        .unwrap()
        .unwrap()
        .value
        .general_names
        .iter()
        .map(|n| n.to_string())
        .collect();
    assert_eq!(
        names,
        [
            "URI(alphacompute://kms)".to_owned(),
            format!("URI(urn:alphacompute:revision:{})", h.node.compose_hash),
            format!("DNSName({HOSTNAME})"),
        ]
    );
}

/// The response decrypts exactly as guest-components d4dce5ce's `decrypt_response` does it,
/// header re-serialization for the AAD included, and to nobody else.
#[test]
fn a_sealed_resource_opens_as_the_guest_opens_it() {
    let tee = tee_secret(5);
    let public = tee.public_key();
    for plaintext in [&b""[..], b"x", &[0xa5; 4096]] {
        let sealed = jwe::seal(&public, plaintext).unwrap();
        assert_eq!(open(&sealed, &tee).unwrap(), plaintext);
        assert!(open(&sealed, &tee_secret(6)).is_none());
        let mut tampered = sealed.clone();
        tampered["iv"] = json!(BASE64_URL_SAFE_NO_PAD.encode([0u8; 12]));
        assert!(open(&tampered, &tee).is_none());
    }
}

/// A regression vector, computed by this implementation from a fixed TEE key, ephemeral key,
/// content key and IV (its interoperability is the test above). The header is
/// `{"alg":"ECDH-ES+A256KW","enc":"A256GCM","epk":{"crv":"P-256","kty":"EC","x":…,"y":…}}`,
/// members in the order kbs-types re-serializes them.
#[test]
fn seal_known_answer() {
    let tee = tee_secret(5);
    let ephemeral = tee_secret(8);
    let sealed = jwe::seal_with(
        &tee.public_key(),
        &ephemeral,
        &[0x11; 32],
        &[0x22; 12],
        b"alpha-kbs",
    )
    .unwrap();
    let header = String::from_utf8(
        BASE64_URL_SAFE_NO_PAD
            .decode(sealed["protected"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    let epk = tee_key(&ephemeral);
    assert_eq!(
        header,
        format!(
            r#"{{"alg":"ECDH-ES+A256KW","enc":"A256GCM","epk":{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}}}"#,
            epk.x, epk.y
        )
    );
    assert_eq!(sealed["iv"], BASE64_URL_SAFE_NO_PAD.encode([0x22; 12]));
    assert_eq!(open(&sealed, &tee).unwrap(), b"alpha-kbs");
    assert_eq!(
        sealed,
        json!({
            "protected": sealed["protected"],
            "encrypted_key": KNOWN_ENCRYPTED_KEY,
            "iv": "IiIiIiIiIiIiIiIi",
            "ciphertext": KNOWN_CIPHERTEXT,
            "tag": KNOWN_TAG,
        })
    );
}

const KNOWN_ENCRYPTED_KEY: &str = "eSfDa_fqHpdkGEYxuGF0iKJeczSpnR_uwd6f6Nu3nQGz9LrIYyXnNg";
const KNOWN_CIPHERTEXT: &str = "dpt3IaHi9D2W";
const KNOWN_TAG: &str = "of0x9aFA2djRDk-cFDlQlA";
