//! The KBS facade's wire shapes against what guest-components d4dce5ce sends: upstream test
//! vectors (kbs-types 0.18.0, the agent's request and runtime-data hashing) and the deny-by-default
//! resource names. The protocol end to end, over a database, is `tests/kbs.rs`.

use axum::http::HeaderValue;
use p256::elliptic_curve::sec1::ToSec1Point;

use super::*;

/// kbs-types 0.18.0 `parse_attestation_ec`, verbatim.
const UPSTREAM_ATTESTATION_EC: &str = r#"
{
    "runtime-data": {
        "nonce": "test_nonce",
        "tee-pubkey": {
            "kty": "EC",
            "crv": "fakecrv",
            "alg": "fakealgorithm",
            "x": "fakex",
            "y": "fakey"
        }
    },
    "tee-evidence": {
        "primary_evidence": "test_primary_evidence",
        "additional_evidence": "test_additional_evidence"
    }
}"#;

/// A P-256 key the attestation agent could have exported (its x and y, base64url).
fn tee_key() -> TeeKey {
    let point = p256::SecretKey::from_slice(&[7; 32])
        .unwrap()
        .public_key()
        .to_sec1_point(false);
    TeeKey {
        kty: "EC".into(),
        crv: "P-256".into(),
        alg: "ECDH-ES+A256KW".into(),
        x: BASE64_URL_SAFE_NO_PAD.encode(point.x().unwrap()),
        y: BASE64_URL_SAFE_NO_PAD.encode(point.y().unwrap()),
    }
}

#[test]
fn parses_the_upstream_attestation_and_refuses_its_fake_key() {
    let attestation: Attestation = serde_json::from_str(UPSTREAM_ATTESTATION_EC).unwrap();
    assert!(attestation.init_data.is_none());
    assert_eq!(attestation.runtime_data.nonce, "test_nonce");
    assert_eq!(
        attestation.tee_evidence.additional_evidence,
        "test_additional_evidence"
    );
    let key: TeeKey = serde_json::from_value(attestation.runtime_data.tee_pubkey).unwrap();
    assert_eq!(key.public_key().unwrap_err().code, "malformed");
    // `"init-data": null`, as the agent sends it without init-data, is the same.
    let mut with_null: Value = serde_json::from_str(UPSTREAM_ATTESTATION_EC).unwrap();
    with_null["init-data"] = Value::Null;
    assert!(
        serde_json::from_value::<Attestation>(with_null)
            .unwrap()
            .init_data
            .is_none()
    );
}

/// The `Request` `build_request(Tee::Tdx)` sends (kbs-types' `HashAlgorithm::list_all`).
#[test]
fn parses_the_agents_request() {
    let request: AuthRequest = serde_json::from_str(
        r#"{"version":"0.4.0","tee":"tdx","extra-params":{"supported-hash-algorithms":["sha256","sha384","sha512","sm3"]}}"#,
    )
    .unwrap();
    assert_eq!(
        (request.version.as_str(), request.tee.as_str()),
        (PROTOCOL_VERSION, TEE)
    );
    // kbs-types 0.18.0 `parse_request`: extra-params may be any value.
    let upstream: AuthRequest =
        serde_json::from_str(r#"{"version":"0.0.0","tee":"tdx","extra-params":""}"#).unwrap();
    assert_eq!(upstream.extra_params, "");
}

#[test]
fn only_the_agents_default_p256_key_is_accepted() {
    assert!(tee_key().public_key().is_ok());
    let refused = |key: TeeKey| key.public_key().unwrap_err().code;
    for (field, value) in [
        ("kty", "RSA"),
        ("crv", "P-521"),
        ("alg", "RSA-OAEP-256"),
        ("x", "AAAA"),
    ] {
        let mut key = serde_json::to_value(tee_key()).unwrap();
        key[field] = json!(value);
        assert_eq!(
            refused(serde_json::from_value(key).unwrap()),
            "malformed",
            "{field}"
        );
    }
    let mut off_curve = tee_key();
    off_curve.y = off_curve.x.clone();
    assert_eq!(refused(off_curve), "malformed");
    // An RSA key's members, or any other, are not fields of this key.
    let mut extra = serde_json::to_value(tee_key()).unwrap();
    extra["n"] = json!("modulus");
    assert!(serde_json::from_value::<TeeKey>(extra).is_err());
}

/// `get_composite_evidence` hashes `serialize_json_canonically` of these objects with SHA-384;
/// written out here byte for byte, so the binding does not depend on how `json!` orders keys.
#[test]
fn binding_is_what_the_agent_hashed_into_report_data_and_the_gpu_nonce() {
    let key = tee_key();
    let nonce = BASE64_STANDARD.encode([0xa5; 32]);
    let additional = r#"{"nvidia":{"device_evidence_list":[]}}"#;
    let attestation: Attestation = serde_json::from_value(json!({
        "runtime-data": { "nonce": nonce, "tee-pubkey": key },
        "tee-evidence": { "primary_evidence": {}, "additional_evidence": additional },
    }))
    .unwrap();
    let jwk = format!(
        r#"{{"alg":"ECDH-ES+A256KW","crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
        key.x, key.y
    );
    let primary = format!(
        r#"{{"additional-evidence":"{{\"nvidia\":{{\"device_evidence_list\":[]}}}}","nonce":"{nonce}","tee-pubkey":{jwk}}}"#
    );
    let device = format!(r#"{{"nonce":"{nonce}","tee-pubkey":{jwk}}}"#);

    let mut report_data = [0u8; 64];
    report_data[..48].copy_from_slice(&Sha384::digest(primary.as_bytes()));
    let gpu_nonce: [u8; 32] = Sha384::digest(device.as_bytes())[..32].try_into().unwrap();
    let key_sha256: [u8; 32] = Sha256::digest(jwk.as_bytes()).into();
    assert_eq!(
        binding(&attestation, &key).unwrap(),
        kata::Binding::exact(report_data, gpu_nonce, key_sha256)
    );
}

#[test]
fn evidence_takes_the_class_from_the_init_data_and_refuses_unknown_devices() {
    let initdata = "algorithm = \"sha384\"\nversion = \"0.1.0\"\n\n[data]\n\"policy.rego\" = '''\npackage agent_policy\n'''\n\"alpha.json\" = '''{\"app_id\":\"01994b3e-5c8a-7d3e-9a1b-2c3d4e5f6a7b\",\"format\":\"alphacompute-initdata/1\",\"runtime_class\":\"kata-qemu-tdx\"}'''\n";
    let attestation = |init: Value, additional: &str| -> Attestation {
        serde_json::from_value(json!({
            "init-data": init,
            "runtime-data": { "nonce": "n", "tee-pubkey": tee_key() },
            "tee-evidence": {
                "primary_evidence": { "quote": BASE64_STANDARD.encode(b"quote"), "cc_eventlog": null },
                "additional_evidence": additional,
            },
        }))
        .unwrap()
    };
    let toml = json!({ "format": "toml", "body": initdata });
    let evidence = evidence_v2(&attestation(toml.clone(), "")).unwrap();
    assert_eq!(evidence.runtime_class, "kata-qemu-tdx");
    assert_eq!(evidence.cpu.quote, b"quote");
    assert_eq!(evidence.initdata, initdata.as_bytes());
    assert!(evidence.gpus.is_empty() && evidence.cpu.event_log.is_empty());

    let refused = |a: Attestation| {
        let e = evidence_v2(&a).unwrap_err();
        (e.code, e.message)
    };
    assert_eq!(
        refused(attestation(Value::Null, "")).0,
        "attestation_failed"
    );
    assert_eq!(
        refused(attestation(
            json!({ "format": "json", "body": initdata }),
            ""
        ))
        .0,
        "attestation_failed"
    );
    let (code, message) = refused(attestation(toml.clone(), r#"{"nvidia-dpu":{}}"#));
    assert_eq!(code, "attestation_failed");
    assert!(message.contains("nvidia-dpu"), "{message}");

    // NVIDIA's devices, NVSwitches left out, as the agent's NVIDIA attester lists them.
    let device = |arch: &str| {
        json!({ "arch": arch, "uuid": "unknown", "evidence": BASE64_STANDARD.encode(b"report"),
                "certificate": BASE64_STANDARD.encode(b"chain") })
    };
    let nvidia =
        json!({ "nvidia": { "device_evidence_list": [device("BLACKWELL"), device("LS10")] } });
    let evidence = evidence_v2(&attestation(toml, &nvidia.to_string())).unwrap();
    assert_eq!(evidence.gpus.len(), 1);
    assert_eq!(evidence.gpus[0].evidence, b"report");
}

#[test]
fn resource_names_are_an_app_id_then_secret_or_key() {
    let app = AppId::mint();
    assert_eq!(
        Resource::parse(&app.to_string(), "secret", "registry.auth").unwrap(),
        Resource::Secret {
            app,
            name: "registry.auth".into()
        }
    );
    assert_eq!(
        Resource::parse(&app.to_string(), "key", "volume.data").unwrap(),
        Resource::Key {
            app,
            purpose: "volume.data".into()
        }
    );
    let upper = app.to_string().to_uppercase();
    let simple = Uuid::from(app).simple().to_string();
    for (repository, kind, tag) in [
        ("default", "key", "1"),
        (upper.as_str(), "key", "1"),
        (simple.as_str(), "key", "1"),
        (&app.to_string(), "cert", "1"),
        (&app.to_string(), "resource-policy", "1"),
        (&app.to_string(), "key", "Upper"),
        (&app.to_string(), "key", &"a".repeat(65)),
        (&app.to_string(), "secret", ".hidden"),
    ] {
        assert_eq!(
            Resource::parse(repository, kind, tag).unwrap_err().code,
            "not_found",
            "{repository}/{kind}/{tag}"
        );
    }
}

#[test]
fn the_token_comes_as_a_bearer_or_the_session_cookie() {
    let headers = |pairs: &[(header::HeaderName, &str)]| {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(name.clone(), HeaderValue::from_str(value).unwrap());
        }
        map
    };
    assert_eq!(
        presented_token(&headers(&[(header::AUTHORIZATION, "Bearer a.b.c")])).as_deref(),
        Some("a.b.c")
    );
    assert_eq!(
        presented_token(&headers(&[(
            header::COOKIE,
            "other=1; kbs-session-id=a.b.c"
        )]))
        .as_deref(),
        Some("a.b.c")
    );
    assert_eq!(
        presented_token(&headers(&[
            (header::COOKIE, "kbs-session-id=cookie"),
            (header::AUTHORIZATION, "Bearer bearer"),
        ]))
        .as_deref(),
        Some("bearer")
    );
    assert_eq!(
        presented_token(&headers(&[(header::AUTHORIZATION, "Basic a.b.c")])),
        None
    );
}

#[test]
fn refusals_carry_the_status_the_client_acts_on() {
    let status = |code| KbsError::from(ApiError::new(code, "m")).status;
    assert_eq!(status("token_invalid"), StatusCode::UNAUTHORIZED);
    assert_eq!(status("token_missing"), StatusCode::UNAUTHORIZED);
    assert_eq!(status("attestation_failed"), StatusCode::UNAUTHORIZED);
    assert_eq!(status("revision_revoked"), StatusCode::UNAUTHORIZED);
    assert_eq!(status("not_found"), StatusCode::NOT_FOUND);
    assert_eq!(status("kbs_disabled"), StatusCode::NOT_FOUND);
    assert_eq!(status("internal"), StatusCode::INTERNAL_SERVER_ERROR);
}
