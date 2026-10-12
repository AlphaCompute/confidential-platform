use super::*;

const APP: &str = "01994b3e-5c8a-7d3e-9a1b-2c3d4e5f6a7b";

fn app() -> AppId {
    APP.parse().unwrap()
}

/// A sealed secret as guest-components' `secret` tool writes one, with `header` and `payload`
/// as given and a signature of the right length (CDH, not the generator, verifies it).
pub(crate) fn sealed(header: &Value, payload: &Value) -> String {
    let b64 = |v: &Value| BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).unwrap());
    format!(
        "sealed.{}.{}.{}",
        b64(header),
        b64(payload),
        BASE64_URL_SAFE_NO_PAD.encode([7u8; 64])
    )
}

pub(crate) fn header(app: &str) -> Value {
    json!({ "alg": "ES256", "kid": format!("kbs:///{app}/sealed-secret-key/sealing") })
}

pub(crate) fn payload(app: &str) -> Value {
    json!({
        "version": "0.1.0", "type": "vault", "name": format!("kbs:///{app}/secret/db_password"),
        "provider": "kbs", "provider_settings": {}, "annotations": {},
    })
}

#[test]
fn a_sealed_secret_names_this_apps_secret_and_sealing_key() {
    let s = check_sealed(&sealed(&header(APP), &payload(APP)), app()).unwrap();
    assert_eq!(s.secret.uri(), format!("kbs:///{APP}/secret/db_password"));
    assert_eq!(
        s.signing_key.uri(),
        format!("kbs:///{APP}/sealed-secret-key/sealing")
    );
}

#[test]
fn sealed_secrets_of_another_shape_or_app_are_refused() {
    let other = AppId::mint().to_string();
    let mut cases: Vec<(String, &str)> = vec![
        ("sealed.a.b".into(), "sealed.<header>"),
        ("sealed.!!.e30.e30".into(), "base64url"),
        (sealed(&header(&other), &payload(APP)), "not this App"),
        (sealed(&header(APP), &payload(&other)), "not this App"),
        (sealed(&json!({ "alg": "ES256" }), &payload(APP)), "header"),
        (
            sealed(
                &json!({ "alg": "HS256", "kid": header(APP)["kid"] }),
                &payload(APP),
            ),
            "header",
        ),
        (
            sealed(
                &json!({ "alg": "ES256", "kid": header(APP)["kid"], "jku": "https://x" }),
                &payload(APP),
            ),
            "header",
        ),
        (
            sealed(
                &json!({ "alg": "ES256", "kid": format!("kbs:///{APP}/secret/sealing") }),
                &payload(APP),
            ),
            "sealed-secret-key",
        ),
        (
            sealed(
                &json!({ "alg": "ES256", "kid": "sealing.jwk" }),
                &payload(APP),
            ),
            "kid",
        ),
    ];
    for (field, value) in [
        ("type", json!("envelope")),
        ("provider", json!("aliyun")),
        ("version", json!("0.2.0")),
        ("provider_settings", json!({ "client_key": "x" })),
        ("annotations", json!({ "key_id": "x" })),
    ] {
        let mut p = payload(APP);
        p[field] = value;
        cases.push((sealed(&header(APP), &p), "vault secret"));
    }
    let mut p = payload(APP);
    p["name"] = json!(format!("kbs:///{APP}/key/volume.x"));
    cases.push((sealed(&header(APP), &p), "secret/<name>"));
    let mut p = payload(APP);
    p["name"] = json!("kbs:///default/secret/x");
    cases.push((sealed(&header(APP), &p), "name"));
    let short = sealed(&header(APP), &payload(APP));
    let short = format!("{}.{}", short.rsplit_once('.').unwrap().0, "AAAA");
    cases.push((short, "ES256 signature"));
    for (value, why) in cases {
        let error = check_sealed(&value, app()).unwrap_err();
        assert!(error.contains(why), "{why}: {error}");
    }
}

#[test]
fn the_kbs_flags_come_together() {
    assert_eq!(kbs_from_flags(None, None).unwrap(), None);
    let cert = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/coco/kbs/cert.pem");
    let kbs = kbs_from_flags(Some("https://kbs.example"), Some(&cert))
        .unwrap()
        .unwrap();
    assert_eq!(kbs.url(), "https://kbs.example");
    assert!(kbs_from_flags(Some("https://kbs.example"), None).is_err());
    assert!(kbs_from_flags(None, Some(&cert)).is_err());
    assert!(kbs_from_flags(Some("http://kbs.example"), Some(&cert)).is_err());
}

#[test]
fn the_compose_opts_in_and_names_scratch_volumes() {
    assert!(!kbs_requested(b"services: {}\n").unwrap());
    assert!(kbs_requested(b"x-alphacompute-kbs: true\n").unwrap());
    assert!(!kbs_requested(b"x-alphacompute-kbs: false\n").unwrap());
    assert!(kbs_requested(b"x-alphacompute-kbs: yes please\n").is_err());
    let scratch = scratch_volumes(b"x-alphacompute-scratch:\n  cache: {size: 50Gi}\n").unwrap();
    assert_eq!(scratch, BTreeMap::from([("cache".into(), "50Gi".into())]));
    for bad in [
        "x-alphacompute-scratch: [cache]\n",
        "x-alphacompute-scratch:\n  cache: {size: 50Gi, medium: Memory}\n",
        "x-alphacompute-scratch:\n  cache: {size: 10}\n",
        "x-alphacompute-scratch:\n  Cache: {size: 10Gi}\n",
    ] {
        assert!(scratch_volumes(bad.as_bytes()).is_err(), "{bad}");
    }
}

/// The Revision's `cert_spki_sha256` is the same hash `alpha sign --check` prints for the KMS CA,
/// computed by alpha-core's own DER walk.
#[test]
fn the_revisions_certificate_hash_is_the_spki_hash_the_platform_document_uses() {
    for _ in 0..3 {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["kbs.example".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let pem = cert.pem();
        let kbs = KbsConfig::new("https://kbs.example", &pem).unwrap();
        assert_eq!(
            Some(kbs.revision().cert_spki_sha256.to_string()),
            crate::sign::ca_spki_sha256(&pem).unwrap()
        );
    }
}
