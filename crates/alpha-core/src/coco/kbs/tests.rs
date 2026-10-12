use super::*;

/// A self-signed P-256 certificate standing in for Trustee's KBS certificate; its SPKI SHA-256
/// is `openssl x509 -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum`.
pub(crate) const CERT: &str = include_str!("../../../../../testdata/coco/kbs/cert.pem");
const CERT_SPKI_SHA256: &str =
    "sha256:4d7e6cc449a9bae42927277d06379b6f3b7a22f8efc67c542bf9185d471f99a8";
pub(crate) const URL: &str = "https://kbs.trustee.alphacompute.internal:8080";
const APP: &str = "01994b3e-5c8a-7d3e-9a1b-2c3d4e5f6a7b";

fn config() -> KbsConfig {
    KbsConfig::new(URL, CERT).unwrap()
}

#[test]
fn the_entries_are_guest_components_settings_for_one_kbs() {
    let c = config();
    assert_eq!(c.cert_pem(), CERT);
    assert_eq!(
        c.revision(),
        RevisionKbs {
            cert_spki_sha256: CERT_SPKI_SHA256.parse().unwrap(),
            url: URL.into(),
        }
    );
    assert_eq!(
        c.aa_toml(),
        format!(
            "[token_configs.kbs]\nurl = \"{URL}\"\ncert = \"\"\"\n{CERT}\"\"\"\ntee_key_algorithm = \"ECDH-ES+A256KW-P256\"\n"
        )
    );
    assert_eq!(
        c.cdh_toml(),
        format!("[kbc]\nname = \"cc_kbc\"\nurl = \"{URL}\"\nkbs_cert = \"\"\"\n{CERT}\"\"\"\n")
    );
    // As AA and CDH read them: TOML whose cert is the PEM, first newline dropped.
    let aa: toml::Table = toml::from_str(&c.aa_toml()).unwrap();
    assert_eq!(aa["token_configs"]["kbs"]["cert"].as_str(), Some(CERT));
    let cdh: toml::Table = toml::from_str(&c.cdh_toml()).unwrap();
    assert_eq!(cdh["kbc"]["kbs_cert"].as_str(), Some(CERT));
    assert_eq!(cdh["kbc"]["url"].as_str(), Some(URL));
    assert_eq!(
        KbsConfig::from_entries(&c.aa_toml(), &c.cdh_toml()).unwrap(),
        c
    );
}

#[test]
fn a_pem_with_other_line_lengths_is_written_in_the_canonical_form() {
    let joined: String = CERT.lines().filter(|l| !l.starts_with("-----")).collect();
    let long = format!("{PEM_BEGIN}\n{joined}\n{PEM_END}");
    assert_eq!(KbsConfig::new(URL, &long).unwrap(), config());
}

#[test]
fn entries_that_say_anything_else_are_refused() {
    let c = config();
    let (aa, cdh) = (c.aa_toml(), c.cdh_toml());
    let other_url = KbsConfig::new("https://evil.example", CERT).unwrap();
    for (aa, cdh, why) in [
        // A setting the generator never writes.
        (
            aa.clone(),
            format!("{cdh}skip_sealed_secret_verification = true\n"),
            "unknown field",
        ),
        (
            aa.clone(),
            format!("credentials = []\n{cdh}"),
            "unknown field",
        ),
        (
            aa.clone(),
            format!("{cdh}[image]\nimage_security_policy_uri = \"kbs:///x/y/z\"\n"),
            "unknown field",
        ),
        (
            format!("{aa}[token_configs.coco_as]\nurl = \"https://as.example\"\n"),
            cdh.clone(),
            "unknown field",
        ),
        (
            format!("[eventlog_config]\nenable_eventlog = true\n{aa}"),
            cdh.clone(),
            "unknown field",
        ),
        (
            aa.replace("ECDH-ES+A256KW-P256", "RSA-OAEP-256"),
            cdh.clone(),
            "tee_key_algorithm",
        ),
        (
            aa.clone(),
            cdh.replace("cc_kbc", "offline_fs_kbc"),
            "kbc.name",
        ),
        // Two KBSes.
        (other_url.aa_toml(), cdh.clone(), "different"),
        (aa.clone(), other_url.cdh_toml(), "different"),
        // The same settings, written another way.
        (aa.replace("url = ", "url =  "), cdh.clone(), "form"),
        (format!("# comment\n{aa}"), cdh.clone(), "form"),
        (aa.replace(URL, "http://kbs.example"), cdh.clone(), "https"),
        (aa.clone(), String::new(), "missing field"),
    ] {
        let error = KbsConfig::from_entries(&aa, &cdh).unwrap_err();
        assert!(error.contains(why), "{why}: {error}");
    }
}

#[test]
fn a_kbs_is_an_https_origin_with_one_certificate() {
    for url in [
        "https://kbs.example",
        "https://kbs.example:8080",
        "https://10.0.0.7:443",
    ] {
        check_url(url).unwrap();
    }
    for url in [
        "http://kbs.example",
        "https://KBS.example",
        "https://kbs.example/",
        "https://kbs.example/kbs/v0",
        "https://user@kbs.example",
        "https://kbs.example:0",
        "https://kbs.example:080",
        "https://kbs.example:65536",
        "https://-kbs.example",
        "https://kbs..example",
        "https://",
        "https://kbs.example?x",
        "https://kbs.example\n",
    ] {
        assert!(check_url(url).is_err(), "{url}");
    }
    let two = format!("{CERT}{CERT}");
    for (pem, why) in [
        (two.as_str(), "more than one"),
        ("", "not one PEM"),
        (
            "-----BEGIN CERTIFICATE-----\n!!\n-----END CERTIFICATE-----",
            "base64",
        ),
        (
            "-----BEGIN CERTIFICATE-----\nMAA=\n-----END CERTIFICATE-----",
            "X.509",
        ),
        (
            "-----BEGIN CERTIFICATE-----\n\n-----END CERTIFICATE-----",
            "empty",
        ),
    ] {
        let error = KbsConfig::new(URL, pem).unwrap_err();
        assert!(error.contains(why), "{why}: {error}");
    }
}

#[test]
fn the_der_walk_takes_only_minimal_definite_lengths() {
    assert_eq!(tlv(&[0x30, 0x00], 0x30).unwrap().0, [0x30, 0x00]);
    assert!(tlv(&[0x30, 0x00], 0x02).is_none());
    // Long form for a length under 128, a leading zero, indefinite, truncated.
    assert!(tlv(&[0x30, 0x81, 0x01, 0x00], 0x30).is_none());
    assert!(tlv(&[0x30, 0x82, 0x00, 0x80], 0x30).is_none());
    assert!(tlv(&[0x30, 0x80, 0x00, 0x00], 0x30).is_none());
    assert!(tlv(&[0x30, 0x05, 0x00], 0x30).is_none());
    let der = pem_certificate(CERT).unwrap();
    let mut trailing = der.clone();
    trailing.push(0);
    assert!(spki(&trailing).is_none());
    assert!(spki(&der[..der.len() - 1]).is_none());
}

#[test]
fn resource_uris_follow_the_contract() {
    let app: AppId = APP.parse().unwrap();
    for (kind, tag) in [
        (ResourceType::Secret, "db_password"),
        (ResourceType::Key, "volume.pgdata"),
        (ResourceType::ImageKey, "model-weights"),
        (ResourceType::SealedSecretKey, "sealing"),
    ] {
        let resource = Resource::new(app, kind, tag).unwrap();
        let uri = resource.uri();
        assert_eq!(uri, format!("kbs:///{APP}/{}/{tag}", kind.name()));
        assert_eq!(Resource::parse(&uri).unwrap(), resource);
    }
    for uri in [
        format!("kbs:///{APP}/key/volume:pgdata"),
        format!("kbs:///{APP}/secret/a/b"),
        format!("kbs:///{APP}/cert/x"),
        format!("kbs:///{APP}/resource-policy/x"),
        format!("kbs:///{}/secret/x", APP.to_uppercase()),
        "kbs:///default/key/1".into(),
        format!("kbs://kbs.example/{APP}/secret/x"),
        format!("kbs:///{APP}/secret/"),
        format!("kbs:///{APP}/secret"),
    ] {
        assert!(Resource::parse(&uri).is_err(), "{uri}");
    }
}
