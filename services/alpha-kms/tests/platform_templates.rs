//! The platform services' CoCo templates (`deploy/coco/platform`) put every value in the measured
//! environment, which is in the init-data that `GET /v1/node/evidence` (and each pod's identity)
//! serves to anyone. Rendered with their example env files, as `alpha coco render` fills them, no
//! template may put a password in a URL, and the KMS's database URL must pass the check a Kata node
//! makes before it listens (Hacktron ACC-FD-101).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use alpha_kms::measured_env::{DATABASE_URL_ENV, carries_password, check_database_url};

fn platform_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/coco/platform")
}

/// `NAME=value` lines; comments and blank lines skipped.
fn env_file(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
        .collect()
}

/// Every `${NAME}` replaced from `values`; the renderer's own (`CC_INIT_DATA`) left as it is.
fn render(template: &str, values: &BTreeMap<String, String>) -> String {
    values.iter().fold(template.to_owned(), |text, (k, v)| {
        text.replace(&format!("${{{k}}}"), v)
    })
}

/// `(name, value)` of every container env entry: a `- name:` line and the `value:` after it.
fn env_values(rendered: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut name = None;
    for line in rendered.lines().map(str::trim) {
        if let Some(n) = line.strip_prefix("- name:") {
            name = Some(n.trim().to_owned());
        } else if let Some(v) = line.strip_prefix("value:")
            && let Some(n) = name.take()
        {
            let v = v.trim();
            let v = v
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
                .or_else(|| v.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
                .unwrap_or(v);
            out.push((n, v.to_owned()));
        }
    }
    out
}

/// Each template rendered with `env/cluster.env` (except the KMS, which has no runtime to pin)
/// and its own env file.
fn rendered_templates() -> Vec<(String, String)> {
    let dir = platform_dir();
    let cluster = env_file(&std::fs::read_to_string(dir.join("env/cluster.env")).unwrap());
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("yaml") {
            continue;
        }
        let stem = path.file_stem().unwrap().to_str().unwrap().to_owned();
        let own = std::fs::read_to_string(dir.join(format!("env/{stem}.env")))
            .unwrap_or_else(|e| panic!("env/{stem}.env: {e}"));
        let mut values = if stem == "alpha-kms" {
            BTreeMap::new()
        } else {
            cluster.clone()
        };
        values.extend(env_file(&own));
        let template = std::fs::read_to_string(&path).unwrap();
        out.push((stem, render(&template, &values)));
    }
    out.sort();
    out
}

#[test]
fn no_platform_template_renders_a_password_into_its_measured_environment() {
    let rendered = rendered_templates();
    let names: Vec<&str> = rendered.iter().map(|(n, _)| n.as_str()).collect();
    for expected in [
        "alpha-broker",
        "alpha-guard",
        "alpha-inference",
        "alpha-kms",
    ] {
        assert!(
            names.contains(&expected),
            "{expected} missing from {names:?}"
        );
    }
    for (template, text) in &rendered {
        let values = env_values(text);
        assert!(!values.is_empty(), "{template}: no env values found");
        for (name, value) in values {
            assert!(
                !value.contains("://") || !carries_password(&value),
                "{template}: {name} renders a password into the public init-data: {value}"
            );
        }
    }
}

#[test]
fn the_kms_template_renders_a_database_url_a_kata_node_starts_with() {
    let rendered = rendered_templates();
    let (_, kms) = rendered.iter().find(|(n, _)| n == "alpha-kms").unwrap();
    let values = env_values(kms);
    let url = values
        .iter()
        .find(|(n, _)| n == DATABASE_URL_ENV)
        .map(|(_, v)| v.as_str())
        .unwrap_or_else(|| panic!("alpha-kms.yaml has no {DATABASE_URL_ENV}"));
    assert!(url.starts_with("<postgres://alpha_kms_node@"), "{url}");
    check_database_url(url, true).unwrap();
    assert!(
        values
            .iter()
            .any(|(n, v)| n == "ALPHACOMPUTE_QUOTE_SOURCE" && v == "coco-aa"),
        "the template runs the KMS as a Kata node, so the check applies"
    );

    // The same template filled with a credential-bearing URL is what a Kata node refuses.
    let template = std::fs::read_to_string(platform_dir().join("alpha-kms.yaml")).unwrap();
    let mut values =
        env_file(&std::fs::read_to_string(platform_dir().join("env/alpha-kms.env")).unwrap());
    values.insert(
        "DATABASE_URL".into(),
        "postgres://alpha_kms_node:s3cret@db:5432/alpha".into(),
    );
    let leaked = env_values(&render(&template, &values));
    let (_, url) = leaked.iter().find(|(n, _)| n == DATABASE_URL_ENV).unwrap();
    assert!(carries_password(url));
    assert!(check_database_url(url, true).is_err());
}
