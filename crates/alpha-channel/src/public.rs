//! What a browser checks about an App's public name with no AlphaCompute server in the path: the
//! platform document under the release keys compiled into the page, the TD's quote under Intel's
//! root and its measurements under that document, the init-data its `MRCONFIGID` names, the
//! binding signed by the key the quote attests, and Certificate Transparency for every certificate
//! a browser would accept for the name. The KMS's certificate is not consulted.

use std::time::SystemTime;

use alpha_attest::{Appraised, PlatformDocument};
use alpha_core::{AppId, ComposeHash, InitData};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use crate::binding::{self, Attestation, Binding, SignedBinding};
use crate::platform::{self, ReleaseKeys, SignedDocument};
use crate::{cert, sha256_label};

#[derive(Debug, Serialize)]
pub struct Check {
    pub name: &'static str,
    pub ok: bool,
    pub detail: String,
}

/// Every check in order, and what the passing ones established. `verified` only when all pass.
#[derive(Debug, Default, Serialize)]
pub struct Report {
    pub verified: bool,
    pub checks: Vec<Check>,
    pub platform_document_version: Option<u64>,
    pub tcb_status: Option<String>,
    pub advisories: Vec<String>,
    pub runtime_class: Option<String>,
    pub revision: Option<ComposeHash>,
    pub app_id: Option<AppId>,
    pub init_data: Option<String>,
    pub served_spki_sha256: Option<String>,
}

impl Report {
    fn check<T>(&mut self, name: &'static str, result: Result<(T, String), String>) -> Option<T> {
        let (value, ok, detail) = match result {
            Ok((value, detail)) => (Some(value), true, detail),
            Err(detail) => (None, false, detail),
        };
        self.checks.push(Check { name, ok, detail });
        value
    }
}

fn need<T>(value: Option<T>, what: &str) -> Result<T, String> {
    value.ok_or_else(|| format!("not checked: {what} did not verify"))
}

/// The texts a verifier read: what the name answers on [`binding::PATH`] and on
/// `/.well-known/alphacompute/attestation`, the signed platform document, and Cert Spotter's issuances for
/// the name with wildcards, None when they could not be read.
pub struct Fetched<'a> {
    pub binding: &'a str,
    pub attestation: &'a str,
    pub platform: &'a str,
    pub issuances: Option<&'a str>,
}

/// `min_version` is the newest platform document version this verifier saw before.
pub fn verify(
    name: &str,
    fetched: &Fetched,
    keys: &ReleaseKeys,
    min_version: u64,
    now: SystemTime,
) -> Report {
    let mut report = Report::default();

    let doc = report.check(
        "platform_document",
        platform_document(fetched.platform, keys, min_version, now),
    );
    report.platform_document_version = doc.as_ref().map(|d| d.version);

    let signed = serde_json::from_str::<SignedBinding>(fetched.binding)
        .map_err(|e| format!("{name} serves no binding: {e}"));
    let leaf = signed
        .as_ref()
        .map_err(Clone::clone)
        .and_then(|s| binding::leaf(s).map_err(|e| e.to_string()));
    let evidence = serde_json::from_str::<Attestation>(fetched.attestation)
        .map_err(|e| format!("{name} serves no attestation evidence: {e}"));

    let appraised = report.check(
        "attestation",
        need(doc.as_ref(), "the platform document").and_then(|doc| {
            let leaf = leaf.as_ref().map_err(Clone::clone)?;
            appraise(evidence.as_ref().map_err(Clone::clone)?, leaf, doc, now)
        }),
    );
    if let Some(a) = &appraised {
        report.tcb_status = Some(a.tcb_status.clone());
        report.advisories = a.advisories.clone();
        report.runtime_class = Some(a.os_image.clone());
        report.revision = Some(a.compose_hash);
    }

    let app_id = report.check(
        "init_data",
        need(doc.as_ref().zip(appraised.as_ref()), "the attestation").and_then(|(doc, a)| {
            let text = &evidence.as_ref().map_err(Clone::clone)?.init_data;
            init_data(text, a.compose_hash, doc)
        }),
    );
    report.init_data = app_id.and(evidence.as_ref().ok().map(|e| e.init_data.clone()));
    report.app_id = app_id;

    let bound = report.check(
        "binding",
        need(appraised.as_ref(), "the attestation").and_then(|_| {
            let (signed, leaf) = signed
                .as_ref()
                .ok()
                .zip(leaf.as_ref().ok())
                .ok_or("no binding")?;
            let binding = binding::open(signed, leaf, name, now).map_err(|e| e.to_string())?;
            let detail = format!(
                "the TD's key signed that it serves {name} with key {} until {}",
                binding.spki_sha256, binding.not_after
            );
            Ok((binding, detail))
        }),
    );
    report.served_spki_sha256 = bound.as_ref().map(|b| b.spki_sha256.clone());

    report.check(
        "certificate_transparency",
        need(bound.as_ref(), "the binding")
            .and_then(|b| transparency(name, b, fetched.issuances, now)),
    );

    report.verified = report.checks.iter().all(|c| c.ok);
    report
}

fn platform_document(
    text: &str,
    keys: &ReleaseKeys,
    min_version: u64,
    now: SystemTime,
) -> Result<(PlatformDocument, String), String> {
    let signed: SignedDocument = alpha_core::parse(text.as_bytes())
        .and_then(serde_json::from_value)
        .map_err(|e| format!("not a signed platform document: {e}"))?;
    platform::verify(&signed, keys, now).map_err(|e| e.to_string())?;
    let doc: PlatformDocument =
        serde_json::from_value(signed.document).map_err(|e| format!("document: {e}"))?;
    if doc.version < min_version {
        return Err(format!(
            "version {} is older than version {min_version}, seen before",
            doc.version
        ));
    }
    let detail = format!(
        "version {} of {}, signed by the release keys built into this page",
        doc.version, doc.issued_at
    );
    Ok((doc, detail))
}

/// The KMS's own appraisal of a Kata TD, over the binding leaf's key: the quote must have been
/// asked for with that key and the served nonce.
// ponytail: GPU certificates are not checked for revocation here, unlike at the KMS; the upgrade
// is OCSP through a CORS-enabled responder.
fn appraise(
    attestation: &Attestation,
    leaf: &[u8],
    doc: &PlatformDocument,
    now: SystemTime,
) -> Result<(Appraised, String), String> {
    let spki = cert::spki_of(leaf).map_err(|e| e.to_string())?;
    let nonce: [u8; 32] = BASE64_URL_SAFE_NO_PAD
        .decode(&attestation.nonce)
        .ok()
        .and_then(|n| n.try_into().ok())
        .ok_or("the nonce is not 32 bytes of base64url")?;
    let appraised = alpha_attest::appraise_kata_evidence(
        &attestation.evidence,
        &nonce,
        &spki,
        None,
        doc,
        &attestation.collateral,
        now,
    )
    .map_err(|e| e.to_string())?;
    let detail = format!(
        "an Intel TDX quote, TCB {}, of {} as the platform document lists, with {} GPUs, \
         holding key {}",
        appraised.tcb_status,
        appraised.os_image,
        appraised.gpu_serials.len(),
        sha256_label(&spki)
    );
    Ok((appraised, detail))
}

fn init_data(
    text: &str,
    revision: ComposeHash,
    doc: &PlatformDocument,
) -> Result<(AppId, String), String> {
    let init_data = InitData::parse(text.to_owned()).map_err(|e| e.to_string())?;
    if init_data.digest() != revision {
        return Err(format!(
            "the init-data is {}, the TD booted {revision}",
            init_data.digest()
        ));
    }
    let policy = doc
        .kata_policy
        .as_ref()
        .ok_or("the platform document pins no agent policy")?;
    init_data
        .check_policy(policy, &doc.kms_ca_pem)
        .map_err(|e| e.to_string())?;
    let app_id = init_data.app_id().ok_or("the init-data names no App")?;
    Ok((
        app_id,
        format!("Revision {revision} of App {app_id}, under the platform's agent policy"),
    ))
}

/// One certificate as Cert Spotter's issuances API lists it; `pubkey_sha256` is the hex SHA-256
/// of its SubjectPublicKeyInfo.
#[derive(Deserialize)]
struct Issuance {
    id: String,
    dns_names: Vec<String>,
    pubkey_sha256: String,
    not_after: String,
}

/// A browser accepts any logged certificate for the name, a wildcard one included, and a page
/// cannot see which one its connection got; so every such certificate must hold the key the TD
/// signed for.
// ponytail: Cert Spotter's index is trusted to list every logged certificate; the upgrade is
// reading the CT logs and checking each entry's inclusion proof.
fn transparency(
    name: &str,
    binding: &Binding,
    issuances_json: Option<&str>,
    now: SystemTime,
) -> Result<((), String), String> {
    let issuances: Vec<Issuance> =
        serde_json::from_str(issuances_json.ok_or("Certificate Transparency could not be read")?)
            .map_err(|e| format!("Certificate Transparency: {e}"))?;
    let now = chrono::DateTime::<chrono::Utc>::from(now);
    let mut valid = 0usize;
    let mut foreign = Vec::new();
    for issuance in &issuances {
        let current = chrono::DateTime::parse_from_rfc3339(&issuance.not_after)
            .map_err(|e| format!("Certificate Transparency not_after: {e}"))?
            > now;
        if !current {
            continue;
        }
        valid = valid.saturating_add(1);
        if binding.spki_sha256 != format!("sha256:{}", issuance.pubkey_sha256) {
            foreign.push(format!(
                "{} ({})",
                issuance.id,
                issuance.dns_names.join(", ")
            ));
        }
    }
    if valid == 0 {
        return Err(format!(
            "Certificate Transparency lists no current certificate for {name}"
        ));
    }
    if !foreign.is_empty() {
        return Err(format!(
            "{} of {valid} certificates a browser accepts for {name} hold another key, so their \
             holder could serve the name instead of this TD: {}",
            foreign.len(),
            foreign.join("; ")
        ));
    }
    Ok((
        (),
        format!("all {valid} certificates for {name} in Certificate Transparency hold that key"),
    ))
}

/// The wasm build verifies with RustCrypto where the native one uses ring, so the real quote is
/// appraised on both.
#[cfg(all(test, target_arch = "wasm32"))]
mod golden {
    use super::*;

    #[wasm_bindgen_test::wasm_bindgen_test]
    fn the_captured_kata_quote_appraises_to_its_init_data() {
        let doc: PlatformDocument = serde_json::from_str(include_str!(
            "../../../testdata/attest/b300-kata-4.0.0/platform-document.json"
        ))
        .unwrap();
        let now: SystemTime = chrono::DateTime::parse_from_rfc3339(
            include_str!("../../../testdata/attest/b300-kata-4.0.0/captured_at.txt").trim(),
        )
        .unwrap()
        .into();
        let evidence = serde_json::from_value(serde_json::json!({
            "format": alpha_attest::KATA_EVIDENCE_FORMAT,
            "quote": BASE64_URL_SAFE_NO_PAD.encode(include_bytes!(
                "../../../testdata/attest/b300-kata-4.0.0/k3-app.quote.bin"
            )),
        }))
        .unwrap();
        let collateral = serde_json::from_str(include_str!(
            "../../../testdata/attest/b300-kata-4.0.0/collateral.json"
        ))
        .unwrap();
        let appraised = alpha_attest::appraise_kata_evidence(
            &evidence,
            include_bytes!("../../../testdata/attest/b300-kata-4.0.0/nonce.bin"),
            include_bytes!("../../../testdata/attest/b300-kata-4.0.0/runtime_spki.der"),
            None,
            &doc,
            &collateral,
            now,
        )
        .unwrap();
        let text = include_str!("../../../testdata/attest/b300-kata-4.0.0/k3-app.toml");
        init_data(text, appraised.compose_hash, &doc).unwrap();
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use std::path::PathBuf;

    use ed25519_dalek::SigningKey as ReleaseKey;
    use p256::ecdsa::SigningKey;
    use p256::pkcs8::EncodePrivateKey;
    use serde_json::{Value, json};

    use super::*;

    fn kata(name: &str) -> Vec<u8> {
        std::fs::read(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../testdata/attest/b300-kata-4.0.0")
                .join(name),
        )
        .unwrap()
    }

    fn captured_at() -> SystemTime {
        chrono::DateTime::parse_from_rfc3339(
            String::from_utf8(kata("captured_at.txt")).unwrap().trim(),
        )
        .unwrap()
        .into()
    }

    fn release_key() -> ReleaseKey {
        ReleaseKey::from_bytes(&[9u8; 32])
    }

    fn platform_json() -> String {
        let document: Value = serde_json::from_slice(&kata("platform-document.json")).unwrap();
        serde_json::to_string(&platform::sign(document, &release_key()).unwrap()).unwrap()
    }

    /// A binding that `key` signs under a self-signed leaf, and the hex SHA-256 of the served key.
    fn binding_json(key: &SigningKey) -> (String, String) {
        let leaf_key = rcgen::KeyPair::try_from(key.to_pkcs8_der().unwrap().as_bytes()).unwrap();
        let leaf = rcgen::CertificateParams::default()
            .self_signed(&leaf_key)
            .unwrap();
        let served_key = rcgen::KeyPair::generate().unwrap();
        let mut served = rcgen::CertificateParams::new(vec![NAME.into()]).unwrap();
        served.not_after = rcgen::date_time_ymd(2100, 1, 1);
        let served = served.self_signed(&served_key).unwrap();
        let signed = binding::sign(key, leaf.pem(), NAME, served.der()).unwrap();
        let spki = sha256_label(&cert::spki_of(served.der()).unwrap());
        (
            serde_json::to_string(&signed).unwrap(),
            spki.replace("sha256:", ""),
        )
    }

    fn attestation_json() -> String {
        json!({
            "evidence": {
                "format": alpha_attest::KATA_EVIDENCE_FORMAT,
                "quote": BASE64_URL_SAFE_NO_PAD.encode(kata("k3-app.quote.bin")),
            },
            "nonce": BASE64_URL_SAFE_NO_PAD.encode(kata("nonce.bin")),
            "init_data": String::from_utf8(kata("k3-app.toml")).unwrap(),
            "collateral": serde_json::from_slice::<Value>(&kata("collateral.json")).unwrap(),
        })
        .to_string()
    }

    const NAME: &str = "hello.alphacompute.cc";

    fn run(binding: &str, issuances: &str, min_version: u64) -> Report {
        let keys = release_key().verifying_key().into();
        let fetched = Fetched {
            binding,
            attestation: &attestation_json(),
            platform: &platform_json(),
            issuances: Some(issuances),
        };
        verify(NAME, &fetched, &keys, min_version, captured_at())
    }

    /// The captured TD's key is the P-256 scalar 0x4b repeated, so the capture verifies end to
    /// end; a binding by any other key fails where the quote ties in.
    #[test]
    fn the_capture_verifies_end_to_end_and_only_under_its_own_key() {
        let td = SigningKey::from_bytes(&[0x4b; 32].into()).unwrap();
        let (binding, served) = binding_json(&td);
        let logged = json!([{ "id": "1", "dns_names": [NAME], "pubkey_sha256": served,
                              "not_after": "2100-01-01T00:00:00Z" }])
        .to_string();
        let report = run(&binding, &logged, 0);
        assert!(report.verified, "{report:#?}");
        let k3 = InitData::parse(String::from_utf8(kata("k3-app.toml")).unwrap()).unwrap();
        assert_eq!(report.revision, Some(k3.digest()));
        assert_eq!(report.app_id, k3.app_id());
        assert_eq!(report.tcb_status.as_deref(), Some("UpToDate"));

        let (other, _) = binding_json(&SigningKey::from_bytes(&[7u8; 32].into()).unwrap());
        let report = run(&other, &logged, 0);
        assert!(
            report.checks[1].detail.contains("report_data"),
            "{report:#?}"
        );

        let report = run(&binding, &logged, u64::MAX);
        assert!(
            report.checks[0].detail.contains("seen before"),
            "{report:#?}"
        );
        assert!(!report.checks[1].ok);
    }

    fn binding(spki_hex: &str) -> Binding {
        Binding {
            format: String::new(),
            name: NAME.into(),
            spki_sha256: format!("sha256:{spki_hex}"),
            not_after: String::new(),
        }
    }

    #[test]
    fn every_current_logged_certificate_must_hold_the_bound_key() {
        let now = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_800_000_000);
        let issuance = |id: &str, names: &[&str], key: &str, not_after: &str| json!({ "id": id, "dns_names": names, "pubkey_sha256": key, "not_after": not_after });
        let ours = "aa".repeat(32);
        let list = |entries: Vec<Value>| Value::Array(entries).to_string();
        let check = |text: Option<&str>| transparency(NAME, &binding(&ours), text, now);

        let current = issuance("1", &[NAME], &ours, "2030-01-01T00:00:00Z");
        let expired_other = issuance("2", &[NAME], &"bb".repeat(32), "2020-01-01T00:00:00Z");
        assert!(check(Some(&list(vec![current.clone(), expired_other]))).is_ok());

        let wildcard = issuance(
            "3",
            &["*.alphacompute.cc", "alphacompute.cc"],
            &"cc".repeat(32),
            "2030-01-01T00:00:00Z",
        );
        let err = check(Some(&list(vec![current, wildcard]))).unwrap_err();
        assert!(
            err.contains("1 of 2") && err.contains("*.alphacompute.cc"),
            "{err}"
        );
        assert!(check(Some("[]")).unwrap_err().contains("no current"));
        assert!(check(None).is_err());
        assert!(check(Some("{}")).is_err());
    }
}
