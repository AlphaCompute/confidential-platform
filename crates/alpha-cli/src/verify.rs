//! `alpha verify`: what a relying party can check about an Endpoint with nothing but the
//! release-signed platform document. An Instance serves no evidence of its own: its leaf from
//! the KMS CA is the KMS's verdict, so that verdict is what is reported, not a local appraisal.

use std::time::SystemTime;

use alpha_attest::PlatformDocument;
use alpha_client::tls::{self, InstanceSans};
use alpha_client::{Client, Pin, system_time_provider};
use alpha_core::{AppId, InitData};
use serde_json::{Value, json};

use crate::node;

/// The leaf `url` presents must chain to the document's KMS CA, be valid now and belong to
/// `app`; with `init_data`, that file must be the leaf's Revision and pass the document's
/// `kata_policy`.
pub async fn instance(
    url: &str,
    app: AppId,
    init_data: Option<&InitData>,
    doc: &PlatformDocument,
) -> Result<Value, String> {
    let sans = alpha_client::instance_leaf(url, &doc.kms_ca_pem, system_time_provider())
        .await
        .map_err(|e| e.to_string())?
        .map_err(|why| format!("no Instance leaf from the KMS CA: {why}"))?;
    check_instance(&sans, app, init_data, doc)?;
    Ok(json!({
        "platform_document_version": doc.version,
        "org_id": sans.org_id,
        "app_id": sans.app_id,
        "revision": sans.compose_hash,
        "runtime_pubkey_sha256": sans.runtime_pubkey_sha256_hex,
        "appraisal": "the KMS appraised the Instance when it issued its leaf, at most an hour \
                      ago, under the platform document the KMS held then",
    }))
}

fn check_instance(
    sans: &InstanceSans,
    app: AppId,
    init_data: Option<&InitData>,
    doc: &PlatformDocument,
) -> Result<(), String> {
    if sans.app_id != app {
        return Err(format!(
            "the Endpoint presents App {}, not {app}",
            sans.app_id
        ));
    }
    let Some(init_data) = init_data else {
        return Ok(());
    };
    if init_data.digest() != sans.compose_hash {
        return Err(format!(
            "the init-data is Revision {}, the leaf names {}",
            init_data.digest(),
            sans.compose_hash
        ));
    }
    let policy = doc
        .kata_policy
        .as_ref()
        .ok_or("the platform document pins no kata_policy")?;
    init_data
        .check_policy(policy)
        .map_err(|e| format!("init-data: {e}"))
}

/// A KMS node proves itself with fresh evidence, appraised here as a custodian would, and must
/// be serving: `/ready` answers over a leaf from the document's KMS CA naming one of its
/// `kms_revisions`, held by the key the evidence attested, so a name that balances across
/// nodes cannot pair one node's quote with another's readiness.
pub async fn kms_node(
    url: &str,
    pccs_url: &str,
    doc: &PlatformDocument,
    now: SystemTime,
) -> Result<Value, String> {
    let (identity, _) = node::attested_node(url, pccs_url, doc, None, now).await?;
    let ca = tls::cert_from_pem(&doc.kms_ca_pem).map_err(|e| e.to_string())?;
    let revisions = doc.kms_revisions.iter().map(|r| r.compose_hash).collect();
    let pin = Pin::CaRevisionsAndSpki(ca, revisions, identity.runtime_spki.clone());
    Client::new(vec![url.to_owned()], pin)
        .map_err(|e| e.to_string())?
        .ready()
        .await
        .map_err(|e| format!("not serving under the KMS CA: {e}"))?;
    Ok(json!({
        "platform_document_version": doc.version,
        "runtime_pubkey_sha256": hex::encode(identity.aad()),
        "appraisal": "the node's quote appraised here against this platform document",
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const K3: &str = include_str!("../../../testdata/attest/b300-kata-4.0.0/k3-app.toml");

    fn doc() -> PlatformDocument {
        serde_json::from_str(include_str!(
            "../../../testdata/attest/b300-kata-4.0.0/platform-document.json"
        ))
        .unwrap()
    }

    fn leaf(init_data: &InitData) -> InstanceSans {
        InstanceSans {
            org_id: "0199e000-0000-7000-8000-0000000000aa".parse().unwrap(),
            app_id: init_data.app_id().unwrap(),
            runtime_pubkey_sha256_hex: "00".repeat(32),
            compose_hash: init_data.digest(),
        }
    }

    #[test]
    fn the_leaf_must_be_the_app_and_the_init_data_its_revision_within_the_policy() {
        let init_data = InitData::parse(K3.into()).unwrap();
        let sans = leaf(&init_data);
        let app = sans.app_id;
        check_instance(&sans, app, Some(&init_data), &doc()).unwrap();

        let other_app = "0199e000-0000-7000-8000-00000000b0b0".parse().unwrap();
        let err = check_instance(&sans, other_app, None, &doc()).unwrap_err();
        assert!(err.contains("presents App"), "{err}");

        let other = InitData::parse(K3.replacen("(c) 2023", "(c) 2024", 1)).unwrap();
        let err = check_instance(&sans, app, Some(&other), &doc()).unwrap_err();
        assert!(err.contains("the leaf names"), "{err}");

        let err = check_instance(&leaf(&other), app, Some(&other), &doc()).unwrap_err();
        assert!(err.contains("pinned rules"), "{err}");

        let mut unpinned = doc();
        unpinned.kata_policy = None;
        let err = check_instance(&sans, app, Some(&init_data), &unpinned).unwrap_err();
        assert!(err.contains("no kata_policy"), "{err}");
    }
}
