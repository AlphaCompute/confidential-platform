//! `alpha bootstrap` and `alpha unseal`: nothing is sealed to a node the CLI has not verified.
//! [`verify_node`] is the whole decision, pure over its arguments; the two commands only
//! move bytes once it has said yes.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use alpha_attest::{Collateral, PlatformDocument, appraise};
use alpha_client::{
    BootstrapBody, BootstrapRequest, Client, NodeEvidence, Pin, UnsealReply, UnsealRequest,
    fetch_node_evidence,
};
use alpha_crypto::{INFO_NODE_BOOTSTRAP, INFO_UNSEAL_SHARE, PublicKey, Sealed};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{random, sha256_prefixed};

/// A node the CLI may seal to: its attested runtime key and X-Wing key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeIdentity {
    pub runtime_spki: Vec<u8>,
    pub xwing: PublicKey,
}

impl NodeIdentity {
    pub fn aad(&self) -> [u8; 32] {
        Sha256::digest(&self.runtime_spki).into()
    }
}

/// The custodian-side checks, in order: the document is not older than the one
/// remembered, the evidence appraises with the X-Wing key bound in `report_data`, the node's
/// Revision is in `kms_revisions`, and the TLS server the evidence came from holds the attested
/// runtime key.
pub fn verify_node(
    evidence: &NodeEvidence,
    nonce: &[u8; 32],
    server_spki: &[u8],
    doc: &PlatformDocument,
    remembered_version: Option<u64>,
    collateral: &Collateral,
    now: SystemTime,
) -> Result<NodeIdentity, String> {
    if let Some(remembered) = remembered_version
        && doc.version < remembered
    {
        return Err(format!(
            "platform document version {} is below the remembered {remembered}",
            doc.version
        ));
    }
    let runtime_spki = evidence.runtime_spki().map_err(|e| e.to_string())?;
    appraise(
        &evidence.evidence().map_err(|e| e.to_string())?,
        nonce,
        &runtime_spki,
        Some(evidence.xwing_pubkey.as_bytes()),
        doc,
        collateral,
        now,
    )
    .map_err(|e| format!("{}: {e}", e.code()))?;
    if server_spki != runtime_spki {
        return Err("server TLS key is not the attested runtime_pubkey".into());
    }
    Ok(NodeIdentity {
        runtime_spki,
        xwing: evidence.xwing_pubkey.clone(),
    })
}

/// Fetches and verifies a sealed node's evidence and returns a client pinned to its runtime key.
pub async fn attested_node(
    endpoint: &str,
    pccs_url: &str,
    doc: &PlatformDocument,
    remembered_version: Option<u64>,
    now: SystemTime,
) -> Result<(NodeIdentity, Client), String> {
    let nonce = random::<32>()?;
    let (evidence, server_spki) = fetch_node_evidence(endpoint, &nonce)
        .await
        .map_err(|e| e.to_string())?;
    let quote = evidence.evidence().map_err(|e| e.to_string())?.quote;
    let collateral = alpha_attest::fetch_collateral(pccs_url, &quote)
        .await
        .map_err(|e| e.to_string())?;
    let identity = verify_node(
        &evidence,
        &nonce,
        &server_spki,
        doc,
        remembered_version,
        &collateral,
        now,
    )?;
    let client = Client::new(
        vec![endpoint.to_owned()],
        Pin::Spki(identity.runtime_spki.clone()),
    )
    .map_err(|e| e.to_string())?;
    Ok((identity, client))
}

pub const SHARE_FORMAT: &str = "alphacompute-share/1";

/// What a custodian keeps: their share sealed to their X-Wing key, the SPKI hash of the node
/// that sealed it (the HPKE aad), and the highest platform-document version they have verified.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShareFile {
    pub format: String,
    pub share_hpke: Sealed,
    pub kms_node_spki_sha256: String,
    pub platform_document_version: u64,
}

impl ShareFile {
    pub fn read(path: &Path) -> Result<Self, String> {
        let text = fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let file: Self =
            serde_json::from_slice(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        if file.format != SHARE_FORMAT {
            return Err(format!("share file: unsupported format {:?}", file.format));
        }
        Ok(file)
    }

    pub fn write(&self, path: &Path) -> Result<(), String> {
        let text = serde_json::to_string_pretty(self).map_err(|e| e.to_string())? + "\n";
        fs::write(path, text).map_err(|e| format!("{}: {e}", path.display()))
    }

    fn aad(&self) -> Result<[u8; 32], String> {
        self.kms_node_spki_sha256
            .strip_prefix("sha256:")
            .and_then(alpha_core::hex_bytes)
            .ok_or_else(|| "share file: kms_node_spki_sha256 is not sha256:<hex>".into())
    }
}

/// Seals the bootstrap body to the verified node, checks the reply's signature under the
/// node's runtime key, writes `share-1.json` … `share-3.json` into `out_dir` and returns
/// `kms_ca_pem` with its SPKI hash.
pub async fn bootstrap(
    client: &Client,
    node: &NodeIdentity,
    custodians: [PublicKey; 3],
    doc_version: u64,
    out_dir: &Path,
) -> Result<Value, String> {
    let body = BootstrapBody { custodians };
    let body_hpke = alpha_crypto::seal(
        &node.xwing,
        INFO_NODE_BOOTSTRAP,
        &node.aad(),
        &serde_json::to_vec(&body).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let reply = client
        .bootstrap(&BootstrapRequest { body_hpke })
        .await
        .map_err(|e| e.to_string())?;
    let payload = reply
        .verify(&node.runtime_spki)
        .map_err(|e| e.to_string())?;
    if payload.shares_hpke.len() != 3 {
        return Err(format!(
            "bootstrap reply: {} shares instead of 3",
            payload.shares_hpke.len()
        ));
    }
    let mut paths: Vec<PathBuf> = Vec::new();
    for (i, share_hpke) in (1..).zip(payload.shares_hpke) {
        let path = out_dir.join(format!("share-{i}.json"));
        ShareFile {
            format: SHARE_FORMAT.into(),
            share_hpke,
            kms_node_spki_sha256: sha256_prefixed(&node.runtime_spki),
            platform_document_version: doc_version,
        }
        .write(&path)?;
        paths.push(path);
    }
    Ok(json!({
        "kms_ca_pem": payload.kms_ca_pem,
        "kms_ca_spki_sha256": crate::sign::ca_spki_sha256(&payload.kms_ca_pem)?,
        "shares": paths,
    }))
}

/// Opens the custodian's share under their key, seals it to the verified node and posts it;
/// the share file then remembers the document version the node was verified against.
pub async fn unseal(
    client: &Client,
    node: &NodeIdentity,
    share_path: &Path,
    custodian: &alpha_crypto::PrivateKey,
    doc_version: u64,
) -> Result<UnsealReply, String> {
    let mut file = ShareFile::read(share_path)?;
    let share = alpha_crypto::open(custodian, INFO_UNSEAL_SHARE, &file.aad()?, &file.share_hpke)
        .map_err(|e| format!("share file: {e}"))?;
    let share_hpke = alpha_crypto::seal(&node.xwing, INFO_UNSEAL_SHARE, &node.aad(), &share)
        .map_err(|e| e.to_string())?;
    if doc_version > file.platform_document_version {
        file.platform_document_version = doc_version;
        file.write(share_path)?;
    }
    client
        .unseal(&UnsealRequest { share_hpke })
        .await
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::{Duration, UNIX_EPOCH};

    use base64::Engine;
    use base64::prelude::BASE64_URL_SAFE_NO_PAD;

    use super::*;

    const KEYED: &str = "phala-0.5.9-1c-2g-keyed";

    fn read(name: &str) -> Vec<u8> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../testdata/attest")
            .join(KEYED)
            .join(name);
        fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
    }

    struct Capture {
        evidence: NodeEvidence,
        nonce: [u8; 32],
        doc: PlatformDocument,
        collateral: Collateral,
        now: SystemTime,
    }

    fn capture() -> Capture {
        let quote = hex::decode(String::from_utf8(read("quote.node.hex")).unwrap().trim()).unwrap();
        let evidence = NodeEvidence {
            quote: BASE64_URL_SAFE_NO_PAD.encode(quote),
            event_log: serde_json::from_slice(&read("event_log.json")).unwrap(),
            runtime_pubkey: BASE64_URL_SAFE_NO_PAD.encode(read("runtime_spki.der")),
            xwing_pubkey: PublicKey::try_from(read("node_xwing_pubkey.bin").as_slice()).unwrap(),
            compose_hash: alpha_core::compose_hash("ignored: the measured one is used"),
        };
        let captured_at = String::from_utf8(read("captured_at.txt")).unwrap();
        let t = chrono::DateTime::parse_from_rfc3339(captured_at.trim()).unwrap();
        Capture {
            evidence,
            nonce: read("nonce.bin").try_into().unwrap(),
            doc: serde_json::from_slice(&read("platform-document.json")).unwrap(),
            collateral: serde_json::from_slice(&read("collateral.json")).unwrap(),
            now: UNIX_EPOCH + Duration::from_secs(t.timestamp() as u64),
        }
    }

    fn verify(
        c: &Capture,
        evidence: &NodeEvidence,
        server_spki: &[u8],
        remembered: Option<u64>,
    ) -> Result<NodeIdentity, String> {
        verify_node(
            evidence,
            &c.nonce,
            server_spki,
            &c.doc,
            remembered,
            &c.collateral,
            c.now,
        )
    }

    #[test]
    fn genuine_node_evidence_over_its_own_key_is_accepted() {
        let c = capture();
        let spki = read("runtime_spki.der");
        let node = verify(&c, &c.evidence, &spki, Some(1)).unwrap();
        assert_eq!(node.runtime_spki, spki);
        assert_eq!(node.xwing, c.evidence.xwing_pubkey);
        assert_eq!(node.aad(), <[u8; 32]>::from(Sha256::digest(&spki)));
    }

    #[test]
    fn substituted_key_old_document_foreign_server_or_unlisted_revision_is_refused() {
        let mut c = capture();
        let spki = read("runtime_spki.der");
        let mut evidence = c.evidence.clone();
        evidence.xwing_pubkey = alpha_crypto::PrivateKey::generate().unwrap().public();
        let err = verify(&c, &evidence, &spki, None).unwrap_err();
        assert!(err.starts_with("attestation_failed"), "{err}");
        let err = verify(&c, &c.evidence, &spki, Some(2)).unwrap_err();
        assert!(err.contains("below the remembered 2"), "{err}");
        let err = verify(&c, &c.evidence, b"someone else's key", None).unwrap_err();
        assert!(err.contains("not the attested runtime_pubkey"), "{err}");
        c.doc.kms_revisions.clear();
        let err = verify(&c, &c.evidence, &spki, None).unwrap_err();
        assert!(err.starts_with("attestation_unknown"), "{err}");
    }

    #[test]
    fn share_file_round_trips_and_needs_its_format() {
        let dir = std::env::temp_dir().join(format!("alpha-share-{}", alpha_core::KeyId::mint()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("share-1.json");
        let file = ShareFile {
            format: SHARE_FORMAT.into(),
            share_hpke: Sealed {
                kem: "x-wing".into(),
                enc: "e".into(),
                ct: "c".into(),
            },
            kms_node_spki_sha256: sha256_prefixed(b"node"),
            platform_document_version: 3,
        };
        file.write(&path).unwrap();
        let back = ShareFile::read(&path).unwrap();
        assert_eq!(back.platform_document_version, 3);
        assert_eq!(
            back.aad().unwrap(),
            <[u8; 32]>::from(Sha256::digest(b"node"))
        );
        fs::write(&path, r#"{"format":"other/1","share_hpke":{"kem":"x-wing","enc":"","ct":""},"kms_node_spki_sha256":"x","platform_document_version":1}"#).unwrap();
        assert!(ShareFile::read(&path).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }
}
