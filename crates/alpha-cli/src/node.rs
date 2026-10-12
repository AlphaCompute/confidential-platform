//! `alpha bootstrap` and `alpha unseal`: nothing is sealed to a node the CLI has not verified.
//! [`verify_node`] is the whole decision, pure over its arguments; the two commands only
//! move bytes once it has said yes. A prototype node and a Kata node (`kata-tdx/1`, its identity
//! the Revision v2 of its init-data) are appraised by `alpha_attest::node`, the same function the
//! serving node runs before a `join`.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use alpha_attest::{AnyEvidence, Appraised, Collateral, PlatformDocument, VerifiedQuote, kata};
use alpha_client::{
    AuditHead, BootstrapBody, BootstrapRequest, Client, NodeEvidence, Pin, UnsealReply,
    UnsealRequest, fetch_node_evidence,
};
use alpha_crypto::{INFO_NODE_BOOTSTRAP, INFO_UNSEAL_SHARE, PublicKey, Sealed};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use alpha_channel::sha256_label;

use crate::random;

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

/// A node that passed [`verify_node`]: what the CLI seals to, and what it found.
#[derive(Clone, Debug)]
pub struct AttestedNode {
    pub identity: NodeIdentity,
    pub appraised: Appraised,
}

impl AttestedNode {
    /// What the custodian is told about the node a share or the bootstrap body went to.
    pub fn summary(&self) -> Value {
        let a = &self.appraised;
        json!({
            "profile": a.coco.as_ref().map_or("prototype-tdx", |c| c.profile.as_str()),
            "revision": a.compose_hash,
            "os_image": a.os_image,
            "tcb_status": a.tcb_status,
            "policy_sha256": a.coco.as_ref().map(|c| c.policy_sha256),
            "runtime_pubkey_sha256": a.runtime_pubkey_sha256,
        })
    }
}

/// The custodian-side checks, in order: the document is not older than the one
/// remembered, the evidence appraises with the X-Wing key bound in `report_data` (a Kata node's
/// on the CPU runtime class), the node's Revision is in `kms_revisions` for the profile it was
/// appraised under, and the TLS server the evidence came from holds the attested runtime key.
pub fn verify_node(
    evidence: &NodeEvidence,
    nonce: &[u8; 32],
    server_spki: &[u8],
    doc: &PlatformDocument,
    remembered_version: Option<u64>,
    collateral: &Collateral,
    now: SystemTime,
) -> Result<AttestedNode, String> {
    check_version(doc, remembered_version)?;
    let runtime_spki = evidence.runtime_spki().map_err(|e| e.to_string())?;
    let appraised = alpha_attest::node::appraise_node(
        &evidence.evidence().map_err(|e| e.to_string())?,
        nonce,
        &runtime_spki,
        evidence.xwing_pubkey.as_bytes(),
        doc,
        collateral,
        now,
    )
    .map_err(|e| format!("{}: {e}", e.code()))?;
    attested(evidence, runtime_spki, server_spki, appraised)
}

/// [`verify_node`] for a Kata node's evidence over a quote `alpha_attest::verify_quote` has
/// verified: every check after DCAP. The KMS's tests run the CLI's half of a Kata genesis through
/// it over synthetic quotes until B300 Kata captures exist (M1); the commands never call it.
pub fn verify_kata_node(
    evidence: &NodeEvidence,
    verified: VerifiedQuote,
    nonce: &[u8; 32],
    server_spki: &[u8],
    doc: &PlatformDocument,
    remembered_version: Option<u64>,
) -> Result<AttestedNode, String> {
    check_version(doc, remembered_version)?;
    let runtime_spki = evidence.runtime_spki().map_err(|e| e.to_string())?;
    let AnyEvidence::V2(v2) = evidence.evidence().map_err(|e| e.to_string())? else {
        return Err("a verified quote comes with alphacompute-evidence/2 only".into());
    };
    let appraised = alpha_attest::node::appraise_kata_node(
        &v2,
        verified,
        nonce,
        &runtime_spki,
        evidence.xwing_pubkey.as_bytes(),
        doc,
    )
    .map_err(|e| format!("{}: {e}", e.code()))?;
    attested(evidence, runtime_spki, server_spki, appraised)
}

fn check_version(doc: &PlatformDocument, remembered_version: Option<u64>) -> Result<(), String> {
    if let Some(remembered) = remembered_version
        && doc.version < remembered
    {
        return Err(format!(
            "platform document version {} is below the remembered {remembered}",
            doc.version
        ));
    }
    Ok(())
}

fn attested(
    evidence: &NodeEvidence,
    runtime_spki: Vec<u8>,
    server_spki: &[u8],
    appraised: Appraised,
) -> Result<AttestedNode, String> {
    if server_spki != runtime_spki {
        return Err("server TLS key is not the attested runtime_pubkey".into());
    }
    Ok(AttestedNode {
        identity: NodeIdentity {
            runtime_spki,
            xwing: evidence.xwing_pubkey.clone(),
        },
        appraised,
    })
}

/// Fetches and verifies a sealed node's evidence and returns a client pinned to its runtime key.
pub async fn attested_node(
    endpoint: &str,
    pccs_url: &str,
    doc: &PlatformDocument,
    remembered_version: Option<u64>,
    now: SystemTime,
) -> Result<(AttestedNode, Client), String> {
    let nonce = random::<32>()?;
    let (evidence, server_spki) = fetch_node_evidence(endpoint, &nonce)
        .await
        .map_err(|e| e.to_string())?;
    let any = evidence.evidence().map_err(|e| e.to_string())?;
    // SEV-SNP evidence is named for what it is, before any collateral is fetched.
    if let AnyEvidence::V2(v2) = &any {
        kata::check_cpu_kind(v2).map_err(|e| format!("{}: {e}", e.code()))?;
    }
    let collateral = alpha_attest::fetch_collateral(pccs_url, any.quote())
        .await
        .map_err(|e| e.to_string())?;
    let node = verify_node(
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
        Pin::Spki(node.identity.runtime_spki.clone()),
    )
    .map_err(|e| e.to_string())?;
    Ok((node, client))
}

pub const SHARE_FORMAT: &str = "alphacompute-share/1";

/// What a custodian keeps: their share sealed to their X-Wing key, the SPKI hash of the node
/// that sealed it (the HPKE aad), the highest platform-document version they have verified, and
/// the latest KMS audit head a node they unsealed served from.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShareFile {
    pub format: String,
    pub share_hpke: Sealed,
    pub kms_node_spki_sha256: String,
    pub platform_document_version: u64,
    /// Sent with the next unseal: the node refuses a database restored from before it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_head: Option<AuditHead>,
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
            kms_node_spki_sha256: sha256_label(&node.runtime_spki),
            platform_document_version: doc_version,
            audit_head: None,
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

/// Opens the custodian's share under their key, seals it to the verified node and posts it with
/// the audit head the share file remembers; the share file then remembers the document version the
/// node was verified against and the head the node serves from. `accept_rollback` sends no head and
/// lets the file remember an earlier one: the custodian's explicit acceptance of a database
/// restored from an older copy.
pub async fn unseal(
    client: &Client,
    node: &NodeIdentity,
    share_path: &Path,
    custodian: &alpha_crypto::PrivateKey,
    doc_version: u64,
    accept_rollback: bool,
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
    let audit_floor = if accept_rollback {
        None
    } else {
        file.audit_head.clone()
    };
    let reply = client
        .unseal(&UnsealRequest {
            share_hpke,
            audit_floor,
        })
        .await
        .map_err(|e| e.to_string())?;
    let remember = match (&reply.audit_head, &file.audit_head) {
        // Accepted: the file forgets the later head, and keeps the restored one if this reply has it.
        _ if accept_rollback => true,
        (Some(head), Some(known)) => known.seq < head.seq,
        (Some(_), None) => true,
        (None, _) => false,
    };
    if remember {
        file.audit_head = reply.audit_head.clone();
        file.write(share_path)?;
    }
    Ok(reply)
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
            evidence_v2: None,
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
        .map(|node| node.identity)
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
    fn node_evidence_in_both_forms_or_neither_or_under_a_kata_build_is_refused() {
        let mut c = capture();
        let spki = read("runtime_spki.der");
        let mut neither = c.evidence.clone();
        neither.quote.clear();
        neither.event_log.clear();
        let err = verify(&c, &neither, &spki, None).unwrap_err();
        assert!(
            err.contains("either quote and event_log or evidence"),
            "{err}"
        );
        // A prototype node's quote is never read as a Kata node's, nor a listed prototype build
        // as a Kata one.
        c.doc.kms_revisions[0].kind = alpha_core::KmsRevisionKind::KataTdx;
        let err = verify(&c, &c.evidence, &spki, None).unwrap_err();
        assert!(err.contains("not listed as a prototype-tdx build"), "{err}");
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
            kms_node_spki_sha256: sha256_label(b"node"),
            platform_document_version: 3,
            audit_head: None,
        };
        file.write(&path).unwrap();
        let back = ShareFile::read(&path).unwrap();
        assert_eq!(back.platform_document_version, 3);
        assert!(!fs::read_to_string(&path).unwrap().contains("audit_head"));
        let head = AuditHead {
            seq: 7,
            link: "AAAA".into(),
        };
        ShareFile {
            audit_head: Some(head.clone()),
            ..file.clone()
        }
        .write(&path)
        .unwrap();
        assert_eq!(ShareFile::read(&path).unwrap().audit_head, Some(head));
        assert_eq!(
            back.aad().unwrap(),
            <[u8; 32]>::from(Sha256::digest(b"node"))
        );
        fs::write(&path, r#"{"format":"other/1","share_hpke":{"kem":"x-wing","enc":"","ct":""},"kms_node_spki_sha256":"x","platform_document_version":1}"#).unwrap();
        assert!(ShareFile::read(&path).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }
}
