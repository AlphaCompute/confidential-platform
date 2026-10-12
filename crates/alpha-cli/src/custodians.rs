//! `alpha custodians propose | rotate | accept`: replacing the custodian set with a new root KEK.
//!
//! 1. `propose`: anyone attests the serving node and takes a nonce from it; the proposal names
//!    the node and the three new custodians' X-Wing keys. It is not secret.
//! 2. `rotate`: each of two current custodians attests the same node, checks that the proposal
//!    names it, and seals the proposal's digest and their share to the node's attested X-Wing key.
//!    The second approval rotates; its reply is the rotation: the new shares sealed to the new
//!    custodians and the node's receipt.
//! 3. `accept`: each new custodian attests a node, verifies the receipt against the KMS CA and
//!    the KMS builds the platform document pins, finds their key in the proposal and keeps their
//!    share as a share file that `alpha unseal` reads.
//!
//! Every command that talks to a node first checks it as `unseal` does and then, unless told not
//! to, checks a Kata node's agent policy against the Alpha baseline ([`Baseline`], D9).

use std::path::Path;

use alpha_attest::PlatformDocument;
use alpha_channel::receipt::{self, Expected};
use alpha_channel::sha256_label;
use alpha_client::{
    Client, ROTATION_FORMAT, ROTATION_ROUTE, RotateReply, RotateRequest, Rotation,
    RotationProposal, sealed_sha256,
};
use alpha_crypto::{INFO_CUSTODIAN_APPROVAL, PrivateKey, PublicKey};
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

use crate::node::{NodeIdentity, SHARE_FORMAT, ShareFile};

/// Whether a Kata node's agent policy must hold the Alpha baseline before a custodian deals with
/// it (D9: no exec, no log reads, no image swap, no env or mount injection, #82). On by default;
/// `--no-policy-baseline` turns it off and the command's output says it was skipped.
#[derive(Clone, Copy)]
pub enum Baseline {
    Check(fn(&str) -> Result<(), String>),
    Skip,
}

/// The baseline checker this build runs.
// ponytail: D9 — the checker is `alpha_core::coco::policy::verify` (#79, #83), which is not in this
// branch's base. Until it merges here this refuses every Kata node, so a custodian either waits
// for it or passes `--no-policy-baseline` knowingly; a prototype node has no agent policy.
pub fn alpha_baseline(_policy: &str) -> Result<(), String> {
    Err("the Alpha agent-policy baseline checker (alpha_core::coco::policy::verify, #79/#83) is not in this build; pass --no-policy-baseline to go on without it".into())
}

/// `held`, `skipped`, or `none` for a prototype node, which runs no agent policy
/// ([`crate::node::AttestedNode::policy`]).
pub fn check_baseline(policy: Option<&str>, baseline: Baseline) -> Result<&'static str, String> {
    match (policy, baseline) {
        (None, _) => Ok("none"),
        (Some(_), Baseline::Skip) => Ok("skipped"),
        (Some(policy), Baseline::Check(check)) => check(policy)
            .map(|()| "held")
            .map_err(|e| format!("policy_denied: the node's agent policy: {e}")),
    }
}

/// The proposal for `node`, over a nonce it mints now (valid for five minutes).
pub async fn propose(
    client: &Client,
    node: &NodeIdentity,
    custodians: [PublicKey; 3],
) -> Result<RotationProposal, String> {
    let [a, b, c] = &custodians;
    if a == b || a == c || b == c {
        return Err("the three new custodians must be three keys".into());
    }
    let nonce = client.attest_nonce().await.map_err(|e| e.to_string())?;
    Ok(RotationProposal {
        format: ROTATION_FORMAT.into(),
        nonce: nonce.nonce,
        kms_node_spki_sha256: sha256_label(&node.runtime_spki),
        custodians,
    })
}

/// What a custodian is shown before approving: the node, the digest both approvals must share,
/// and each new custodian key's SHA-256, to compare with what the new custodians printed.
pub fn describe(proposal: &RotationProposal) -> Result<Value, String> {
    Ok(json!({
        "proposal_sha256": sha256_label_of(&proposal.digest().map_err(|e| e.to_string())?),
        "kms_node_spki_sha256": proposal.kms_node_spki_sha256,
        "custodians_sha256": proposal.custodians.iter()
            .map(|c| sha256_label(c.as_bytes())).collect::<Vec<_>>(),
    }))
}

fn sha256_label_of(digest: &[u8; 32]) -> String {
    format!("sha256:{}", hex::encode(digest))
}

/// One current custodian's approval, posted to the attested `node`, which the proposal must
/// name. The share file remembers the document version, as `unseal` does. When this approval
/// was the second, the reply's rotation is verified against `doc` before it is returned.
pub async fn approve(
    client: &Client,
    node: &NodeIdentity,
    proposal: &RotationProposal,
    share_path: &Path,
    custodian: &PrivateKey,
    doc: &PlatformDocument,
) -> Result<RotateReply, String> {
    if proposal.format != ROTATION_FORMAT {
        return Err(format!("proposal: format is not {ROTATION_FORMAT}"));
    }
    if proposal.kms_node_spki_sha256 != sha256_label(&node.runtime_spki) {
        return Err("proposal: it names another node than the one attested".into());
    }
    let mut file = ShareFile::read(share_path)?;
    let share = file.open(custodian)?;
    let digest = proposal.digest().map_err(|e| e.to_string())?;
    let approval = Zeroizing::new([digest.as_slice(), share.as_slice()].concat());
    let approval_hpke =
        alpha_crypto::seal(&node.xwing, INFO_CUSTODIAN_APPROVAL, &node.aad(), &approval)
            .map_err(|e| e.to_string())?;
    if doc.version > file.platform_document_version {
        file.platform_document_version = doc.version;
        file.write(share_path)?;
    }
    let reply = client
        .rotate_custodians(&RotateRequest {
            proposal: proposal.clone(),
            approval_hpke,
        })
        .await
        .map_err(|e| e.to_string())?;
    if let Some(rotation) = &reply.rotation {
        if rotation.proposal != *proposal {
            return Err("the node rotated under another proposal".into());
        }
        verify_rotation(rotation, doc)?;
    }
    Ok(reply)
}

/// The rotation's receipt verifies under a leaf of the KMS CA the document pins, from a KMS build
/// it lists, for this proposal, and names exactly the shares beside it. Returns the signed
/// response.
pub fn verify_rotation(rotation: &Rotation, doc: &PlatformDocument) -> Result<Value, String> {
    let proposal = &rotation.proposal;
    if rotation.shares_hpke.len() != 3 {
        return Err(format!(
            "rotation: {} shares instead of 3",
            rotation.shares_hpke.len()
        ));
    }
    let shares = rotation
        .shares_hpke
        .iter()
        .map(sealed_sha256)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    let mut response = Map::new();
    response.insert("rotation_id".into(), json!(rotation.id));
    for (k, v) in describe(proposal)?
        .as_object()
        .into_iter()
        .flat_map(|o| o.iter())
    {
        response.insert(k.clone(), v.clone());
    }
    response.insert("shares_hpke_sha256".into(), json!(shares));
    let request = serde_json::to_value(proposal).map_err(|e| e.to_string())?;
    let expected = Expected {
        route: ROTATION_ROUTE.into(),
        request_sha256: receipt::request_sha256(&request).map_err(|e| e.to_string())?,
        response,
    };
    let bytes = serde_json::to_vec(&rotation.receipt).map_err(|e| e.to_string())?;
    let revisions: Vec<_> = doc.kms_revisions.iter().map(|r| r.compose_hash).collect();
    receipt::verify(&bytes, &doc.kms_ca_pem, &revisions, &expected)
        .map_err(|e| format!("rotation receipt: {e}"))
}

/// A new custodian's half: the receipt verified, their key found among the proposal's three, their
/// share opened, then written to `out` (which must not exist) as a share file for `alpha unseal`.
pub fn accept(
    rotation: &Rotation,
    doc: &PlatformDocument,
    custodian: &PrivateKey,
    out: &Path,
) -> Result<Value, String> {
    let signed = verify_rotation(rotation, doc)?;
    let public = custodian.public();
    let index = rotation
        .proposal
        .custodians
        .iter()
        .position(|c| *c == public)
        .ok_or("your custodian key is not one of the rotation's three")?;
    let share_hpke = rotation
        .shares_hpke
        .get(index)
        .ok_or("rotation: no share for your key")?
        .clone();
    let file = ShareFile {
        format: SHARE_FORMAT.into(),
        share_hpke,
        kms_node_spki_sha256: rotation.proposal.kms_node_spki_sha256.clone(),
        platform_document_version: doc.version,
        audit_head: None,
    };
    // Opens, so the custodian learns now, not at the next unseal, that the share is theirs.
    file.open(custodian)?;
    file.create(out)?;
    Ok(json!({
        "share": out,
        "custodian": index.saturating_add(1),
        "rotation_id": rotation.id,
        "proposal_sha256": signed.get("proposal_sha256"),
        "approved_by_shares": signed.get("approved_by_shares"),
        "kms_node_spki_sha256": rotation.proposal.kms_node_spki_sha256,
    }))
}

/// Whether the node the custodian just attested is the one that rotated.
pub fn is_rotating_node(rotation: &Rotation, node: &NodeIdentity) -> bool {
    rotation.proposal.kms_node_spki_sha256 == sha256_label(&node.runtime_spki)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proposal(custodians: [PublicKey; 3]) -> RotationProposal {
        RotationProposal {
            format: ROTATION_FORMAT.into(),
            nonce: "n".into(),
            kms_node_spki_sha256: sha256_label(b"node"),
            custodians,
        }
    }

    fn keys() -> [PublicKey; 3] {
        [0, 1, 2].map(|_| PrivateKey::generate().unwrap().public())
    }

    #[test]
    fn the_digest_covers_every_field() {
        let p = proposal(keys());
        let d = p.digest().unwrap();
        let mut q = p.clone();
        q.nonce = "m".into();
        assert_ne!(q.digest().unwrap(), d);
        let mut q = p.clone();
        q.custodians.swap(0, 1);
        assert_ne!(q.digest().unwrap(), d);
        let mut q = p.clone();
        q.kms_node_spki_sha256 = sha256_label(b"other");
        assert_ne!(q.digest().unwrap(), d);
        assert_eq!(p.clone().digest().unwrap(), d);
        assert_eq!(
            describe(&p).unwrap()["proposal_sha256"],
            json!(sha256_label_of(&d))
        );
    }

    #[test]
    fn the_baseline_applies_to_a_kata_node_only_and_says_what_it_did() {
        fn holds(p: &str) -> Result<(), String> {
            if p.contains("ExecProcessRequest := false") {
                Ok(())
            } else {
                Err("exec is allowed".into())
            }
        }
        let checked = Baseline::Check(holds);
        assert_eq!(check_baseline(None, checked), Ok("none"));
        assert_eq!(
            check_baseline(Some("default ExecProcessRequest := false"), checked),
            Ok("held")
        );
        let e = check_baseline(Some("default ExecProcessRequest := true"), checked).unwrap_err();
        assert!(
            e.starts_with("policy_denied") && e.contains("exec is allowed"),
            "{e}"
        );
        assert_eq!(
            check_baseline(Some("anything"), Baseline::Skip),
            Ok("skipped")
        );
        // This build's checker refuses every Kata node until the real one is wired (D9).
        let e = check_baseline(Some("anything"), Baseline::Check(alpha_baseline)).unwrap_err();
        assert!(e.contains("--no-policy-baseline"), "{e}");
    }
}
