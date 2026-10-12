//! The trust-zone Postgres pod's half of M2(a): the database's volume key from an unsealed KMS
//! node, before the database it opens is up (`docs/db-volume-key.md`).
//!
//! The pod first attests the KMS node exactly as a custodian's CLI does (`alpha_attest::node`:
//! the node's evidence over the pod's nonce, its build in `kms_revisions`, the TLS key equal to the
//! attested runtime key), because a node that has just been unsealed serves no KMS-CA leaf yet. It
//! then generates an X-Wing key, quotes over `report_data(xwing, kms nonce, None)` and posts its
//! evidence to `POST /v1/node/db-key`. The node appraises the pod (`kata-tdx/1`, its Revision v2 in
//! `db_revisions`) and answers with the key sealed to that X-Wing key, its aad the node's
//! runtime-key hash, so only this pod, talking to that node, opens it.

use std::time::SystemTime;

use alpha_attest::{AnyEvidence, PlatformDocument, report_data};
use alpha_crypto::{INFO_DB_VOLUME_KEY, PrivateKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{Client, DbKeyReply, DbKeyRequest, Error, Pin, decode, fetch_node_evidence};

/// What the pod's TD quotes over: the X-Wing key in the place of a runtime key, then the nonce.
pub fn pod_report_data(xwing: &PrivateKey, nonce: &[u8; 32]) -> [u8; 64] {
    report_data(xwing.public().as_bytes(), nonce, None)
}

/// The request for `nonce` (base64url, from the node), with the evidence `quote` returns over
/// [`pod_report_data`].
pub fn request(
    nonce: &str,
    xwing: &PrivateKey,
    quote: impl FnOnce(&[u8; 64]) -> Result<AnyEvidence, String>,
) -> Result<DbKeyRequest, Error> {
    let raw: [u8; 32] = decode("nonce", nonce)?
        .try_into()
        .map_err(|_| Error::Invalid("nonce: expected 32 bytes".into()))?;
    let evidence = quote(&pod_report_data(xwing, &raw)).map_err(Error::Invalid)?;
    Ok(DbKeyRequest {
        nonce: nonce.to_owned(),
        evidence,
        xwing_pubkey: xwing.public(),
    })
}

/// The key, from the node whose runtime key `node_spki` the pod attested.
pub fn open(
    reply: &DbKeyReply,
    xwing: &PrivateKey,
    node_spki: &[u8],
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let aad: [u8; 32] = Sha256::digest(node_spki).into();
    let key = alpha_crypto::open(xwing, INFO_DB_VOLUME_KEY, &aad, &reply.key_hpke)
        .map_err(|e| Error::Invalid(format!("db key: {e}")))?;
    <[u8; 32]>::try_from(key.as_slice())
        .map(Zeroizing::new)
        .map_err(|_| Error::Invalid("db key: not 32 bytes".into()))
}

/// The whole exchange with the KMS node at `endpoint`, DCAP collateral from `pccs_url`.
pub async fn fetch(
    endpoint: &str,
    doc: &PlatformDocument,
    pccs_url: &str,
    quote: impl FnOnce(&[u8; 64]) -> Result<AnyEvidence, String>,
    now: SystemTime,
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce).map_err(|e| Error::Invalid(format!("rng: {e}")))?;
    let (evidence, server_spki) = fetch_node_evidence(endpoint, &nonce).await?;
    let node_spki = evidence.runtime_spki()?;
    let any = evidence.evidence()?;
    let collateral = alpha_attest::fetch_collateral(pccs_url, any.quote())
        .await
        .map_err(|e| Error::Invalid(e.to_string()))?;
    alpha_attest::node::appraise_node(
        &any,
        &nonce,
        &node_spki,
        evidence.xwing_pubkey.as_bytes(),
        doc,
        &collateral,
        now,
    )
    .map_err(|e| Error::Invalid(format!("kms node: {}: {e}", e.code())))?;
    if server_spki != node_spki {
        return Err(Error::Invalid(
            "kms node: the TLS key is not the attested runtime key".into(),
        ));
    }
    let client = Client::new(vec![endpoint.to_owned()], Pin::Spki(node_spki.clone()))?;
    let xwing = PrivateKey::generate().map_err(|e| Error::Invalid(e.to_string()))?;
    let nonce = client.node_nonce().await?.nonce;
    let reply = client.db_key(&request(&nonce, &xwing, quote)?).await?;
    open(&reply, &xwing, &node_spki)
}
