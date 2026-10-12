//! Checking an organization's export of the KMS's decisions about it (PRD-06, evidence to the
//! customer; draft). The KMS answers `POST /v1/decisions/export` with the rows, the request it
//! answered, and a node receipt over both, so the answer alone can be checked offline by anyone
//! pinning the KMS CA and Revisions from the platform document — the customer's auditor included.

use alpha_channel::receipt::{self, DECISIONS_EXPORT_ROUTE, Expected};
use alpha_core::{ComposeHash, OrgId};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::Error;

pub const FORMAT: &str = "alphacompute-kms-decisions/1";

/// One audit row as the KMS recorded it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Row {
    pub seq: i64,
    pub ts: String,
    pub actor_kind: String,
    pub actor: String,
    pub action: String,
    pub object: Option<String>,
    pub outcome: String,
    pub details: Value,
    pub evidence_sha256: Option<String>,
}

/// What the receipt covers, and nothing else.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Decisions {
    pub format: String,
    pub org_id: OrgId,
    pub request: Value,
    pub rows: Vec<Row>,
    pub next_after_seq: i64,
    pub more: bool,
}

/// Verifies an export's receipt and returns only what the KMS signed: the receipt is a listed
/// KMS node's, under the pinned CA, for route `decisions.export`, over exactly the request the
/// answer echoes. The rows are in strictly increasing sequence order. It does not prove the
/// export is complete (no row left out); see `docs/customer-evidence.md`.
pub fn verify(
    reply_json: &[u8],
    kms_ca_pem: &str,
    kms_revisions: &[ComposeHash],
) -> Result<Decisions, Error> {
    let reply =
        alpha_core::parse(reply_json).map_err(|e| Error::Invalid(format!("decisions: {e}")))?;
    let receipt = reply
        .get("receipt")
        .ok_or_else(|| Error::Invalid("decisions: no receipt".into()))?;
    let request = reply
        .get("request")
        .ok_or_else(|| Error::Invalid("decisions: no request".into()))?;
    let expected = Expected {
        route: DECISIONS_EXPORT_ROUTE.into(),
        request_sha256: receipt::request_sha256(request)
            .map_err(|e| Error::Invalid(format!("decisions: {e}")))?,
        response: Map::new(),
    };
    let receipt_json =
        serde_json::to_vec(receipt).map_err(|e| Error::Invalid(format!("receipt: {e}")))?;
    let signed = receipt::verify(&receipt_json, kms_ca_pem, kms_revisions, &expected)
        .map_err(|e| Error::Invalid(format!("decisions receipt: {e}")))?;
    let decisions: Decisions =
        serde_json::from_value(signed).map_err(|e| Error::Invalid(format!("decisions: {e}")))?;
    if decisions.format != FORMAT {
        return Err(Error::Invalid(format!(
            "decisions: format {:?}",
            decisions.format
        )));
    }
    if decisions.request != *request {
        return Err(Error::Invalid(
            "decisions: the signed request is not the one the answer shows".into(),
        ));
    }
    if decisions.rows.windows(2).any(|w| match w {
        [a, b] => a.seq >= b.seq,
        _ => false,
    }) {
        return Err(Error::Invalid(
            "decisions: rows out of sequence order".into(),
        ));
    }
    Ok(decisions)
}
