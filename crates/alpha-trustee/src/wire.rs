//! The bodies of the KMS's `/v1/trustee` routes. Every route but the grant is called by a Trustee
//! pod's feed over mTLS with the pod's own leaf, which must name a Revision the platform
//! document's `trustee.revisions` lists.

use std::collections::BTreeMap;

use alpha_core::{AppId, ComposeHash};
use serde::{Deserialize, Serialize};

use crate::resource::GrantEntry;

/// `POST /v1/trustee/attestations`: the token the pod's KBS issued for an attestation and the
/// init-data the attested pod sent with it, as the feed saw both pass.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attestation {
    pub token: String,
    /// base64url.
    pub initdata: String,
}

/// What the KMS made of an [`Attestation`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Admitted {
    pub app_id: AppId,
    pub revision: ComposeHash,
    /// Hex, as the token's `init_data` claim writes it.
    pub mrconfigid: String,
    pub expires_at: String,
}

/// `POST /v1/trustee/releases`: one resource for the pod whose token has this digest, asked by a
/// feed whose installed state was generated at `state_generated_at`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Release {
    /// `sha256:<hex>` of the token.
    pub token_sha256: String,
    /// `kbs:///<App id>/<type>/<tag>`.
    pub resource: String,
    pub state_generated_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Released {
    /// base64url.
    pub value: String,
    pub app_id: AppId,
    pub mrconfigid: String,
}

/// `GET /v1/trustee/state`: everything a Trustee pod decides by, generated now.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub generated_at: String,
    /// After this the pod installs the deny-all policy and releases nothing until it has a newer
    /// state: `generated_at` plus the document's `trustee.max_state_age_secs`.
    pub not_after: String,
    pub platform_version: u64,
    /// The KBS resource policy (Rego).
    pub resource_policy: String,
    /// The Attestation Service policies by id (Rego).
    pub attestation_policies: BTreeMap<String, String>,
    /// The RVPS registration message.
    pub reference_values: String,
    /// What Trustee's NVIDIA verifier calls.
    pub nras_verifier_url: String,
    /// Each init-data the resource policy admits, by App.
    pub admitted: Vec<StateEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateEntry {
    pub app_id: AppId,
    pub mrconfigid: String,
}

/// `POST /v1/trustee/kbs-leaf`: a one-hour server leaf over the caller's own key, naming the
/// platform document's `trustee.kbs_hostname`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KbsLeaf {
    pub certificate_chain: Vec<String>,
    pub not_after: String,
}

/// The payload of `PUT /v1/trustee/grants/{app_id}`, signed under
/// [`alpha_core::context::TRUSTEE_GRANT`]: the App's resources Trustee may release to the App's
/// own attested pods. An empty list opts the App out.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantPayload {
    pub app_id: AppId,
    pub resources: Vec<GrantEntry>,
    pub issued_at: String,
}
