//! Option B (PRD-02 deliverable 26): Trustee v0.21.0's KBS, Attestation Service and RVPS in the
//! verifier pool, fed by alpha-kms (`docs/trustee.md`). What the KMS and the Trustee pod's
//! `alpha-trustee-feed` share:
//!
//! - [`resource`]: the resources pods ask the KBS for, `kbs:///<App id>/<type>/<tag>`, and the
//!   tenant-signed grant that opts an App's resources in;
//! - [`ear`]: what a Trustee attestation token (an EAR) says about a pod, as the KMS reads it;
//! - [`policy`]: the KBS resource policy, the Attestation Service's appraisal policies and the
//!   RVPS reference values, generated from the KMS's Revisions and grants and from the
//!   release-signed platform document, never written by hand;
//! - [`wire`]: the bodies of the KMS's `/v1/trustee` routes;
//! - [`vault`]: the Vault KV v1 read reply through which the KBS's `Vault` resource backend
//!   receives a value the KMS released for one request.

#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )
)]

pub mod ear;
pub mod policy;
pub mod resource;
pub mod vault;
pub mod wire;

pub use resource::{GrantEntry, Resource, ResourceType};

/// The Trustee release whose protocol, claims and configuration this crate follows.
pub const TRUSTEE_VERSION: &str = "v0.21.0";
