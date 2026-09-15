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

pub mod compose;
pub mod id;
pub mod phala;
pub mod signing;

pub use compose::{
    ComposeHash, ParseComposeHashError, RegistrationError, check_registration, compose_hash,
    hex_bytes,
};
pub use id::{AppId, KeyId, OrgId, PrincipalId, RequestId, SecretId};
pub use signing::{context, jcs, signing_digest};
