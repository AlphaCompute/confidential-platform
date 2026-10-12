//! Our own DSM (PRD-06 I3) against the stand-in: an API-key session, AES-GCM round trips bound
//! to their associated data, Ed25519 signing, and a DSM whose admin disabled the keys.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::sync::atomic::Ordering;

use alpha_dsm::stand_in::{AES_KEY, API_KEY, SIGNING_KEY, StandIn};
use alpha_dsm::{Error, OwnDsm};
use ed25519_dalek::{Signature, Verifier};
use zeroize::Zeroizing;

#[tokio::test]
async fn our_dsm_wraps_unwraps_and_signs_and_refuses_when_its_admin_says_so() {
    let dsm = StandIn::new();
    let (endpoint, ca) = dsm.serve().await;
    let aes = OwnDsm::new(
        &StandIn::config(&endpoint, &ca, AES_KEY),
        Zeroizing::new(API_KEY.into()),
    )
    .unwrap();

    let wrapped = aes.encrypt(b"cofactor", b"ad").await.unwrap();
    assert_eq!(&*aes.decrypt(&wrapped, b"ad").await.unwrap(), b"cofactor");
    // The associated data binds: the same ciphertext under other data does not open.
    assert!(aes.decrypt(&wrapped, b"other").await.is_err());
    let mut tampered = wrapped.clone();
    tampered.tag = tampered.cipher.clone();
    assert!(aes.decrypt(&tampered, b"ad").await.is_err());

    let signer = OwnDsm::new(
        &StandIn::config(&endpoint, &ca, SIGNING_KEY),
        Zeroizing::new(API_KEY.into()),
    )
    .unwrap();
    let signature = signer.sign(b"digest").await.unwrap();
    dsm.verifying_key()
        .verify(b"digest", &Signature::from_slice(&signature).unwrap())
        .unwrap();
    // The AES key cannot sign, and the signing key cannot encrypt.
    assert!(aes.sign(b"digest").await.is_err());
    assert!(signer.encrypt(b"x", b"ad").await.is_err());

    dsm.disabled.store(true, Ordering::SeqCst);
    match aes.decrypt(&wrapped, b"ad").await {
        Err(Error::Refused { status: 403, .. }) => {}
        other => panic!("{other:?}"),
    }
    dsm.disabled.store(false, Ordering::SeqCst);

    let wrong = OwnDsm::new(
        &StandIn::config(&endpoint, &ca, AES_KEY),
        Zeroizing::new("d3Jvbmc6a2V5".into()),
    )
    .unwrap();
    match wrong.encrypt(b"x", b"ad").await {
        Err(Error::Refused { status: 401, .. }) => {}
        other => panic!("{other:?}"),
    }

    // A DSM under another CA is never reached.
    let (_, other_ca) = StandIn::new().serve().await;
    let calls = dsm.calls.load(Ordering::SeqCst);
    let pinned_elsewhere = OwnDsm::new(
        &StandIn::config(&endpoint, &other_ca, AES_KEY),
        Zeroizing::new(API_KEY.into()),
    )
    .unwrap();
    assert!(matches!(
        pinned_elsewhere.encrypt(b"x", b"ad").await,
        Err(Error::Transport(_))
    ));
    assert_eq!(dsm.calls.load(Ordering::SeqCst), calls);
}
