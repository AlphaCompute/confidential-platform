//! Known-answer tests: the X-Wing KEM vectors of draft-connolly-cfrg-xwing-kem, the HPKE
//! vector of draft-ietf-hpke-pq for X-Wing + HKDF-SHA256 (recipient side, with the AEAD the
//! draft ships), and a fixed envelope of our own suite that `open` must reproduce.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::fs;
use std::path::PathBuf;

use alpha_crypto::{INFO_UNSEAL_SHARE, PrivateKey, Sealed, open};
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::XWing;
use hpke::{Deserializable, Kem, OpModeR, Serializable};
use serde::Deserialize;
use x_wing::{Decapsulate, Decapsulator, KeyExport};

fn read(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/crypto")
        .join(name);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

#[derive(Deserialize)]
struct KemVector {
    #[serde(with = "hex::serde")]
    seed: [u8; 32],
    #[serde(with = "hex::serde")]
    eseed: [u8; 64],
    #[serde(with = "hex::serde")]
    ss: [u8; 32],
    #[serde(with = "hex::serde")]
    sk: [u8; 32],
    #[serde(with = "hex::serde")]
    pk: Vec<u8>,
    #[serde(with = "hex::serde")]
    ct: Vec<u8>,
}

#[test]
fn xwing_kem_vectors() {
    let vectors: Vec<KemVector> = serde_json::from_str(&read("xwing-kem.json")).unwrap();
    assert_eq!(vectors.len(), 3);
    for v in vectors {
        assert_eq!(v.seed, v.sk);
        let dk = x_wing::DecapsulationKey::from(v.seed);
        assert_eq!(dk.encapsulation_key().to_bytes().as_slice(), v.pk);
        let (ct, ss) = dk
            .encapsulation_key()
            .encapsulate_deterministic(&v.eseed.into());
        assert_eq!(ct.as_slice(), v.ct);
        assert_eq!(ss.as_slice(), v.ss);
        assert_eq!(dk.decapsulate(&ct).as_slice(), v.ss);
        assert_eq!(
            PrivateKey::from_seed(v.seed)
                .unwrap()
                .public()
                .as_bytes()
                .as_slice(),
            v.pk
        );
    }
}

#[derive(Deserialize)]
struct HpkeVector {
    mode: u8,
    kem_id: u16,
    kdf_id: u16,
    aead_id: u16,
    #[serde(with = "hex::serde")]
    info: Vec<u8>,
    #[serde(rename = "skRm", with = "hex::serde")]
    sk_recip: Vec<u8>,
    #[serde(rename = "pkRm", with = "hex::serde")]
    pk_recip: Vec<u8>,
    #[serde(with = "hex::serde")]
    enc: Vec<u8>,
    encryptions: Vec<Encryption>,
    exports: Vec<Export>,
}

#[derive(Deserialize)]
struct Encryption {
    #[serde(with = "hex::serde")]
    aad: Vec<u8>,
    #[serde(with = "hex::serde")]
    ct: Vec<u8>,
    #[serde(with = "hex::serde")]
    pt: Vec<u8>,
}

#[derive(Deserialize)]
struct Export {
    #[serde(with = "hex::serde")]
    exporter_context: Vec<u8>,
    #[serde(rename = "L")]
    len: usize,
    #[serde(with = "hex::serde")]
    exported_value: Vec<u8>,
}

#[test]
fn hpke_xwing_hkdfsha256_vector() {
    let v: HpkeVector =
        serde_json::from_str(&read("hpke-xwing-hkdfsha256-chacha20poly1305.json")).unwrap();
    assert_eq!((v.mode, v.kem_id, v.kdf_id, v.aead_id), (0, 0x647a, 1, 3));
    let sk = <XWing as Kem>::PrivateKey::from_bytes(&v.sk_recip).unwrap();
    assert_eq!(XWing::sk_to_pk(&sk).to_bytes().as_slice(), v.pk_recip);
    let enc = <XWing as Kem>::EncappedKey::from_bytes(&v.enc).unwrap();
    let mut ctx = hpke::setup_receiver::<ChaCha20Poly1305, HkdfSha256, XWing>(
        &OpModeR::Base,
        &sk,
        &enc,
        &v.info,
    )
    .unwrap();
    for e in &v.encryptions {
        assert_eq!(ctx.open(&e.ct, &e.aad).unwrap(), e.pt);
    }
    for x in &v.exports {
        let mut out = vec![0u8; x.len];
        ctx.export(&x.exporter_context, &mut out).unwrap();
        assert_eq!(out, x.exported_value);
    }
}

#[derive(Deserialize)]
struct EnvelopeVector {
    #[serde(with = "hex::serde")]
    seed: [u8; 32],
    #[serde(with = "hex::serde")]
    kms_node_spki_sha256: [u8; 32],
    info: String,
    sealed: Sealed,
    #[serde(with = "hex::serde")]
    plaintext: Vec<u8>,
}

#[test]
fn envelope_vector() {
    let v: EnvelopeVector = serde_json::from_str(&read("envelope-unseal-share.json")).unwrap();
    assert_eq!(v.info.as_bytes(), INFO_UNSEAL_SHARE);
    let key = PrivateKey::from_seed(v.seed).unwrap();
    let opened = open(&key, v.info.as_bytes(), &v.kms_node_spki_sha256, &v.sealed).unwrap();
    assert_eq!(opened.as_slice(), v.plaintext);
    let mut other = v.kms_node_spki_sha256;
    other[0] ^= 1;
    assert!(open(&key, v.info.as_bytes(), &other, &v.sealed).is_err());
}
