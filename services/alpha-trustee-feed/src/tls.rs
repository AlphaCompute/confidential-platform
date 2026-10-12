//! The KBS's public TLS, terminated in the TD: the leaf alpha-kms issues for
//! `trustee.kbs_hostname` over this pod's attested key, chained to the KMS CA, which is the
//! certificate the pods' init-data pins for the KBS (`docs/trustee.md`). Renewed with the pod's
//! own leaf, swapped whole so a handshake in flight sees one chain.

use std::sync::Arc;

use alpha_trustee::wire::KbsLeaf;
use parking_lot::RwLock;
use rustls::crypto::CryptoProvider;
use rustls::crypto::aws_lc_rs::{self, kx_group};
use rustls::server::{ClientHello, ResolvesServerCert, WebPkiClientVerifier};
use rustls::sign::CertifiedKey;
use rustls::{ServerConfig, pki_types::CertificateDer};

use crate::Error;

#[derive(Debug)]
pub struct GateCert(RwLock<Arc<CertifiedKey>>);

fn certified(leaf: &KbsLeaf, pkcs8: &[u8]) -> Result<Arc<CertifiedKey>, Error> {
    let chain = leaf
        .certificate_chain
        .iter()
        .map(|pem| alpha_client::tls::cert_from_pem(pem))
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .map_err(|e| Error::Tls(e.to_string()))?;
    alpha_client::tls::certified(chain, pkcs8).map_err(|e| Error::Tls(e.to_string()))
}

impl GateCert {
    pub fn new(leaf: &KbsLeaf, pkcs8: &[u8]) -> Result<Self, Error> {
        Ok(Self(RwLock::new(certified(leaf, pkcs8)?)))
    }

    pub fn replace(&self, leaf: &KbsLeaf, pkcs8: &[u8]) -> Result<(), Error> {
        let certified = certified(leaf, pkcs8)?;
        *self.0.write() = certified;
        Ok(())
    }
}

impl ResolvesServerCert for GateCert {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.read().clone())
    }
}

/// TLS 1.3, `X25519MLKEM768` first and `X25519` for a guest whose client lacks it: what is
/// read here is sealed to the pod's TEE key anyway (ECDH-ES P-256).
// ponytail: G0 — whether the guest's KBS client (reqwest 0.13, rustls) offers X25519MLKEM768;
// once it does, X25519 goes.
pub fn server_config(cert: Arc<GateCert>) -> Result<Arc<ServerConfig>, Error> {
    let provider = Arc::new(CryptoProvider {
        kx_groups: vec![kx_group::X25519MLKEM768, kx_group::X25519],
        ..aws_lc_rs::default_provider()
    });
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| Error::Tls(e.to_string()))?
        .with_client_cert_verifier(WebPkiClientVerifier::no_client_auth())
        .with_cert_resolver(cert);
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}
