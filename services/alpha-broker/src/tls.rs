//! The one listener: TLS 1.3 with `X25519MLKEM768` and this Instance's leaf. A client
//! certificate is requested, not required: the connect routes are called without one, and a
//! chain that is presented must end at the KMS CA or the handshake fails. `/proxy` then
//! requires that one was presented.

use std::sync::Arc;

use alpha_client::tls::provider;
use rustls::pki_types::CertificateDer;
use rustls::server::{ResolvesServerCert, WebPkiClientVerifier};
use rustls::{RootCertStore, ServerConfig};

use crate::Error;

pub fn server_config(
    cert: Arc<dyn ResolvesServerCert>,
    kms_ca: CertificateDer<'static>,
) -> Result<Arc<ServerConfig>, Error> {
    let tls = |e: &dyn std::fmt::Display| Error::internal(format!("tls: {e}"));
    let mut roots = RootCertStore::empty();
    roots.add(kms_ca).map_err(|e| tls(&e))?;
    let provider = provider();
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .allow_unauthenticated()
        .build()
        .map_err(|e| tls(&e))?;
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| tls(&e))?
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(cert);
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}
