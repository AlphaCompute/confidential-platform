//! The one listener: TLS 1.3 with `X25519MLKEM768`, a server certificate that follows the
//! node's phase, and a client certificate that is requested but checked by the route.

use std::sync::Arc;

use parking_lot::RwLock;
use std::time::SystemTime;

use alpha_client::tls::provider;
use axum::Router;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::service::TowerToHyperService;
use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{DigitallySignedStruct, DistinguishedName, ServerConfig, SignatureScheme};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::certs;
use crate::error::ApiError;

/// The certificate chain the peer presented, if any; routes that need one verify it.
#[derive(Clone, Debug, Default)]
pub struct PeerCerts(pub Vec<CertificateDer<'static>>);

fn certified(pkcs8: &[u8], chain: Vec<Vec<u8>>) -> Result<Arc<CertifiedKey>, ApiError> {
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8.to_vec()));
    let signing = provider()
        .key_provider
        .load_private_key(key)
        .map_err(|e| ApiError::internal(format!("runtime key: {e}")))?;
    Ok(Arc::new(CertifiedKey::new(
        chain.into_iter().map(CertificateDer::from).collect(),
        signing,
    )))
}

#[derive(Debug)]
pub struct ServerCert(RwLock<Arc<CertifiedKey>>);

impl ServerCert {
    pub fn sealed(runtime_pkcs8: &[u8], now: SystemTime) -> Result<Self, ApiError> {
        let cert = certs::self_signed(&certs::key_pair(runtime_pkcs8)?, now)?;
        Ok(Self(RwLock::new(certified(runtime_pkcs8, vec![cert])?)))
    }

    pub fn serve(
        &self,
        runtime_pkcs8: &[u8],
        leaf_der: Vec<u8>,
        ca_der: Vec<u8>,
    ) -> Result<(), ApiError> {
        *self.0.write() = certified(runtime_pkcs8, vec![leaf_der, ca_der])?;
        Ok(())
    }
}

impl ResolvesServerCert for ServerCert {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.read().clone())
    }
}

/// Requests a client certificate and accepts any chain the peer proves possession of; the
/// route that needs a chain to `ca` or to a runtime key checks it in its extractor.
#[derive(Debug)]
struct AcceptAnyClient(Arc<CryptoProvider>);

impl ClientCertVerifier for AcceptAnyClient {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn verify_client_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

pub fn server_config(server_cert: Arc<ServerCert>) -> Result<Arc<ServerConfig>, ApiError> {
    let provider = provider();
    let mut config = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| ApiError::internal(format!("tls: {e}")))?
        .with_client_cert_verifier(Arc::new(AcceptAnyClient(provider)))
        .with_cert_resolver(server_cert);
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// Accepts until `shutdown` resolves, then drains the open connections.
pub async fn serve(
    listener: TcpListener,
    server_cert: Arc<ServerCert>,
    app: Router,
    shutdown: impl Future<Output = ()>,
) -> Result<(), ApiError> {
    let acceptor = TlsAcceptor::from(server_config(server_cert)?);
    let graceful = GracefulShutdown::new();
    let mut shutdown = std::pin::pin!(shutdown);
    loop {
        let (stream, _) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(accepted) => accepted,
                Err(_) => continue,
            },
            () = &mut shutdown => break,
        };
        let acceptor = acceptor.clone();
        let app = app.clone();
        let watcher = graceful.watcher();
        tokio::spawn(async move {
            let Ok(tls) = acceptor.accept(stream).await else {
                return;
            };
            let peer = PeerCerts(
                tls.get_ref()
                    .1
                    .peer_certificates()
                    .map(|c| c.to_vec())
                    .unwrap_or_default(),
            );
            let service = TowerToHyperService::new(app.layer(axum::Extension(peer)));
            let builder = Builder::new(TokioExecutor::new());
            let conn = builder.serve_connection(TokioIo::new(tls), service);
            let _ = watcher.watch(conn).await;
        });
    }
    graceful.shutdown().await;
    Ok(())
}
