//! The one listener: TLS 1.3 with `X25519MLKEM768`, a server certificate that follows the
//! node's phase, and a client certificate that is requested but checked by the route.

use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use axum::Router;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::service::TowerToHyperService;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::crypto::aws_lc_rs::{self, kx_group};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{
    ClientConfig, DigitallySignedStruct, DistinguishedName, ServerConfig, SignatureScheme,
};
use rustls_pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, TrustAnchor, UnixTime,
};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::certs;
use crate::error::ApiError;

/// The certificate chain the peer presented, if any; routes that need one verify it.
#[derive(Clone, Debug, Default)]
pub struct PeerCerts(pub Vec<CertificateDer<'static>>);

fn provider() -> Arc<CryptoProvider> {
    Arc::new(CryptoProvider {
        kx_groups: vec![kx_group::X25519MLKEM768],
        ..aws_lc_rs::default_provider()
    })
}

fn certified(pkcs8: &[u8], chain: Vec<Vec<u8>>) -> Arc<CertifiedKey> {
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8.to_vec()));
    let signing = provider()
        .key_provider
        .load_private_key(key)
        .expect("a P-256 key we generated");
    Arc::new(CertifiedKey::new(
        chain.into_iter().map(CertificateDer::from).collect(),
        signing,
    ))
}

#[derive(Debug)]
pub struct ServerCert(RwLock<Arc<CertifiedKey>>);

impl ServerCert {
    pub fn sealed(runtime_pkcs8: &[u8], now: SystemTime) -> Self {
        let cert = certs::self_signed(&certs::key_pair(runtime_pkcs8), now);
        Self(RwLock::new(certified(runtime_pkcs8, vec![cert])))
    }

    pub fn serve(&self, runtime_pkcs8: &[u8], leaf_der: Vec<u8>, ca_der: Vec<u8>) {
        *self.0.write().unwrap() = certified(runtime_pkcs8, vec![leaf_der, ca_der]);
    }

    pub fn current(&self) -> Arc<CertifiedKey> {
        self.0.read().unwrap().clone()
    }
}

impl ResolvesServerCert for ServerCert {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.current())
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

pub fn server_config(server_cert: Arc<ServerCert>) -> Arc<ServerConfig> {
    let provider = provider();
    let mut config = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 is supported")
        .with_client_cert_verifier(Arc::new(AcceptAnyClient(provider)))
        .with_cert_resolver(server_cert);
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

/// Accepts until `shutdown` resolves, then drains the open connections.
pub async fn serve(
    listener: TcpListener,
    server_cert: Arc<ServerCert>,
    app: Router,
    shutdown: impl Future<Output = ()>,
) {
    let acceptor = TlsAcceptor::from(server_config(server_cert));
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
}

/// The other node as a TLS server: its chain must end at the pinned `ca` and its leaf must
/// carry one of the allowed Revision SANs; the host name is only routing and is not checked.
#[derive(Debug)]
pub struct PinnedServer {
    anchor: TrustAnchor<'static>,
    revisions: Vec<String>,
    provider: Arc<CryptoProvider>,
}

impl PinnedServer {
    pub fn new(ca: CertificateDer<'static>, revisions: Vec<String>) -> Result<Self, ApiError> {
        let anchor = webpki::anchor_from_trusted_cert(&ca)
            .map_err(|e| ApiError::internal(format!("kms_ca_pem: {e}")))?
            .to_owned();
        Ok(Self {
            anchor,
            revisions,
            provider: provider(),
        })
    }
}

impl ServerCertVerifier for PinnedServer {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let cert = webpki::EndEntityCert::try_from(end_entity)
            .map_err(|e| rustls::Error::General(e.to_string()))?;
        cert.verify_for_usage(
            self.provider.signature_verification_algorithms.all,
            std::slice::from_ref(&self.anchor),
            intermediates,
            now,
            webpki::KeyUsage::server_auth(),
            None,
            None,
        )
        .map_err(|e| rustls::Error::General(e.to_string()))?;
        let sans = certs::uri_sans(end_entity).map_err(|e| rustls::Error::General(e.message))?;
        if !sans.iter().any(|s| self.revisions.contains(s)) {
            return Err(rustls::Error::General(
                "server certificate carries no allowed KMS revision".into(),
            ));
        }
        Ok(ServerCertVerified::assertion())
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
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub fn client_config(verifier: PinnedServer, cert_der: Vec<u8>, pkcs8: &[u8]) -> ClientConfig {
    ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 is supported")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_client_auth_cert(
            vec![CertificateDer::from(cert_der)],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8.to_vec())),
        )
        .expect("a P-256 key we generated")
}
