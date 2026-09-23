//! The one listener: TLS 1.3 with `X25519MLKEM768` and this Instance's leaf. A client
//! certificate is requested, not required: the connect routes are called without one, and a
//! chain that is presented must end at the KMS CA or the handshake fails. `/proxy` then
//! requires that one was presented.

use std::future::Future;
use std::sync::Arc;

use alpha_client::tls::provider;
use axum::Router;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::service::TowerToHyperService;
use rustls::pki_types::CertificateDer;
use rustls::server::{ResolvesServerCert, WebPkiClientVerifier};
use rustls::{RootCertStore, ServerConfig};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::Error;

/// The chain the peer presented, leaf first; empty when it presented none.
#[derive(Clone, Debug, Default)]
pub struct PeerCerts(pub Vec<CertificateDer<'static>>);

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

/// Accepts until `shutdown` resolves, then drains the open connections.
pub async fn serve(
    listener: TcpListener,
    config: Arc<ServerConfig>,
    app: Router,
    shutdown: impl Future<Output = ()>,
) {
    let acceptor = TlsAcceptor::from(config);
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
                    .map(<[_]>::to_vec)
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
