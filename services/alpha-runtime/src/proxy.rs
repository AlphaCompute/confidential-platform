//! TLS for a wrapped compose: the current Instance leaf on the Endpoint, then the bytes copied
//! both ways to the published service's plain port.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::ServerConfig;
use rustls::server::{ClientHello, NoServerSessionStorage, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

use crate::{Error, Runtime, Upstream};

const HANDSHAKE: Duration = Duration::from_secs(10);
const CONNECT: Duration = Duration::from_secs(10);
/// Docker kills the container this long after SIGTERM anyway.
const DRAIN: Duration = Duration::from_secs(10);

/// How the proxy stops: let open connections finish for at most [`DRAIN`], or cut them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stop {
    Drain,
    Now,
}

struct CurrentLeaf(Arc<Runtime>);

impl std::fmt::Debug for CurrentLeaf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CurrentLeaf")
    }
}

impl ResolvesServerCert for CurrentLeaf {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.0.attested().map(|a| a.certified.clone())
    }
}

fn server_config(runtime: Arc<Runtime>) -> Result<Arc<ServerConfig>, Error> {
    let mut config = ServerConfig::builder_with_provider(alpha_client::tls::provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| Error::Socket(format!("tls: {e}")))?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(CurrentLeaf(runtime)));
    // A resumed session presents no certificate, and each connection must prove the current leaf.
    config.send_tls13_tickets = 0;
    config.session_storage = Arc::new(NoServerSessionStorage {});
    // ponytail: no ALPN, so a browser speaks HTTP/1.1 and HTTP/2 by prior knowledge still passes,
    // but a client that insists on `h2` (gRPC) is not served; the upgrade is a measured opt-in
    // that advertises `h2` for an `h2c` backend.
    config.alpn_protocols = Vec::new();
    Ok(Arc::new(config))
}

/// The Endpoint's listener with its TLS configuration, bound only for a compose that names an
/// upstream.
pub struct Endpoint {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    upstream: Upstream,
}

impl Endpoint {
    /// `None` when the configuration names no upstream.
    pub async fn bind(runtime: Arc<Runtime>, addr: SocketAddr) -> Result<Option<Self>, Error> {
        let Some(upstream) = runtime.config().tls_upstream.clone() else {
            return Ok(None);
        };
        let acceptor = TlsAcceptor::from(server_config(runtime)?);
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| Error::Socket(format!("{addr}: {e}")))?;
        Ok(Some(Self {
            listener,
            acceptor,
            upstream,
        }))
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Accepts until `stop` resolves; no idle timeout, so WebSockets and long polls stay open.
    pub async fn serve(self, stop: impl Future<Output = Stop>) {
        let mut stop = std::pin::pin!(stop);
        let mut open = JoinSet::new();
        let how = loop {
            while open.try_join_next().is_some() {}
            let tcp = tokio::select! {
                accepted = self.listener.accept() => match accepted {
                    Ok((tcp, _)) => tcp,
                    // Out of descriptors, accept fails at once until one frees up.
                    Err(_) => {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                },
                how = &mut stop => break how,
            };
            open.spawn(proxy(self.acceptor.clone(), tcp, self.upstream.clone()));
        };
        drop(self.listener);
        if how == Stop::Drain {
            let _ = timeout(DRAIN, async { while open.join_next().await.is_some() {} }).await;
        }
        open.abort_all();
        while open.join_next().await.is_some() {}
    }
}

async fn proxy(acceptor: TlsAcceptor, tcp: TcpStream, upstream: Upstream) {
    let _ = tcp.set_nodelay(true);
    let Ok(Ok(mut tls)) = timeout(HANDSHAKE, acceptor.accept(tcp)).await else {
        return;
    };
    let connect = TcpStream::connect((upstream.host.as_str(), upstream.port));
    let mut backend = match timeout(CONNECT, connect).await {
        Ok(Ok(backend)) => backend,
        Ok(Err(e)) => {
            eprintln!("alpha-runtime: upstream {upstream}: {e}");
            let _ = tokio::io::AsyncWriteExt::shutdown(&mut tls).await;
            return;
        }
        Err(_) => {
            eprintln!("alpha-runtime: upstream {upstream}: no answer within {CONNECT:?}");
            let _ = tokio::io::AsyncWriteExt::shutdown(&mut tls).await;
            return;
        }
    };
    let _ = backend.set_nodelay(true);
    let _ = tokio::io::copy_bidirectional(&mut tls, &mut backend).await;
}
