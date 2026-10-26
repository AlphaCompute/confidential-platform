//! TLS for a wrapped compose: the current Instance leaf on the Endpoint, then the bytes copied
//! both ways to the published service's plain port. With caller Apps configured, only a client
//! presenting an Instance leaf of one of them under the KMS CA gets past the handshake.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use alpha_client::tls;
use alpha_core::AppId;
use axum::extract::State;
use axum::http::StatusCode;
use axum::http::header::CONTENT_TYPE;
use rustls::pki_types::CertificateDer;
use rustls::server::{
    ClientHello, NoServerSessionStorage, ResolvesServerCert, WebPkiClientVerifier,
};
use rustls::sign::CertifiedKey;
use rustls::{RootCertStore, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

use crate::{Error, Exit, Runtime};

const HANDSHAKE: Duration = Duration::from_secs(10);
const CONNECT: Duration = Duration::from_secs(10);
/// Docker kills the container this long after SIGTERM anyway.
const DRAIN: Duration = Duration::from_secs(10);
/// The whole readiness exchange with the upstream, connect included.
const READY_CHECK: Duration = Duration::from_secs(2);

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
    let tls_error = |e: &dyn std::fmt::Display| Error::Socket(format!("tls: {e}"));
    let builder = ServerConfig::builder_with_details(tls::provider(), runtime.time.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| tls_error(&e))?;
    let builder = if runtime.config().tls_callers.is_empty() {
        builder.with_no_client_auth()
    } else {
        // The CA of the first attestation, whose SPKI the runtime checked against the measured
        // hash; a CA under another key fails the runtime's next renewal anyway.
        let ca = runtime
            .last()
            .and_then(|a| a.certified.cert.last().cloned())
            .ok_or(Error::NotAttested)?;
        let mut roots = RootCertStore::empty();
        roots.add(ca).map_err(|e| tls_error(&e))?;
        builder.with_client_cert_verifier(
            WebPkiClientVerifier::builder_with_provider(Arc::new(roots), tls::provider())
                .build()
                .map_err(|e| tls_error(&e))?,
        )
    };
    let mut config = builder
        // ponytail: no ALPN, so a browser speaks HTTP/1.1 and HTTP/2 by prior knowledge still
        // passes, but a client that insists on `h2` (gRPC) is not served; the upgrade is a
        // measured opt-in that advertises `h2` for an `h2c` backend.
        .with_cert_resolver(Arc::new(CurrentLeaf(runtime)));
    // A resumed session presents no certificate, and each connection must prove the current leaf.
    config.send_tls13_tickets = 0;
    config.session_storage = Arc::new(NoServerSessionStorage {});
    Ok(Arc::new(config))
}

/// The Endpoint's listener with its TLS configuration and its plain-HTTP probe listener, bound
/// only for a compose that names an upstream.
pub struct Endpoint {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    upstream: String,
    callers: Arc<[AppId]>,
    probe: (TcpListener, axum::Router),
}

async fn bind_tcp(addr: SocketAddr) -> Result<TcpListener, Error> {
    TcpListener::bind(addr)
        .await
        .map_err(|e| Error::Socket(format!("{addr}: {e}")))
}

impl Endpoint {
    /// `None` when the configuration names no upstream. With caller Apps, call it after the
    /// first attestation: the KMS CA comes from its chain.
    pub async fn bind(
        runtime: Arc<Runtime>,
        addr: SocketAddr,
        probe_addr: SocketAddr,
    ) -> Result<Option<Self>, Error> {
        let config = runtime.config();
        let Some(upstream) = config.tls_upstream.clone() else {
            return Ok(None);
        };
        let callers = config.tls_callers.clone().into();
        let probe = axum::Router::new()
            .route("/leaf", axum::routing::get(leaf_chain))
            .route("/ready", axum::routing::get(ready))
            .with_state(runtime.clone());
        let probe = (bind_tcp(probe_addr).await?, probe);
        let acceptor = TlsAcceptor::from(server_config(runtime)?);
        Ok(Some(Self {
            listener: bind_tcp(addr).await?,
            acceptor,
            upstream,
            callers,
            probe,
        }))
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub fn probe_addr(&self) -> std::io::Result<SocketAddr> {
        self.probe.0.local_addr()
    }

    /// Accepts until `stop` resolves; no idle timeout, so WebSockets and long polls stay open.
    /// Open connections get at most [`DRAIN`] on a shutdown and are cut on revocation.
    pub async fn serve(self, stop: impl Future<Output = Exit>) {
        let mut stop = std::pin::pin!(stop);
        let (listener, router) = self.probe;
        let probe = tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, router).await {
                alpha_client::error!("probe_listener_failed", error = e.kind());
            }
        });
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
            open.spawn(proxy(
                self.acceptor.clone(),
                tcp,
                self.upstream.clone(),
                self.callers.clone(),
            ));
        };
        drop(self.listener);
        probe.abort();
        if how == Exit::Drained {
            let _ = timeout(DRAIN, async { while open.join_next().await.is_some() {} }).await;
        }
        open.abort_all();
        while open.join_next().await.is_some() {}
    }
}

/// Whether the client's leaf, already chained to the KMS CA in the handshake, is an Instance
/// of a listed App; a KMS node's leaf chains there too but carries no Instance SANs.
fn admitted(peer: Option<&[CertificateDer<'_>]>, callers: &[AppId]) -> bool {
    callers.is_empty()
        || peer
            .and_then(<[_]>::first)
            .and_then(|leaf| tls::uri_sans(leaf).ok())
            .and_then(|sans| tls::parse_instance_sans(&sans).ok())
            .is_some_and(|instance| callers.contains(&instance.app_id))
}

async fn proxy(acceptor: TlsAcceptor, tcp: TcpStream, upstream: String, callers: Arc<[AppId]>) {
    let _ = tcp.set_nodelay(true);
    let Ok(Ok(mut tls)) = timeout(HANDSHAKE, acceptor.accept(tcp)).await else {
        return;
    };
    if !admitted(tls.get_ref().1.peer_certificates(), &callers) {
        let _ = tls.shutdown().await;
        return;
    }
    let connected = timeout(CONNECT, TcpStream::connect(upstream.as_str()))
        .await
        .map_err(|_| std::io::ErrorKind::TimedOut)
        .and_then(|r| r.map_err(|e| e.kind()));
    let mut backend = match connected {
        Ok(backend) => backend,
        Err(kind) => {
            alpha_client::warn!(
                "upstream_unreachable",
                upstream = alpha_client::log::Field::text(&upstream),
                error = kind,
            );
            let _ = tls.shutdown().await;
            return;
        }
    };
    let _ = backend.set_nodelay(true);
    let _ = tokio::io::copy_bidirectional(&mut tls, &mut backend).await;
}

/// The PEM chain the Endpoint presents now, leaf first; it is public, as every handshake shows it.
async fn leaf_chain(
    State(runtime): State<Arc<Runtime>>,
) -> Result<impl axum::response::IntoResponse, StatusCode> {
    let attested = runtime.attested().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let chain = attested
        .chain_pem
        .iter()
        .map(|pem| format!("{}\n", pem.trim_end()))
        .collect::<String>();
    Ok(([(CONTENT_TYPE, "application/pem-certificate-chain")], chain))
}

/// 200 only while the leaf is current and the upstream answers its own path with a 2xx now.
async fn ready(State(runtime): State<Arc<Runtime>>) -> StatusCode {
    let config = runtime.config();
    let (Some(upstream), Some(path)) = (&config.tls_upstream, &config.tls_ready) else {
        return StatusCode::SERVICE_UNAVAILABLE;
    };
    if runtime.attested().is_some() && upstream_answers(upstream, path).await {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

async fn upstream_answers(upstream: &str, path: &str) -> bool {
    let check = async {
        let mut tcp = TcpStream::connect(upstream).await.ok()?;
        let request =
            format!("GET {path} HTTP/1.1\r\nHost: {upstream}\r\nConnection: close\r\n\r\n");
        tcp.write_all(request.as_bytes()).await.ok()?;
        let mut status = [0u8; 10];
        tcp.read_exact(&mut status).await.ok()?;
        Some(status.starts_with(b"HTTP/1.") && status.ends_with(b" 2"))
    };
    matches!(timeout(READY_CHECK, check).await, Ok(Some(true)))
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn upstream(reply: &'static [u8]) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            while let Ok((mut tcp, _)) = listener.accept().await {
                let mut request = [0u8; 1024];
                let _ = tcp.read(&mut request).await;
                let _ = tcp.write_all(reply).await;
            }
        });
        addr
    }

    fn leaf(sans: &[String]) -> CertificateDer<'static> {
        let mut params = rcgen::CertificateParams::default();
        params.subject_alt_names = sans
            .iter()
            .map(|s| rcgen::SanType::URI(s.as_str().try_into().unwrap()))
            .collect();
        let key = rcgen::KeyPair::generate().unwrap();
        params.self_signed(&key).unwrap().der().clone()
    }

    #[test]
    fn only_an_instance_leaf_of_a_listed_app_is_admitted() {
        let (org, listed, other) = (alpha_core::OrgId::mint(), AppId::mint(), AppId::mint());
        let revision = format!("urn:alphacompute:revision:sha256:{}", "ab".repeat(32));
        let instance = |app: AppId| {
            leaf(&[
                format!("alphacompute://{org}/{app}/{}", "cd".repeat(32)),
                revision.clone(),
            ])
        };
        let callers = [listed];
        assert!(admitted(Some(&[instance(listed)]), &callers));
        assert!(!admitted(Some(&[instance(other)]), &callers));
        let node = leaf(&[tls::KMS_SAN.to_owned(), revision.clone()]);
        assert!(!admitted(Some(&[node]), &callers));
        assert!(!admitted(None, &callers));
        assert!(admitted(None, &[]));
    }

    #[tokio::test]
    async fn the_upstream_answers_only_with_a_2xx_status_line() {
        let ok = upstream(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await;
        assert!(upstream_answers(&ok, "/health").await);
        let loading = upstream(b"HTTP/1.1 503 Service Unavailable\r\n\r\n").await;
        assert!(!upstream_answers(&loading, "/health").await);
        let garbage = upstream(b"SSH-2.0-OpenSSH_9.6\r\n").await;
        assert!(!upstream_answers(&garbage, "/health").await);
        let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = closed.local_addr().unwrap().to_string();
        drop(closed);
        assert!(!upstream_answers(&addr, "/health").await);
    }
}
