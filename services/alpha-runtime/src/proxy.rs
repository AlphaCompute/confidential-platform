//! TLS for a wrapped compose: the current Instance leaf on the Endpoint, then the bytes copied
//! both ways to the published service's plain port. With caller Apps configured, only a client
//! presenting an Instance leaf of one of them under the KMS CA gets past the handshake. With a
//! public name, a browser on that name gets the ACME certificate instead, the binding of its
//! key to the Instance leaf at [`binding::PATH`], and the evidence behind that leaf at
//! [`ATTESTATION_PATH`].

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use alpha_channel::binding;
use alpha_client::tls;
use alpha_core::AppId;
use axum::extract::State;
use axum::http::StatusCode;
use axum::http::header::CONTENT_TYPE;
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use p256::ecdsa::SigningKey;
use p256::pkcs8::DecodePrivateKey;
use rustls::pki_types::CertificateDer;
use rustls::server::{
    Acceptor, ClientHello, NoServerSessionStorage, ResolvesServerCert, WebPkiClientVerifier,
};
use rustls::sign::{CertifiedKey, SingleCertAndKey};
use rustls::{RootCertStore, ServerConfig};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_rustls::LazyConfigAcceptor;

use crate::acme::{self, Edge, Route};
use crate::{Attested, Error, Exit, Runtime};

const HANDSHAKE: Duration = Duration::from_secs(10);
const CONNECT: Duration = Duration::from_secs(10);
/// Docker kills the container this long after SIGTERM anyway.
const DRAIN: Duration = Duration::from_secs(10);
/// The whole readiness exchange with the upstream, connect included.
const READY_CHECK: Duration = Duration::from_secs(2);
/// Answered with the JSON the browser verifier appraises the TD from.
const ATTESTATION_PATH: &str = "/.well-known/alphacompute/attestation";
/// A verifier's challenge on the binding path: `?challenge=` and 32 bytes in base64url, which the
/// binding key signs back, so the answer cannot be a replay.
const CHALLENGE: &str = "?challenge=";
const CHALLENGE_LEN: usize = 43;

/// What a fresh connection to the public name asks the runtime itself for.
#[derive(Debug, PartialEq, Eq)]
enum Asked {
    Binding(Option<[u8; 32]>),
    Attestation,
}

/// Where the bytes read so far stand against the requests in [`Asked`].
#[derive(Debug, PartialEq, Eq)]
enum Head {
    Partial,
    Asked(Asked),
    Other,
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

/// Browsers and the ACME CA's validators may lack `X25519MLKEM768`, the one group the
/// platform's own hops accept, and TLS 1.3; only the public name is served to them.
fn public_config(cert: Arc<CertifiedKey>, alpn: Option<&[u8]>) -> Option<Arc<ServerConfig>> {
    let mut config = ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .ok()?
    .with_no_client_auth()
    .with_cert_resolver(Arc::new(SingleCertAndKey::from(cert)));
    config.alpn_protocols = alpn.into_iter().map(<[u8]>::to_vec).collect();
    // The config lives for one connection, so a ticket could never resume.
    config.send_tls13_tickets = 0;
    config.session_storage = Arc::new(NoServerSessionStorage {});
    Some(Arc::new(config))
}

struct Configs {
    instance: Arc<ServerConfig>,
    public: Option<(String, Arc<Edge>)>,
}

enum Handshake<'a> {
    Instance,
    Challenge,
    Public(&'a str, Arc<CertifiedKey>),
}

/// A client on the public name keeps the Instance leaf until the first certificate arrives,
/// and while the Instance leaf has expired, so no public handshake outlives the attestation.
/// A public handshake gets the certificate read here, which its binding then signs, even if a
/// renewal replaces it in between.
fn select<'a>(
    configs: &'a Configs,
    attested: bool,
    hello: &ClientHello<'_>,
) -> Option<(Handshake<'a>, Arc<ServerConfig>)> {
    let instance = Some((Handshake::Instance, configs.instance.clone()));
    let Some((name, edge)) = &configs.public else {
        return instance;
    };
    match acme::route(name, hello.server_name(), hello.alpn()) {
        Route::Challenge => {
            let config = public_config(edge.challenge.read().clone()?, Some(acme::ACME_TLS_ALPN))?;
            Some((Handshake::Challenge, config))
        }
        Route::Public if attested => match edge.served.read().clone() {
            Some(cert) => {
                // rustls refuses a client whose ALPN offer misses every advertised protocol,
                // so a client that does not offer `http/1.1` gets no ALPN at all.
                let http = hello
                    .alpn()
                    .is_some_and(|mut offered| offered.any(|p| p == b"http/1.1"));
                let config = public_config(cert.clone(), http.then_some(&b"http/1.1"[..]))?;
                Some((Handshake::Public(name, cert), config))
            }
            None => instance,
        },
        _ => instance,
    }
}

/// The Endpoint's listener with its TLS configuration, bound only for a compose that names an
/// upstream.
pub struct Endpoint {
    listener: TcpListener,
    configs: Arc<Configs>,
    runtime: Arc<Runtime>,
    upstream: String,
    callers: Arc<[AppId]>,
}

async fn bind_tcp(addr: SocketAddr) -> Result<TcpListener, Error> {
    TcpListener::bind(addr)
        .await
        .map_err(|e| Error::Socket(format!("{addr}: {e}")))
}

/// Serves the plain-HTTP probe listener for a compose that names an upstream, from before the
/// first attestation, so the host can read why it fails; its address, or `None` without an
/// upstream.
pub async fn serve_probe(
    runtime: Arc<Runtime>,
    addr: SocketAddr,
) -> Result<Option<SocketAddr>, Error> {
    if runtime.config().tls_upstream.is_none() {
        return Ok(None);
    }
    let listener = bind_tcp(addr).await?;
    let local = listener
        .local_addr()
        .map_err(|e| Error::Socket(format!("{addr}: {e}")))?;
    let router = axum::Router::new()
        .route("/leaf", axum::routing::get(leaf_chain))
        .route("/ready", axum::routing::get(ready))
        .with_state(runtime);
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, router).await {
            alpha_client::error!("probe_listener_failed", error = e.kind());
        }
    });
    Ok(Some(local))
}

impl Endpoint {
    /// `None` when the configuration names no upstream. With caller Apps, call it after the
    /// first attestation: the KMS CA comes from its chain.
    pub async fn bind(runtime: Arc<Runtime>, addr: SocketAddr) -> Result<Option<Self>, Error> {
        let config = runtime.config();
        let Some(upstream) = config.tls_upstream.clone() else {
            return Ok(None);
        };
        let callers = config.tls_callers.clone().into();
        let configs = Arc::new(Configs {
            instance: server_config(runtime.clone())?,
            public: config.public.clone().map(|name| (name, Arc::default())),
        });
        Ok(Some(Self {
            listener: bind_tcp(addr).await?,
            configs,
            runtime,
            upstream,
            callers,
        }))
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Accepts until `stop` resolves; no idle timeout, so WebSockets and long polls stay open.
    /// Open connections get at most [`DRAIN`] on a shutdown and are cut on revocation.
    pub async fn serve(self, stop: impl Future<Output = Exit>) {
        let mut stop = std::pin::pin!(stop);
        let issuer = self.configs.public.as_ref().map(|(name, edge)| {
            tokio::spawn(acme::issue_forever(
                edge.clone(),
                name.clone(),
                self.runtime.clone(),
            ))
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
                self.configs.clone(),
                self.runtime.clone(),
                tcp,
                self.upstream.clone(),
                self.callers.clone(),
            ));
        };
        drop(self.listener);
        if let Some(issuer) = issuer {
            issuer.abort();
        }
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

async fn proxy(
    configs: Arc<Configs>,
    runtime: Arc<Runtime>,
    tcp: TcpStream,
    upstream: String,
    callers: Arc<[AppId]>,
) {
    let _ = tcp.set_nodelay(true);
    let handshake = async {
        let start = LazyConfigAcceptor::new(Acceptor::default(), tcp)
            .await
            .ok()?;
        let (picked, config) = select(
            &configs,
            runtime.attested().is_some(),
            &start.client_hello(),
        )?;
        Some((picked, start.into_stream(config).await.ok()?))
    };
    let Ok(Some((picked, mut tls))) = timeout(HANDSHAKE, handshake).await else {
        return;
    };
    let mut head = Vec::new();
    let refused = match picked {
        Handshake::Challenge => true,
        Handshake::Public(name, served) => {
            let Ok(Ok(asks)) = timeout(HANDSHAKE, read_head(&mut tls, &mut head)).await else {
                return;
            };
            if let Some(asked) = &asks {
                let body = match asked {
                    &Asked::Binding(challenge) => {
                        binding_body(&runtime, name, &served, challenge.as_ref())
                    }
                    Asked::Attestation => runtime.attested().and_then(|a| a.attestation.clone()),
                };
                let _ = tls.write_all(&reply(body)).await;
            }
            asks.is_some()
        }
        Handshake::Instance => !admitted(tls.get_ref().1.peer_certificates(), &callers),
    };
    if refused {
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
    if backend.write_all(&head).await.is_err() {
        return;
    }
    let _ = tokio::io::copy_bidirectional(&mut tls, &mut backend).await;
}

fn parse_head(head: &[u8]) -> Head {
    let binding = format!("GET {} ", binding::PATH);
    let attestation = format!("GET {ATTESTATION_PATH} ");
    let challenged = format!("GET {}{CHALLENGE}", binding::PATH);
    if head.starts_with(binding.as_bytes()) {
        return Head::Asked(Asked::Binding(None));
    }
    if head.starts_with(attestation.as_bytes()) {
        return Head::Asked(Asked::Attestation);
    }
    if let Some(rest) = head.strip_prefix(challenged.as_bytes()) {
        let Some((token, tail)) = rest.split_at_checked(rest.len().min(CHALLENGE_LEN)) else {
            return Head::Other;
        };
        if !token
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_')
        {
            return Head::Other;
        }
        // A tail exists only after all CHALLENGE_LEN characters.
        return match tail.first() {
            None => Head::Partial,
            Some(b' ') => BASE64_URL_SAFE_NO_PAD
                .decode(token)
                .ok()
                .and_then(|c| c.try_into().ok())
                .map_or(Head::Other, |c| Head::Asked(Asked::Binding(Some(c)))),
            Some(_) => Head::Other,
        };
    }
    if [binding, attestation, challenged]
        .iter()
        .any(|r| r.as_bytes().starts_with(head))
    {
        Head::Partial
    } else {
        Head::Other
    }
}

/// Reads until the bytes open a request in [`Asked`] or can no longer open one. A request later on
/// a kept-alive connection reaches the upstream, so a verifier asks on a fresh connection.
async fn read_head(
    tls: &mut (impl AsyncRead + Unpin),
    head: &mut Vec<u8>,
) -> std::io::Result<Option<Asked>> {
    let mut buf = [0u8; 64];
    loop {
        match parse_head(head) {
            Head::Asked(asked) => return Ok(Some(asked)),
            Head::Other => return Ok(None),
            Head::Partial => {}
        }
        let n = tls.read(&mut buf).await?;
        let Some(read) = buf.get(..n).filter(|r| !r.is_empty()) else {
            return Ok(None);
        };
        head.extend_from_slice(read);
    }
}

/// The binding of the certificate this connection was served, signed with the runtime key, and
/// the answer to `challenge` when there is one.
fn binding_body(
    runtime: &Runtime,
    name: &str,
    served: &CertifiedKey,
    challenge: Option<&[u8; 32]>,
) -> Option<Vec<u8>> {
    let attested = runtime.attested()?;
    let key = SigningKey::from_pkcs8_der(runtime.tls_private_key()).ok()?;
    let served = served.end_entity_cert().ok()?;
    let mut signed = binding::sign(&key, chain_pem(&attested), name, served).ok()?;
    if let Some(challenge) = challenge {
        signed.answer(&key, challenge).ok()?;
    }
    serde_json::to_vec(&signed).ok()
}

/// A whole HTTP response that closes the connection; any origin may read it, since every byte of
/// it is public and a verifier page runs on another origin.
fn reply(body: Option<Vec<u8>>) -> Vec<u8> {
    let (status, body) = match body {
        Some(body) => ("200 OK", body),
        None => ("503 Service Unavailable", b"{}".to_vec()),
    };
    let mut reply = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nCache-Control: no-store\r\n\
         Access-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    reply.extend_from_slice(&body);
    reply
}

fn chain_pem(attested: &Attested) -> String {
    attested
        .chain_pem
        .iter()
        .map(|pem| format!("{}\n", pem.trim_end()))
        .collect()
}

/// The PEM chain the Endpoint presents now, leaf first; it is public, as every handshake shows it.
async fn leaf_chain(
    State(runtime): State<Arc<Runtime>>,
) -> Result<impl axum::response::IntoResponse, StatusCode> {
    let attested = runtime.attested().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    Ok((
        [(CONTENT_TYPE, "application/pem-certificate-chain")],
        chain_pem(&attested),
    ))
}

/// 200 only while the leaf is current and, with a readiness path, the upstream answers it with a
/// 2xx now. Without a current leaf the 503's body is the closed code of the last attestation's
/// error, never the KMS's message.
async fn ready(State(runtime): State<Arc<Runtime>>) -> (StatusCode, &'static str) {
    if runtime.attested().is_none() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            runtime.attest_error().unwrap_or_default(),
        );
    }
    let config = runtime.config();
    match (&config.tls_upstream, &config.tls_ready) {
        (Some(upstream), Some(path)) if !upstream_answers(upstream, path).await => {
            (StatusCode::SERVICE_UNAVAILABLE, "")
        }
        _ => (StatusCode::OK, ""),
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

    const PUBLIC_NAME: &str = "hello.alphacompute.cc";

    fn signed_by(issuer: &rcgen::Issuer<'_, rcgen::KeyPair>) -> Arc<CertifiedKey> {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new([PUBLIC_NAME.to_owned()])
            .unwrap()
            .signed_by(&key, issuer)
            .unwrap();
        tls::certified(vec![cert.der().clone()], &key.serialize_der()).unwrap()
    }

    /// One full handshake on the public name through `select`: whether the public certificate
    /// was served and the protocol negotiated, or `None` when the handshake fails.
    async fn public_handshake(offered: &[&[u8]]) -> Option<(bool, Option<Vec<u8>>)> {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca = rcgen::CertificateParams::default();
        ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert = ca.self_signed(&ca_key).unwrap();
        let issuer = rcgen::Issuer::new(ca, ca_key);
        let (instance, public) = (signed_by(&issuer), signed_by(&issuer));
        let public_der = public.cert.first().unwrap().clone();
        let edge = Arc::new(Edge::default());
        *edge.served.write() = Some(public);
        let configs = Configs {
            instance: public_config(instance, None).unwrap(),
            public: Some((PUBLIC_NAME.to_owned(), edge)),
        };

        let mut roots = RootCertStore::empty();
        roots.add(ca_cert.der().clone()).unwrap();
        let mut client = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        client.alpn_protocols = offered.iter().map(|p| p.to_vec()).collect();

        let (client_io, server_io) = tokio::io::duplex(1 << 16);
        let server = async {
            let start = LazyConfigAcceptor::new(Acceptor::default(), server_io)
                .await
                .ok()?;
            let (_, config) = select(&configs, true, &start.client_hello())?;
            start.into_stream(config).await.ok()
        };
        let client = tokio_rustls::TlsConnector::from(Arc::new(client)).connect(
            rustls::pki_types::ServerName::try_from(PUBLIC_NAME).unwrap(),
            client_io,
        );
        let (server, client) = tokio::join!(server, client);
        server?;
        let conn = client.ok()?.into_inner().1;
        let served = conn.peer_certificates()?.first()? == &public_der;
        Some((served, conn.alpn_protocol().map(<[u8]>::to_vec)))
    }

    #[tokio::test]
    async fn the_public_name_serves_any_alpn_offer_and_the_leaf_only_on_the_instance_id() {
        let http = Some(b"http/1.1".to_vec());
        assert_eq!(public_handshake(&[]).await, Some((true, None)));
        assert_eq!(public_handshake(&[b"grpc-exp"]).await, Some((true, None)));
        assert_eq!(
            public_handshake(&[b"h2", b"http/1.1"]).await,
            Some((true, http))
        );
        assert_eq!(
            public_handshake(&[b"alphacompute-instance/1", b"http/1.1"]).await,
            Some((false, None))
        );
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

    #[tokio::test]
    async fn only_the_runtime_requests_are_answered_and_other_bytes_reach_the_upstream() {
        let challenge = [7u8; 32];
        let token = BASE64_URL_SAFE_NO_PAD.encode(challenge);
        for (target, asked) in [
            (binding::PATH.to_owned(), Asked::Binding(None)),
            (
                format!("{}?challenge={token}", binding::PATH),
                Asked::Binding(Some(challenge)),
            ),
            (ATTESTATION_PATH.to_owned(), Asked::Attestation),
        ] {
            let mut head = Vec::new();
            let asks = format!("GET {target} HTTP/1.1\r\nHost: a.example\r\n\r\n");
            let answered = read_head(&mut asks.as_bytes(), &mut head).await.unwrap();
            assert_eq!(answered, Some(asked));
        }
        let short = format!(
            "GET {}?challenge={} HTTP/1.1\r\n\r\n",
            binding::PATH,
            &token[1..]
        );
        let long = format!("GET {}?challenge={token}A HTTP/1.1\r\n\r\n", binding::PATH);
        let foreign = format!(
            "GET {}?challenge={} HTTP/1.1\r\n\r\n",
            binding::PATH,
            "+".repeat(43)
        );
        for request in [
            &b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n"[..],
            b"GET /.well-known/alphacompute/bindings HTTP/1.1\r\n\r\n",
            b"POST /.well-known/alphacompute/binding HTTP/1.1\r\n\r\n",
            b"GET /.well-known/alphacompute/binding?other=1 HTTP/1.1\r\n\r\n",
            short.as_bytes(),
            long.as_bytes(),
            foreign.as_bytes(),
            b"GET /.well",
        ] {
            let mut head = Vec::new();
            assert_eq!(read_head(&mut &request[..], &mut head).await.unwrap(), None);
            assert!(request.starts_with(&head) && !head.is_empty());
        }
    }
}
