//! Readiness for an orchestrator that probes from outside the pod VM: the kubelet runs probes on
//! the node, and a confidential pod's agent policy refuses exec, so neither the upstream's
//! loopback port nor an exec probe is reachable. With `ALPHACOMPUTE_TLS_UPSTREAM_READY`, plain
//! HTTP on [`READY_PORT`] answers `GET /ready` 200 only while this runtime holds a current leaf
//! and the upstream answers that path 2xx right now, else 503, with an empty body either way.
//! Nothing else is served there and nothing of the upstream's answer is relayed.

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::Error;

pub const READY_PORT: u16 = 8444;
pub const READY_ENV: &str = "ALPHACOMPUTE_TLS_UPSTREAM_READY";
/// A probe's whole exchange with the upstream, connection included.
pub const CHECK_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_PATH: usize = 256;

/// `ALPHACOMPUTE_TLS_UPSTREAM_READY`: the upstream's own readiness path, such as vLLM's
/// `/health`, which answers 200 only once the model is loaded. It needs
/// `ALPHACOMPUTE_TLS_UPSTREAM`; unset, no readiness listener.
pub fn parse_ready(
    text: Option<&str>,
    tls_upstream: Option<&str>,
) -> Result<Option<String>, Error> {
    let Some(text) = text else {
        return Ok(None);
    };
    let refused = |m: &str| Error::Config(format!("ALPHACOMPUTE_TLS_UPSTREAM_READY: {m}"));
    if tls_upstream.is_none() {
        return Err(refused("set without ALPHACOMPUTE_TLS_UPSTREAM"));
    }
    if !text.starts_with('/')
        || text.len() > MAX_PATH
        || !text.bytes().all(|b| b.is_ascii_graphic())
    {
        return Err(refused(
            "must be an HTTP path: a leading /, printable ASCII, no spaces, at most 256 bytes",
        ));
    }
    Ok(Some(text.to_owned()))
}

/// Whether `GET path` on `upstream` answers with a 2xx status line within `timeout`.
pub async fn upstream_answers(upstream: &str, path: &str, timeout: Duration) -> bool {
    let probe = async {
        let mut tcp = TcpStream::connect(upstream).await.ok()?;
        let request =
            format!("GET {path} HTTP/1.1\r\nHost: {upstream}\r\nConnection: close\r\n\r\n");
        tcp.write_all(request.as_bytes()).await.ok()?;
        // "HTTP/1.1 200": the version and the status's first digit are all that is read.
        let mut head = [0u8; 12];
        tcp.read_exact(&mut head).await.ok()?;
        Some(head)
    };
    match tokio::time::timeout(timeout, probe).await {
        Ok(Some(head)) => head.starts_with(b"HTTP/1.1 2") || head.starts_with(b"HTTP/1.0 2"),
        _ => false,
    }
}

/// Whether this runtime holds a leaf that has not expired.
pub type Attested = Arc<dyn Fn() -> bool + Send + Sync>;

#[derive(Clone)]
struct Ready {
    attested: Attested,
    upstream: Arc<str>,
    path: Arc<str>,
    timeout: Duration,
}

async fn ready(State(ready): State<Ready>) -> StatusCode {
    if (ready.attested)() && upstream_answers(&ready.upstream, &ready.path, ready.timeout).await {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

/// `GET /ready` alone.
pub fn router(attested: Attested, upstream: &str, path: &str, timeout: Duration) -> Router {
    Router::new().route("/ready", get(ready)).with_state(Ready {
        attested,
        upstream: upstream.into(),
        path: path.into(),
        timeout,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use tokio::net::TcpListener;

    use super::*;

    /// A raw upstream on loopback answering every connection with `reply` (after `delay`),
    /// counting the connections.
    async fn upstream(reply: &'static str, delay: Duration) -> (String, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let hits = Arc::new(AtomicUsize::new(0));
        let counted = hits.clone();
        tokio::spawn(async move {
            while let Ok((mut tcp, _)) = listener.accept().await {
                counted.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = tcp.read(&mut buf).await;
                    tokio::time::sleep(delay).await;
                    let _ = tcp.write_all(reply.as_bytes()).await;
                });
            }
        });
        (addr, hits)
    }

    const OK: &str = "HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n";
    const LOADING: &str = "HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\n\r\n";

    #[test]
    fn the_ready_path_is_an_http_path_and_needs_an_upstream() {
        assert_eq!(parse_ready(None, None).unwrap(), None);
        assert_eq!(
            parse_ready(Some("/health"), Some("127.0.0.1:8000")).unwrap(),
            Some("/health".to_owned())
        );
        let long = format!("/{}", "a".repeat(MAX_PATH));
        for (bad, upstream) in [
            ("/health", None),
            ("health", Some("127.0.0.1:8000")),
            ("/he alth", Some("127.0.0.1:8000")),
            ("/health\r\nX: y", Some("127.0.0.1:8000")),
            (long.as_str(), Some("127.0.0.1:8000")),
        ] {
            let Err(Error::Config(m)) = parse_ready(Some(bad), upstream) else {
                panic!("{bad:?} was accepted");
            };
            assert!(m.starts_with("ALPHACOMPUTE_TLS_UPSTREAM_READY:"), "{m}");
        }
    }

    #[tokio::test]
    async fn only_a_2xx_within_the_timeout_is_an_answer() {
        let short = Duration::from_millis(200);
        let (ok, _) = upstream(OK, Duration::ZERO).await;
        assert!(upstream_answers(&ok, "/health", short).await);
        let (loading, _) = upstream(LOADING, Duration::ZERO).await;
        assert!(!upstream_answers(&loading, "/health", short).await);
        let (garbage, _) = upstream("SSH-2.0-x\r\n", Duration::ZERO).await;
        assert!(!upstream_answers(&garbage, "/health", short).await);
        let (slow, _) = upstream(OK, Duration::from_secs(2)).await;
        assert!(!upstream_answers(&slow, "/health", short).await);
        let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = closed.local_addr().unwrap().to_string();
        drop(closed);
        assert!(!upstream_answers(&addr, "/health", short).await);
    }

    async fn probe(router: Router) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        let mut tcp = TcpStream::connect(addr).await.unwrap();
        tcp.write_all(b"GET /ready HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut answer = String::new();
        tcp.read_to_string(&mut answer).await.unwrap();
        answer
            .get(9..12)
            .and_then(|code| code.parse().ok())
            .unwrap()
    }

    /// Ready only while attested and the upstream answers; an expired leaf is not ready
    /// without the upstream even being asked.
    #[tokio::test]
    async fn ready_needs_a_current_leaf_and_an_answering_upstream() {
        let timeout = Duration::from_millis(200);
        let leaf = Arc::new(AtomicBool::new(true));
        let attested: Attested = {
            let leaf = leaf.clone();
            Arc::new(move || leaf.load(Ordering::SeqCst))
        };
        let (ok, hits) = upstream(OK, Duration::ZERO).await;
        assert_eq!(
            probe(router(attested.clone(), &ok, "/health", timeout)).await,
            200
        );
        let (loading, _) = upstream(LOADING, Duration::ZERO).await;
        assert_eq!(
            probe(router(attested.clone(), &loading, "/health", timeout)).await,
            503
        );
        leaf.store(false, Ordering::SeqCst);
        assert_eq!(probe(router(attested, &ok, "/health", timeout)).await, 503);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }
}
