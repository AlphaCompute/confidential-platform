//! Client for the three routes `alpha-runtime` serves on `/run/alpha/runtime.sock`: the
//! Instance's identity, a named Secret's bytes, and a liveness probe. No route needs a header —
//! access is the right to open the socket, over plain HTTP/1.1.

use std::path::PathBuf;

use alpha_attest::AttestationResult;
use alpha_core::{AppId, ComposeHash, OrgId};
use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes;
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use tokio::net::UnixStream;
use zeroize::Zeroizing;

use crate::{Error, decode};

pub const SOCKET_PATH: &str = "/run/alpha/runtime.sock";

/// A secret name as it becomes a path segment: no separator, no traversal.
fn valid_secret_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// A client for one `alpha-runtime` unix socket, usually `/run/alpha/runtime.sock`.
pub struct RuntimeSocket {
    path: PathBuf,
}

impl RuntimeSocket {
    pub fn at(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    async fn get(&self, route: &str) -> Result<(StatusCode, Bytes), Error> {
        let connect = |e: std::io::Error| Error::Connect(format!("{}: {e}", self.path.display()));
        let stream = UnixStream::connect(&self.path).await.map_err(connect)?;
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|e| Error::Connect(format!("{}: {e}", self.path.display())))?;
        tokio::spawn(conn);
        let request = Request::builder()
            .method(Method::GET)
            .uri(route)
            .header(hyper::header::HOST, "runtime")
            .body(Empty::<Bytes>::new())
            .map_err(|e| Error::Invalid(format!("request: {e}")))?;
        let response = sender
            .send_request(request)
            .await
            .map_err(|e| Error::Connect(format!("{}: {e}", self.path.display())))?;
        let status = response.status();
        let body = response
            .into_body()
            .collect()
            .await
            .map_err(|e| Error::Invalid(format!("body: {e}")))?
            .to_bytes();
        Ok((status, body))
    }

    /// The Instance's identity and its current TLS key and chain.
    pub async fn identity(&self) -> Result<RuntimeIdentity, Error> {
        #[derive(Deserialize)]
        struct Wire {
            app_id: AppId,
            org_id: OrgId,
            compose_hash: ComposeHash,
            certificate_chain: Vec<String>,
            tls_private_key: String,
            attestation_result: AttestationResult,
        }

        let (status, body) = self.get("/v1/identity").await?;
        if !status.is_success() {
            return Err(crate::api_error("runtime", status, &body));
        }
        let wire: Wire =
            serde_json::from_slice(&body).map_err(|e| Error::Invalid(format!("identity: {e}")))?;
        Ok(RuntimeIdentity {
            app_id: wire.app_id,
            org_id: wire.org_id,
            compose_hash: wire.compose_hash,
            certificate_chain: wire.certificate_chain.join("\n"),
            tls_private_key: Zeroizing::new(decode("tls_private_key", &wire.tls_private_key)?),
            attestation_result: wire.attestation_result,
        })
    }

    /// A named Secret's bytes. `name` becomes a path segment, so it is checked before any
    /// request is made.
    pub async fn secret(&self, name: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
        if !valid_secret_name(name) {
            return Err(Error::Invalid(format!("secret name {name:?} is invalid")));
        }
        let (status, body) = self.get(&format!("/v1/secrets/{name}")).await?;
        if !status.is_success() {
            return Err(crate::api_error("runtime", status, &body));
        }
        let secret: crate::Secret =
            serde_json::from_slice(&body).map_err(|e| Error::Invalid(format!("secret: {e}")))?;
        decode("value", &secret.value).map(Zeroizing::new)
    }

    pub async fn healthz(&self) -> Result<RuntimeHealth, Error> {
        let (status, body) = self.get("/healthz").await?;
        if !status.is_success() {
            return Err(crate::api_error("runtime", status, &body));
        }
        serde_json::from_slice(&body).map_err(|e| Error::Invalid(format!("healthz: {e}")))
    }
}

impl Default for RuntimeSocket {
    fn default() -> Self {
        Self::at(SOCKET_PATH)
    }
}

/// What `/v1/identity` serves: who this Instance is, and the TLS material to serve its Endpoint.
pub struct RuntimeIdentity {
    pub app_id: AppId,
    pub org_id: OrgId,
    pub compose_hash: ComposeHash,
    /// PEM, leaf first, as the runtime serves it.
    pub certificate_chain: String,
    pub tls_private_key: Zeroizing<Vec<u8>>,
    pub attestation_result: AttestationResult,
}

impl std::fmt::Debug for RuntimeIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuntimeIdentity")
            .field("app_id", &self.app_id)
            .field("org_id", &self.org_id)
            .field("compose_hash", &self.compose_hash)
            .field("certificate_chain", &self.certificate_chain)
            .field("tls_private_key", &"<redacted>")
            .field("attestation_result", &self.attestation_result)
            .finish()
    }
}

#[derive(Debug, Deserialize)]
pub struct RuntimeHealth {
    pub attested: bool,
    pub cert_not_after: Option<String>,
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;

    use super::*;

    /// Short: a unix socket path is capped at 104 bytes on macOS.
    fn socket_path() -> PathBuf {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("ac{:x}-{n}.sock", std::process::id()))
    }

    /// Binds a fresh socket, accepts one connection, answers with `status` and `body` once.
    fn canned(status: u16, body: &'static str) -> PathBuf {
        let path = socket_path();
        let listener = UnixListener::bind(&path).unwrap();
        tokio::spawn(async move {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).await;
            let reply = format!(
                "HTTP/1.1 {status} x\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(reply.as_bytes()).await;
            let _ = stream.shutdown().await;
        });
        path
    }

    fn api_code(err: Error) -> String {
        match err {
            Error::Api(e) => e.code,
            other => panic!("expected Error::Api, got {other}"),
        }
    }

    #[tokio::test]
    async fn not_attested_surfaces_as_an_api_error_with_the_runtimes_code() {
        let body =
            r#"{"error":{"code":"not_attested","message":"not attested","request_id":"r1"}}"#;
        let path = canned(503, body);
        let err = RuntimeSocket::at(path).identity().await.unwrap_err();
        assert_eq!(api_code(err), "not_attested");
    }

    #[tokio::test]
    async fn a_missing_secret_surfaces_as_an_api_error_with_the_runtimes_code() {
        let body = r#"{"error":{"code":"not_found","message":"no such secret","request_id":"r2"}}"#;
        let path = canned(404, body);
        let err = RuntimeSocket::at(path).secret("x").await.unwrap_err();
        assert_eq!(api_code(err), "not_found");
    }

    #[tokio::test]
    async fn a_missing_socket_is_a_connect_error_naming_the_path_on_every_route() {
        let path = socket_path();
        let client = RuntimeSocket::at(&path);
        let want = path.display().to_string();
        let assert_connect = |err: Error| match err {
            Error::Connect(msg) => assert!(msg.contains(&want), "{msg}"),
            other => panic!("expected Error::Connect, got {other}"),
        };
        assert_connect(client.identity().await.unwrap_err());
        assert_connect(client.secret("x").await.unwrap_err());
        assert_connect(client.healthz().await.unwrap_err());
    }

    // Nothing is listening at this path in either test below: a connect attempt would surface
    // as `Error::Connect`, not `Error::Invalid` — that is how each proves the client never tries.

    #[tokio::test]
    async fn a_secret_name_with_a_path_separator_is_refused_before_any_request() {
        let client = RuntimeSocket::at(socket_path());
        match client.secret("../x").await {
            Err(Error::Invalid(_)) => {}
            other => panic!("expected Error::Invalid, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn an_empty_secret_name_is_refused_before_any_request() {
        let client = RuntimeSocket::at(socket_path());
        match client.secret("").await {
            Err(Error::Invalid(_)) => {}
            other => panic!("expected Error::Invalid, got {other:?}"),
        }
    }
}
