//! The inference front on loopback for the App's own containers: plain HTTP in, and out over
//! mTLS with the current Instance leaf to a front pinned to the KMS CA and its Revisions, so a
//! stock OpenAI client needs only a base URL.

use std::net::SocketAddr;
use std::sync::Arc;

use alpha_client::tls::{self, Pin};
use axum::body::{Body, HttpBody};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderName, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::json;
use tokio::net::TcpListener;
use tokio::time::timeout;

use crate::proxy::{CONNECT, CurrentLeaf, DRAIN};
use crate::{Error, Exit, Runtime};

/// Loopback only: every container of the pod shares the network namespace, nothing else does.
pub const ADDR: ([u8; 4], u16) = ([127, 0, 0, 1], 8090);

/// RFC 9110 §7.6.1, and the App's own credentials: the front authenticates the leaf.
const DROPPED: [HeaderName; 7] = [
    header::AUTHORIZATION,
    header::HOST,
    header::CONNECTION,
    HeaderName::from_static("keep-alive"),
    header::TE,
    header::TRANSFER_ENCODING,
    header::UPGRADE,
];

struct Front {
    runtime: Arc<Runtime>,
    url: String,
    client: reqwest::Client,
}

pub struct Forwarder {
    listener: TcpListener,
    router: axum::Router,
}

impl Forwarder {
    /// `None` when the configuration names no front. Call it after the first attestation: the
    /// KMS CA comes from its chain.
    pub async fn bind(runtime: Arc<Runtime>, addr: SocketAddr) -> Result<Option<Self>, Error> {
        let Some(front) = runtime.config().inference.clone() else {
            return Ok(None);
        };
        let ca = runtime
            .last()
            .and_then(|a| a.certified.cert.last().cloned())
            .ok_or(Error::NotAttested)?;
        let config = tls::renewing_client_config(
            Pin::CaAndInstanceRevisions(ca, front.revisions, None),
            Arc::new(CurrentLeaf(runtime.clone())),
            runtime.time.clone(),
        )?;
        // No overall timeout: the front bounds a completion itself, and any shorter bound here
        // would cut a long stream.
        let client = reqwest::Client::builder()
            .tls_backend_preconfigured(config)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT)
            .build()
            .map_err(|e| Error::Socket(format!("inference client: {e}")))?;
        let router = axum::Router::new()
            .fallback(forward)
            .with_state(Arc::new(Front {
                runtime,
                url: front.url,
                client,
            }));
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| Error::Socket(format!("{addr}: {e}")))?;
        Ok(Some(Self { listener, router }))
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Serves until `stop` resolves; a drain gives open requests at most [`DRAIN`], any other
    /// exit cuts them.
    pub async fn serve(self, stop: impl Future<Output = Exit>) {
        let (drain, drained) = tokio::sync::oneshot::channel::<()>();
        let mut server = tokio::spawn(
            axum::serve(self.listener, self.router)
                .with_graceful_shutdown(async move {
                    let _ = drained.await;
                })
                .into_future(),
        );
        if stop.await == Exit::Drained {
            let _ = drain.send(());
            let _ = timeout(DRAIN, &mut server).await;
        }
        server.abort();
    }
}

/// OpenAI's error shape, which every OpenAI SDK reads.
fn refused(status: StatusCode, kind: &str, code: &str, message: &str) -> Response {
    let body = json!({ "error": { "message": message, "type": kind, "code": code } });
    (status, axum::Json(body)).into_response()
}

fn strip(headers: &mut HeaderMap) {
    for name in &DROPPED {
        headers.remove(name);
    }
}

async fn forward(State(front): State<Arc<Front>>, request: Request) -> Response {
    // Judged after the URL parser removes dot segments, so `/v1/../x` cannot leave `/v1/`.
    let Some(url) = request
        .uri()
        .path_and_query()
        .and_then(|target| reqwest::Url::parse(&format!("{}{target}", front.url)).ok())
        .filter(|url| url.path().starts_with("/v1/"))
    else {
        return refused(
            StatusCode::NOT_FOUND,
            "invalid_request_error",
            "not_found",
            "only /v1/ is forwarded to the inference front",
        );
    };
    if front.runtime.attested().is_none() {
        return refused(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "not_attested",
            "the runtime holds no valid Instance certificate",
        );
    }
    let (mut parts, body) = request.into_parts();
    strip(&mut parts.headers);
    let mut sent = front
        .client
        .request(parts.method, url)
        .headers(parts.headers);
    // A streamed body goes out chunked, which a GET must not carry.
    if body.size_hint().exact() != Some(0) {
        sent = sent.body(reqwest::Body::wrap_stream(body.into_data_stream()));
    }
    let Ok(answer) = sent.send().await else {
        alpha_client::warn!("inference_front_unreachable");
        return refused(
            StatusCode::BAD_GATEWAY,
            "server_error",
            "front_unreachable",
            "the inference front could not be reached or did not prove its Revision",
        );
    };
    let status = answer.status();
    let mut headers = answer.headers().clone();
    strip(&mut headers);
    (status, headers, Body::from_stream(answer.bytes_stream())).into_response()
}
