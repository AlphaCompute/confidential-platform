//! Prometheus families of a service, served as text on `127.0.0.1:9464/metrics`. Labels come
//! from the route template and the response status only, never from a request's content.

use std::collections::BTreeMap;
use std::fmt::Write;

use axum::Router;
use axum::extract::{MatchedPath, Request};
use axum::middleware::Next;
use axum::response::Response;
use axum::routing::get;
use parking_lot::Mutex;
use tokio::net::TcpListener;

static REQUESTS: Mutex<BTreeMap<(String, u16), u64>> = Mutex::new(BTreeMap::new());

async fn record(request: Request, next: Next) -> Response {
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map_or("other", MatchedPath::as_str)
        .to_owned();
    let response = next.run(request).await;
    let mut requests = REQUESTS.lock();
    let count = requests
        .entry((route, response.status().as_u16()))
        .or_default();
    *count = count.saturating_add(1);
    response
}

/// Route templates come from code and hold no `"`, `\` or newline, so they need no escaping.
fn text() -> String {
    let mut text = String::from(
        "# HELP alpha_http_requests_total HTTP responses\n\
         # TYPE alpha_http_requests_total counter\n",
    );
    for ((route, status), count) in REQUESTS.lock().iter() {
        let _ = writeln!(
            text,
            "alpha_http_requests_total{{route=\"{route}\",status=\"{status}\"}} {count}"
        );
    }
    text
}

/// Serves `/metrics` on `127.0.0.1:9464` for the life of the process and returns `router`
/// counting every response by route template and status. A request that matches no route counts
/// as `other`, so a probed path never becomes a series.
pub async fn serve(router: Router) -> std::io::Result<Router> {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 9464)).await?;
    let metrics = Router::new().route("/metrics", get(|| async { text() }));
    tokio::spawn(async move { axum::serve(listener, metrics).await });
    Ok(router.layer(axum::middleware::from_fn(record)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use tower::ServiceExt;

    #[tokio::test]
    async fn a_response_counts_under_its_route_template_not_its_path() {
        let app = Router::new()
            .route("/v1/apps/{id}", get(|| async { "" }))
            .layer(axum::middleware::from_fn(record));
        for uri in ["/v1/apps/0192f1d2", "/v1/apps/0192f1d3", "/probe/secret"] {
            let request = Request::builder().uri(uri).body(Body::empty()).unwrap();
            app.clone().oneshot(request).await.unwrap();
        }
        let text = text();
        assert!(
            text.contains(r#"alpha_http_requests_total{route="/v1/apps/{id}",status="200"} 2"#),
            "{text}"
        );
        assert!(
            text.contains(r#"alpha_http_requests_total{route="other",status="404"} 1"#),
            "{text}"
        );
        assert!(
            !text.contains("0192f1d2") && !text.contains("/probe"),
            "{text}"
        );
    }
}
