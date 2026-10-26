//! Prometheus families of a service, served as text on `127.0.0.1:9464/metrics`. Labels come
//! from the route template and the response status only, never from a request's content.

use std::sync::LazyLock;

use axum::Router;
use axum::extract::{MatchedPath, Request};
use axum::middleware::Next;
use axum::response::Response;
use axum::routing::get;
use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::registry::Registry;
use tokio::net::TcpListener;

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct RouteStatus {
    route: String,
    status: u16,
}

struct Metrics {
    registry: Registry,
    requests: Family<RouteStatus, Counter>,
}

static METRICS: LazyLock<Metrics> = LazyLock::new(|| {
    let requests = Family::<RouteStatus, Counter>::default();
    let mut registry = Registry::with_prefix("alpha");
    registry.register("http_requests", "HTTP responses", requests.clone());
    Metrics { registry, requests }
});

async fn record(request: Request, next: Next) -> Response {
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map_or("other", MatchedPath::as_str)
        .to_owned();
    let response = next.run(request).await;
    METRICS
        .requests
        .get_or_create(&RouteStatus {
            route,
            status: response.status().as_u16(),
        })
        .inc();
    response
}

fn text() -> String {
    let mut text = String::new();
    // Writing to a String fails only on a label encoder error, which the derived sets lack.
    let _ = prometheus_client::encoding::text::encode(&mut text, &METRICS.registry);
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
