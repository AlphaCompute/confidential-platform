//! Prometheus families of a service, served as text on `127.0.0.1:9464/metrics`. Labels come
//! from the route template and the response status only, never from a request's content.

use std::sync::LazyLock;
use std::time::Instant;

use axum::Router;
use axum::extract::{MatchedPath, Request};
use axum::middleware::Next;
use axum::response::Response;
use axum::routing::get;
use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::histogram::Histogram;
use prometheus_client::registry::Registry;
use tokio::net::TcpListener;

/// Loopback only: the runtime in the same pod or a local run reads it.
pub const LISTEN: (std::net::Ipv4Addr, u16) = (std::net::Ipv4Addr::LOCALHOST, 9464);

const BUCKETS: [f64; 10] = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 10.0];

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct RouteStatus {
    route: String,
    status: u16,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct Route {
    route: String,
}

struct Metrics {
    registry: Registry,
    requests: Family<RouteStatus, Counter>,
    durations: Family<Route, Histogram>,
}

static METRICS: LazyLock<Metrics> = LazyLock::new(|| {
    let requests = Family::<RouteStatus, Counter>::default();
    let durations = Family::<Route, Histogram>::new_with_constructor(
        (|| Histogram::new(BUCKETS)) as fn() -> Histogram,
    );
    let mut registry = Registry::with_prefix("alpha");
    registry.register("http_requests", "HTTP responses", requests.clone());
    registry.register(
        "http_request_duration_seconds",
        "Time to the response head",
        durations.clone(),
    );
    Metrics {
        registry,
        requests,
        durations,
    }
});

/// Counts every response of `router` by route template and status. A request that matches no
/// route counts as `other`, so a probed path never becomes a series.
pub fn track(router: Router) -> Router {
    router.layer(axum::middleware::from_fn(record))
}

async fn record(request: Request, next: Next) -> Response {
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map_or("other", MatchedPath::as_str)
        .to_owned();
    let started = Instant::now();
    let response = next.run(request).await;
    METRICS
        .durations
        .get_or_create(&Route {
            route: route.clone(),
        })
        .observe(started.elapsed().as_secs_f64());
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

/// Binds [`LISTEN`] and serves `/metrics` there for the life of the process.
pub async fn spawn() -> std::io::Result<()> {
    let listener = TcpListener::bind(LISTEN).await?;
    let router = Router::new().route("/metrics", get(|| async { text() }));
    tokio::spawn(async move { axum::serve(listener, router).await });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use tower::ServiceExt;

    #[tokio::test]
    async fn a_response_counts_under_its_route_template_not_its_path() {
        let app = track(Router::new().route("/v1/apps/{id}", get(|| async { "" })));
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
