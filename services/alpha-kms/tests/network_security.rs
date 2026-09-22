//! Exercise the actual pinned client against bounded adversarial TLS responses.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod common;
use axum::{
    Router,
    body::Body,
    http::{Response, StatusCode},
    routing::get,
};
use common::*;
use std::time::{Duration, Instant};

#[tokio::test]
async fn pinned_client_refuses_redirect_oversized_body_and_stalled_provider() {
    let Some(h) = harness().await else {
        return;
    };
    for scenario in ["redirect", "oversized", "stall"] {
        let router = Router::new().route(
            "/ready",
            get(move || async move {
                match scenario {
                    "redirect" => Response::builder()
                        .status(StatusCode::TEMPORARY_REDIRECT)
                        .header("Location", "http://127.0.0.1:1/stolen")
                        .body(Body::empty())
                        .unwrap(),
                    "oversized" => Response::new(Body::from(vec![b' '; 2 * 1024 * 1024 + 1])),
                    _ => {
                        tokio::time::sleep(Duration::from_secs(60)).await;
                        Response::new(Body::empty())
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("https://{}", listener.local_addr().unwrap());
        let cert = h.node.server_cert.clone();
        let server = tokio::spawn(alpha_kms::tls::serve(
            listener,
            cert,
            router,
            std::future::pending(),
        ));
        let started = Instant::now();
        let refused = spki_client(&url, &h.node).ready().await.unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(18));
        if scenario == "redirect" {
            assert!(
                refused.to_string().contains("307"),
                "redirect was followed: {refused}"
            );
        }
        if scenario == "oversized" {
            assert!(refused.to_string().contains("limit"));
        }
        server.abort();
    }
}
