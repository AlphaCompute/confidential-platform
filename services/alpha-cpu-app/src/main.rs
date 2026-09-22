#[tokio::main]
async fn main() -> Result<(), String> {
    let socket = std::env::var("ALPHACOMPUTE_RUNTIME_SOCKET")
        .unwrap_or_else(|_| "/run/alpha/runtime.sock".into());
    // Compose starts independent services concurrently; wait for runtime attestation
    // within a bounded startup window without serving an unverified endpoint.
    let app = tokio::time::timeout(std::time::Duration::from_secs(120), async {
        loop {
            if let Ok(app) =
                alpha_cpu_app::Application::connect(std::path::Path::new(&socket)).await
            {
                break app;
            }
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
    })
    .await
    .map_err(|_| "runtime authorization unavailable at startup")?;
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8443")
        .await
        .map_err(|e| e.to_string())?;
    app.serve(listener, async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await
}
