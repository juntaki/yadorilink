//! Minimal standalone relay server binary (task 4.2). Content-blind:
//! forwards opaque encrypted WireGuard datagrams by destination public key.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use yadorilink_transport::relay_server::{RelayMetrics, RelayRuntime};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let addr = std::env::var("YADORILINK_RELAY_ADDR").unwrap_or_else(|_| "0.0.0.0:7444".into());
    let listener = TcpListener::bind(&addr).await?;
    tracing::info!(addr, "yadorilink-relay listening");
    let runtime = RelayRuntime::new();

    if let Ok(metrics_addr) = std::env::var("YADORILINK_RELAY_METRICS_ADDR") {
        let metrics_listener = TcpListener::bind(&metrics_addr).await?;
        let metrics = runtime.metrics();
        tracing::info!(addr = metrics_addr, "yadorilink-relay metrics listening");
        tokio::spawn(serve_metrics(metrics_listener, metrics));
    }

    runtime.serve(listener).await?;
    Ok(())
}

async fn serve_metrics(listener: TcpListener, metrics: RelayMetrics) {
    loop {
        let Ok((mut stream, peer_addr)) = listener.accept().await else {
            continue;
        };
        let metrics = metrics.clone();
        tokio::spawn(async move {
            let mut request = [0u8; 1024];
            let Ok(n) = stream.read(&mut request).await else { return };
            let first_line = std::str::from_utf8(&request[..n])
                .ok()
                .and_then(|req| req.lines().next())
                .unwrap_or("");
            let (status, body) = if first_line.starts_with("GET /metrics ") {
                ("200 OK", metrics.render_openmetrics())
            } else {
                ("404 Not Found", "not found\n".to_string())
            };
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            if stream.write_all(response.as_bytes()).await.is_err() {
                tracing::debug!(%peer_addr, "failed to write relay metrics response");
            }
        });
    }
}
