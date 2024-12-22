use std::net::SocketAddr;
use std::sync::Arc;

use hyper_util::rt::TokioExecutor;
use hyper_util::server::conn::auto::Builder as HttpConnectionBuilder;
use hyper_util::service::TowerToHyperService;
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::server::NamedService;
use tonic::transport::Server;
use tracing::{info, Level};

use postel::{load_certs, load_private_key, serve_http_with_shutdown};

// Define a service for demonstration purposes
pub struct GreeterService;

impl NamedService for GreeterService {
    const NAME: &'static str = "greeter";
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Initialize logging
    tracing_subscriber::fmt().with_max_level(Level::INFO).init();

    // Configure server address
    let addr = SocketAddr::from(([127, 0, 0, 1], 8443));

    // Set up gRPC health service
    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter.set_serving::<GreeterService>().await;

    // Set up TCP listener
    let listener = TcpListener::bind(addr).await?;
    info!("Server listening on https://{}", addr);
    let incoming = TcpListenerStream::new(listener);

    // Create HTTP connection builder
    let builder = HttpConnectionBuilder::new(TokioExecutor::new());

    // Set up TLS configuration
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let certs = load_certs("examples/sample.pem")?;
    let key = load_private_key("examples/sample.rsa")?;

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    // Configure ALPN protocols - required for gRPC
    config.alpn_protocols = vec![b"h2".to_vec()];
    let tls_config = Arc::new(config);

    // Create a shutdown signal
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

    // Start server in the background
    let server = tokio::spawn(async move {
        info!("Server starting up...");

        let svc = Server::builder()
            .add_service(health_service)
            .into_service()
            .into_axum_router();

        let hyper_svc = TowerToHyperService::new(svc);

        serve_http_with_shutdown(
            hyper_svc,
            incoming,
            builder,
            Some(tls_config),
            Some(async {
                shutdown_rx.await.ok();
                info!("Shutdown signal received");
            }),
        )
        .await
        .expect("Server failed unexpectedly");
    });

    // Keep the main thread running until Ctrl+C
    tokio::signal::ctrl_c().await?;
    info!("Initiating graceful shutdown");
    let _ = shutdown_tx.send(());

    // Wait for server to shutdown
    server.await?;

    Ok(())
}
