use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hyper_util::rt::TokioExecutor;
use hyper_util::server::conn::auto::Builder as HttpConnectionBuilder;
use hyper_util::service::TowerToHyperService;
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::server::NamedService;
use tonic::transport::Server;
use tonic::transport::{Certificate, Channel, ClientTlsConfig};
use tonic_health::pb::health_client::HealthClient;
use tower::ServiceExt;

use postel::{load_certs, load_private_key, serve_http_with_shutdown};

pub struct TestService;

impl NamedService for TestService {
    const NAME: &'static str = "test.service";
}

async fn setup_test_server(
) -> Result<(SocketAddr, tokio::sync::oneshot::Sender<()>), Box<dyn std::error::Error + Send + Sync>>
{
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");
    // Setup server with random port
    let addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let listener = TcpListener::bind(addr).await?;
    let server_addr = listener.local_addr()?;
    let incoming = TcpListenerStream::new(listener);

    // Setup TLS
    let certs = load_certs("examples/sample.pem")?;
    let key = load_private_key("examples/sample.rsa")?;

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    config.alpn_protocols = vec![b"h2".to_vec()];
    let tls_config = Arc::new(config);

    // Setup gRPC services
    let reflection_server = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(tonic_health::pb::FILE_DESCRIPTOR_SET)
        .build_v1alpha()?;

    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter.set_serving::<TestService>().await;

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

    // Build and start server
    let builder = HttpConnectionBuilder::new(TokioExecutor::new());

    let svc = Server::builder()
        .add_service(health_service)
        .add_service(reflection_server)
        .into_service()
        .into_axum_router()
        .into_service()
        .boxed_clone();

    let hyper_svc = TowerToHyperService::new(svc);

    tokio::spawn(async move {
        serve_http_with_shutdown(
            hyper_svc,
            incoming,
            builder,
            Some(tls_config),
            Some(async {
                shutdown_rx.await.ok();
            }),
        )
        .await
        .expect("Server failed unexpectedly");
    });

    // Give server a moment to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    Ok((server_addr, shutdown_tx))
}

async fn setup_test_client(
    addr: SocketAddr,
) -> Result<HealthClient<Channel>, Box<dyn std::error::Error + Send + Sync>> {
    let pem = std::fs::read_to_string("examples/sample.pem")?;
    let ca = Certificate::from_pem(pem);

    let tls_config = ClientTlsConfig::new()
        .ca_certificate(ca)
        .domain_name("localhost");

    let channel = Channel::builder(format!("https://{}", addr).parse()?)
        .tls_config(tls_config)?
        .connect()
        .await?;

    Ok(HealthClient::new(channel))
}

#[tokio::test]
async fn test_grpc_health_check() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (addr, shutdown_tx) = setup_test_server().await?;
    let mut client = setup_test_client(addr).await?;

    // Test service check
    let response = client
        .check(tonic_health::pb::HealthCheckRequest {
            service: "test.service".to_string(),
        })
        .await?;

    assert_eq!(
        response.into_inner().status(),
        tonic_health::pb::health_check_response::ServingStatus::Serving
    );

    // Clean shutdown
    shutdown_tx.send(()).unwrap();

    Ok(())
}
