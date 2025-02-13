use std::sync::Arc;
use std::time::{Duration, Instant};
use std::net::SocketAddr;

use bytes::Bytes;
use http::{Request, Response, Uri};
use http_body_util::{BodyExt, Empty, Full, Either};
use hyper::body::Incoming;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::{
    client::legacy::Client,
    rt::{TokioExecutor, TokioTimer},
    server::conn::auto::Builder as HttpConnectionBuilder,
    service::TowerToHyperService,
};
use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use rustls::{
    crypto::aws_lc_rs::Ticketer,
    pki_types::{CertificateDer, PrivatePkcs8KeyDer},
    server::ServerSessionMemoryCache,
    ClientConfig, RootCertStore, ServerConfig,
};
use tokio::net::TcpSocket;
use tokio::sync::oneshot;
use tokio_stream::wrappers::TcpListenerStream;
use tower::Service;
use tracing::{info, error};

// Stress test configuration
#[derive(Clone)]
struct StressConfig {
    duration: Duration,
    concurrent_clients: usize,
    request_types: Vec<RequestType>,
    payload_sizes: Vec<usize>,
}

#[derive(Clone)]
enum RequestType {
    Get,
    Post,
}

struct StressResults {
    total_requests: usize,
    successful_requests: usize,
    failed_requests: usize,
    total_bytes: usize,
    min_latency: Duration,
    max_latency: Duration,
    avg_latency: Duration,
    throughput_mbps: f64,
}

// Server setup code
async fn setup_optimized_listener() -> std::io::Result<(TcpListenerStream, SocketAddr)> {
    let addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let socket = TcpSocket::new_v4()?;

    socket.set_send_buffer_size(1_048_576)?;
    socket.set_recv_buffer_size(1_048_576)?;
    socket.set_nodelay(true)?;
    socket.set_reuseaddr(true)?;
    socket.set_reuseport(true)?;
    socket.set_keepalive(true)?;

    socket.bind(addr)?;
    let listener = socket.listen(16384)?;
    let addr = listener.local_addr()?;

    Ok((TcpListenerStream::new(listener), addr))
}

// Echo service
#[derive(Clone)]
struct EchoService;

impl Service<Request<Incoming>> for EchoService {
    type Response = Response<Full<Bytes>>;
    type Error = std::convert::Infallible;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Incoming>) -> Self::Future {
        Box::pin(async move {
            Ok(match (req.method(), req.uri().path()) {
                (&hyper::Method::GET, "/") => {
                    Response::new(Full::new(Bytes::from_static(b"Hello, World!")))
                }
                (&hyper::Method::POST, "/echo") => {
                    let body = req.collect().await.unwrap().to_bytes();
                    Response::new(Full::new(body))
                }
                _ => Response::new(Full::new(Bytes::from_static(b"Not Found")))
            })
        })
    }
}

async fn run_stress_test(config: StressConfig) -> StressResults {
    // Initialize TLS and server
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install crypto provider");

    // Generate TLS certificates
    let key_pair = KeyPair::generate().expect("Failed to generate key pair");
    let mut params = CertificateParams::new(vec!["localhost".to_string()])
        .expect("Failed to create certificate params");
    params.distinguished_name = DistinguishedName::new();
    let cert = params.self_signed(&key_pair).expect("Failed to generate certificate");

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivatePkcs8KeyDer::from(key_pair.serialize_der());

    // Configure server TLS
    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der.into())
        .expect("Failed to configure server");

    server_config.alpn_protocols = vec![b"h2".to_vec()];
    server_config.max_fragment_size = Some(16384);
    server_config.send_tls13_tickets = 8;
    server_config.session_storage = ServerSessionMemoryCache::new(10240);
    server_config.ticketer = Ticketer::new().unwrap();
    server_config.max_early_data_size = 16384;

    // Configure client TLS
    let mut root_store = RootCertStore::empty();
    root_store.add(cert_der).expect("Failed to add certificate to root store");

    let mut client_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    client_config.enable_sni = false;
    client_config.max_fragment_size = Some(16384);
    client_config.enable_early_data = true;

    // Start server
    let (incoming, addr) = setup_optimized_listener().await.expect("Failed to create listener");
    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    let mut http = HttpConnectionBuilder::new(TokioExecutor::new());

    // Configure HTTP/2 settings with timer
    http.http2()
        .timer(TokioTimer::new())
        .initial_stream_window_size(Some(4 * 1024 * 1024))
        .initial_connection_window_size(Some(16_777_215))
        .adaptive_window(true)
        .max_frame_size(Some(1024 * 1024))
        .max_concurrent_streams(Some(16384))
        .max_send_buf_size(4 * 1024 * 1024)
        .enable_connect_protocol()
        .max_header_list_size(64 * 1024)
        .keep_alive_interval(Some(Duration::from_secs(30)))
        .keep_alive_timeout(Duration::from_secs(60));

    let service = TowerToHyperService::new(EchoService);
    let server_config = Arc::new(server_config);

    tokio::spawn(async move {
        let _ = postel::serve_http_with_shutdown(
            service,
            incoming,
            http,
            Some(server_config),
            Some(async { shutdown_rx.await.ok(); }),
        ).await;
    });

    // Create client with explicit timer configuration
    let https = HttpsConnectorBuilder::new()
        .with_tls_config(client_config)
        .https_only()
        .enable_http2()
        .build();

    let client = Client::builder(TokioExecutor::new())
        .http2_only(true)
        .timer(TokioTimer::new()) // Add explicit timer
        .pool_timer(TokioTimer::new()) // Add pool timer
        .http2_initial_stream_window_size(4 * 1024 * 1024)
        .http2_initial_connection_window_size(16_777_215)
        .http2_adaptive_window(true)
        .http2_max_frame_size(1024 * 1024)
        .http2_keep_alive_interval(Duration::from_secs(30))
        .http2_keep_alive_timeout(Duration::from_secs(60))
        .pool_idle_timeout(Duration::from_secs(60))
        .pool_max_idle_per_host(32)
        .build::<_, Either<Empty<Bytes>, Full<Bytes>>>(https);

    // Create URLs
    let base_url = Uri::builder()
        .scheme("https")
        .authority(format!("localhost:{}", addr.port()))
        .path_and_query("/")
        .build()
        .expect("Failed to build base URL");

    let echo_url = Uri::builder()
        .scheme("https")
        .authority(format!("localhost:{}", addr.port()))
        .path_and_query("/echo")
        .build()
        .expect("Failed to build echo URL");

    // Run stress test
    let start_time = Instant::now();
    let mut handles = Vec::new();
    let mut results = StressResults {
        total_requests: 0,
        successful_requests: 0,
        failed_requests: 0,
        total_bytes: 0,
        min_latency: Duration::from_secs(24 * 60 * 60),
        max_latency: Duration::ZERO,
        avg_latency: Duration::ZERO,
        throughput_mbps: 0.0,
    };

    info!("Starting stress test with {} concurrent clients", config.concurrent_clients);

    for _ in 0..config.concurrent_clients {
        let client = client.clone();
        let config = config.clone();
        let base_url = base_url.clone();
        let echo_url = echo_url.clone();

        handles.push(tokio::spawn(async move {
            let mut client_results = Vec::new();
            let client_start = Instant::now();

            while client_start.elapsed() < config.duration {
                for req_type in &config.request_types {
                    match req_type {
                        RequestType::Get => {
                            let start = Instant::now();
                            match client.request(
                                Request::builder()
                                    .method(hyper::Method::GET)
                                    .uri(base_url.clone())
                                    .body(Either::Left(Empty::new()))
                                    .unwrap()
                            ).await {
                                Ok(res) => {
                                    let bytes = res.into_body().collect().await.unwrap().to_bytes();
                                    client_results.push((true, start.elapsed(), bytes.len()));
                                }
                                Err(e) => {
                                    client_results.push((false, start.elapsed(), 0));
                                    error!("GET request failed: {}", e);
                                }
                            }
                        }
                        RequestType::Post => {
                            for &size in &config.payload_sizes {
                                let payload = vec![0u8; size];
                                let start = Instant::now();
                                match client.request(
                                    Request::builder()
                                        .method(hyper::Method::POST)
                                        .uri(echo_url.clone())
                                        .body(Either::Right(Full::new(Bytes::from(payload))))
                                        .unwrap()
                                ).await {
                                    Ok(res) => {
                                        let bytes = res.into_body().collect().await.unwrap().to_bytes();
                                        client_results.push((true, start.elapsed(), bytes.len() + size));
                                    }
                                    Err(e) => {
                                        client_results.push((false, start.elapsed(), 0));
                                        error!("POST request failed: {}", e);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            client_results
        }));
    }

    // Collect results
    let mut total_latency = Duration::ZERO;
    let mut latency_count = 0;

    for handle in handles {
        if let Ok(client_results) = handle.await {
            for (success, latency, bytes) in client_results {
                results.total_requests += 1;
                if success {
                    results.successful_requests += 1;
                    results.total_bytes += bytes;
                    results.min_latency = results.min_latency.min(latency);
                    results.max_latency = results.max_latency.max(latency);
                    total_latency += latency;
                    latency_count += 1;
                } else {
                    results.failed_requests += 1;
                }
            }
        }
    }

    // Calculate final statistics
    let test_duration = start_time.elapsed();
    if latency_count > 0 {
        results.avg_latency = total_latency / latency_count as u32;
    }
    results.throughput_mbps = (results.total_bytes as f64 * 8.0) / (test_duration.as_secs_f64() * 1_000_000.0);

    // Cleanup
    shutdown_tx.send(()).unwrap();

    results
}

#[tokio::main]
async fn main() {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let config = StressConfig {
        duration: Duration::from_secs(60),
        concurrent_clients: 256,
        request_types: vec![RequestType::Get, RequestType::Post],
        payload_sizes: vec![1024, 16384, 262144, 4096000],
    };

    info!("Starting HTTP/2 stress test...");
    let results = run_stress_test(config).await;

    println!("\nStress Test Results:");
    println!("Total Requests: {}", results.total_requests);
    println!("Successful Requests: {}", results.successful_requests);
    println!("Failed Requests: {}", results.failed_requests);
    println!("Success Rate: {:.2}%", (results.successful_requests as f64 / results.total_requests as f64) * 100.0);
    println!("Total Data Transferred: {:.2} MB", results.total_bytes as f64 / 1_000_000.0);
    println!("Min Latency: {:.2}ms", results.min_latency.as_secs_f64() * 1000.0);
    println!("Max Latency: {:.2}ms", results.max_latency.as_secs_f64() * 1000.0);
    println!("Avg Latency: {:.2}ms", results.avg_latency.as_secs_f64() * 1000.0);
    println!("Throughput: {:.2} Mbps", results.throughput_mbps);
}