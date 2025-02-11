//! Hello World Benchmark for postel
//!
//! This module implements a comprehensive benchmark for the postel crate,
//! testing its performance in various scenarios including latency, throughput,
//! and concurrent requests.
//!
//! It uses a very basic echo service that responds with "Hello, World!" to GET requests
//! and echoes back the request body for POST requests. The server is configured with
//! an optimized ECDSA certificate and various TLS performance improvements.
//! It exercises the full stack from Socket → TCP → TLS → HTTP/2 → postel → tower-service.
//! This allows developers of the library to optimize the full stack for performance.
//! The library provides a detailed benchmark report with latency, throughput, and
//! concurrency stress tests.
//! It additionally has provision to generate flamegraphs for each benchmark run.
//!
//! For developers who use postel, this provides a good starting point to
//! understand the performance of the library
//! and how to use it optimally in their applications.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use http::{Request, Response, StatusCode, Uri};
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioTimer};
use hyper_util::server::conn::auto::Builder as HttpConnectionBuilder;
use hyper_util::service::TowerToHyperService;
use pprof::criterion::{Output, PProfProfiler};
use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use rustls::crypto::aws_lc_rs::Ticketer;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::server::ServerSessionMemoryCache;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use std::convert::Infallible;
use tokio::net::TcpSocket;
use tokio::runtime::Runtime;
use tokio::sync::oneshot;
use tokio::time::{Duration, Instant};
use tokio_stream::wrappers::TcpListenerStream;
use tracing::info;

use postel::serve_http_with_shutdown;

/// Holds the TLS configuration for both server and client
struct TlsConfig {
    server_config: ServerConfig,
    client_config: ClientConfig,
}

/// Generates a shared TLS configuration for both server and client
///
/// This function creates a self-signed ECDSA certificate and configures both
/// the server and client to use it. It also applies various optimizations
/// to improve TLS performance.
fn generate_shared_ecdsa_config() -> TlsConfig {
    // Generate ECDSA key pair
    let key_pair = KeyPair::generate().expect("Failed to generate key pair");

    // Generate certificate parameters
    let mut params = CertificateParams::new(vec!["localhost".to_string()])
        .expect("Failed to create certificate params");
    params.distinguished_name = DistinguishedName::new();

    // Generate the self-signed certificate
    let cert = params
        .self_signed(&key_pair)
        .expect("Failed to generate self-signed certificate");

    // Serialize the certificate and private key
    let cert_der = cert.der().to_vec();
    let key_der = key_pair.serialize_der();

    // Create Rustls certificate and private key
    let cert = CertificateDer::from(cert_der);
    let key = PrivatePkcs8KeyDer::from(key_der);

    // Configure Server
    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key.into())
        .expect("Failed to configure server");

    // Server optimizations
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    server_config.max_fragment_size = Some(16384);
    server_config.send_tls13_tickets = 8; // Enable 0.5-RTT data
    server_config.session_storage = ServerSessionMemoryCache::new(10240);
    server_config.ticketer = Ticketer::new().unwrap();
    server_config.max_early_data_size = 16384; // Enable 0-RTT data

    // Configure Client
    let mut root_store = RootCertStore::empty();
    root_store
        .add(cert)
        .expect("Failed to add certificate to root store");

    let mut client_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // Client optimizations
    client_config.enable_sni = false; // Since we're using localhost
    client_config.max_fragment_size = Some(16384);
    client_config.enable_early_data = true; // Enable 0-RTT data
    client_config.resumption = rustls::client::Resumption::in_memory_sessions(10240);

    TlsConfig {
        server_config,
        client_config,
    }
}

fn create_optimized_runtime(thread_count: usize) -> io::Result<Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(thread_count)
        .max_blocking_threads(thread_count)
        .enable_all()
        .build()
}

// Pre-allocate static responses
const HELLO: &[u8] = b"Hello, World!";
const NOT_FOUND: &[u8] = b"Not Found";

const BASE_PATH: &str = "/";

const ECHO_PATH: &str = "/echo";

#[derive(Clone, Copy)]
struct EchoService {
    hello_response: &'static [u8],
    not_found_response: &'static [u8],
}

impl EchoService {
    const fn new() -> Self {
        Self {
            hello_response: HELLO,
            not_found_response: NOT_FOUND,
        }
    }
}

impl tower::Service<Request<Incoming>> for EchoService {
    type Response = Response<Full<Bytes>>;
    type Error = Infallible;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    #[inline]
    fn poll_ready(
        &mut self,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    #[inline]
    fn call(&mut self, req: Request<Incoming>) -> Self::Future {
        let service = *self; // Copy the service since it's Copy
        Box::pin(async move {
            Ok(match (req.method(), req.uri().path()) {
                (&hyper::Method::GET, BASE_PATH) => {
                    Response::new(Full::new(Bytes::from_static(service.hello_response)))
                }
                (&hyper::Method::POST, ECHO_PATH) => {
                    let body = req.collect().await.unwrap().to_bytes();
                    Response::new(Full::new(body))
                }
                _ => {
                    let mut res =
                        Response::new(Full::new(Bytes::from_static(service.not_found_response)));
                    *res.status_mut() = StatusCode::NOT_FOUND;
                    res
                }
            })
        })
    }
}

async fn setup_server(
) -> Result<(TcpListenerStream, SocketAddr), Box<dyn std::error::Error + Send + Sync>> {
    let addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let socket = TcpSocket::new_v4()?;

    // Optimize TCP parameters
    socket.set_send_buffer_size(262_144)?; // 256 KB
    socket.set_recv_buffer_size(262_144)?; // 256 KB
    socket.set_nodelay(true)?;
    socket.set_reuseaddr(true)?;
    socket.set_reuseport(true)?;
    socket.set_keepalive(true)?;

    socket.bind(addr)?;
    let listener = socket.listen(8192)?; // Increased backlog for high-traffic scenarios

    let server_addr = listener.local_addr()?;
    let incoming = TcpListenerStream::new(listener);

    Ok((incoming, server_addr))
}

async fn start_server(
    tls_config: ServerConfig,
) -> Result<(SocketAddr, oneshot::Sender<()>), Box<dyn std::error::Error + Send + Sync>> {
    let tls_config = Arc::new(tls_config);
    let (incoming, server_addr) = setup_server().await?;
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let mut http_server_builder = HttpConnectionBuilder::new(TokioExecutor::new());
    http_server_builder
        // HTTP/1 optimizations
        .http1()
        // Enable half-close for better connection handling
        .half_close(true)
        // Enable keep-alive to reduce overhead for multiple requests
        .keep_alive(true)
        // Increase max buffer size to 1MB for better performance with larger payloads
        .max_buf_size(1024 * 1024)
        // Enable immediate flushing of pipelined responses for lower latency
        .pipeline_flush(true)
        // Preserve original header case for compatibility
        .preserve_header_case(true)
        // Disable automatic title casing of headers to reduce processing overhead
        .title_case_headers(false)
        // HTTP/2 optimizations
        .http2()
        // Add the timer to the builder to avoid potential issues
        .timer(TokioTimer::new())
        // Increase initial stream window size to 4MB for better throughput
        .initial_stream_window_size(Some(4 * 1024 * 1024))
        // Increase initial connection window size to 8MB for improved performance
        .initial_connection_window_size(Some(8 * 1024 * 1024))
        // Enable adaptive window for dynamic flow control
        .adaptive_window(true)
        // Increase max frame size to 1MB for larger data chunks
        .max_frame_size(Some(1024 * 1024))
        // Allow up to 1024 concurrent streams for better parallelism without overwhelming the connection
        .max_concurrent_streams(Some(1024))
        // Increase max send buffer size to 4MB for improved write performance
        .max_send_buf_size(4 * 1024 * 1024)
        // Enable CONNECT protocol support for proxying and tunneling
        .enable_connect_protocol()
        // Increase max header list size to 64KB to handle larger headers
        .max_header_list_size(64 * 1024)
        // Set keep-alive interval to 30 seconds for more responsive connection management
        .keep_alive_interval(Some(Duration::from_secs(30)))
        // Set keep-alive timeout to 60 seconds to balance connection reuse and resource conservation
        .keep_alive_timeout(Duration::from_secs(60));

    let tower_service_fn = EchoService::new();

    let hyper_service = TowerToHyperService::new(tower_service_fn);
    tokio::spawn(async move {
        serve_http_with_shutdown(
            hyper_service,
            incoming,
            http_server_builder,
            Some(tls_config),
            Some(async {
                shutdown_rx.await.ok();
            }),
        )
        .await
        .unwrap();
    });
    Ok((server_addr, shutdown_tx))
}

#[inline]
async fn send_request(
    client: &Client<
        hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        Empty<Bytes>,
    >,
    url: Uri,
) -> Result<(Duration, usize), Box<dyn std::error::Error + Send + Sync>> {
    let start = Instant::now();
    let res = client.get(url).await?;
    assert_eq!(res.status(), StatusCode::OK);
    let body = res.into_body().collect().await?.to_bytes();
    assert_eq!(&body[..], b"Hello, World!");
    Ok((start.elapsed(), body.len()))
}

#[inline]
async fn concurrent_benchmark(
    client: &Client<
        hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        Empty<Bytes>,
    >,
    url: Uri,
    num_requests: usize,
) -> (Duration, Vec<Duration>, usize) {
    let start = Instant::now();
    let mut handles = Vec::with_capacity(num_requests);

    for _ in 0..num_requests {
        let client = client.clone();
        let url = url.clone();
        let handle = tokio::spawn(async move { send_request(&client, url).await });
        handles.push(handle);
    }

    let mut request_times = Vec::with_capacity(num_requests);
    let mut total_bytes = 0;

    for handle in handles {
        if let Ok(Ok((duration, bytes))) = handle.await {
            request_times.push(duration);
            total_bytes += bytes;
        }
    }

    let total_time = start.elapsed();
    (total_time, request_times, total_bytes)
}

fn bench_server(c: &mut Criterion) {
    let server_runtime = Arc::new(create_optimized_runtime(num_cpus::get() / 2).unwrap());

    let (server_addr, shutdown_tx, client) = server_runtime.block_on(async {
        // Setup default rustls crypto provider
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .expect("Failed to install rustls crypto provider");
        let tls_config = generate_shared_ecdsa_config();
        let (server_addr, shutdown_tx) = start_server(tls_config.server_config.clone())
            .await
            .expect("Failed to start server");
        info!("Server started on {}", server_addr);

        let https = HttpsConnectorBuilder::new()
            .with_tls_config(tls_config.client_config)
            .https_only()
            .enable_http2()
            .build();

        let client = Client::builder(TokioExecutor::new())
            // HTTP/2 settings
            .http2_only(true)
            // Ensures all connections use HTTP/2 protocol
            .http2_initial_stream_window_size(4 * 1024 * 1024)
            // Sets initial HTTP/2 stream flow control window to 4MB
            .http2_initial_connection_window_size(8 * 1024 * 1024)
            // Sets initial HTTP/2 connection flow control window to 8MB
            .http2_adaptive_window(true)
            // Enables dynamic adjustment of flow control window based on network conditions
            .http2_max_frame_size(1024 * 1024)
            // Sets maximum HTTP/2 frame size to 1MB
            .http2_keep_alive_interval(Duration::from_secs(30))
            // Sends keep-alive pings every 30 seconds
            .http2_keep_alive_timeout(Duration::from_secs(60))
            // Allows 60 seconds for keep-alive responses before timing out
            .http2_max_concurrent_reset_streams(250)
            // Limits the number of concurrent streams per connection to 250
            .http2_max_send_buf_size(4 * 1024 * 1024)
            // Sets maximum send buffer size to 4MB
            // Connection pooling settings
            .pool_idle_timeout(Duration::from_secs(60))
            // Keeps idle connections alive for 60 seconds
            .pool_max_idle_per_host(32)
            // Sets maximum number of idle connections per host to 32
            // This is key, you have a lot of pain in store at runtime if you
            // don't set these.
            .timer(TokioTimer::new())
            .pool_timer(TokioTimer::new())
            .build(https);

        (server_addr, shutdown_tx, client)
    });

    let url = Uri::builder()
        .scheme("https")
        .authority(format!("localhost:{}", server_addr.port()))
        .path_and_query("/")
        .build()
        .expect("Failed to build URI");

    let mut group = c.benchmark_group("postel");
    group.sample_size(20);
    group.measurement_time(Duration::from_secs(30));

    // Latency
    group.throughput(Throughput::Elements(1));
    group.bench_function("serial_latency", |b| {
        let client = client.clone();
        let url = url.clone();
        let client_runtime = create_optimized_runtime(num_cpus::get() / 2).unwrap();
        b.to_async(client_runtime)
            .iter(|| async { send_request(&client, url.clone()).await.unwrap() });
    });

    // Concurrency stress test
    let concurrent_requests = vec![10, 50, 250, 1250];
    for &num_requests in &concurrent_requests {
        group.throughput(Throughput::Elements(num_requests as u64));
        group.bench_with_input(
            BenchmarkId::new("concurrent_latency", num_requests),
            &num_requests,
            |b, &num_requests| {
                let client = client.clone();
                let url = url.clone();
                let client_runtime = create_optimized_runtime(num_cpus::get() / 2).unwrap();
                b.to_async(client_runtime).iter(|| async {
                    concurrent_benchmark(&client, url.clone(), num_requests).await
                });
            },
        );
    }

    group.finish();

    server_runtime.block_on(async {
        shutdown_tx.send(()).unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
    });
}

#[cfg(not(feature = "dev-profiling"))]
criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(10)
        .measurement_time(Duration::from_secs(30))
        .warm_up_time(Duration::from_secs(5));
    targets = bench_server
}

#[cfg(feature = "dev-profiling")]
criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(10)
        .measurement_time(Duration::from_secs(30))
        .warm_up_time(Duration::from_secs(5))
        .with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)));
    targets = bench_server
}

criterion_main!(benches);
