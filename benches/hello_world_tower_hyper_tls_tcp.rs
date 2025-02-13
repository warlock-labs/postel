//! HTTP/2 Benchmarking Suite
//!
//! This module implements a comprehensive benchmark suite for testing HTTP/2 server
//! performance. It measures latency, throughput, and concurrency characteristics
//! using a simple echo service. The benchmarks exercise the full network stack:
//!   Socket → TCP → TLS → HTTP/2 → Application Layer
//!
//! Key features:
//! - Measures both GET and POST request performance
//! - Tests various payload sizes for throughput analysis
//! - Evaluates concurrent request handling
//! - Uses optimized TLS (ECDSA) and TCP configurations
//! - Supports flamegraph generation when compiled with dev-profiling feature

use postel::serve_http_with_shutdown;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use futures_util::future::BoxFuture;
use http::{Request, Response, StatusCode, Uri};
use http_body_util::{BodyExt, Empty, Full, Either};
use hyper::body::Incoming;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::{
    client::legacy::Client,
    rt::{TokioExecutor, TokioTimer},
    server::conn::auto::Builder as HttpConnectionBuilder,
    service::TowerToHyperService,
};
#[cfg(feature = "dev-profiling")]
use pprof::criterion::{Output, PProfProfiler};
use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use rustls::{
    crypto::aws_lc_rs::Ticketer,
    pki_types::{CertificateDer, PrivatePkcs8KeyDer},
    server::ServerSessionMemoryCache,
    ClientConfig, RootCertStore, ServerConfig,
};
use std::convert::Infallible;
use tokio::{
    net::TcpSocket,
    runtime::Runtime,
    sync::oneshot,
    time::Instant,
};
use tokio_stream::wrappers::TcpListenerStream;
use tower::Service;
use tracing::info;

// Type alias for our HTTPS client that supports both empty and full request bodies
type HttpsClient = Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    Either<Empty<Bytes>, Full<Bytes>>
>;

/// Configuration for TLS (both server and client)
struct TlsConfig {
    server_config: ServerConfig,
    client_config: ClientConfig,
}

/// Generates an optimized TLS configuration using ECDSA certificates
///
/// Creates a self-signed certificate and configures both server and client
/// with performance optimizations including:
/// - Session resumption
/// - 0-RTT and 0.5-RTT data
/// - Increased fragment sizes
/// - Memory-based session caching
fn generate_tls_config() -> TlsConfig {
    // Generate ECDSA key pair and certificate
    let key_pair = KeyPair::generate().expect("Failed to generate key pair");
    let mut params = CertificateParams::new(vec!["localhost".to_string()])
        .expect("Failed to create certificate params");
    params.distinguished_name = DistinguishedName::new();
    let cert = params
        .self_signed(&key_pair)
        .expect("Failed to generate self-signed certificate");

    // Convert to DER format
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivatePkcs8KeyDer::from(key_pair.serialize_der());

    // Configure server
    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der.into())
        .expect("Failed to configure server");

    // Configure TLS server optimization settings
    // Force HTTP/2 only by setting ALPN protocols list to just h2
    // This ensures we always use HTTP/2's multiplexing capabilities
    server_config.alpn_protocols = vec![b"h2".to_vec()];

    // Set maximum TLS fragment size to 16KB
    // This matches common TLS record size limits and helps optimize
    // encryption/decryption operations for larger payloads
    server_config.max_fragment_size = Some(16384);

    // Allow server to send up to 8 session tickets per connection
    // More tickets improves probability of successful 0-RTT resumption
    // by providing backup tickets if some are lost/expired
    server_config.send_tls13_tickets = 8;

    // Configure session cache to store up to 10240 sessions in memory
    // Large cache helps improve connection reuse and enables 0-RTT
    // Sized to balance memory usage vs hit rate
    server_config.session_storage = ServerSessionMemoryCache::new(10240);

    // Enable session ticket encryption for session resumption
    // Required for 0-RTT and session ticket functionality
    server_config.ticketer = Ticketer::new().unwrap();

    // Allow up to 16KB of 0-RTT (early) data
    // Enables clients to send data in first round trip
    // Size matches fragment size for consistency
    server_config.max_early_data_size = 16384;

    // Configure client
    let mut root_store = RootCertStore::empty();
    root_store
        .add(cert_der)
        .expect("Failed to add certificate to root store");

    let mut client_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // Apply client optimizations
    client_config.enable_sni = false;
    client_config.max_fragment_size = Some(16384);
    client_config.enable_early_data = true;
    client_config.resumption = rustls::client::Resumption::in_memory_sessions(10240);

    TlsConfig {
        server_config,
        client_config,
    }
}

fn create_runtime(available_cores: usize) -> io::Result<Runtime> {
    let worker_threads = (available_cores * 4).min(2048);

    let blocking_threads = available_cores.max(64);

    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .max_blocking_threads(blocking_threads)
        .thread_keep_alive(Duration::from_secs(30))
        .thread_stack_size(4 * 1024 * 1024)
        .enable_all()
        .build()
}

// Pre-allocated response content
const HELLO: &[u8] = b"Hello, World!";
const NOT_FOUND: &[u8] = b"Not Found";

// Request paths
const BASE_PATH: &str = "/";
const ECHO_PATH: &str = "/echo";

/// Simple echo service that responds to GET and POST requests
#[derive(Clone, Copy)]
struct EchoService;

impl Service<Request<Incoming>> for EchoService {
    type Response = Response<Full<Bytes>>;
    type Error = Infallible;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(
        &mut self,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Incoming>) -> Self::Future {
        Box::pin(async move {
            Ok(match (req.method(), req.uri().path()) {
                // GET / -> "Hello, World!"
                (&hyper::Method::GET, BASE_PATH) => {
                    Response::new(Full::new(Bytes::from_static(HELLO)))
                }
                // POST /echo -> Echo back request body
                (&hyper::Method::POST, ECHO_PATH) => {
                    let body = req.collect().await.unwrap().to_bytes();
                    Response::new(Full::new(body))
                }
                // Everything else -> 404
                _ => Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Full::new(Bytes::from_static(NOT_FOUND)))
                    .unwrap(),
            })
        })
    }
}

/// Sets up a TCP listener with optimized configuration for high-performance networking
///
/// Configures socket with optimized parameters for:
/// - Large buffer sizes for throughput
/// - Low latency settings
/// - Connection reuse
/// - High concurrent connection handling
async fn setup_listener() -> io::Result<(TcpListenerStream, SocketAddr)> {
    // Bind to localhost with OS-assigned port
    let addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let socket = TcpSocket::new_v4()?;

    // Configure TCP optimization flags

    // Set 1MB send buffer for handling large outbound data volumes
    // Larger buffer helps maintain throughput when receiver is slower
    socket.set_send_buffer_size(1_048_576)?;

    // Set 1MB receive buffer for handling large inbound data volumes
    // Larger buffer helps prevent drops during burst traffic
    socket.set_recv_buffer_size(1_048_576)?;

    // Enable TCP_NODELAY to disable Nagle's algorithm
    // Reduces latency by sending packets immediately
    socket.set_nodelay(true)?;

    // Enable SO_REUSEADDR to allow binding to an address that is already in use
    // Helps with quick server restarts by avoiding "address in use" errors
    socket.set_reuseaddr(true)?;

    // Enable SO_REUSEPORT for better load distribution across threads
    // Allows multiple sockets to bind to the same port for parallel accept
    socket.set_reuseport(true)?;

    // Enable TCP keepalive to detect dead connections
    // Helps clean up stale connections and free resources
    socket.set_keepalive(true)?;

    // Bind socket to address
    socket.bind(addr)?;

    // Start listening with large backlog (16384 pending connections)
    // High backlog helps handle connection bursts without dropping
    let listener = socket.listen(16384)?;

    // Get actual bound address (important since port was OS-assigned)
    let addr = listener.local_addr()?;

    // Wrap in TcpListenerStream for async accept
    Ok((TcpListenerStream::new(listener), addr))
}

/// Creates and starts an HTTP server with optimized settings for high throughput
///
/// Sets up both HTTP/1.1 and HTTP/2 with tuned parameters for:
/// - Large payload handling
/// - High concurrency
/// - Efficient connection management
/// - Optimal buffer sizes
async fn start_server(
    server_config: ServerConfig,
) -> Result<(SocketAddr, oneshot::Sender<()>), Box<dyn std::error::Error + Send + Sync>> {
    // Set up TCP listener with optimized socket settings
    let (incoming, addr) = setup_listener().await?;

    // Channel for graceful shutdown signaling
    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    // Initialize the HTTP connection builder with Tokio executor
    let mut http = HttpConnectionBuilder::new(TokioExecutor::new());

    // Configure HTTP/1.1 settings
    // While we mainly use HTTP/2, keeping HTTP/1.1 optimized for fallback
    http.http1()
        // Enable half-close support for better connection cleanup
        .half_close(true)
        // Enable keep-alive to reuse connections
        .keep_alive(true)
        // Set 1MB buffer for efficient payload handling
        .max_buf_size(1024 * 1024)
        // Enable immediate flushing of pipelined responses
        .pipeline_flush(true);

    // Configure HTTP/2 settings optimized for high throughput
    http.http2()
        // Set up timer for connection management
        .timer(TokioTimer::new())
        // Set 4MB initial stream window for higher per-stream throughput
        .initial_stream_window_size(Some(4 * 1024 * 1024))
        // Set connection window to max allowed by RFC 9113 (~16MB)
        .initial_connection_window_size(Some(16_777_215))
        // Enable dynamic window sizing based on actual usage
        .adaptive_window(true)
        // Use 1MB frame size for efficient large payload transfer
        .max_frame_size(Some(1024 * 1024))
        // Allow up to 16384 concurrent streams per connection
        .max_concurrent_streams(Some(16384))
        // Set 4MB send buffer for handling large payloads
        .max_send_buf_size(4 * 1024 * 1024)
        // Enable CONNECT protocol for proxy support
        .enable_connect_protocol()
        // Set 64KB max header size for reasonable memory usage
        .max_header_list_size(64 * 1024)
        // Send keepalive pings every 30 seconds
        .keep_alive_interval(Some(Duration::from_secs(30)))
        // Allow 60 seconds before timing out keepalive
        .keep_alive_timeout(Duration::from_secs(60));

    // Create service by wrapping our EchoService with Tower adapter
    let service = TowerToHyperService::new(EchoService);
    // Wrap TLS config in Arc for sharing across worker threads
    let server_config = Arc::new(server_config);

    // Spawn server task that runs until shutdown signal
    tokio::spawn(async move {
        serve_http_with_shutdown(
            service,
            incoming,
            http,
            Some(server_config),
            Some(async {
                shutdown_rx.await.ok();
            }),
        )
            .await
            .unwrap();
    });

    Ok((addr, shutdown_tx))
}

/// Sends a GET request and measures round-trip time
/// Returns elapsed time and bytes received
#[inline]
async fn send_get_request(
    client: &HttpsClient,
    url: Uri,
) -> Result<(Duration, usize), Box<dyn std::error::Error + Send + Sync>> {
    let start = Instant::now();

    // Reuse request builder for GET requests since URL is the only variant
    let req = Request::builder()
        .method(hyper::Method::GET)
        .uri(url)
        // Empty body for GET request
        .body(Either::Left(Empty::new()))
        .unwrap();

    // Send request and await complete response
    let res = client.request(req).await?;
    let body = res.into_body().collect().await?.to_bytes();

    Ok((start.elapsed(), body.len()))
}

/// Sends a POST request with payload and measures round-trip time
/// Returns elapsed time and bytes received
#[inline]
async fn send_post_request(
    client: &HttpsClient,
    url: Uri,
    payload: Vec<u8>,
) -> Result<(Duration, usize), Box<dyn std::error::Error + Send + Sync>> {
    let start = Instant::now();

    // Convert payload to Bytes once
    let bytes = Bytes::from(payload);

    // Build and send request
    let res = client
        .request(
            Request::builder()
                .method(hyper::Method::POST)
                .uri(url)
                // Wrap payload in Full body
                .body(Either::Right(Full::new(bytes)))
                .unwrap()
        )
        .await?;

    // Collect response body
    let recv_len = res.into_body().collect().await?.to_bytes().len();

    Ok((start.elapsed(), recv_len))
}

/// Executes multiple requests concurrently and collects timing data
async fn run_concurrent_requests(
    client: &HttpsClient,
    url: Uri,
    num_requests: usize,
) -> (Duration, Vec<Duration>, usize) {
    let start = Instant::now();
    let mut handles = Vec::with_capacity(num_requests);

    for _ in 0..num_requests {
        let client = client.clone();
        let url = url.clone();
        handles.push(tokio::spawn(async move {
            send_get_request(&client, url).await
        }));
    }

    let mut request_times = Vec::with_capacity(num_requests);
    let mut total_bytes = 0;

    for handle in handles {
        if let Ok(Ok((duration, bytes))) = handle.await {
            request_times.push(duration);
            total_bytes += bytes;
        }
    }

    (start.elapsed(), request_times, total_bytes)
}

/// Main benchmark function that runs all tests
fn bench_http2_server(c: &mut Criterion) {
    let available_cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    // Create server runtime with half of available CPU cores
    let server_runtime = Arc::new(create_runtime(available_cores / 2).unwrap());

    // Setup server and client
    let (server_addr, shutdown_tx, client) = server_runtime.block_on(async {
        // Initialize crypto provider
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .expect("Failed to install rustls crypto provider");

        let tls_config = generate_tls_config();
        let (addr, shutdown_tx) = start_server(tls_config.server_config)
            .await
            .expect("Failed to start server");
        info!("Server started on {}", addr);

        // Create HTTPS connector
        let https = HttpsConnectorBuilder::new()
            .with_tls_config(tls_config.client_config)
            .https_only()
            .enable_http2()
            .build();

        // Configure HTTP client with optimized settings for high throughput and concurrent requests
        let client = Client::builder(TokioExecutor::new())
            // Force HTTP/2 only mode for consistent multiplexing behavior
            .http2_only(true)

            // Set initial stream window size to 4MB to allow more data in flight per stream
            // This helps with throughput for larger payloads
            .http2_initial_stream_window_size(4 * 1024 * 1024)

            // Set connection window size to max allowed by RFC 9113 (~16MB)
            // This controls the total amount of data that can be in flight across all streams
            .http2_initial_connection_window_size(16_777_215)

            // Enable dynamic adjustment of flow control windows based on usage patterns
            // Helps optimize throughput by adapting to actual traffic patterns
            .http2_adaptive_window(true)

            // Set max frame size to 1MB for efficient transfer of larger payloads
            // Default is much smaller which requires more frames for large data
            .http2_max_frame_size(1024 * 1024)

            // Configure keep-alive settings for connection reuse
            // Send pings every 30s to keep connections alive
            .http2_keep_alive_interval(Duration::from_secs(30))
            // Allow 60s before timing out a keep-alive, giving time for slow responses
            .http2_keep_alive_timeout(Duration::from_secs(60))

            // Allow up to 16384 concurrent stream resets before forcing connection close
            // High value to handle many concurrent streams failing without dropping connection
            .http2_max_concurrent_reset_streams(16384)

            // Set max send buffer to 4MB per stream
            // Allows buffering of larger payloads before applying backpressure
            .http2_max_send_buf_size(4 * 1024 * 1024)

            // Connection pooling settings
            // Keep idle connections for 60s to allow reuse
            .pool_idle_timeout(Duration::from_secs(60))
            // Maintain up to 32 idle connections per host
            // Helps with burst traffic by having connections ready
            .pool_max_idle_per_host(32)

            // Configure timers for connection management
            // Required for proper keep-alive and timeout handling
            .timer(TokioTimer::new())
            .pool_timer(TokioTimer::new())

            // Build the client with support for both empty GET requests (Empty)
            // and POST requests with bodies (Full)
            .build::<_, Either<Empty<Bytes>, Full<Bytes>>>(https);

        (addr, shutdown_tx, client)
    });

    // Create benchmark URLs
    let base_url = Uri::builder()
        .scheme("https")
        .authority(format!("localhost:{}", server_addr.port()))
        .path_and_query("/")
        .build()
        .expect("Failed to build base URI");

    let echo_url = Uri::builder()
        .scheme("https")
        .authority(format!("localhost:{}", server_addr.port()))
        .path_and_query("/echo")
        .build()
        .expect("Failed to build echo URI");

    let mut group = c.benchmark_group("http2");
    group.sample_size(20);
    group.measurement_time(Duration::from_secs(30));

    // Benchmark 1: Single Request Latency
    // Measures the baseline latency for individual requests
    group.throughput(Throughput::Elements(1));
    group.bench_function("single_request_latency", |b| {
        let client = client.clone();
        let url = base_url.clone();
        let client_runtime = create_runtime(available_cores / 2).unwrap();
        b.to_async(client_runtime)
            .iter(|| async { send_get_request(&client, url.clone()).await.unwrap() });
    });

    // Benchmark 2: Concurrent Request Latency
    // Tests how the server handles multiple simultaneous requests
    let concurrent_requests = vec![10, 50, 250, 1000];
    for &num_requests in &concurrent_requests {
        group.throughput(Throughput::Elements(num_requests as u64));
        group.bench_with_input(
            BenchmarkId::new("concurrent_requests", num_requests),
            &num_requests,
            |b, &num_requests| {
                let client = client.clone();
                let url = base_url.clone();
                let client_runtime = create_runtime(available_cores / 2).unwrap();
                b.to_async(client_runtime).iter(|| async {
                    run_concurrent_requests(&client, url.clone(), num_requests).await
                });
            },
        );
    }

    // Benchmark 3: Throughput with Various Payload Sizes
    // Measures how efficiently the server handles different payload sizes
    let payload_sizes = vec![
        1024,   // 1KB
        16384,  // 16KB (TLS record size)
        65536,  // 64KB
        262144, // 256KB
        4096000, // 4MB
        16777216, // 16MB
    ];

    for &size in &payload_sizes {
        // Account for both sending and receiving the payload
        group.throughput(Throughput::Bytes((size * 2) as u64));
        group.bench_with_input(
            BenchmarkId::new("payload_throughput", size),
            &size,
            |b, &size| {
                let client = client.clone();
                let url = echo_url.clone();
                let client_runtime = create_runtime(available_cores / 2).unwrap();
                let payload = vec![0u8; size];

                b.to_async(client_runtime).iter(|| async {
                    send_post_request(&client, url.clone(), payload.clone()).await.unwrap()
                });
            },
        );
    }

    // Benchmark 4: Concurrent Throughput
    // Tests throughput under various levels of concurrency with proper byte counting
    let concurrency_levels = vec![10, 50, 250, 1000];
    for &concurrency in &concurrency_levels {
        // Set throughput measurement based on total data transferred
        // Each request sends and receives 16MB, multiply by concurrency for total bytes
        let total_bytes = 16777216 * 2 * concurrency as u64; // multiply by 2 for send+receive
        group.throughput(Throughput::Bytes(total_bytes));

        group.bench_with_input(
            BenchmarkId::new("concurrent_throughput", concurrency),
            &concurrency,
            |b, &concurrency| {
                let client = client.clone();
                let url = echo_url.clone();
                let client_runtime = create_runtime(available_cores / 2).unwrap();
                let payload = vec![0u8; 16777216]; // 16MB baseline payload

                b.to_async(client_runtime).iter(|| async {
                    let start = Instant::now();
                    let mut handles = Vec::with_capacity(concurrency);
                    let mut total_bytes = 0;

                    // Launch concurrent requests
                    for _ in 0..concurrency {
                        let client = client.clone();
                        let url = url.clone();
                        let payload = payload.clone();
                        handles.push(tokio::spawn(async move {
                            send_post_request(&client, url, payload).await
                        }));
                    }

                    // Collect results and sum up total bytes transferred
                    for handle in handles {
                        match handle.await {
                            Ok(Ok((_, bytes))) => {
                                total_bytes += bytes;
                                total_bytes += 16777216; // Add sent bytes
                            }
                            Err(e) => panic!("Task failed: {}", e),
                            Ok(Err(e)) => panic!("Request failed: {}", e),
                        }
                    }

                    // Return both elapsed time and total bytes for proper throughput calculation
                    (start.elapsed(), total_bytes)
                });
            },
        );
    }

    group.finish();

    // Cleanup: Shutdown server
    server_runtime.block_on(async {
        shutdown_tx.send(()).unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
    });
}

// Configure benchmark suite
#[cfg(not(feature = "dev-profiling"))]
criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(10)
        .measurement_time(Duration::from_secs(30))
        .warm_up_time(Duration::from_secs(5));
    targets = bench_http2_server
}

// Configure benchmark suite with profiling
#[cfg(feature = "dev-profiling")]
criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(10)
        .measurement_time(Duration::from_secs(30))
        .warm_up_time(Duration::from_secs(5))
        .with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)));
    targets = bench_http2_server
}

criterion_main!(benches);