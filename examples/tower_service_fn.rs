use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioTimer};
use hyper_util::server::conn::auto::Builder as HttpConnectionBuilder;
use hyper_util::service::TowerToHyperService;
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tower::{Layer, ServiceBuilder};
use tracing::{debug, info, trace, Level};

use postel::{load_certs, load_private_key, serve_http_with_shutdown};

// Define a simple service that responds with "Hello, World!"
lazy_static::lazy_static! {
    static ref HELLO: Bytes = Bytes::from("Hello, World!");
}

async fn hello(_: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    Ok(Response::new(Full::new(HELLO.clone()))) // Zero-copy clone
}
// Define a Custom middleware to add a header to all responses, for example
struct AddHeaderLayer;

impl<S> Layer<S> for AddHeaderLayer {
    type Service = AddHeaderService<S>;

    fn layer(&self, service: S) -> Self::Service {
        AddHeaderService { inner: service }
    }
}

#[derive(Clone)]
struct AddHeaderService<S> {
    inner: S,
}

impl<S, B> tower::Service<Request<B>> for AddHeaderService<S>
where
    S: tower::Service<Request<B>, Response = Response<Full<Bytes>>>,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        trace!("Adding custom header to response");
        let future = self.inner.call(req);
        Box::pin(async move {
            let mut resp = future.await?;
            resp.headers_mut()
                .insert("X-Custom-Header", "Hello from middleware!".parse().unwrap());
            Ok(resp)
        })
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Initialize logging
    tracing_subscriber::fmt().with_max_level(Level::INFO).init();

    // 1. Set up the TCP listener
    let addr = SocketAddr::from(([127, 0, 0, 1], 8443));

    let listener = TcpListener::bind(addr).await?;
    info!("Listening on https://{}", addr);
    let incoming = TcpListenerStream::new(listener);

    // 2. Create the HTTP connection builder
    let mut builder = HttpConnectionBuilder::new(TokioExecutor::new());
    builder
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

    // 3. Set up the Tower service with middleware
    let svc = tower::service_fn(hello);
    let svc = ServiceBuilder::new()
        .layer(AddHeaderLayer) // Custom middleware
        .service(svc);

    // 4. Convert the Tower service to a Hyper service
    let svc = TowerToHyperService::new(svc);

    // 5. Set up TLS config
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let certs = load_certs("examples/sample.pem")?;
    let key = load_private_key("examples/sample.rsa")?;

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(std::io::Error::other)?;

    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"http/1.0".to_vec()];
    let tls_config = Arc::new(config);

    // 6. Set up graceful shutdown
    let (shutdown_tx, _shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    // Spawn a task to send the shutdown signal after 1 second
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let _ = shutdown_tx.send(());
        debug!("Shutdown signal sent");
    });

    // 7. Create a shutdown signal
    let (shutdown_tx, _shutdown_rx) = tokio::sync::oneshot::channel();

    // 8. Start the server
    let server = tokio::spawn(async move {
        info!("Starting HTTPS server...");
        serve_http_with_shutdown(
            svc,
            incoming,
            builder,
            Some(tls_config),
            Some(async {
                _shutdown_rx.await.ok();
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

    info!("Server has shut down");
    // Et voilà!
    // A flexible, high-performance server with custom services,
    // middleware, http, tls, tcp, and graceful shutdown
    Ok(())
}
