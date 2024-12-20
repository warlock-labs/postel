use crate::io::Transport;
use std::future::pending;
use std::{future::Future, pin::pin, sync::Arc};
use tokio_rustls::TlsAcceptor;

use bytes::Bytes;
use http::{Request, Response};
use http_body::Body;
use hyper::body::Incoming;
use hyper::service::Service;
use hyper_util::rt::TokioTimer;
use hyper_util::{
    rt::TokioIo,
    server::conn::auto::{Builder as HttpConnectionBuilder, HttpServerConnExec},
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::sleep;
use tokio::time::Duration;
use tokio_stream::Stream;
use tokio_stream::StreamExt as _;
use tracing::{debug, trace};

use crate::fuse::Fuse;

/// Sleeps for a specified duration or waits indefinitely.
///
/// This function is used to implement timeouts or indefinite waiting periods.
///
/// # Arguments
///
/// * `wait_for` - An `Option<Duration>` specifying how long to sleep.
///   If `None`, the function will wait indefinitely.
#[inline]
async fn sleep_or_pending(wait_for: Option<Duration>) {
    match wait_for {
        Some(wait) => sleep(wait).await,
        None => pending().await,
    };
}

/// Serves HTTP an HTTP connection on the transport from a hyper service backend.
///
/// This method handles an HTTP connection on a given transport `IO`, processing requests through
/// the provided service and managing the connection lifecycle.
///
/// # Type Parameters
///
/// * `B`: The body type for the HTTP response.
/// * `IO`: The I/O type for the HTTP connection.
/// * `S`: The service type that processes HTTP requests.
/// * `E`: The executor type for the HTTP server connection.
///
/// # Arguments
///
/// * `hyper_io`: The I/O object representing the inbound hyper IO stream.
/// * `hyper_service`: The hyper `Service` implementation used to process HTTP requests.
/// * `builder`: A `Builder` used to create and serve the HTTP connection.
/// * `watcher`: An optional `tokio::sync::watch::Receiver` for graceful shutdown signaling.
/// * `max_connection_age`: An optional `Duration` specifying the maximum age of the connection
///   before initiating a graceful shutdown.
#[inline]
pub async fn serve_http_connection<B, IO, S, E>(
    hyper_io: IO,
    hyper_service: S,
    builder: HttpConnectionBuilder<E>,
    watcher: Option<tokio::sync::watch::Receiver<()>>,
    max_connection_age: Option<Duration>,
) where
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>> + Send + Sync,
    IO: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
    S: Service<Request<Incoming>, Response = Response<B>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>> + Send,
    E: HttpServerConnExec<S::Future, B> + Send + Sync + 'static,
{
    // Set up a fused future for the watcher
    let mut watcher = watcher.clone();
    let mut sig = pin!(Fuse {
        inner: watcher.as_mut().map(|w| w.changed()),
    });

    // Set up the sleep future for max connection age
    let sleep = sleep_or_pending(max_connection_age);
    tokio::pin!(sleep);

    // TODO(It's absolutely terrible that we have to clone the builder here)
    // and configure it rather than passing it in.
    // this is due to an API flaw in the hyper_util crate.
    // this builder doesn't have a way to convert back to a builder
    // once you start building.

    let mut builder = builder.clone();
    builder
        // HTTP/1 settings
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
        // HTTP/2 settings
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
        // Allow up to 250 concurrent streams for better parallelism without overwhelming the connection
        .max_concurrent_streams(Some(250))
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

    // Create and pin the HTTP connection
    //
    // This handles all the HTTP connection logic via hyper.
    // This is a pointer to a blocking task, effectively
    // Which tells us how it's doing via the hyper_io transport.
    let mut conn = pin!(builder.serve_connection_with_upgrades(hyper_io, hyper_service));

    // Here we wait for the http connection to terminate
    loop {
        tokio::select! {
            // Handle the connection result
            rv = &mut conn => {
                if let Err(err) = rv {
                    // Log any errors that occur while serving the HTTP connection
                    debug!("failed serving HTTP connection: {:#}", err);
                }
                break;
            },
            // Handle max connection age timeout
            _ = &mut sleep  => {
                // Initiate a graceful shutdown when max connection age is reached
                conn.as_mut().graceful_shutdown();
                sleep.set(sleep_or_pending(None));
            },
            // Handle graceful shutdown signal
            _ = &mut sig => {
                // Initiate a graceful shutdown when signal is received
                conn.as_mut().graceful_shutdown();
            }
        }
    }

    trace!("HTTP connection closed");
}

/// Serves HTTP/HTTPS requests with graceful shutdown capability.
///
/// This function sets up an HTTP/HTTPS server that can handle incoming connections and
/// process requests using the provided service. It supports both plain HTTP and HTTPS
/// connections, as well as graceful shutdown.
///
/// # Type Parameters
///
/// * `E`: The executor type for the HTTP server connection.
/// * `F`: The future type for the shutdown signal.
/// * `I`: The incoming stream of IO objects.
/// * `IO`: The I/O type for the HTTP connection.
/// * `IE`: The error type for the incoming stream.
/// * `ResBody`: The response body type.
/// * `S`: The service type that processes HTTP requests.
///
/// # Arguments
///
/// * `service`: The service used to process HTTP requests.
/// * `incoming`: The stream of incoming connections.
/// * `builder`: The `HttpConnectionBuilder` used to configure the server.
/// * `tls_config`: An optional TLS configuration for HTTPS support.
/// * `signal`: An optional future that, when resolved, signals the server to shut down gracefully.
///
/// # Returns
///
/// A `Result` indicating success or failure of the server operation.
///
/// # Examples
///
/// These examples provide some very basic ways to use the server. With that said,
/// the server is very flexible and can be used in a variety of ways. This is
/// because you as the integrator have control over every level of the stack at
/// construction, with all the native builders exposed via generics.
///
/// Setting up an HTTP server with graceful shutdown:
///
/// ```rust,no_run
/// use std::convert::Infallible;
/// use bytes::Bytes;
/// use http_body_util::Full;
/// use hyper::body::Incoming;
/// use hyper::{Request, Response};
/// use hyper_util::rt::TokioExecutor;
/// use hyper_util::server::conn::auto::Builder as HttpConnectionBuilder;
/// use tokio::net::TcpListener;
/// use tokio_stream::wrappers::TcpListenerStream;
/// use tower::ServiceBuilder;
/// use std::net::SocketAddr;
///
/// use postel::serve_http_with_shutdown;
///
/// async fn hello(_: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
///     Ok(Response::new(Full::new(Bytes::from("Hello, World!"))))
/// }
///
/// #[tokio::main(flavor = "current_thread")]
/// async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
///     let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
///     let listener = TcpListener::bind(addr).await?;
///     let incoming = TcpListenerStream::new(listener);
///
///     let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
///
///     let builder = HttpConnectionBuilder::new(TokioExecutor::new());
///     let svc = hyper::service::service_fn(hello);
///     let svc = ServiceBuilder::new().service(svc);
///
///     tokio::spawn(async move {
///         // Simulate a shutdown signal after 60 seconds
///         tokio::time::sleep(std::time::Duration::from_secs(60)).await;
///         let _ = shutdown_tx.send(());
///     });
///
///     serve_http_with_shutdown(
///         svc,
///         incoming,
///         builder,
///         None, // No TLS config for plain HTTP
///         Some(async {
///             shutdown_rx.await.ok();
///         }),
///     ).await?;
///
///     Ok(())
/// }
/// ```
///
/// Setting up an HTTPS server:
///
/// ```rust,no_run
/// use std::convert::Infallible;
/// use std::sync::Arc;
/// use bytes::Bytes;
/// use http_body_util::Full;
/// use hyper::body::Incoming;
/// use hyper::{Request, Response};
/// use hyper_util::rt::TokioExecutor;
/// use hyper_util::server::conn::auto::Builder as HttpConnectionBuilder;
/// use tokio::net::TcpListener;
/// use tokio_stream::wrappers::TcpListenerStream;
/// use tower::ServiceBuilder;
/// use rustls::ServerConfig;
/// use std::io;
/// use std::net::SocketAddr;
/// use std::future::Future;
///
/// use postel::{serve_http_with_shutdown, load_certs, load_private_key};
///
/// async fn hello(_: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
///     Ok(Response::new(Full::new(Bytes::from("Hello, World!"))))
/// }
///
/// #[tokio::main(flavor = "current_thread")]
/// async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
///     let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
///     let listener = TcpListener::bind(addr).await?;
///     let incoming = TcpListenerStream::new(listener);
///
///     let builder = HttpConnectionBuilder::new(TokioExecutor::new());
///     let svc = hyper::service::service_fn(hello);
///     let svc = ServiceBuilder::new().service(svc);
///
///     // Set up TLS config
///     let certs = load_certs("examples/sample.pem")?;
///     let key = load_private_key("examples/sample.rsa")?;
///
///     let config = ServerConfig::builder()
///         .with_no_client_auth()
///         .with_single_cert(certs, key)
///         .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
///     let tls_config = Arc::new(config);
///
///     serve_http_with_shutdown(
///         svc,
///         incoming,
///         builder,
///         Some(tls_config),
///         Some(std::future::pending::<()>()), // A never-resolving future as a placeholder
///     ).await?;
///
///     Ok(())
/// }
/// ```
///
/// Setting up an HTTPS server with a Tower service:
///
/// ```rust,no_run
/// use std::convert::Infallible;
/// use std::sync::Arc;
/// use bytes::Bytes;
/// use http_body_util::Full;
/// use hyper::body::Incoming;
/// use hyper::{Request, Response};
/// use hyper_util::rt::TokioExecutor;
/// use hyper_util::server::conn::auto::Builder as HttpConnectionBuilder;
/// use hyper_util::service::TowerToHyperService;
/// use tokio::net::TcpListener;
/// use tokio_stream::wrappers::TcpListenerStream;
/// use tower::{ServiceBuilder, ServiceExt};
/// use rustls::ServerConfig;
/// use std::io;
/// use std::net::SocketAddr;
/// use std::future::Future;
///
/// use postel::{serve_http_with_shutdown, load_certs, load_private_key};
///
/// async fn hello(_: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
///     Ok(Response::new(Full::new(Bytes::from("Hello, World!"))))
/// }
///
/// #[tokio::main(flavor = "current_thread")]
/// async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
///     let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
///     let listener = TcpListener::bind(addr).await?;
///     let incoming = TcpListenerStream::new(listener);
///
///     let builder = HttpConnectionBuilder::new(TokioExecutor::new());
///
///     // Set up the Tower service
///     let svc = tower::service_fn(hello);
///     let svc = ServiceBuilder::new()
///         .service(svc);
///
///     // Convert the Tower service to a Hyper service
///     let svc = TowerToHyperService::new(svc);
///
///     // Set up TLS config
///     let certs = load_certs("examples/sample.pem")?;
///     let key = load_private_key("examples/sample.rsa")?;
///
///     let config = ServerConfig::builder()
///         .with_no_client_auth()
///         .with_single_cert(certs, key)
///         .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
///     let tls_config = Arc::new(config);
///
///     serve_http_with_shutdown(
///         svc,
///         incoming,
///         builder,
///         Some(tls_config),
///         Some(std::future::pending::<()>()), // A never-resolving future as a placeholder
///     ).await?;
///
///     Ok(())
/// }
/// ```
///
/// # Notes
///
/// - The server will continue to accept new connections until the `signal` future resolves.
/// - When using TLS, make sure to provide a properly configured `ServerConfig`.
/// - The function will return when all connections have been closed after the shutdown signal.
#[inline]
pub async fn serve_http_with_shutdown<E, F, I, IO, IE, ResBody, S>(
    service: S,
    incoming: I,
    builder: HttpConnectionBuilder<E>,
    tls_config: Option<Arc<rustls::ServerConfig>>,
    signal: Option<F>,
) -> Result<(), super::Error>
where
    F: Future<Output = ()> + Send + 'static,
    I: Stream<Item = Result<IO, IE>> + Send + 'static,
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    IE: Into<crate::Error> + Send + 'static,
    S: Service<Request<Incoming>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>> + Send,
    ResBody: Body<Data = Bytes> + Send + Sync + 'static,
    ResBody::Error: Into<crate::Error> + Send + Sync,
    E: HttpServerConnExec<S::Future, ResBody> + Send + Sync + 'static,
{
    // Create a channel for signaling graceful shutdown to listening connections
    let (signal_tx, signal_rx) = tokio::sync::watch::channel(());
    let signal_tx = Arc::new(signal_tx);

    // We say that graceful shutdown is enabled if a signal is provided
    let graceful = signal.is_some();

    // The signal future that will resolve when the server should shut down
    let mut sig = pin!(Fuse { inner: signal });

    // Prepare the incoming stream of TCP connections
    // from the provided stream of IO objects, which is coming
    // most likely from a TCP stream.
    let incoming = crate::tcp::serve_tcp_incoming(incoming);

    // Pin the incoming stream to the stack
    let mut incoming = pin!(incoming);

    // Create TLS acceptor if TLS config is provided
    let tls_acceptor = tls_config.map(TlsAcceptor::from);

    // Enter the main server loop
    loop {
        // Select between the future which returns first,
        // A shutdown signal or an incoming IO result.
        tokio::select! {
            // Check if we received a graceful shutdown signal for the server
            _ = &mut sig => {
                // Exit the loop if we did, and shut down the server
                trace!("signal received, shutting down");
                break;
            },
            // Wait for the next IO result from the incoming stream
            io = incoming.next() => {
                // If we got an IO result from the incoming stream
                // This effectively demultiplexes the incoming stream of IO objects,
                // which each represent a connection which may then be individually
                // streamed/handled.
                //
                // So this is effectively a demultiplexer for the incoming stream of IO objects.
                //
                // Because of the way the stream handling is implemented,
                // the responses are multiplexed back over the same stream to the client.
                // However, that would not be intuitive just from looking it this code
                // because the reverse multiplexing is "invisible" to the reader.
                let io = match io {
                    // We check if it's a valid stream
                    Some(Ok(io)) => io,
                    // or if it's a non-fatal error
                    Some(Err(e)) => {
                        trace!("error accepting connection: {:#}", e);
                        // if it's a non-fatal error, we continue processing IO objects
                        continue;
                    },
                    None => {
                        // If we got a fatal error, meaning we lost connection or something else
                        // we break out of the loop
                        break
                    },
                };

                trace!("TCP streaming connection accepted");

                // For each of these TCP streams, we are going to want to
                // spawn a new task to handle the connection.

                // Clone necessary values for the spawned task
                let service = service.clone();
                let builder = builder.clone();
                let tls_acceptor = tls_acceptor.clone();
                let signal_rx = signal_rx.clone();

                // Spawn a new task to handle this connection
                tokio::spawn(async move {
                        // Abstract the transport layer for hyper

                        let transport = if let Some(tls_acceptor) = &tls_acceptor {
                            // If TLS is enabled, then we perform a TLS handshake
                            // Clone the TLS acceptor and IO for use in the blocking task
                            let tls_acceptor = tls_acceptor.clone();
                            let io = io;

                            match tokio::task::spawn_blocking(move || {
                                // Perform the TLS handshake in a blocking task
                                // Because this is one of the most computationally heavy things the sever does.
                                // In the case of ECDSA and very fast handshakes, this has more downside
                                // than upside, but in the case of RSA and slow handshakes, this is a good idea.
                                // It amortizes out to about 2 µs of overhead per connection.
                                // and moves this computationally heavy task off the main thread pool.
                                tokio::runtime::Handle::current().block_on(tls_acceptor.accept(io))
                            }).await {
                                // Handle the result of the TLS handshake
                                Ok(Ok(tls_stream)) => Transport::new_tls(tls_stream),
                                    Ok(Err(e)) => {
                                        // This connection failed to handshake
                                        debug!("TLS handshake failed: {:#}", e);
                                        return;
                                    },
                               Err(e) => {
                                   // This connection was malformed and the server was unable to handle it
                                   debug!("TLS handshake task panicked: {:#}", e);
                                   return;
                               }

                            }
                       }
                       else {
                          // If TLS is not enabled, then we use a plain transport
                          Transport::new_plain(io)
                       };

                    // Convert our abstracted tokio transport into a hyper transport
                    let hyper_io = TokioIo::new(transport);

                    // Serve the HTTP connections on this transport
                    serve_http_connection(
                        hyper_io,
                        service,
                        builder,
                        graceful.then_some(signal_rx),
                        None
                    ).await;
                });
            }
        }
    }

    // Handle graceful shutdown
    if graceful {
        // Broadcast the shutdown signal to all connections
        let _ = signal_tx.send(());
        // Drop the sender to signal that no more connections will be accepted
        drop(signal_rx);
        trace!(
            "waiting for {} connections to close",
            signal_tx.receiver_count()
        );

        // Wait for all connections to close
        // TODO(Add a timeout here, optionally)
        signal_tx.closed().await;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{load_certs, load_private_key};
    use bytes::Bytes;
    use http_body_util::{BodyExt, Empty, Full};
    use hyper::{body::Incoming, Request, Response, StatusCode};
    use hyper_util::rt::TokioExecutor;
    use hyper_util::service::TowerToHyperService;
    use rustls::ServerConfig;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::oneshot;
    use tokio_stream::wrappers::TcpListenerStream;

    async fn echo(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, hyper::Error> {
        match (req.method(), req.uri().path()) {
            (&hyper::Method::GET, "/") => {
                Ok(Response::new(Full::new(Bytes::from("Hello, World!"))))
            }
            (&hyper::Method::POST, "/echo") => {
                let body = req.collect().await?.to_bytes();
                Ok(Response::new(Full::new(body)))
            }
            _ => {
                let mut res = Response::new(Full::new(Bytes::from("Not Found")));
                *res.status_mut() = StatusCode::NOT_FOUND;
                Ok(res)
            }
        }
    }

    async fn setup_test_server(addr: SocketAddr) -> (TcpListenerStream, SocketAddr) {
        let listener = TcpListener::bind(addr).await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let incoming = TcpListenerStream::new(listener);
        (incoming, server_addr)
    }

    async fn create_test_tls_config() -> Arc<ServerConfig> {
        let certs = load_certs("examples/sample.pem").unwrap();
        let key = load_private_key("examples/sample.rsa").unwrap();
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
        Arc::new(config)
    }

    async fn send_request(
        addr: SocketAddr,
        req: Request<Empty<Bytes>>,
    ) -> Result<Response<Incoming>, Box<dyn std::error::Error>> {
        let stream = TcpStream::connect(addr).await?;
        let io = TokioIo::new(stream);

        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
        tokio::spawn(async move {
            if let Err(err) = conn.await {
                eprintln!("Connection failed: {:?}", err);
            }
        });

        Ok(sender.send_request(req).await?)
    }

    // HTTP Tests

    mod http_tests {
        use super::*;

        #[tokio::test]
        async fn test_http_basic_requests() {
            let addr = SocketAddr::from(([127, 0, 0, 1], 0));
            let (incoming, server_addr) = setup_test_server(addr).await;

            let (shutdown_tx, shutdown_rx) = oneshot::channel();

            let http_server_builder = HttpConnectionBuilder::new(TokioExecutor::new());
            let tower_service_fn = tower::service_fn(echo);
            let hyper_service = TowerToHyperService::new(tower_service_fn);

            let server = tokio::spawn(serve_http_with_shutdown(
                hyper_service,
                incoming,
                http_server_builder,
                None,
                Some(async {
                    shutdown_rx.await.ok();
                }),
            ));

            // Test GET request
            let req = Request::builder()
                .uri("/")
                .body(Empty::<Bytes>::new())
                .unwrap();
            let res = send_request(server_addr, req).await.unwrap();
            assert_eq!(res.status(), StatusCode::OK);
            let body = res.collect().await.unwrap().to_bytes();
            assert_eq!(&body[..], b"Hello, World!");

            // Test POST request
            let req = Request::builder()
                .method(hyper::Method::POST)
                .uri("/echo")
                .body(Empty::<Bytes>::new())
                .unwrap();
            let res = send_request(server_addr, req).await.unwrap();
            assert_eq!(res.status(), StatusCode::OK);

            // Test 404 response
            let req = Request::builder()
                .uri("/not_found")
                .body(Empty::<Bytes>::new())
                .unwrap();
            let res = send_request(server_addr, req).await.unwrap();
            assert_eq!(res.status(), StatusCode::NOT_FOUND);

            shutdown_tx.send(()).unwrap();
            server.await.unwrap().unwrap();
        }

        #[tokio::test]
        async fn test_http_concurrent_requests() {
            let addr = SocketAddr::from(([127, 0, 0, 1], 0));
            let (incoming, server_addr) = setup_test_server(addr).await;

            let (shutdown_tx, shutdown_rx) = oneshot::channel();

            let http_server_builder = HttpConnectionBuilder::new(TokioExecutor::new());
            let tower_service_fn = tower::service_fn(echo);
            let hyper_service = TowerToHyperService::new(tower_service_fn);

            let server = tokio::spawn(serve_http_with_shutdown(
                hyper_service,
                incoming,
                http_server_builder,
                None,
                Some(async {
                    shutdown_rx.await.ok();
                }),
            ));

            let mut handles = vec![];
            for _ in 0..10 {
                let addr = server_addr;
                let handle = tokio::spawn(async move {
                    let req = Request::builder()
                        .uri("/")
                        .body(Empty::<Bytes>::new())
                        .unwrap();
                    let res = send_request(addr, req).await.unwrap();
                    assert_eq!(res.status(), StatusCode::OK);
                });
                handles.push(handle);
            }

            for handle in handles {
                handle.await.unwrap();
            }

            shutdown_tx.send(()).unwrap();
            server.await.unwrap().unwrap();
        }

        #[tokio::test]
        async fn test_http_graceful_shutdown() {
            let addr = SocketAddr::from(([127, 0, 0, 1], 0));
            let (incoming, server_addr) = setup_test_server(addr).await;

            let (shutdown_tx, shutdown_rx) = oneshot::channel();

            let http_server_builder = HttpConnectionBuilder::new(TokioExecutor::new());
            let tower_service_fn = tower::service_fn(echo);
            let hyper_service = TowerToHyperService::new(tower_service_fn);

            let server = tokio::spawn(serve_http_with_shutdown(
                hyper_service,
                incoming,
                http_server_builder,
                None,
                Some(async {
                    shutdown_rx.await.ok();
                }),
            ));

            // Send a request before shutdown
            let req = Request::builder()
                .uri("/")
                .body(Empty::<Bytes>::new())
                .unwrap();
            let res = send_request(server_addr, req)
                .await
                .expect("Failed to send initial request");
            assert_eq!(res.status(), StatusCode::OK);

            // Initiate graceful shutdown
            shutdown_tx.send(()).unwrap();

            // Wait for the server to shut down
            let shutdown_timeout = Duration::from_millis(150);
            let shutdown_result = tokio::time::timeout(shutdown_timeout, async {
                loop {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    let req = Request::builder()
                        .uri("/")
                        .body(Empty::<Bytes>::new())
                        .unwrap();
                    match send_request(server_addr, req).await {
                        Ok(_) => continue, // Server still accepting connections
                        Err(e) if e.to_string().contains("Connection refused") => {
                            // Server has shut down as expected
                            return Ok(());
                        }
                        Err(e) => return Err(e), // Unexpected error
                    }
                }
            })
            .await;

            match shutdown_result {
                Ok(Ok(())) => println!("Server shut down successfully"),
                Ok(Err(e)) => panic!("Unexpected error during shutdown: {}", e),
                Err(_) => panic!("Timeout waiting for server to shut down"),
            }

            // Ensure the server task completes
            server.await.unwrap().unwrap();
        }
    }

    // HTTPS Tests

    mod https_tests {
        use super::*;
        use crate::test::helper::RUSTLS;
        use once_cell::sync::Lazy;

        async fn create_https_client() -> (
            tokio_rustls::TlsConnector,
            rustls::pki_types::ServerName<'static>,
        ) {
            let mut root_cert_store = rustls::RootCertStore::empty();
            root_cert_store.add_parsable_certificates(load_certs("examples/sample.pem").unwrap());

            let client_config = rustls::ClientConfig::builder()
                .with_root_certificates(root_cert_store)
                .with_no_client_auth();

            let tls_connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
            let domain = rustls::pki_types::ServerName::try_from("localhost")
                .expect("Failed to create ServerName");

            (tls_connector, domain)
        }

        #[tokio::test]
        async fn test_https_connection() {
            Lazy::force(&RUSTLS);

            let addr = SocketAddr::from(([127, 0, 0, 1], 0));
            let (incoming, server_addr) = setup_test_server(addr).await;

            let tls_config = create_test_tls_config().await;
            let (shutdown_tx, shutdown_rx) = oneshot::channel();

            let http_server_builder = HttpConnectionBuilder::new(TokioExecutor::new());
            let tower_service_fn = tower::service_fn(echo);
            let hyper_service = TowerToHyperService::new(tower_service_fn);

            let server = tokio::spawn(serve_http_with_shutdown(
                hyper_service,
                incoming,
                http_server_builder,
                Some(tls_config),
                Some(async {
                    shutdown_rx.await.ok();
                }),
            ));

            let (tls_connector, domain) = create_https_client().await;

            let tcp_stream = TcpStream::connect(server_addr).await.unwrap();
            let tls_stream = tls_connector.connect(domain, tcp_stream).await.unwrap();

            let (mut sender, conn) =
                hyper::client::conn::http1::handshake(TokioIo::new(tls_stream))
                    .await
                    .unwrap();

            tokio::spawn(async move {
                if let Err(err) = conn.await {
                    eprintln!("Connection failed: {:?}", err);
                }
            });

            let req = Request::builder()
                .uri("/")
                .body(Empty::<Bytes>::new())
                .unwrap();

            let res = sender.send_request(req).await.unwrap();
            assert_eq!(res.status(), StatusCode::OK);

            let body = res.collect().await.unwrap().to_bytes();
            assert_eq!(&body[..], b"Hello, World!");

            shutdown_tx.send(()).unwrap();
            server.await.unwrap().unwrap();
        }

        #[tokio::test]
        async fn test_https_invalid_client_cert() {
            Lazy::force(&RUSTLS);

            let addr = SocketAddr::from(([127, 0, 0, 1], 0));
            let (incoming, server_addr) = setup_test_server(addr).await;

            let tls_config = create_test_tls_config().await;
            let (shutdown_tx, shutdown_rx) = oneshot::channel();

            let http_server_builder = HttpConnectionBuilder::new(TokioExecutor::new());
            let tower_service_fn = tower::service_fn(echo);
            let hyper_service = TowerToHyperService::new(tower_service_fn);

            let server = tokio::spawn(serve_http_with_shutdown(
                hyper_service,
                incoming,
                http_server_builder,
                Some(tls_config),
                Some(async {
                    shutdown_rx.await.ok();
                }),
            ));

            let client_config = rustls::ClientConfig::builder()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth();

            let tls_connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));

            let tcp_stream = TcpStream::connect(server_addr).await.unwrap();
            let domain = rustls::pki_types::ServerName::try_from("localhost").unwrap();

            let result = tls_connector.connect(domain, tcp_stream).await;
            assert!(
                result.is_err(),
                "Expected TLS connection to fail due to invalid client certificate"
            );

            shutdown_tx.send(()).unwrap();
            server.await.unwrap().unwrap();
        }
        #[tokio::test]
        async fn test_https_graceful_shutdown() {
            Lazy::force(&RUSTLS);

            let addr = SocketAddr::from(([127, 0, 0, 1], 0));
            let (incoming, server_addr) = setup_test_server(addr).await;

            let tls_config = create_test_tls_config().await;
            let (shutdown_tx, shutdown_rx) = oneshot::channel();

            let http_server_builder = HttpConnectionBuilder::new(TokioExecutor::new());
            let tower_service_fn = tower::service_fn(echo);
            let hyper_service = TowerToHyperService::new(tower_service_fn);

            let server = tokio::spawn(serve_http_with_shutdown(
                hyper_service,
                incoming,
                http_server_builder,
                Some(tls_config),
                Some(async {
                    shutdown_rx.await.ok();
                }),
            ));

            let (tls_connector, domain) = create_https_client().await;

            // Establish a connection
            let tcp_stream = TcpStream::connect(server_addr).await.unwrap();
            let tls_stream = tls_connector.connect(domain, tcp_stream).await.unwrap();

            let (mut sender, conn) =
                hyper::client::conn::http1::handshake(TokioIo::new(tls_stream))
                    .await
                    .unwrap();

            tokio::spawn(async move {
                if let Err(err) = conn.await {
                    eprintln!("Connection failed: {:?}", err);
                }
            });

            // Send a request
            let req = Request::builder()
                .uri("/")
                .body(Empty::<Bytes>::new())
                .unwrap();

            let res = sender.send_request(req).await.unwrap();
            assert_eq!(res.status(), StatusCode::OK);

            // Initiate graceful shutdown
            shutdown_tx.send(()).unwrap();

            // Wait a bit to allow the server to start shutting down
            tokio::time::sleep(Duration::from_millis(10)).await;

            // Try to send another request, it should fail
            let req = Request::builder()
                .uri("/")
                .body(Empty::<Bytes>::new())
                .unwrap();

            let result = sender.send_request(req).await;
            assert!(
                result.is_err(),
                "Expected request to fail after graceful shutdown"
            );

            server.await.unwrap().unwrap();
        }
    }
}
