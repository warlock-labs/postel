use std::future::{pending, Future};
use std::pin::pin;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures::stream::StreamExt;
use http::{Request, Response};
use http_body::Body;
use hyper::body::Incoming;
use hyper::rt::{Read, Write};
use hyper::service::Service;
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto::{Builder as HttpConnectionBuilder, HttpServerConnExec};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::sleep;
use tokio_rustls::TlsAcceptor;
use tokio_stream::Stream;
use tracing::{debug, trace};

use crate::fuse::Fuse;
use crate::io::Transport;

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

/// Handles TLS connection acceptance with proper error handling
async fn accept_tls_connection<IO>(
    io: IO,
    tls_acceptor: Arc<TlsAcceptor>,
) -> Result<tokio_rustls::server::TlsStream<IO>, crate::Error>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Perform TLS handshake in a blocking task to avoid impacting the runtime
    // Because this is one of the most computationally heavy things the sever does.
    // In the case of ECDSA and very fast handshakes, this has more downside
    // than upside, but in the case of RSA and slow handshakes, this is a good idea.
    // It amortizes out to about 2 µs of overhead per connection.
    // and moves this computationally heavy task off the main thread pool.
    match tokio::task::spawn_blocking(move || {
        tokio::runtime::Handle::current().block_on(tls_acceptor.accept(io))
    })
    .await
    {
        Ok(Ok(stream)) => Ok(stream),
        // This connection was malformed and the server was unable to handle it
        Ok(Err(e)) => Err(e.into()),
        Err(e) => Err(e.into()),
    }
}

/// Serves an HTTP connection, managing its lifecycle and handling requests.
///
/// This function takes a connection and processes HTTP requests using the provided service,
/// handling connection shutdown and cleanup appropriately.
///
/// # Type Parameters
///
/// * `B`: The body type for HTTP responses
/// * `IO`: The I/O type for the connection
/// * `S`: The service type that processes HTTP requests
/// * `E`: The executor type for the server connection
///
/// # Arguments
///
/// * `hyper_io`: The I/O object for the connection
/// * `hyper_service`: The service implementation for processing requests
/// * `builder`: Configuration builder for the connection
/// * `watcher`: Optional shutdown signal receiver
/// * `max_connection_age`: Optional maximum connection lifetime
#[inline]
pub async fn serve_http_connection<B, IO, S, E>(
    hyper_io: IO,
    hyper_service: S,
    builder: HttpConnectionBuilder<E>,
    watcher: Option<tokio::sync::watch::Receiver<()>>,
    max_connection_age: Option<Duration>,
) where
    B: Body + 'static,
    B::Error: Into<crate::Error>,
    IO: Read + Write + Unpin + Send + 'static,
    S: Service<Request<Incoming>, Response = Response<B>> + Clone + Send + 'static,
    S::Future: Send,
    S::Error: Into<crate::Error>,
    E: HttpServerConnExec<S::Future, B>,
{
    // Set up shutdown signal monitoring
    let mut watcher = watcher;
    let mut sig = pin!(Fuse {
        inner: watcher.as_mut().map(|w| w.changed()),
    });

    // Configure connection lifetime monitoring
    let sleep = sleep_or_pending(max_connection_age);
    tokio::pin!(sleep);

    // Create and pin the HTTP connection
    //
    // This handles all the HTTP connection logic via hyper.
    // This is a pointer to a blocking task, effectively
    // Which tells us how it's doing via the hyper_io transport.
    let mut conn = pin!(builder.serve_connection_with_upgrades(hyper_io, hyper_service));

    // Here we wait for the http connection to terminate
    loop {
        tokio::select! {
            result = &mut conn => {
                if let Err(err) = result {
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
    S::Future: Send,
    S::Error: Into<crate::Error>,
    ResBody: Body<Data = Bytes> + Send + 'static,
    ResBody::Error: Into<crate::Error> + Send,
    E: HttpServerConnExec<S::Future, ResBody> + Send + Sync + 'static,
{
    // Initialize shutdown signaling
    let (signal_tx, signal_rx) = tokio::sync::watch::channel(());
    let signal_tx = Arc::new(signal_tx);

    // We say that graceful shutdown is enabled if a signal is provided
    let graceful = signal.is_some();

    // The signal future that will resolve when the server should shut down
    let mut sig = pin!(Fuse { inner: signal });

    // Configure TLS if enabled
    let tls_acceptor = tls_config.map(|config| Arc::new(TlsAcceptor::from(config)));

    // Prepare connection handling
    let incoming = crate::tcp::serve_tcp_incoming(incoming);

    // Pin the incoming stream to the stack
    let mut incoming = pin!(incoming);

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
            Some(io_result) = incoming.next() => {
                let connection_service = service.clone();
                let connection_builder = builder.clone();
                let connection_signal_rx = graceful.then_some(signal_rx.clone());
                let connection_tls_acceptor = tls_acceptor.clone();

                tokio::spawn(async move {
                            let io = match io_result {
                            Ok(io) => io,
                            Err(e) => {
                                trace!("error accepting connection: {:#}", e);
                                return;
                            }
                        };

                        trace!("TCP streaming connection accepted");

                        let transport = if let Some(connection_tls_acceptor) = &connection_tls_acceptor {
                            match accept_tls_connection(io, Arc::clone(connection_tls_acceptor)).await {
                                Ok(tls_stream) => Transport::new_tls(tls_stream),
                                Err(e) => {
                                    // This connection failed to handshake
                                    debug!("TLS handshake failed: {:#}", e);
                                    return;
                                }
                            }
                        } else {
                            Transport::new_plain(io)
                        };

                        // Convert our abstracted tokio transport into a hyper transport
                        let hyper_io = TokioIo::new(transport);


                        // Create future for serving the connection
                        serve_http_connection(
                            hyper_io,
                            connection_service,
                            connection_builder,
                            connection_signal_rx,
                            None
                        ).await;
                    }
                );
            },
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
        signal_tx.closed().await;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http::StatusCode;
    use http_body_util::{BodyExt, Full};
    use hyper::{Request, Response};
    use hyper_util::rt::TokioExecutor;
    use rustls::ServerConfig;
    use std::net::SocketAddr;
    use std::time::Duration;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::oneshot;
    use tokio_stream::wrappers::TcpListenerStream;

    // Common test handler used by both HTTP and HTTPS tests
    async fn test_handler(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, hyper::Error> {
        match (req.method(), req.uri().path()) {
            (&hyper::Method::GET, "/") => {
                Ok(Response::new(Full::new(Bytes::from("Hello, World!"))))
            }
            (&hyper::Method::POST, "/echo") => {
                let body = req.collect().await?.to_bytes();
                Ok(Response::new(Full::new(body)))
            }
            (&hyper::Method::GET, "/delay") => {
                tokio::time::sleep(Duration::from_millis(100)).await;
                Ok(Response::new(Full::new(Bytes::from("Delayed response"))))
            }
            (&hyper::Method::GET, "/large") => {
                let large_data = vec![b'x'; 1024 * 1024]; // 1MB response
                Ok(Response::new(Full::new(Bytes::from(large_data))))
            }
            _ => {
                let mut res = Response::new(Full::new(Bytes::from("Not Found")));
                *res.status_mut() = StatusCode::NOT_FOUND;
                Ok(res)
            }
        }
    }

    // Helper for setting up test server
    async fn setup_test_server(
        // TODO this is not passed through in any meaningful way yet
        _max_conn_age: Option<Duration>,
    ) -> (SocketAddr, oneshot::Sender<()>) {
        let addr = SocketAddr::from(([127, 0, 0, 1], 0));
        let listener = TcpListener::bind(addr).await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let incoming = TcpListenerStream::new(listener);

        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let builder = HttpConnectionBuilder::new(TokioExecutor::new());
        let service = hyper::service::service_fn(test_handler);

        tokio::spawn(serve_http_with_shutdown(
            service,
            incoming,
            builder,
            None,
            Some(async {
                shutdown_rx.await.ok();
            }),
        ));

        (server_addr, shutdown_tx)
    }

    mod payload_tests {
        use super::*;

        #[tokio::test]
        async fn test_large_payload() {
            let (addr, shutdown_tx) = setup_test_server(None).await;
            let stream = TcpStream::connect(addr).await.unwrap();
            let io = TokioIo::new(stream);
            let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();

            tokio::spawn(async move {
                if let Err(err) = conn.await {
                    eprintln!("Connection failed: {:?}", err);
                }
            });

            // Test large response
            let req = Request::builder()
                .uri("/large")
                .body(Full::new(Bytes::new()))
                .unwrap();
            let res = sender.send_request(req).await.unwrap();
            assert_eq!(res.status(), StatusCode::OK);
            let body = res.collect().await.unwrap().to_bytes();
            assert_eq!(body.len(), 1024 * 1024);

            // Test large request
            let large_data = vec![b'x'; 1024 * 1024];
            let req = Request::builder()
                .method(hyper::Method::POST)
                .uri("/echo")
                .body(Full::new(Bytes::from(large_data.clone())))
                .unwrap();
            let res = sender.send_request(req).await.unwrap();
            assert_eq!(res.status(), StatusCode::OK);
            let body = res.collect().await.unwrap().to_bytes();
            assert_eq!(body.len(), large_data.len());

            shutdown_tx.send(()).unwrap();
        }

        #[tokio::test]
        async fn test_concurrent_large_payloads() {
            let (addr, shutdown_tx) = setup_test_server(None).await;
            let mut handles = Vec::new();

            for _ in 0..3 {
                let socket_addr = addr;
                let handle = tokio::spawn(async move {
                    let stream = TcpStream::connect(socket_addr).await.unwrap();
                    let io = TokioIo::new(stream);
                    let (mut sender, conn) =
                        hyper::client::conn::http1::handshake(io).await.unwrap();

                    tokio::spawn(async move {
                        if let Err(err) = conn.await {
                            eprintln!("Connection failed: {:?}", err);
                        }
                    });

                    let req = Request::builder()
                        .uri("/large")
                        .body(Full::new(Bytes::new()))
                        .unwrap();
                    let res = sender.send_request(req).await.unwrap();
                    assert_eq!(res.status(), StatusCode::OK);
                    let body = res.collect().await.unwrap();
                    assert_eq!(body.to_bytes().len(), 1024 * 1024);
                });
                handles.push(handle);
            }

            for handle in handles {
                handle.await.unwrap();
            }

            shutdown_tx.send(()).unwrap();
        }
    }

    mod shutdown_tests {
        use super::*;

        #[tokio::test]
        async fn test_graceful_shutdown_with_active_requests() {
            let (addr, shutdown_tx) = setup_test_server(None).await;

            // Start a slow request
            let slow_req = tokio::spawn(async move {
                let stream = TcpStream::connect(addr).await.unwrap();
                let io = TokioIo::new(stream);
                let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();

                tokio::spawn(async move {
                    if let Err(err) = conn.await {
                        eprintln!("Connection failed: {:?}", err);
                    }
                });

                let req = Request::builder()
                    .uri("/delay")
                    .body(Full::new(Bytes::new()))
                    .unwrap();
                sender.send_request(req).await
            });

            // Wait a bit then initiate shutdown
            tokio::time::sleep(Duration::from_millis(50)).await;
            shutdown_tx.send(()).unwrap();

            // The slow request should complete successfully
            let res = slow_req.await.unwrap().unwrap();
            assert_eq!(res.status(), StatusCode::OK);
            let body = res.collect().await.unwrap().to_bytes();
            assert_eq!(&body[..], b"Delayed response");
        }

        #[tokio::test]
        async fn test_shutdown_rejects_new_connections() {
            let (addr, shutdown_tx) = setup_test_server(None).await;

            // Send shutdown signal
            shutdown_tx.send(()).unwrap();

            // Wait a bit for shutdown to process
            tokio::time::sleep(Duration::from_millis(50)).await;

            // Attempt to connect should fail
            let result = TcpStream::connect(addr).await;
            assert!(result.is_err());
        }
    }

    mod https_tests {
        use super::*;
        use crate::test::helper::RUSTLS;
        use crate::{load_certs, load_private_key};
        use once_cell::sync::Lazy;

        async fn setup_test_tls_config() -> Arc<ServerConfig> {
            let certs = load_certs("examples/sample.pem").unwrap();
            let key = load_private_key("examples/sample.rsa").unwrap();
            let config = ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .unwrap();
            Arc::new(config)
        }

        async fn setup_test_client() -> (
            tokio_rustls::TlsConnector,
            rustls::pki_types::ServerName<'static>,
        ) {
            let mut root_store = rustls::RootCertStore::empty();
            root_store.add_parsable_certificates(load_certs("examples/sample.pem").unwrap());

            let client_config = rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();

            let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
            let domain = rustls::pki_types::ServerName::try_from("localhost").unwrap();

            (connector, domain)
        }

        async fn setup_tls_test_server() -> (SocketAddr, oneshot::Sender<()>, Arc<ServerConfig>) {
            let addr = SocketAddr::from(([127, 0, 0, 1], 0));
            let listener = TcpListener::bind(addr).await.unwrap();
            let server_addr = listener.local_addr().unwrap();
            let incoming = TcpListenerStream::new(listener);
            let (shutdown_tx, shutdown_rx) = oneshot::channel();
            let tls_config = setup_test_tls_config().await;
            let builder = HttpConnectionBuilder::new(TokioExecutor::new());
            let service = hyper::service::service_fn(test_handler);

            tokio::spawn(serve_http_with_shutdown(
                service,
                incoming,
                builder,
                Some(tls_config.clone()),
                Some(async {
                    shutdown_rx.await.ok();
                }),
            ));

            (server_addr, shutdown_tx, tls_config)
        }

        async fn connect_tls_client(
            addr: SocketAddr,
            connector: tokio_rustls::TlsConnector,
            domain: rustls::pki_types::ServerName<'static>,
        ) -> hyper::client::conn::http1::SendRequest<Full<Bytes>> {
            let tcp = TcpStream::connect(addr).await.unwrap();
            let tls_stream = connector.connect(domain, tcp).await.unwrap();
            let io = TokioIo::new(tls_stream);

            let (sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();

            tokio::spawn(async move {
                if let Err(err) = conn.await {
                    eprintln!("Connection failed: {:?}", err);
                }
            });

            sender
        }

        mod tls_connection_tests {
            use super::*;

            #[tokio::test]
            async fn test_tls_basic_request() {
                Lazy::force(&RUSTLS);
                let (addr, shutdown_tx, _) = setup_tls_test_server().await;
                let (connector, domain) = setup_test_client().await;
                let mut sender = connect_tls_client(addr, connector, domain).await;

                let req = Request::builder()
                    .uri("/")
                    .body(Full::new(Bytes::new()))
                    .unwrap();

                let res = sender.send_request(req).await.unwrap();
                assert_eq!(res.status(), StatusCode::OK);
                let body = res.collect().await.unwrap().to_bytes();
                assert_eq!(&body[..], b"Hello, World!");

                shutdown_tx.send(()).unwrap();
            }

            #[tokio::test]
            async fn test_tls_multiple_requests_same_connection() {
                Lazy::force(&RUSTLS);
                let (addr, shutdown_tx, _) = setup_tls_test_server().await;
                let (connector, domain) = setup_test_client().await;
                let mut sender = connect_tls_client(addr, connector, domain).await;

                // Send multiple requests on the same connection
                for _ in 0..3 {
                    let req = Request::builder()
                        .uri("/")
                        .body(Full::new(Bytes::new()))
                        .unwrap();

                    let res = sender.send_request(req).await.unwrap();
                    assert_eq!(res.status(), StatusCode::OK);
                    let body = res.collect().await.unwrap().to_bytes();
                    assert_eq!(&body[..], b"Hello, World!");
                }

                shutdown_tx.send(()).unwrap();
            }

            #[tokio::test]
            async fn test_tls_concurrent_connections() {
                Lazy::force(&RUSTLS);
                let (addr, shutdown_tx, _) = setup_tls_test_server().await;
                let mut handles = Vec::new();

                // Create multiple concurrent TLS connections
                for _ in 0..5 {
                    let socket_addr = addr;
                    let handle = tokio::spawn(async move {
                        let (connector, domain) = setup_test_client().await;
                        let mut sender = connect_tls_client(socket_addr, connector, domain).await;

                        let req = Request::builder()
                            .uri("/")
                            .body(Full::new(Bytes::new()))
                            .unwrap();

                        let res = sender.send_request(req).await.unwrap();
                        assert_eq!(res.status(), StatusCode::OK);
                        let body = res.collect().await.unwrap().to_bytes();
                        assert_eq!(&body[..], b"Hello, World!");
                    });
                    handles.push(handle);
                }

                for handle in handles {
                    handle.await.unwrap();
                }

                shutdown_tx.send(()).unwrap();
            }
        }

        mod tls_error_tests {
            use super::*;

            #[tokio::test]
            async fn test_invalid_client_cert() {
                Lazy::force(&RUSTLS);
                let (addr, shutdown_tx, _) = setup_tls_test_server().await;

                // Create a client with empty root store (won't trust server cert)
                let client_config = rustls::ClientConfig::builder()
                    .with_root_certificates(rustls::RootCertStore::empty())
                    .with_no_client_auth();

                let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
                let domain = rustls::pki_types::ServerName::try_from("localhost").unwrap();

                let tcp = TcpStream::connect(addr).await.unwrap();
                let result = connector.connect(domain, tcp).await;

                // Should fail due to untrusted certificate
                assert!(result.is_err());

                shutdown_tx.send(()).unwrap();
            }

            #[tokio::test]
            async fn test_wrong_hostname() {
                Lazy::force(&RUSTLS);
                let (addr, shutdown_tx, _) = setup_tls_test_server().await;
                let (connector, _) = setup_test_client().await;

                // Try to connect with wrong hostname
                let wrong_domain = rustls::pki_types::ServerName::try_from("wronghost").unwrap();
                let tcp = TcpStream::connect(addr).await.unwrap();
                let result = connector.connect(wrong_domain, tcp).await;

                // Should fail due to hostname mismatch
                assert!(result.is_err());

                shutdown_tx.send(()).unwrap();
            }
        }

        mod tls_payload_tests {
            use super::*;

            #[tokio::test]
            async fn test_tls_large_payload() {
                Lazy::force(&RUSTLS);
                let (addr, shutdown_tx, _) = setup_tls_test_server().await;
                let (connector, domain) = setup_test_client().await;
                let mut sender = connect_tls_client(addr, connector, domain).await;

                // Test large response
                let req = Request::builder()
                    .uri("/large")
                    .body(Full::new(Bytes::new()))
                    .unwrap();
                let res = sender.send_request(req).await.unwrap();
                assert_eq!(res.status(), StatusCode::OK);
                let body = res.collect().await.unwrap().to_bytes();
                assert_eq!(body.len(), 1024 * 1024);

                // Test large request
                let large_data = vec![b'x'; 1024 * 1024];
                let req = Request::builder()
                    .method(hyper::Method::POST)
                    .uri("/echo")
                    .body(Full::new(Bytes::from(large_data.clone())))
                    .unwrap();
                let res = sender.send_request(req).await.unwrap();
                assert_eq!(res.status(), StatusCode::OK);
                let body = res.collect().await.unwrap().to_bytes();
                assert_eq!(body.len(), large_data.len());

                shutdown_tx.send(()).unwrap();
            }
        }

        mod tls_shutdown_tests {
            use super::*;

            #[tokio::test]
            async fn test_tls_graceful_shutdown() {
                Lazy::force(&RUSTLS);
                let (addr, shutdown_tx, _) = setup_tls_test_server().await;
                let (connector, domain) = setup_test_client().await;
                let mut sender = connect_tls_client(addr, connector, domain).await;

                // Send a request before shutdown
                let req = Request::builder()
                    .uri("/")
                    .body(Full::new(Bytes::new()))
                    .unwrap();
                let res = sender.send_request(req).await.unwrap();
                assert_eq!(res.status(), StatusCode::OK);

                // Initiate shutdown
                shutdown_tx.send(()).unwrap();

                // Wait a bit
                tokio::time::sleep(Duration::from_millis(50)).await;

                // Try to send another request on the same connection
                let req = Request::builder()
                    .uri("/")
                    .body(Full::new(Bytes::new()))
                    .unwrap();
                let result = sender.send_request(req).await;

                // Should fail as connection is shutting down
                assert!(result.is_err());
            }
        }
    }
}
