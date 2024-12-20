use std::ops::ControlFlow;
use std::pin::pin;
use std::{fs, io};

use futures::stream::StreamExt;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsAcceptor;
use tokio_stream::Stream;

use crate::error::handle_accept_error;
use crate::Error as TransportError;

/// Creates a stream of TLS-encrypted connections from a stream of TCP connections.
///
/// This function takes a stream of TCP connections and a TLS acceptor, and produces
/// a new stream that yields TLS-encrypted connections. It handles both successful
/// TLS handshakes and various error scenarios, providing a robust way to upgrade
/// TCP connections to TLS.
///
/// # Type Parameters
///
/// * `IO`: The I/O type representing the underlying TCP connection. It must implement
///   `AsyncRead`, `AsyncWrite`, `Unpin`], `Send`, and have a static lifetime.
/// * `IE`: The error type of the incoming TCP stream, which must be convertible to
///           the crate's `TransportError`.
///
/// # Arguments
///
/// * `tcp_stream`: A stream that yields `Result<IO, IE>` items, representing incoming
///   TCP connections or errors.
/// * `tls`: A `TlsAcceptor` used to perform the TLS handshake on each TCP connection.
///
/// # Returns
///
/// A new `Stream` that yields `Result<tokio_rustls::server::TlsStream<IO>, TransportError>`
/// items. Each item is either a successfully established TLS connection or an error.
///
/// # Error Handling
///
/// - TCP connection errors from the input stream are passed through the `handle_accept_error` function.
/// - TLS handshake errors are converted to `TransportError`.
/// - Non-fatal errors result in skipping the current connection attempt and continuing to the next.
/// - Fatal errors are propagated, potentially leading to stream termination.
///
/// # Examples
///
/// ```rust,no_run
/// use std::net::SocketAddr;
/// use tokio_stream::wrappers::TcpListenerStream;
/// use tokio::net::TcpListener;
/// use tokio_rustls::TlsAcceptor;
/// use std::sync::Arc;///
/// use hyper_server::{serve_tcp_incoming, serve_tls_incoming};
///
/// async fn run_tls_server(tls_config: Arc<rustls::ServerConfig>) {
///     let addr = SocketAddr::from(([127, 0, 0, 1], 8443));
///     let listener = TcpListener::bind("127.0.0.1:443").await.unwrap();
///     let tcp_stream = TcpListenerStream::new(listener);
///     let tls_acceptor = TlsAcceptor::from(tls_config);
///
///     let tcp_incoming = serve_tcp_incoming(tcp_stream);
///     let tls_stream = serve_tls_incoming(tcp_incoming, tls_acceptor);
///
///     // Use the tls_stream for further processing...
/// }
/// ```
#[inline]
pub fn serve_tls_incoming<IO, IE>(
    tcp_stream: impl Stream<Item = Result<IO, IE>> + Send + 'static,
    tls: TlsAcceptor,
) -> impl Stream<Item = Result<tokio_rustls::server::TlsStream<IO>, TransportError>>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    IE: Into<TransportError> + Send + 'static,
{
    async_stream::stream! {
        // Pin the TCP stream to the stack so that it's available and not moved in the loop
        let mut tcp_stream = pin!(tcp_stream);

        while let Some(result) = tcp_stream.next().await {
            match result {
                Ok(io) => {
                    // Attempt to perform the TLS handshake on the accepted TCP connection
                    match tls.accept(io).await {
                        Ok(tls_stream) => {
                            // Successful TLS handshake, yield the encrypted stream
                            yield Ok(tls_stream)
                        },
                        Err(e) => {
                            // Handle TLS handshake errors
                            // Convert the rustls error to a TransportError for consistent error handling
                            let transport_error = <io::Error as Into<TransportError>>::into(e);
                            match handle_accept_error(transport_error) {
                                ControlFlow::Continue(()) => {
                                    // Non-fatal error, skip this connection and continue to the next
                                    continue;
                                },
                                ControlFlow::Break(e) => {
                                    // Fatal error, yield the error and potentially end the stream
                                    yield Err(e)
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    // Handle TCP connection errors
                    // These errors are from the underlying TCP stream and are already `TransportError`s
                    match handle_accept_error(e.into()) {
                        ControlFlow::Continue(()) => {
                            // Non-fatal error, skip this connection and continue to the next
                            continue;
                        },
                        ControlFlow::Break(e) => {
                            // Fatal error, yield the error and potentially end the stream
                            yield Err(e)
                        }
                    }
                }
            }
        }
    }
}

/// Load the public certificate from a file.
///
/// This function reads a PEM-encoded certificate file and returns a vector of
/// parsed certificates.
///
/// # Arguments
///
/// * `filename`: The path to the certificate file.
///
/// # Returns
///
/// A `Result` containing a vector of `CertificateDer` on success, or an `io::Error` on failure.
#[inline]
pub fn load_certs(filename: &str) -> io::Result<Vec<CertificateDer<'static>>> {
    // Open certificate file
    let certfile = fs::File::open(filename)?;
    let mut reader = io::BufReader::new(certfile);

    // Load and return certificates
    // The `collect()` method is used to gather all certificates into a vector
    rustls_pemfile::certs(&mut reader).collect()
}

/// Load the private key from a file.
///
/// This function reads a PEM-encoded private key file and returns the parsed private key.
///
/// # Arguments
///
/// * `filename`: The path to the private key file.
///
/// # Returns
///
/// A `Result` containing a `PrivateKeyDer` on success, or an `io::Error` on failure.
#[inline]
pub fn load_private_key(filename: &str) -> io::Result<PrivateKeyDer<'static>> {
    // Open keyfile
    let keyfile = fs::File::open(filename)?;
    let mut reader = io::BufReader::new(keyfile);

    // Load and return a single private key
    // The `?` operator is used for error propagation
    rustls_pemfile::private_key(&mut reader)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "No private key found in file"))
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use futures::StreamExt;
    use rcgen::{CertificateParams, DistinguishedName, KeyPair};
    use rustls::pki_types::PrivatePkcs8KeyDer;
    use super::*;
    use crate::tcp::serve_tcp_incoming;
    use crate::test::helper::RUSTLS;
    use futures::StreamExt;
    use once_cell::sync::Lazy;
    use rustls::pki_types::{CertificateDer, ServerName};
    use rustls::RootCertStore;
    use rustls::{ClientConfig, ServerConfig};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::TlsAcceptor;
    use tokio_stream::wrappers::TcpListenerStream;
    use tracing::{debug, error, info, warn};

    use crate::tcp::serve_tcp_incoming;

    use super::*;

    struct TlsConfig {
        server_config: ServerConfig,
        client_config: ClientConfig,
    }

    fn generate_dynamic_tls_config() -> TlsConfig {
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

        // Configure Client
        let mut root_store = RootCertStore::empty();
        root_store
            .add(cert)
            .expect("Failed to add certificate to root store");

        let client_config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        TlsConfig {
            server_config,
            client_config,
        }
    }

    fn init_crypto_provider() {
        match rustls::crypto::aws_lc_rs::default_provider().install_default() {
            Ok(_) => debug!("Default crypto provider installed successfully"),
            Err(_) => {
                // Crypto provider already installed
                debug!("Crypto provider already installed");
            }
        }
    }

    async fn create_test_tls_acceptor() -> io::Result<(TlsAcceptor, ClientConfig)> {
        debug!("Creating test TLS acceptor");
        let tls_config = generate_dynamic_tls_config();

        Ok((
            TlsAcceptor::from(Arc::new(tls_config.server_config)),
            tls_config.client_config,
        ))
    }

    #[tokio::test]
    async fn test_tls_incoming_success() -> Result<(), Box<dyn std::error::Error>> {
        Lazy::force(&RUSTLS);
        let _guard = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .try_init();

        info!("Starting test_tls_incoming_success");
        let addr = SocketAddr::from(([127, 0, 0, 1], 0));
        let listener = TcpListener::bind(addr).await?;
        let server_addr = listener.local_addr()?;
        debug!("Server listening on {}", server_addr);
        let incoming = TcpListenerStream::new(listener);

        let (tls_acceptor, client_config) = create_test_tls_acceptor().await?;

        let tcp_incoming = serve_tcp_incoming(incoming);

        let server_task = tokio::spawn(async move {
            debug!("Server task started");
            let mut tls_stream = Box::pin(serve_tls_incoming(tcp_incoming, tls_acceptor));
            let result = tls_stream.next().await;
            debug!("Server received connection: {:?}", result.is_some());
            result
        });

        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));

        debug!("Client connecting to {}", server_addr);
        let tcp_stream = TcpStream::connect(server_addr).await?;
        let domain = ServerName::try_from("localhost")?;
        let _client_stream = connector.connect(domain, tcp_stream).await?;
        debug!("Client connected successfully");

        let result = server_task
            .await?
            .ok_or("Server task completed without result")?;
        match result {
            Ok(_) => info!("TLS connection established successfully"),
            Err(ref e) => error!("TLS connection failed: {}", e),
        }
        assert!(result.is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn test_tls_incoming_invalid_cert() -> Result<(), Box<dyn std::error::Error>> {
        Lazy::force(&RUSTLS);
      
        let _guard = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .try_init();

        info!("Starting test_tls_incoming_invalid_cert");
        let addr = SocketAddr::from(([127, 0, 0, 1], 0));
        let listener = TcpListener::bind(addr).await?;
        let server_addr = listener.local_addr()?;
        debug!("Server listening on {}", server_addr);
        let incoming = TcpListenerStream::new(listener);

        let (tls_acceptor, _) = create_test_tls_acceptor().await?;

        let tcp_incoming = serve_tcp_incoming(incoming);

        let server_task = tokio::spawn(async move {
            debug!("Server task started");
            let mut tls_stream = Box::pin(serve_tls_incoming(tcp_incoming, tls_acceptor));
            tokio::time::timeout(std::time::Duration::from_millis(1), tls_stream.next()).await
        });

        let untrusted_client_config = ClientConfig::builder()
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(untrusted_client_config));

        debug!("Client connecting to {}", server_addr);
        let tcp_stream = TcpStream::connect(server_addr).await?;
        let domain = ServerName::try_from("localhost")?;

        let client_result = connector.connect(domain, tcp_stream).await;
        assert!(
            client_result.is_err(),
            "Client connection should fail due to untrusted certificate"
        );
        info!(
            "Client connection failed as expected: {}",
            client_result.unwrap_err()
        );

        let server_result = server_task.await?;
        match server_result {
            Ok(Some(Ok(_))) => {
                warn!("Server accepted connection unexpectedly");
                panic!("Server should not establish connection");
            }
            Ok(Some(Err(e))) => {
                info!("Server did not establish connection as expected: {}", e);
            }
            Ok(None) => {
                info!("Server timed out waiting for connection, as expected");
            }
            Err(e) => {
                info!("Server task timed out: {}", e);
            }
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_tls_incoming_client_hello_timeout() -> Result<(), Box<dyn std::error::Error>> {
        Lazy::force(&RUSTLS);

        let _guard = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .try_init();

        info!("Starting test_tls_incoming_client_hello_timeout");
        let addr = SocketAddr::from(([127, 0, 0, 1], 0));
        let listener = TcpListener::bind(addr).await?;
        let server_addr = listener.local_addr()?;
        debug!("Server listening on {}", server_addr);
        let incoming = TcpListenerStream::new(listener);

        let (tls_acceptor, _) = create_test_tls_acceptor().await?;

        let tcp_incoming = serve_tcp_incoming(incoming);

        let server_task = tokio::spawn(async move {
            debug!("Server task started");
            let mut tls_stream = Box::pin(serve_tls_incoming(tcp_incoming, tls_acceptor));
            let result =
                tokio::time::timeout(std::time::Duration::from_millis(1), tls_stream.next()).await;
            debug!("Server task completed with result: {:?}", result.is_err());
            result
        });

        debug!("Client connecting with plain TCP to {}", server_addr);
        let _tcp_stream = TcpStream::connect(server_addr).await?;
        debug!("Client connected with plain TCP");

        let result = server_task.await?;
        match result {
            Ok(_) => warn!("Server did not timeout as expected"),
            Err(ref e) => info!("Server timed out as expected: {}", e),
        }
        assert!(result.is_err()); // Timeout error

        Ok(())
    }
}
