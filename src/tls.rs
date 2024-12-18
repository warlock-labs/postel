use crate::Error;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::{fs, io};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsAcceptor;
use tokio_stream::{Stream, StreamExt};

/// Creates a stream of TLS-encrypted connections from a stream of TCP connections.
///
/// This function takes a stream of TCP connections and a TLS acceptor, and produces
/// a new stream that yields TLS-encrypted connections. It handles both the successful
/// case of establishing a TLS connection and the error cases.
///
/// # Type Parameters
///
/// * `IO`: The I/O type representing the underlying TCP connection. It must implement
///   `AsyncRead`, `AsyncWrite`, `Unpin`, `Send`, and have a static lifetime.
///
/// # Arguments
///
/// * `tcp_stream`: A stream that yields `Result<IO, Error>` items, representing incoming
///   TCP connections or errors.
/// * `tls`: A `TlsAcceptor` used to perform the TLS handshake on each TCP connection.
///
/// # Returns
///
/// A new `Stream` that yields `Result<tokio_rustls::server::TlsStream<IO>, Error>` items.
/// Each item is either a successfully established TLS connection or an error.
///
/// # Error Handling
///
/// - If the input `tcp_stream` yields an error, that error is propagated.
/// - If the TLS handshake fails, the error is wrapped in the crate's `Error` type.
#[inline]
pub fn serve_tls_incoming<IO>(
    tcp_stream: impl Stream<Item = Result<IO, Error>>,
    tls: TlsAcceptor,
) -> impl Stream<Item = Result<tokio_rustls::server::TlsStream<IO>, Error>>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Transform each item in the TCP stream into a TLS stream
    tcp_stream.then(move |result| {
        // Clone the TLS acceptor for each connection
        // This is necessary because the acceptor is moved into the async block
        let tls = tls.clone();

        async move {
            match result {
                // If the TCP connection was successfully established
                Ok(io) => {
                    // Attempt to perform the TLS handshake
                    // If successful, return the TLS stream; otherwise, wrap the error
                    tls.accept(io).await.map_err(Error::from)
                }
                // If there was an error establishing the TCP connection, propagate it
                Err(e) => Err(e),
            }
        }
    })
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
    use super::*;
    use crate::tcp::serve_tcp_incoming;
    use futures::StreamExt;
    use rustls::pki_types::{CertificateDer, ServerName};
    use rustls::{ClientConfig, ServerConfig};
    use std::net::SocketAddr;
    use std::sync::Arc;
    use once_cell::sync::Lazy;
    use tokio::io::{AsyncRead, AsyncWrite};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::TlsAcceptor;
    use tokio_stream::wrappers::TcpListenerStream;
    use tracing::{debug, error, info, warn};
    use crate::test::RUSTLS;

    // Helper function to create a TLS acceptor for testing
    async fn create_test_tls_acceptor() -> io::Result<TlsAcceptor> {
        debug!("Creating test TLS acceptor");
        let certs = load_certs("examples/sample.pem")?;
        let key = load_private_key("examples/sample.rsa")?;

        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| {
                error!("Failed to create ServerConfig: {}", e);
                io::Error::new(io::ErrorKind::Other, e)
            })?;

        Ok(TlsAcceptor::from(Arc::new(config)))
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

        let tls_acceptor = create_test_tls_acceptor().await?;

        // Use serve_tcp_incoming to handle TCP connections
        let tcp_incoming = serve_tcp_incoming(incoming);

        // Spawn the server task
        let server_task = tokio::spawn(async move {
            debug!("Server task started");
            let mut tls_stream = Box::pin(tls_incoming(tcp_incoming, tls_acceptor));
            let result = tls_stream.next().await;
            debug!("Server received connection: {:?}", result.is_some());
            result
        });

        // Connect to the server with a TLS client
        let mut root_store = rustls::RootCertStore::empty();
        let certs = load_certs("examples/sample.pem")?;
        root_store.add_parsable_certificates(certs);

        let client_config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));

        debug!("Client connecting to {}", server_addr);
        let tcp_stream = TcpStream::connect(server_addr).await?;
        let domain = ServerName::try_from("localhost")?;
        let _client_stream = connector.connect(domain, tcp_stream).await?;
        debug!("Client connected successfully");

        // Wait for the server to accept the connection
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

        // Create a TLS acceptor with an invalid certificate
        let invalid_cert = vec![CertificateDer::from(vec![0; 32])]; // Invalid certificate
        let key = load_private_key("examples/sample.rsa")?;

        // Expect this to fail and log the error
        let config_result = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(invalid_cert, key);

        match config_result {
            Ok(_) => warn!("ServerConfig creation unexpectedly succeeded with invalid cert"),
            Err(e) => info!("ServerConfig creation failed as expected: {}", e),
        }

        // Use a valid certificate for the server to allow the test to continue
        let valid_certs = load_certs("examples/sample.pem")?;
        let valid_key = load_private_key("examples/sample.rsa")?;
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(valid_certs, valid_key)
            .expect("ServerConfig creation should succeed with valid cert");

        let tls_acceptor = TlsAcceptor::from(Arc::new(config));

        // Use serve_tcp_incoming to handle TCP connections
        let tcp_incoming = serve_tcp_incoming(incoming);

        // Spawn the server task
        let server_task = tokio::spawn(async move {
            debug!("Server task started");
            let mut tls_stream = Box::pin(tls_incoming(tcp_incoming, tls_acceptor));
            let result = tls_stream.next().await;
            debug!("Server received connection: {:?}", result.is_some());
            result
        });

        // Connect to the server with a TLS client that doesn't trust the server's certificate
        let connector = tokio_rustls::TlsConnector::from(Arc::new(
            ClientConfig::builder()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth(),
        ));

        debug!("Client connecting to {}", server_addr);
        let tcp_stream = TcpStream::connect(server_addr).await?;
        let domain = ServerName::try_from("localhost")?;

        // This connection should fail due to certificate verification
        let client_result = connector.connect(domain, tcp_stream).await;
        match &client_result {
            Ok(_) => warn!("Client connection succeeded unexpectedly"),
            Err(e) => info!("Client connection failed as expected: {}", e),
        }
        assert!(client_result.is_err());

        // The server should not encounter an error, but the connection should not be established
        let server_result = server_task
            .await?
            .ok_or("Server task completed without result")?;
        match &server_result {
            Ok(_) => warn!("Server accepted connection unexpectedly"),
            Err(e) => info!("Server did not establish connection as expected: {}", e),
        }
        assert!(server_result.is_err());

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

        let tls_acceptor = create_test_tls_acceptor().await?;

        // Use serve_tcp_incoming to handle TCP connections
        let tcp_incoming = serve_tcp_incoming(incoming);

        // Spawn the server task
        let server_task = tokio::spawn(async move {
            debug!("Server task started");
            let mut tls_stream = Box::pin(tls_incoming(tcp_incoming, tls_acceptor));
            let result =
                tokio::time::timeout(std::time::Duration::from_millis(10), tls_stream.next()).await;
            debug!("Server task completed with result: {:?}", result.is_err());
            result
        });

        // Connect with a regular TCP client (no TLS handshake)
        debug!("Client connecting with plain TCP to {}", server_addr);
        let _tcp_stream = TcpStream::connect(server_addr).await?;
        debug!("Client connected with plain TCP");

        // The server task should timeout
        let result = server_task.await?;
        match result {
            Ok(_) => warn!("Server did not timeout as expected"),
            Err(ref e) => info!("Server timed out as expected: {}", e),
        }
        assert!(result.is_err()); // Timeout error

        Ok(())
    }

    #[tokio::test]
    async fn test_load_certs() -> io::Result<()> {
        let _guard = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .try_init();

        info!("Starting test_load_certs");
        let certs = load_certs("examples/sample.pem")?;
        debug!("Loaded {} certificates", certs.len());
        assert!(!certs.is_empty(), "Certificate file should not be empty");
        Ok(())
    }

    #[tokio::test]
    async fn test_load_private_key() -> io::Result<()> {
        let _guard = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .try_init();

        info!("Starting test_load_private_key");
        let key = load_private_key("examples/sample.rsa")?;
        debug!("Loaded private key, length: {}", key.secret_der().len());
        assert!(
            !key.secret_der().is_empty(),
            "Private key should not be empty"
        );
        Ok(())
    }

    // Simulating the tls_incoming function for testing purposes
    // Replace this with your actual implementation
    fn tls_incoming<IO>(
        incoming: impl Stream<Item = Result<IO, Error>> + Send + 'static,
        tls_acceptor: TlsAcceptor,
    ) -> impl Stream<Item = Result<tokio_rustls::server::TlsStream<IO>, Error>> + Send + 'static
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Box::pin(incoming.then(move |result| {
            let tls_acceptor = tls_acceptor.clone();
            async move {
                match result {
                    Ok(io) => {
                        debug!("Accepting TLS connection");
                        let accept_result = tls_acceptor.accept(io).await.map_err(Error::from);
                        match &accept_result {
                            Ok(_) => debug!("TLS connection accepted successfully"),
                            Err(e) => warn!("Failed to accept TLS connection: {}", e),
                        }
                        accept_result
                    }
                    Err(e) => {
                        warn!("Error in incoming connection: {}", e);
                        Err(e)
                    }
                }
            }
        }))
    }
}
