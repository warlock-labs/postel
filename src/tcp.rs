use crate::error::handle_accept_error;
use crate::Error as TransportError;
use std::ops::ControlFlow;
use std::pin::pin;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_stream::{Stream, StreamExt};

/// Creates an IO stream that yields a TCP stream for each incoming connection.
///
/// This function takes a stream of incoming connections and handles errors that may occur
/// during the acceptance process. It will continue to yield connections even if non-fatal
/// errors occur, but will terminate if a fatal error is encountered.
///
/// Effectively, it acts as a demultiplexer for incoming TCP connections.
///
/// # Type Parameters
///
/// * `IO`: The type of the I/O object yielded by the incoming stream,
///   usually a tokio IO.
/// * `IE`: The type of the error that can be produced by the incoming stream,
///   usually a Tokio error.
///
/// # Arguments
///
/// * `incoming`: A stream that yields results of incoming connection attempts.
///
/// # Returns
///
/// A stream that yields `Result<IO, Error>` for each incoming connection.
///
/// # Error Handling
///
/// This function determines whether to continue accepting
/// connections after an error occurs. Non-fatal errors are logged to debug
/// and skipped, while fatal errors cause the stream to yield an error
/// and terminate.
///
/// # Examples
///
/// ```rust,no_run
/// use std::net::SocketAddr;
/// use tokio::net::TcpListener;
/// use tokio_stream::wrappers::TcpListenerStream;
/// use postel::serve_tcp_incoming;
///
/// #[tokio::main]
/// async fn main() {
///     let addr = SocketAddr::from(([127, 0, 0, 1], 0));  // Using port 0 for dynamic port assignment
///     let listener = TcpListener::bind(addr).await.unwrap();
///     let incoming = TcpListenerStream::new(listener);
///     let tcp_stream = serve_tcp_incoming(incoming);
///
///     // Use the tcp_stream for further processing
/// }
/// ```
#[inline]
pub fn serve_tcp_incoming<IO, IE>(
    incoming: impl Stream<Item = Result<IO, IE>> + Send + 'static,
) -> impl Stream<Item = Result<IO, TransportError>>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    IE: Into<TransportError> + Send + 'static,
{
    async_stream::stream! {
        // We pin the stream on the stack to ensure that it's safe to
        // pass out of scope
        let mut incoming = pin!(incoming);

        // Continuously process incoming connections
        while let Some(item) = incoming.next().await {
            match item {
                // If the connection is successfully established, yield it
                Ok(io) => {
                    // Spawn a new task for each connection
                    let handle = tokio::spawn(async move {
                        Ok(io)
                    });

                    // Await the result from the spawned task
                    match handle.await {
                        Ok(result) => yield result,
                        Err(e) => yield Err(e.into()),
                    }
                },
                // Handle errors using the handle_accept_error function
                Err(e) => match handle_accept_error(e.into()) {
                    // For non-fatal errors, continue to the next incoming
                    // connection on the `IO` stream
                    ControlFlow::Continue(()) => continue,
                    // For fatal errors, yield the error and terminate
                    // the stream, breaking the loop
                    ControlFlow::Break(e) => yield Err(e),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::stream::iter;
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use tokio_stream::Stream;

    // Mock IO struct for testing
    // This struct simulates an AsyncRead and AsyncWrite implementation
    // with controllable behavior for testing various scenarios
    struct MockIO {
        // We use Option here to allow consuming the result in poll_read and poll_write
        read_result: Option<io::Result<()>>,
        write_result: Option<io::Result<usize>>,
    }

    impl AsyncRead for MockIO {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            // Take the result, leaving None in its place
            Poll::Ready(self.read_result.take().unwrap_or(Ok(())))
        }
    }

    impl AsyncWrite for MockIO {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &[u8],
        ) -> Poll<io::Result<usize>> {
            // Take the result, leaving None in its place
            Poll::Ready(self.write_result.take().unwrap_or(Ok(0)))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl Unpin for MockIO {}

    // Helper function to create a stream of mock IOs
    // This function allows us to easily create test scenarios with predefined outcomes
    fn mock_incoming(
        results: Vec<Result<MockIO, io::Error>>,
    ) -> impl Stream<Item = Result<MockIO, io::Error>> {
        iter(results)
    }

    // Test that non-fatal errors are handled correctly by handle_accept_error
    #[tokio::test]
    async fn test_handle_accept_error_non_fatal() {
        let non_fatal_errors = vec![
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::Interrupted,
            io::ErrorKind::InvalidData,
            io::ErrorKind::WouldBlock,
        ];

        for kind in non_fatal_errors {
            let error = io::Error::new(kind, "Test non-fatal error");
            assert!(matches!(
                handle_accept_error(error),
                ControlFlow::Continue(())
            ));
        }
    }

    // Test that fatal errors are handled correctly by handle_accept_error
    #[tokio::test]
    async fn test_handle_accept_error_fatal() {
        let fatal_error = io::Error::new(io::ErrorKind::PermissionDenied, "Test fatal error");
        assert!(matches!(
            handle_accept_error(fatal_error),
            ControlFlow::Break(_)
        ));
    }

    // Test successful TCP connection acceptance
    #[tokio::test]
    async fn test_serve_tcp_incoming_success() {
        let mock_io = MockIO {
            read_result: Some(Ok(())),
            write_result: Some(Ok(5)),
        };
        let incoming = mock_incoming(vec![Ok(mock_io)]);
        let mut stream = Box::pin(serve_tcp_incoming(incoming));

        if let Some(result) = stream.next().await {
            assert!(result.is_ok());
        } else {
            panic!("Stream ended unexpectedly");
        }
    }

    // Test handling of non-fatal errors during connection acceptance
    #[tokio::test]
    async fn test_serve_tcp_incoming_non_fatal_error() {
        let non_fatal_error = io::Error::new(io::ErrorKind::WouldBlock, "Would block");
        let incoming = mock_incoming(vec![
            Err(non_fatal_error),
            Ok(MockIO {
                read_result: Some(Ok(())),
                write_result: Some(Ok(5)),
            }),
        ]);
        let mut stream = Box::pin(serve_tcp_incoming(incoming));

        if let Some(result) = stream.next().await {
            assert!(result.is_ok());
        } else {
            panic!("Stream ended unexpectedly");
        }
    }

    // Test handling of fatal errors during connection acceptance
    #[tokio::test]
    async fn test_serve_tcp_incoming_fatal_error() {
        let fatal_error = io::Error::new(io::ErrorKind::PermissionDenied, "Permission denied");
        let incoming = mock_incoming(vec![Err(fatal_error)]);
        let mut stream = Box::pin(serve_tcp_incoming(incoming));

        if let Some(result) = stream.next().await {
            assert!(result.is_err());
        } else {
            panic!("Stream ended unexpectedly");
        }

        // Stream should be terminated after a fatal error
        assert!(stream.next().await.is_none());
    }

    // Test a mix of successful connections, non-fatal errors, and fatal errors
    #[tokio::test]
    async fn test_serve_tcp_incoming_mixed_results() {
        let incoming = mock_incoming(vec![
            Ok(MockIO {
                read_result: Some(Ok(())),
                write_result: Some(Ok(5)),
            }),
            Err(io::Error::new(io::ErrorKind::WouldBlock, "Would block")),
            Ok(MockIO {
                read_result: Some(Ok(())),
                write_result: Some(Ok(3)),
            }),
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Permission denied",
            )),
        ]);
        let mut stream = Box::pin(serve_tcp_incoming(incoming));

        // First successful connection
        assert!(stream.next().await.unwrap().is_ok());

        // Second successful connection (after skipping non-fatal error)
        assert!(stream.next().await.unwrap().is_ok());

        // Fatal error
        assert!(stream.next().await.unwrap().is_err());

        // Stream should be terminated after a fatal error
        assert!(stream.next().await.is_none());
    }

    // Test behavior with an empty incoming stream
    #[tokio::test]
    async fn test_serve_tcp_incoming_empty_stream() {
        let incoming = mock_incoming(vec![]);
        let mut stream = Box::pin(serve_tcp_incoming(incoming));

        assert!(stream.next().await.is_none());
    }
}
