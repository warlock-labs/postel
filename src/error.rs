use crate::Error as TransportError;
use std::ops::ControlFlow;
use std::{error::Error as StdError, fmt, io};
use tracing::debug;

/// Handles errors that occur during connection acceptance.
///
/// This function determines whether an error should be treated as fatal (breaking the accept loop)
/// or non-fatal (allowing the loop to continue). This handler is crucial for maintaining the
/// stability and reliability of the server by appropriately handling different types of
/// errors at the accept stage.
///
/// # Arguments
///
/// * `e` - The error to handle, which can be converted into the crate's [`crate::Error`] type.
///
/// # Returns
///
/// * [`ControlFlow::Continue(())`] if the error is non-fatal and the accept loop should continue.
/// * [`ControlFlow::Break(Error)`] if the error is fatal and the accept loop should terminate.
///
/// # Error Handling
///
/// The function categorizes errors as follows:
/// - Non-fatal errors:
///       [`io::ErrorKind::ConnectionAborted`],
///       [`io::ErrorKind::Interrupted`],
///       [`io::ErrorKind::InvalidData`],
///       [`io::ErrorKind::WouldBlock`]
/// - Fatal errors: All other error types
pub(crate) fn handle_accept_error(e: impl Into<TransportError>) -> ControlFlow<TransportError> {
    // Convert the input error into our crate's Error type
    let e = e.into();

    // Log the error for debugging purposes
    debug!(error = %e, "connection accept loop error");

    // Check if the error is an I/O error
    if let Some(e) = e.downcast_ref::<io::Error>() {
        // Determine if the error is non-fatal
        if matches!(
            e.kind(),
            io::ErrorKind::ConnectionAborted  // Connection was aborted by the client or network
                | io::ErrorKind::Interrupted  // The operation was interrupted (e.g., by a signal)
                // Raised if TLS handshake failed
                | io::ErrorKind::InvalidData  // Received invalid data (might be temporary)
                | io::ErrorKind::WouldBlock // Operation would block (common in non-blocking I/O)
        ) {
            // For non-fatal errors, we continue the accept loop
            return ControlFlow::Continue(());
        }
    }

    // If it's not a non-fatal I/O error, then treat it as fatal error
    // This includes all other error types and I/O errors not explicitly handled above
    ControlFlow::Break(e)
}

/// A type alias for the source of an error, which is a boxed trait object.
/// This allows for dynamic dispatch and type erasure of the original error type.
type Source = Box<dyn StdError + Send + Sync + 'static>;

/// Represents errors that originate from the server.
/// This struct provides a public API for error handling.
pub struct Error {
    inner: ErrorImpl,
}

/// The internal implementation of the Error struct.
/// This separation allows for better control over the public API.
struct ErrorImpl {
    kind: Kind,
    source: Option<Source>,
}

/// Enum representing different kinds of errors that can occur.
/// Currently, only includes a Transport variant, but can be extended for more error types.
#[derive(Debug)]
pub enum Kind {
    Transport,
}

impl Error {
    /// Creates a new Error with a specific kind.
    pub fn new(kind: Kind) -> Self {
        Self {
            inner: ErrorImpl { kind, source: None },
        }
    }

    /// Attaches a source error to this Error.
    /// This method consumes self and returns a new Error, allowing for method chaining.
    pub fn with(mut self, source: impl Into<Source>) -> Self {
        self.inner.source = Some(source.into());
        self
    }

    /// Creates a new Transport Error with the given source.
    /// This is a convenience method combining new() and with().
    pub fn from_source(source: impl Into<crate::Error>) -> Self {
        Error::new(Kind::Transport).with(source)
    }

    /// Returns a string slice describing the error.
    fn description(&self) -> &str {
        match &self.inner.kind {
            Kind::Transport => "transport error",
        }
    }
}

/// Implements the Debug trait for Error.
/// This provides a custom debug representation of the error.
impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut f = f.debug_tuple("tonic::transport::Error");

        f.field(&self.inner.kind);

        if let Some(source) = &self.inner.source {
            f.field(source);
        }

        f.finish()
    }
}

/// Implements the Display trait for Error.
/// This provides a user-friendly string representation of the error.
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.description())
    }
}

/// Implements the std::error::Error trait for Error.
/// This allows our custom Error to be used with the standard error handling mechanisms in Rust.
impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.inner
            .source
            .as_ref()
            .map(|source| &**source as &(dyn StdError + 'static))
    }
}
