//! This module provides an abstraction layer for handling both plain TCP and TLS connections.
//! It allows higher-level code to work with a unified `Transport` type, regardless of whether
//! the underlying connection is encrypted or not.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::server::TlsStream;

/// Represents either a plain TCP connection or a TLS-encrypted connection.
///
/// This enum allows the rest of the application to work with connections
/// without needing to know whether they're encrypted or not.
pub(crate) enum Transport<IO> {
    /// Represents a plain, unencrypted connection.
    Plain(IO),
    /// Represents a TLS-encrypted connection.
    /// We use `Box` here to keep the enum size constant, as `TlsStream` might be larger than `IO`.
    Tls(Box<TlsStream<IO>>),
}

impl<IO> Transport<IO> {
    /// Creates a new `Transport` instance for a plain, unencrypted connection.
    ///
    /// # Arguments
    ///
    /// * `io` - The I/O object representing the connection.
    ///
    /// # Returns
    ///
    /// Returns a `Transport::Plain` variant containing the provided I/O object.
    #[inline]
    pub(crate) fn new_plain(io: IO) -> Self {
        Self::Plain(io)
    }

    /// Creates a new `Transport` instance for a TLS-encrypted connection.
    ///
    /// # Arguments
    ///
    /// * `io` - The `TlsStream` object representing the encrypted connection.
    ///
    /// # Returns
    ///
    /// Returns a `Transport::Tls` variant containing the provided TLS stream.
    #[inline]
    pub(crate) fn new_tls(io: TlsStream<IO>) -> Self {
        Self::Tls(Box::new(io))
    }
}

/// Implementation of `AsyncRead` for `Transport`.
///
/// This allows `Transport` to be used in asynchronous read operations,
/// regardless of whether it's a plain or TLS connection.
impl<IO> AsyncRead for Transport<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    /// Attempts to read from the transport into the provided buffer.
    ///
    /// # Arguments
    ///
    /// * `self` - Pinned mutable reference to the transport.
    /// * `cx` - The context for the current task.
    /// * `buf` - The buffer to read into.
    ///
    /// # Returns
    ///
    /// Returns a `Poll` indicating whether the operation is complete or pending.
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Transport::Plain(io) => Pin::new(io).poll_read(cx, buf),
            Transport::Tls(io) => Pin::new(io).poll_read(cx, buf),
        }
    }
}

/// Implementation of `AsyncWrite` for `Transport`.
///
/// This allows `Transport` to be used in asynchronous write operations,
/// regardless of whether it's a plain or TLS connection.
impl<IO> AsyncWrite for Transport<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    /// Attempts to write data from the provided buffer into the transport.
    ///
    /// # Arguments
    ///
    /// * `self` - Pinned mutable reference to the transport.
    /// * `cx` - The context for the current task.
    /// * `buf` - The buffer containing data to write.
    ///
    /// # Returns
    ///
    /// Returns a `Poll` containing the number of bytes written if successful.
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Transport::Plain(io) => Pin::new(io).poll_write(cx, buf),
            Transport::Tls(io) => Pin::new(io).poll_write(cx, buf),
        }
    }

    /// Attempts to flush the transport, ensuring all intermediately buffered contents reach their destination.
    ///
    /// # Arguments
    ///
    /// * `self` - Pinned mutable reference to the transport.
    /// * `cx` - The context for the current task.
    ///
    /// # Returns
    ///
    /// Returns a `Poll` indicating whether the flush operation is complete or pending.
    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Transport::Plain(io) => Pin::new(io).poll_flush(cx),
            Transport::Tls(io) => Pin::new(io).poll_flush(cx),
        }
    }

    /// Attempts to shut down the transport.
    ///
    /// # Arguments
    ///
    /// * `self` - Pinned mutable reference to the transport.
    /// * `cx` - The context for the current task.
    ///
    /// # Returns
    ///
    /// Returns a `Poll` indicating whether the shutdown operation is complete or pending.
    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Transport::Plain(io) => Pin::new(io).poll_shutdown(cx),
            Transport::Tls(io) => Pin::new(io).poll_shutdown(cx),
        }
    }

    /// Attempts to write a sequence of buffers to the transport.
    ///
    /// # Arguments
    ///
    /// * `self` - Pinned mutable reference to the transport.
    /// * `cx` - The context for the current task.
    /// * `bufs` - A slice of `IoSlice`s to write.
    ///
    /// # Returns
    ///
    /// Returns a `Poll` containing the number of bytes written if successful.
    #[inline]
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        match self.get_mut() {
            Transport::Plain(io) => Pin::new(io).poll_write_vectored(cx, bufs),
            Transport::Tls(io) => Pin::new(io).poll_write_vectored(cx, bufs),
        }
    }

    /// Determines whether this transport can write vectored data efficiently.
    ///
    /// # Returns
    ///
    /// Returns `true` if the transport supports vectored writing, `false` otherwise.
    #[inline]
    fn is_write_vectored(&self) -> bool {
        match self {
            Transport::Plain(io) => io.is_write_vectored(),
            Transport::Tls(io) => io.is_write_vectored(),
        }
    }
}
