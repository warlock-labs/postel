#[cfg(all(feature = "jemalloc", not(target_env = "msvc")))]
use tikv_jemallocator::Jemalloc;

#[cfg(all(feature = "jemalloc", not(target_env = "msvc")))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

pub use error::{Error as TransportError, Kind as TransportErrorKind};
pub use http::serve_http_connection;
pub use http::serve_http_with_shutdown;
pub use tcp::serve_tcp_incoming;
pub use tls::load_certs;
pub use tls::load_private_key;
pub use tls::serve_tls_incoming;

mod error;
mod fuse;
mod http;
mod io;
mod tcp;
mod tls;
mod test;

pub(crate) type Error = Box<dyn std::error::Error + Send + Sync>;
