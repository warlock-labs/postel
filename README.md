# postel

[![License](https://img.shields.io/crates/l/hyper-server)](https://choosealicense.com/licenses/mit/)
[![Crates.io](https://img.shields.io/crates/v/hyper-server)](https://crates.io/crates/hyper-server)
[![Docs](https://img.shields.io/crates/v/hyper-server?color=blue&label=docs)](https://docs.rs/hyper-server/)
![CI](https://github.com/warlock-labs/hyper-server/actions/workflows/CI.yml/badge.svg)
[![codecov](https://codecov.io/gh/warlock-labs/postel/branch/master/graph/badge.svg?token=kd22mPKFAL)](https://codecov.io/gh/warlock-labs/postel)

A high-performance, modular server implementation built on [hyper], designed to
work seamlessly with [axum], [tonic], [tower], and other tower-compatible
frameworks.

## Features

- HTTP/1 and HTTP/2 support
- TLS/HTTPS through [rustls]
- High performance leveraging [hyper] 1.0
- Modular architecture based on `tokio::net::TcpListener`, `tokio-rustls::Acceptor`, and `hyper::server::conn::auto`
- Flexible integration with [tower] the ecosystem, supporting various backends:
    - [axum]
    - [tonic]
    - Any `hyper::service::Service`, `tower::Service`, or `tower::Layer` composition

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
postel = "0.7.0"
```

## Usage

Here's an example of how to use postel with a simple tower lambda service via TCP/TLS/HTTP2 transport:

```rust
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, Response};
use hyper::body::Incoming;
use hyper_util::rt::TokioExecutor;
use hyper_util::server::conn::auto::Builder as HttpConnectionBuilder;
use hyper_util::service::TowerToHyperService;
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tower::{Layer, ServiceBuilder};
use tracing::{trace, debug, info};

use postel::{load_certs, load_private_key, serve_http_with_shutdown};

// Define a simple service that responds with "Hello, World!"
async fn hello(_: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    Ok(Response::new(Full::new(Bytes::from("Hello, World!"))))
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
    S: tower::Service<Request<B>, Response=Response<Full<Bytes>>>,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output=Result<Self::Response, Self::Error>> + Send>,
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

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = SocketAddr::from(([127, 0, 0, 1], 8443));
    // 1. Set up the TCP listener
    let listener = TcpListener::bind(addr).await?;
    info!("Listening on https://{}", addr);
    let incoming = TcpListenerStream::new(listener);

    // 2. Create the HTTP connection builder
    let builder = HttpConnectionBuilder::new(TokioExecutor::new());

    // 3. Set up the Tower service with middleware
    let svc = tower::service_fn(hello);
    let svc = ServiceBuilder::new()
        .layer(AddHeaderLayer) // Custom middleware
        .service(svc);

    // 4. Convert the Tower service to a Hyper service
    let svc = TowerToHyperService::new(svc);

    // 5. Set up TLS config
    let certs = load_certs("examples/sample.pem")?;
    let key = load_private_key("examples/sample.rsa")?;

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"http/1.0".to_vec()];
    let tls_config = Arc::new(config);

    // 6. Set up graceful shutdown
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    // Spawn a task to send the shutdown signal after 1 second
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let _ = shutdown_tx.send(());
        debug!("Shutdown signal sent");
    });

    // 7. Start the server
    info!("Starting HTTPS server...");
    serve_http_with_shutdown(
        svc,
        incoming,
        builder,
        Some(tls_config),
        Some(async {
            shutdown_rx.await.ok();
            info!("Shutdown signal received, starting graceful shutdown");
        }),
    )
        .await?;

    info!("Server has shut down");
    // Et voilà!
    // A flexible, high-performance server with custom services, middleware, 
    // http, tls, tcp, and graceful shutdown
    Ok(())
}
```

For more advanced usage and examples, please refer to, or contribute to,
the [examples directory](/examples).

## Architecture

postel provides a layered, composable architecture:

1. TCP Listening: `tokio::net::TcpListener`
2. TLS (optional): `rustls::TlsAcceptor`
3. HTTP: `hyper_util::server::conn::auto`
4. Service: `hyper::service::Service`
5. Middleware: `tower::Service`
6. Application: Your choice of tower-compatible framework (axum, tonic, etc.) or custom service implementation

This structure allows for easy customization and extension at each layer. You
can integrate your own implementations at any level of the stack, providing
maximum flexibility for your specific use case.

## Security

postel takes security seriously. We use `rustls` for TLS support, which
provides modern, secure defaults. However, please ensure that you configure
your server appropriately for your use case, especially when deploying in
production environments.

If you discover any security-related issues, please email team@warlock.xyz
instead of using the issue tracker.

## API

For detailed API documentation, please refer to the [API docs on docs.rs](https://docs.rs/hyper-server/).

## Minimum Supported Rust Version

postel's MSRV is `1.80`.

## Contributing

We welcome contributions to postel! Our contributing guidelines are
inspired by the Rule of St. Benedict, emphasizing humility, listening,
and community. Before contributing, please familiarize yourself with these
principles at [The Rule of St. Benedict](http://www.benedictfriend.org/the-rule.html).

Key points for contributors:

- Listen first, speak second (Chapter 6)
- Be humble in your contributions (Chapter 7)
- Work diligently and carefully (Chapter 48)
- Treat all code and ideas with respect (Chapter 72)

## License

This project is licensed under the MIT License — see
the [LICENSE](/LICENSE) file for details.

[axum]: https://crates.io/crates/axum

[hyper]: https://crates.io/crates/hyper

[rustls]: https://crates.io/crates/rustls

[tower]: https://crates.io/crates/tower

[tonic]: https://crates.io/crates/tonic

[tungstenite]: https://crates.io/crates/tungstenite
