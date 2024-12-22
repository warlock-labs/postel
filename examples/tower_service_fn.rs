use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::{Request, Response};
use hyper_util::rt::TokioExecutor;
use hyper_util::server::conn::auto::Builder as HttpConnectionBuilder;
use hyper_util::service::TowerToHyperService;
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tower::{Layer, ServiceBuilder};
use tracing::{debug, info, trace};

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

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // 1. Set up the TCP listener
    let addr = SocketAddr::from(([127, 0, 0, 1], 8443));

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
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

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
    // A flexible, high-performance server with custom services,
    // middleware, http, tls, tcp, and graceful shutdown
    Ok(())
}
