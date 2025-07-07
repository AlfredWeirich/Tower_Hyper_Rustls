use std::{
    fmt::Debug,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use server::ServiceRespBody;

use hyper::{Request, Response};
use tower::{Layer, Service};

/// A Tower Layer that wraps a service with logging functionality, tagged with a server name.
#[derive(Clone)]
pub struct SimpleLoggerLayer {
    server_name: Arc<String>,
}

impl SimpleLoggerLayer {
    /// Create a new SimpleLoggerLayer with a name for the service/server.
    pub fn new(server_name: impl Into<String>) -> Self {
        Self {
            server_name: Arc::new(server_name.into()),
        }
    }
}

impl<S> Layer<S> for SimpleLoggerLayer {
    type Service = SimpleLoggerService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SimpleLoggerService {
            inner,
            server_name: Arc::clone(&self.server_name),
        }
    }
}

/// Middleware service that logs requests/responses and tags all logs with server_name.
#[derive(Clone)]
pub struct SimpleLoggerService<S> {
    inner: S,
    server_name: Arc<String>,
}

impl<S, ReqBody> Service<Request<ReqBody>> for SimpleLoggerService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ServiceRespBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
    S::Error: Debug + Send + 'static,
{
    type Response = Response<ServiceRespBody>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let server_name = Arc::clone(&self.server_name);
        tracing::info!(
            "{}: --> Request: {} {}",
            server_name,
            req.method(),
            req.uri()
        );

        // Clone inner to use in the async block
        let mut inner = self.inner.clone();
        let fut = inner.call(req);

        Box::pin(async move {
            let response = fut.await;
            match &response {
                Ok(res) => {
                    tracing::info!("{}: <-- Response: {}", server_name, res.status());
                }
                Err(err) => {
                    tracing::error!("{}: !! Error: {:?}", server_name, err);
                }
            }
            response
        })
    }
}
