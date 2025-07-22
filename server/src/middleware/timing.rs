use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Instant,
};

use hyper::{Request, Response};
use tower::{Layer, Service};

use server::ServiceRespBody;

/// A Tower `Layer` that wraps a service with timing functionality and a server name.
#[derive(Clone)]
pub struct TimingLayer {
    server_name: &'static str,
}

impl TimingLayer {
    pub fn new(server_name: &'static str) -> Self {
        Self {
            server_name: server_name,
        }
    }
}

impl<S> Layer<S> for TimingLayer {
    type Service = TimingMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TimingMiddleware {
            inner,
            server_name: self.server_name,
        }
    }
}

/// Middleware that logs request duration, tagged with server_name.
#[derive(Clone)]
pub struct TimingMiddleware<S> {
    inner: S,
    server_name: &'static str,
}

impl<S, ReqBody> Service<Request<ReqBody>> for TimingMiddleware<S>
where
    S: Service<Request<ReqBody>, Response = Response<ServiceRespBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
{
    type Response = Response<ServiceRespBody>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let mut inner = self.inner.clone();
        let server_name = self.server_name;
        let start = Instant::now();

        Box::pin(async move {
            let result = inner.call(req).await;
            let duration = start.elapsed();
            tracing::info!("{}: == Took {:.2?}", server_name, duration);
            result
        })
    }
}
