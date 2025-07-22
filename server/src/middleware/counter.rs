use hyper::{Request, Response};
use pin_project::pin_project;
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    sync::atomic::{AtomicUsize, Ordering},
    task::{Context, Poll},
};
use tower::{Layer, Service};

/// A Tower Layer that wraps services to count the number of handled requests,
/// with a server name label for all tracing.
#[derive(Clone)]
pub struct CountingLayer {
    server_name: &'static str,
}

impl CountingLayer {
    /// Create a new `CountingLayer` with a name for this server/service.
    pub fn new(server_name: &'static str) -> Self {
        Self {
            server_name: server_name,
        }
    }
}

impl<S> Layer<S> for CountingLayer {
    type Service = CountingService<S>;
    fn layer(&self, inner: S) -> Self::Service {
        CountingService::new(inner, self.server_name)
    }
}

/// Middleware service that wraps another service and counts handled requests,
/// tagging all traces with a server name.
#[derive(Clone)]
pub struct CountingService<S> {
    inner: S,
    count: Arc<AtomicUsize>,
    server_name: &'static str,
}

impl<S> CountingService<S> {
    /// Create a new CountingService wrapping `inner` with `server_name`.
    pub fn new(inner: S, server_name: &'static str) -> Self {
        Self {
            inner,
            count: Arc::new(AtomicUsize::new(0)),
            server_name: server_name,
        }
    }
}

#[pin_project]
pub struct CountingFuture<F, ResBody, Error>
where
    F: Future<Output = Result<Response<ResBody>, Error>>,
{
    #[pin]
    inner_fut: F,
    count: Arc<AtomicUsize>,
    server_name: &'static str,
}

impl<F, ResBody, Error> Future for CountingFuture<F, ResBody, Error>
where
    F: Future<Output = Result<Response<ResBody>, Error>>,
{
    type Output = Result<Response<ResBody>, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        match this.inner_fut.poll(cx) {
            Poll::Ready(result) => {
                let old = this.count.fetch_add(1, Ordering::Relaxed) + 1;
                tracing::info!("{}: Request count: {old}", this.server_name);
                Poll::Ready(result)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for CountingService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    S::Future: Future<Output = Result<Response<ResBody>, S::Error>> + Send + 'static,
{
    type Response = Response<ResBody>;
    type Error = S::Error;
    type Future = CountingFuture<S::Future, ResBody, S::Error>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let inner_fut = self.inner.call(req);
        CountingFuture {
            inner_fut,
            count: Arc::clone(&self.count),
            server_name: self.server_name,
        }
    }
}
