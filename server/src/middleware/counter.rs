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
    server_name: Arc<String>,
}

impl CountingLayer {
    /// Create a new `CountingLayer` with a name for this server/service.
    pub fn new(server_name: impl Into<String>) -> Self {
        Self {
            server_name: Arc::new(server_name.into()),
        }
    }
}

impl<S> Layer<S> for CountingLayer {
    type Service = CountingService<S>;
    fn layer(&self, inner: S) -> Self::Service {
        CountingService::new(inner, self.server_name.as_ref())
    }
}

/// Middleware service that wraps another service and counts handled requests,
/// tagging all traces with a server name.
#[derive(Clone)]
pub struct CountingService<S> {
    inner: S,
    count: Arc<AtomicUsize>,
    server_name: Arc<String>,
}

impl<S> CountingService<S> {
    /// Create a new CountingService wrapping `inner` with `server_name`.
    pub fn new(inner: S, server_name: impl Into<String>) -> Self {
        Self {
            inner,
            count: Arc::new(AtomicUsize::new(0)),
            server_name: Arc::new(server_name.into()),
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
    server_name: Arc<String>,
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
            server_name: Arc::clone(&self.server_name),
        }
    }
}

// // This module provides a Tower middleware that counts the number of requests handled by a service.
// // It can be used to monitor the request load on a service in a thread-safe manner.
// // The `CountingLayer` can be applied to any service, and it wraps the service in a `CountingService`
// // that increments a shared counter each time a request is processed.
// // The counter can be accessed via the `get_count` method, which returns the total number of requests
// // that have been handled by the service so far.
// // The `CountingFuture` is used to ensure that the counter is incremented only after the inner service's
// // future resolves, allowing for accurate counting even in asynchronous contexts.
// // The middleware is designed to be composable with other Tower layers and services, making it easy to
// // integrate into existing Tower-based applications.

// use hyper::{Request, Response};
// use pin_project::pin_project;
// use std::{
//     future::Future,
//     pin::Pin,
//     sync::atomic::{AtomicUsize, Ordering},
//     sync::Arc,
//     task::{Context, Poll},
// };
// use tower::{Layer, Service};

// /// A Tower Layer that wraps services to count the number of handled requests.
// ///
// /// Can be composed in a Tower stack using `ServiceBuilder` or manually.
// /// The counter is thread-safe and can be accessed for monitoring.
// #[derive(Clone, Default)]
// pub struct CountingLayer;

// impl CountingLayer {
//     /// Create a new `CountingLayer`.
//     #[allow(dead_code)]
//     pub fn new() -> Self {
//         Self
//     }
// }

// impl<S> Layer<S> for CountingLayer {
//     type Service = CountingService<S>;

//     /// Wraps the given service with a `CountingService`, which counts requests.
//     fn layer(&self, inner: S) -> Self::Service {
//         CountingService::new(inner)
//     }
// }

// /// A Tower Service middleware that wraps another service and counts handled requests.
// ///
// /// The counter is internally thread-safe and shared if the middleware is cloned.
// #[derive(Clone)]
// pub struct CountingService<S> {
//     inner: S,
//     count: Arc<AtomicUsize>,
// }

// impl<S> CountingService<S> {
//     /// Creates a new `CountingService` wrapping the given inner service.
//     pub fn new(inner: S) -> Self {
//         Self {
//             inner,
//             count: Arc::new(AtomicUsize::new(0)),
//         }
//     }

//     /// Returns the total number of requests that have completed so far.
//     ///
//     /// Note: If this service is cloned, all clones share the same counter.
//     #[allow(dead_code)]
//     pub fn get_count(&self) -> usize {
//         self.count.load(Ordering::Relaxed)
//     }
// }

// /// Future returned by `CountingService`, which increments the count once the
// /// inner service's future completes.
// ///
// /// Uses pin-project to safely handle potentially non-Unpin inner futures.
// #[pin_project]
// pub struct CountingFuture<F, ResBody, Error>
// where
//     F: Future<Output = Result<Response<ResBody>, Error>>,
// {
//     /// The future returned by the inner service.
//     #[pin]
//     inner_fut: F,
//     /// Shared counter, incremented once the future resolves.
//     count: Arc<AtomicUsize>,
// }

// impl<F, ResBody, Error> Future for CountingFuture<F, ResBody, Error>
// where
//     F: Future<Output = Result<Response<ResBody>, Error>>,
// {
//     type Output = Result<Response<ResBody>, Error>;

//     /// Polls the inner future. When it is ready, increments the request counter.
//     fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
//         let this = self.project(); // Projects all #[pin] fields as Pin<&mut F>
//         match this.inner_fut.poll(cx) {
//             Poll::Ready(result) => {
//                 // Atomically increment the counter when the response is ready.
//                 let old = this.count.fetch_add(1, Ordering::Relaxed) + 1;

//                 tracing::info!("Request count: {old}");
//                 Poll::Ready(result)
//             }
//             Poll::Pending => Poll::Pending,
//         }
//     }
// }

// impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for CountingService<S>
// where
//     S: Service<Request<ReqBody>, Response = Response<ResBody>>,
//     S::Future: Future<Output = Result<Response<ResBody>, S::Error>> + Send + 'static,
// {
//     type Response = Response<ResBody>;
//     type Error = S::Error;
//     type Future = CountingFuture<S::Future, ResBody, S::Error>;

//     /// Polls the inner service for readiness.
//     fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
//         self.inner.poll_ready(cx)
//     }

//     /// Calls the inner service, returning a future that increments the request count
//     /// once the inner future completes.
//     fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
//         let inner_fut = self.inner.call(req);
//         CountingFuture {
//             inner_fut,
//             count: Arc::clone(&self.count),
//         }
//     }
// }
