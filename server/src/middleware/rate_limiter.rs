use std::{
    fmt::Debug,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use bytes::Bytes;
use http_body_util::Full;

#[cfg(feature = "boxed_body")]
use http_body_util::BodyExt;

use hyper::{Request, Response, StatusCode};
use tokio::sync::Mutex;
use tower::{Layer, Service};
use tracing::{info, trace, warn};

use server::ServiceRespBody;
#[cfg(feature = "boxed_body")]
use server::SrvError; // BoxBody<Bytes, SrvError>

// ============ SIMPLE RATE LIMITER ============

#[derive(Clone)]
pub struct SimpleRateLimiterLayer {
    limit_duration: Duration,
    server_name: &'static str,
}

impl SimpleRateLimiterLayer {
    pub fn new(per: Duration, server_name: &'static str) -> Self {
        Self {
            limit_duration: per,
            server_name: server_name,
        }
    }
}

impl<S> Layer<S> for SimpleRateLimiterLayer {
    type Service = SimpleRateLimiterService<S>;
    fn layer(&self, inner: S) -> Self::Service {
        SimpleRateLimiterService::new(inner, self.limit_duration, self.server_name)
    }
}

#[derive(Clone)]
pub struct SimpleRateLimiterService<S> {
    inner: S,
    state: Arc<Mutex<RateLimitState>>,
    limit_duration: Duration,
    server_name: &'static str,
}

#[derive(Debug)]
struct RateLimitState {
    next_allowed: Instant,
}

impl<S> SimpleRateLimiterService<S> {
    pub fn new(inner: S, per: Duration, server_name: &'static str) -> Self {
        trace!(
            "{}: Creating SimpleRateLimiterService with limit duration: {:?}",
            server_name, per
        );
        Self {
            inner,
            state: Arc::new(Mutex::new(RateLimitState {
                next_allowed: Instant::now(),
            })),
            limit_duration: per,
            server_name,
        }
    }
}

impl<S, ReqBody> Service<Request<ReqBody>> for SimpleRateLimiterService<S>
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
        let state = self.state.clone();
        let delay = self.limit_duration;
        let server_name = self.server_name;

        Box::pin(async move {
            let mut state = state.lock().await;
            let now = Instant::now();

            if now < state.next_allowed {
                warn!("{}: Too Many Requests (simple limiter)", server_name);
                #[cfg(feature = "boxed_body")]
                let body: ServiceRespBody = Full::new(Bytes::from_static(b"Too Many Requests"))
                    .map_err(SrvError::from)
                    .boxed();
                #[cfg(not(feature = "boxed_body"))]
                let body: ServiceRespBody = Full::new(Bytes::from_static(b"Too Many Requests"));
                let mut response = Response::new(body);
                *response.status_mut() = StatusCode::TOO_MANY_REQUESTS;
                return Ok(response);
            }

            state.next_allowed = now + delay;
            drop(state);

            trace!("{}: Allowed request", server_name);
            inner.call(req).await
        })
    }
}

// ============ TOKEN BUCKET RATE LIMITER ============

#[derive(Clone)]
pub struct TokenBucketRateLimiterLayer {
    capacity: usize,
    refill_tokens: usize,
    interval: Duration,
    server_name: &'static str,
}

impl TokenBucketRateLimiterLayer {
    pub fn new(
        capacity: usize,
        refill_tokens: usize,
        interval: Duration,
        server_name: &'static str,
    ) -> Self {
        Self {
            capacity,
            refill_tokens,
            interval,
            server_name: server_name,
        }
    }
}

impl<S> Layer<S> for TokenBucketRateLimiterLayer {
    type Service = TokenBucketRateLimiterService<S>;
    fn layer(&self, inner: S) -> Self::Service {
        TokenBucketRateLimiterService::new(
            inner,
            self.capacity,
            self.refill_tokens,
            self.interval,
            self.server_name,
        )
    }
}

#[derive(Debug)]
struct TokenBucket {
    tokens: usize,
    last_refill: Instant,
}

impl TokenBucket {
    fn refill(&mut self, capacity: usize, refill_tokens: usize, interval: Duration) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill);

        if elapsed >= interval {
            let intervals_passed = elapsed.as_secs_f64() / interval.as_secs_f64();
            let added_tokens = (intervals_passed * refill_tokens as f64).floor() as usize;

            self.tokens = (self.tokens + added_tokens).min(capacity);
            self.last_refill = now;
        }
    }

    fn try_consume(&mut self) -> bool {
        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }
}

#[derive(Clone)]
pub struct TokenBucketRateLimiterService<S> {
    inner: S,
    state: Arc<Mutex<TokenBucket>>,
    capacity: usize,
    refill_tokens: usize,
    interval: Duration,
    server_name: &'static str,
}

impl<S> TokenBucketRateLimiterService<S> {
    pub fn new(
        inner: S,
        capacity: usize,
        refill_tokens: usize,
        interval: Duration,
        server_name: &'static str,
    ) -> Self {
        let state = Arc::new(Mutex::new(TokenBucket {
            tokens: capacity,
            last_refill: Instant::now(),
        }));

        Self {
            inner,
            state,
            capacity,
            refill_tokens,
            interval,
            server_name,
        }
    }
}

impl<S, ReqBody> Service<Request<ReqBody>> for TokenBucketRateLimiterService<S>
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
        let state = self.state.clone();
        let capacity = self.capacity;
        let refill_tokens = self.refill_tokens;
        let interval = self.interval;
        let server_name = self.server_name;

        Box::pin(async move {
            let mut bucket = state.lock().await;
            bucket.refill(capacity, refill_tokens, interval);

            if bucket.try_consume() {
                info!(
                    "{}: Token consumed (bucket limiter). Remaining: {}",
                    server_name, bucket.tokens
                );
                drop(bucket);
                inner.call(req).await
            } else {
                warn!(
                    "{}: Too Many Requests – no tokens available (bucket limiter).",
                    server_name
                );
                /*

                #[cfg(feature = "boxed_body")]
                let body:ServiceRespBody = Full::new(Bytes::from_static(b"Too Many Requests")).map_err(SrvError::from).boxed();
                #[cfg(not(feature = "boxed_body"))]
                let body:ServiceRespBody = Full::new(Bytes::from_static(b"Too Many Requests"));
                let mut response = Response::new(body);
                *response.status_mut() = StatusCode::TOO_MANY_REQUESTS;
                return Ok(response);

                 */
                #[cfg(feature = "boxed_body")]
                let body: ServiceRespBody = Full::new(Bytes::from_static(b"Too Many Requests"))
                    .map_err(SrvError::from)
                    .boxed();
                #[cfg(not(feature = "boxed_body"))]
                let body: ServiceRespBody = Full::new(Bytes::from_static(b"Too Many Requests"));
                let mut response = Response::new(body);
                *response.status_mut() = StatusCode::TOO_MANY_REQUESTS;
                Ok(response)
            }
        })
    }
}
