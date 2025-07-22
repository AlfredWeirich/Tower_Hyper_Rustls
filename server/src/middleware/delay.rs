use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{self, Sleep};
use tower::{Layer, Service};

/// A Tower layer that adds an artificial delay to poll_ready and tags logs with a server name.
#[derive(Clone)]
pub struct DelayLayer {
    delay: Duration,
    server_name: &'static str,
}

impl DelayLayer {
    pub fn new(delay: Duration, server_name: &'static str) -> Self {
        Self {
            delay,
            server_name: server_name,
        }
    }
}

impl<S> Layer<S> for DelayLayer {
    type Service = DelayService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        DelayService {
            inner,
            delay: self.delay,
            sleep: None,
            server_name: self.server_name,
        }
    }
}

pub struct DelayService<S> {
    inner: S,
    delay: Duration,
    sleep: Option<Pin<Box<Sleep>>>,
    server_name: &'static str,
}

impl<S: Clone> Clone for DelayService<S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            delay: self.delay,
            sleep: None, // Don't clone sleep state!
            server_name: self.server_name,
        }
    }
}

impl<S, Request> Service<Request> for DelayService<S>
where
    S: Service<Request>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // If we haven't started sleeping yet, create a new Sleep.
        if self.sleep.is_none() {
            tracing::info!(
                "{}: Injecting a delay of {:?} before readiness",
                self.server_name,
                self.delay
            );
            self.sleep = Some(Box::pin(time::sleep(self.delay)));
        }

        // Now, poll the Sleep future.
        let sleep = self.sleep.as_mut().unwrap();
        if Pin::new(sleep).poll(cx).is_pending() {
            return Poll::Pending;
        }

        // Sleep is done, clear it for next time.
        self.sleep = None;

        // Now delegate to the inner service.
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request) -> Self::Future {
        tracing::info!("{}: Passing request through DelayLayer", self.server_name);
        self.inner.call(req)
    }
}
