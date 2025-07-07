use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{self, Sleep};
use tower::{Layer, Service};

/// A Tower layer that adds an artificial delay to poll_ready and tags logs with a server name.
#[derive(Clone)]
pub struct DelayLayer {
    delay: Duration,
    server_name: Arc<String>,
}

impl DelayLayer {
    pub fn new(delay: Duration, server_name: impl Into<String>) -> Self {
        Self {
            delay,
            server_name: Arc::new(server_name.into()),
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
            server_name: Arc::clone(&self.server_name),
        }
    }
}

pub struct DelayService<S> {
    inner: S,
    delay: Duration,
    sleep: Option<Pin<Box<Sleep>>>,
    server_name: Arc<String>,
}

impl<S: Clone> Clone for DelayService<S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            delay: self.delay,
            sleep: None, // Don't clone sleep state!
            server_name: Arc::clone(&self.server_name),
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
        tracing::info!(
            "{}: Passing request through DelayService (no delay on call)",
            self.server_name
        );
        self.inner.call(req)
    }
}

// use std::{
//     future::Future,
//     pin::Pin,
//     task::{Context, Poll},
//     time::Duration,
// };
// use tokio::time::{self, Sleep};
// use tower::{Layer, Service};

// /// A Tower layer that adds an artificial delay to poll_ready.
// #[derive(Clone)]
// pub struct DelayLayer {
//     delay: Duration,
// }

// impl DelayLayer {
//     pub fn new(delay: Duration) -> Self {
//         Self { delay }
//     }
// }

// impl<S> Layer<S> for DelayLayer {
//     type Service = DelayService<S>;

//     fn layer(&self, inner: S) -> Self::Service {
//         DelayService {
//             inner,
//             delay: self.delay,
//             sleep: None,
//         }
//     }
// }

// pub struct DelayService<S> {
//     inner: S,
//     delay: Duration,
//     sleep: Option<Pin<Box<Sleep>>>,
// }
// impl<S: Clone> Clone for DelayService<S> {
//     fn clone(&self) -> Self {
//         Self {
//             inner: self.inner.clone(),
//             delay: self.delay,
//             sleep: None, // Do NOT clone the sleep state
//         }
//     }
// }

// impl<S, Request> Service<Request> for DelayService<S>
// where
//     S: Service<Request>,
// {
//     type Response = S::Response;
//     type Error = S::Error;
//     type Future = S::Future;

//     fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
//         // If we haven't started sleeping yet, create a new Sleep.
//         if self.sleep.is_none() {
//             self.sleep = Some(Box::pin(time::sleep(self.delay)));
//         }

//         // Now, poll the Sleep future.
//         let sleep = self.sleep.as_mut().unwrap();
//         if Pin::new(sleep).poll(cx).is_pending() {
//             return Poll::Pending;
//         }

//         // Sleep is done, clear it for next time.
//         self.sleep = None;

//         // Now delegate to the inner service.
//         self.inner.poll_ready(cx)
//     }

//     fn call(&mut self, req: Request) -> Self::Future {
//         self.inner.call(req)
//     }
// }
