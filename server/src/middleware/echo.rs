//! # Echo Service
//!
//! A simple diagnostic / load-testing service that echoes request data back to
//! the client. It handles a small set of hard-coded routes and is selected as
//! the base service when `ServiceType::Echo` is configured.
//!
//! ## Supported Routes
//!
//! | Method | Path   | Behaviour |
//! |--------|--------|-----------|
//! | GET    | `/`    | Returns `"Echo!"` after a synthetic CPU + sleep load. |
//! | GET    | `/help`| Returns a server-name banner. |
//! | GET    | `/name`| Returns the path and query string. |
//! | POST   | `/`    | Echoes the request body back as the response body. |
//! | PUT    | `/`    | Same as POST — echoes the request body. |
//! | *      | *      | Returns **404 Not Found**. |

// === Standard Library ===
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

// === External Crates ===
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode};
use tokio::time::sleep;
use tower::Service;

// === Internal Modules ===
use crate::{ServiceRespBody, SrvBody, SrvError};

/// A simple Tower service that echoes responses, tagged by server_name.
///
/// This service is intentionally straightforward so it can be used as a
/// baseline for benchmarking the middleware stack without involving any
/// upstream backend.
#[derive(Clone, Debug)]
pub struct EchoService {
    /// Identifies which server instance this echo service belongs to.
    server_name: &'static str,
}

impl EchoService {
    /// Create a new EchoService with the given server name.
    pub fn new(server_name: &'static str) -> Self {
        Self {
            server_name: server_name,
        }
    }
}

impl Service<Request<SrvBody>> for EchoService {
    type Response = Response<ServiceRespBody>;
    type Error = SrvError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    /// The echo service is always ready to accept requests.
    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    /// Dispatches the request to the appropriate handler based on
    /// the HTTP method and path.
    ///
    /// - **GET `/`** – Runs a synthetic load via [`load_test_echo`], then
    ///   returns a short text body.
    /// - **GET `/help`** – Returns a help banner containing the server name.
    /// - **GET `/name`** – Reflects the URI path and query string.
    /// - **POST `/`** / **PUT `/`** – Collects the full request body and
    ///   echoes it back verbatim.
    /// - **Anything else** – Returns a 404 Not Found.
    fn call(&mut self, req: Request<SrvBody>) -> Self::Future {
        // let method = req.method().clone();
        // let path = req.uri().path().to_string();
        let server_name = self.server_name;

        Box::pin(async move {
            match (req.method(), req.uri().path()) {
                // ── GET / ────────────────────────────────────────────
                (&hyper::Method::GET, "/") => {
                    tracing::info!("{}: GET /", server_name);
                    // Run a synthetic CPU + sleep workload for load testing.
                    let _load_resp = load_test_echo().await;
                    // #[cfg(feature = "boxed_body")]
                    let body: ServiceRespBody = Full::new(Bytes::from("Echo!"))
                        .map_err(SrvError::from)
                        .boxed();

                    let response = Response::new(body);
                    Ok(response)
                }
                // ── GET /help ────────────────────────────────────────
                (&hyper::Method::GET, "/help") => {
                    tracing::info!("{}: GET /help", server_name);
                    let msg = format!("=====> This is the help page from {server_name}\n");
                    // #[cfg(feature = "boxed_body")]
                    let body: ServiceRespBody =
                        Full::new(Bytes::from(msg)).map_err(SrvError::from).boxed();

                    let response = Response::new(body);
                    Ok(response)
                }
                // ── GET /name ────────────────────────────────────────
                (&hyper::Method::GET, "/name") => {
                    tracing::info!("{}: GET /name", server_name);
                    let msg = format!("Echo! Path: /name, Query: {:?}\n", req.uri().query());
                    let body: ServiceRespBody =
                        Full::new(Bytes::from(msg)).map_err(SrvError::from).boxed();

                    let response = Response::new(body);
                    Ok(response)
                }
                // ── POST / ──────────────────────────────────────────
                (&hyper::Method::POST, "/") => {
                    tracing::info!("{}: POST /", server_name);
                    // Collect the entire incoming body into a contiguous buffer.
                    let body_bytes = req.collect().await?.to_bytes();
                    // #[cfg(feature = "boxed_body")]
                    let body: ServiceRespBody =
                        Full::new(body_bytes).map_err(SrvError::from).boxed();

                    let response = Response::new(body);
                    Ok(response)
                }
                // ── PUT / ───────────────────────────────────────────
                (&hyper::Method::PUT, "/") => {
                    tracing::info!("{}: PUT /", server_name);
                    let body_bytes = req.collect().await?.to_bytes();
                    tracing::trace!("{}: PUT / body: {:?}", server_name, body_bytes);
                    // #[cfg(feature = "boxed_body")]
                    let body: ServiceRespBody =
                        Full::new(body_bytes).map_err(SrvError::from).boxed();

                    let response = Response::new(body);
                    Ok(response)
                }
                // ── Catch-all → 404 ─────────────────────────────────
                (other, other_path) => {
                    tracing::warn!("{}: {} {} -> 404", server_name, other, other_path);
                    // #[cfg(feature = "boxed_body")]
                    let body: ServiceRespBody = Full::new(Bytes::from("Not Found"))
                        .map_err(SrvError::from)
                        .boxed();

                    let mut not_found = Response::new(body);
                    *not_found.status_mut() = StatusCode::NOT_FOUND;
                    Ok(not_found)
                }
            }
        })
    }
}

/// Synthetic CPU + I/O workload used by the `GET /` handler for load testing.
///
/// Allocates a 256 MB `Vec<f64>`, performs a trivial floating-point
/// computation, sleeps for 1 second (simulating I/O latency), and returns a
/// checksum string. The result is discarded by the caller; the purpose is
/// purely to exercise CPU and memory pressure.
pub async fn load_test_echo() -> String {
    let mut data = vec![1.0f64; 32_000_000]; //256MB

    // for i in 0..2 {
    //     for val in data.iter_mut() {
    //         *val = (*val + (i as f64).sin().cos().tan()).abs().sqrt();
    //     }
    // }
    for i in 0..1 {
        for val in data.iter_mut() {
            *val = *val + (i as f64).sin().cos();
        }
    }

    // Prevent optimization: sum is used and affects output
    let checksum: f64 = data.iter().sum();

    // Simulate I/O latency
    sleep(Duration::from_millis(1000)).await;

    format!("Result checksum: {:.6}", checksum)
}
