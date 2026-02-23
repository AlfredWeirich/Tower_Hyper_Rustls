// === Standard Library ===
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

// === External Crates ===
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode, header};
use tower::Service;

// === Internal Modules ===
use crate::{ServiceRespBody, SrvBody, SrvError};

#[derive(Clone, Debug)]
pub struct EchoService {
    server_name: &'static str,
}

impl EchoService {
    pub fn new(server_name: &'static str) -> Self {
        Self { server_name }
    }
}

impl Service<Request<SrvBody>> for EchoService {
    type Response = Response<ServiceRespBody>;
    type Error = SrvError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<SrvBody>) -> Self::Future {
        let server_name = self.server_name;

        Box::pin(async move {
            match (req.method(), req.uri().path()) {
                // ── GET / ────────────────────────────────────────────
                (&hyper::Method::GET, "/") => {
                    // 1. Extract query string
                    let query = req.uri().query().unwrap_or("none");

                    // 2. Offload heavy CPU work (commented out for high-performance benchmarking)
                    // tokio::task::spawn_blocking(move || load_test_echo_sync())
                    //     .await
                    //     .map_err(|_| SrvError::from("Task Join Error".to_string()))?;

                    // 3. Create the message including the query
                    let msg = format!("Echo /! Query: {} from Server: {server_name}\n", query);

                    let body: ServiceRespBody =
                        Full::new(Bytes::from(msg)).map_err(SrvError::from).boxed();

                    let response = Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "text/plain")
                        .body(body)
                        .unwrap();

                    Ok(response)
                }

                // ── GET /name ────────────────────────────────────────────
                (&hyper::Method::GET, "/name") => {
                    // 1. Extract query string
                    let query = req.uri().query().unwrap_or("none");

                    // 2. Offload heavy CPU work (commented out for high-performance benchmarking)
                    // tokio::task::spawn_blocking(move || load_test_echo_sync())
                    //     .await
                    //     .map_err(|_| SrvError::from("Task Join Error".to_string()))?;

                    // 3. Create the message including the query
                    let msg = format!("Echo /name! Query: {} from Server: {server_name}\n", query);

                    let body: ServiceRespBody =
                        Full::new(Bytes::from(msg)).map_err(SrvError::from).boxed();

                    let response = Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "text/plain")
                        .body(body)
                        .unwrap();

                    Ok(response)
                }

                // ── GET /health ──────────────────────────────────────
                (&hyper::Method::GET, "/health") => {
                    let msg = r#"{"status": "healthy", "message": "echo service is alive"}"#;
                    let body = Full::new(Bytes::from_static(msg.as_bytes()))
                        .map_err(SrvError::from)
                        .boxed();
                    let response = Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(body)
                        .unwrap();
                    Ok(response)
                }

                // ── GET /help ────────────────────────────────────────
                (&hyper::Method::GET, "/help") => {
                    let msg = format!("=====> This is the help page from {server_name}\n");
                    let body = Full::new(Bytes::from(msg)).map_err(SrvError::from).boxed();
                    Ok(Response::new(body))
                }

                // ── POST / ──────────────────────────────────────────
                (&hyper::Method::POST, "/") => {
                    let content_type =
                        req.headers().get(header::CONTENT_TYPE).cloned().unwrap_or(
                            header::HeaderValue::from_static("application/octet-stream"),
                        );

                    let body_bytes = req.collect().await?.to_bytes();
                    let body = Full::new(body_bytes).map_err(SrvError::from).boxed();

                    let response = Response::builder()
                        .header(header::CONTENT_TYPE, content_type)
                        .body(body)
                        .unwrap();
                    Ok(response)
                }

                // ── PUT / ───────────────────────────────────────────
                (&hyper::Method::PUT, "/") => {
                    let body_bytes = req.collect().await?.to_bytes();
                    let body_str = String::from_utf8_lossy(&body_bytes);
                    let trimmed = body_str.trim();

                    let final_bytes = if let Some(pos) = trimmed.rfind('}') {
                        let mut new_body = trimmed[..pos].to_string();
                        let msg = format!(", \"note\": \"from echo name: {}\" }}", server_name);
                        new_body.push_str(&msg);
                        Bytes::from(new_body)
                    } else {
                        body_bytes
                    };

                    let response = Response::builder()
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Full::new(final_bytes).map_err(SrvError::from).boxed())
                        .unwrap();

                    Ok(response)
                }

                // ── Catch-all ───────────────────────────────────────
                (other, other_path) => {
                    tracing::warn!("{}: {} {} -> 404", server_name, other, other_path);
                    let body = Full::new(Bytes::from_static(b"Not Found"))
                        .map_err(SrvError::from)
                        .boxed();

                    let response = Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .body(body)
                        .unwrap();
                    Ok(response)
                }
            }
        })
    }
}

/// CPU-intensive workload.
/// Since we are in a 'sync' function on a blocking thread, we don't need .await or sleep.
#[allow(dead_code)]
fn load_test_echo_sync() -> String {
    let mut data = vec![1.0f64; 32_000_000]; // 256MB
    for i in 0..1 {
        for val in data.iter_mut() {
            *val = *val + (i as f64).sin().cos();
        }
    }
    let checksum: f64 = data.iter().sum();
    format!("Result checksum: {:.6}", checksum)
}
