use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode, body::Incoming};
use tower::Service;

use server::ServiceRespBody;
use server::SrvError; // BoxBody<Bytes, SrvError>

/// A simple Tower service that echoes responses, tagged by server_name.
#[derive(Clone, Debug)]
pub struct EchoService {
    server_name: Arc<String>,
}

impl EchoService {
    /// Create a new EchoService with the given server name.
    pub fn new(server_name: impl Into<String>) -> Self {
        Self {
            server_name: Arc::new(server_name.into()),
        }
    }
}

impl Service<Request<Incoming>> for EchoService {
    //    type Response = Response<BoxBody<Bytes, SrvError>>;
    type Response = Response<ServiceRespBody>;
    type Error = SrvError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Incoming>) -> Self::Future {
        // let method = req.method().clone();
        // let path = req.uri().path().to_string();
        let server_name = Arc::clone(&self.server_name);

        Box::pin(async move {
            match (req.method(), req.uri().path()) {
                (&hyper::Method::GET, "/") => {
                    tracing::info!("{}: GET /", server_name);
                    #[cfg(feature = "boxed_body")]
                    let body: ServiceRespBody = Full::new(Bytes::from("Echo!"))
                        .map_err(SrvError::from)
                        .boxed();
                    #[cfg(not(feature = "boxed_body"))]
                    let body: ServiceRespBody = Full::new(Bytes::from("Echo!"));
                    let response = Response::new(body);
                    Ok(response)
                }
                (&hyper::Method::GET, "/help") => {
                    tracing::info!("{}: GET /help", server_name);
                    let msg = format!("=====> This is the help page from {server_name}.\n");
                    #[cfg(feature = "boxed_body")]
                    let body: ServiceRespBody =
                        Full::new(Bytes::from(msg)).map_err(SrvError::from).boxed();
                    #[cfg(not(feature = "boxed_body"))]
                    let body: ServiceRespBody = Full::new(Bytes::from(msg));
                    let response = Response::new(body);
                    Ok(response)
                }
                (&hyper::Method::POST, "/") => {
                    tracing::info!("{}: POST /", server_name);
                    let body_bytes = req.collect().await?.to_bytes();
                    #[cfg(feature = "boxed_body")]
                    let body: ServiceRespBody =
                        Full::new(body_bytes).map_err(SrvError::from).boxed();
                    #[cfg(not(feature = "boxed_body"))]
                    let body: ServiceRespBody = Full::new(body_bytes);
                    let response = Response::new(body);
                    Ok(response)
                }
                (&hyper::Method::PUT, "/") => {
                    tracing::info!("{}: PUT /", server_name);
                    let body_bytes = req.collect().await?.to_bytes();
                    #[cfg(feature = "boxed_body")]
                    let body: ServiceRespBody =
                        Full::new(body_bytes).map_err(SrvError::from).boxed();
                    #[cfg(not(feature = "boxed_body"))]
                    let body: ServiceRespBody = Full::new(body_bytes);
                    let response = Response::new(body);
                    Ok(response)
                }
                (other, other_path) => {
                    tracing::warn!("{}: {} {} -> 404", server_name, other, other_path);
                    #[cfg(feature = "boxed_body")]
                    let body: ServiceRespBody = Full::new(Bytes::from("Not Found"))
                        .map_err(SrvError::from)
                        .boxed();
                    #[cfg(not(feature = "boxed_body"))]
                    let body: ServiceRespBody = Full::new(Bytes::from("Not Found"));
                    let mut not_found = Response::new(body);
                    *not_found.status_mut() = StatusCode::NOT_FOUND;
                    Ok(not_found)
                }
            }
        })
    }
}
