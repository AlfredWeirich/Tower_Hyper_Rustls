use bytes::Bytes;
#[cfg(feature = "boxed_body")]
use http_body_util::BodyExt;
use http_body_util::Full;
use hyper::{Request, Response, StatusCode};
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tower::{Layer, Service};

use crate::configuration::CompiledAllowedPathes; // Adjust to your module path

#[cfg(feature = "boxed_body")]
use server::SrvError;

#[derive(Clone)]
pub struct InspectionLayer {
    rules: Arc<CompiledAllowedPathes>,
    server_name: Arc<String>,
}

impl InspectionLayer {
    /// Create a new InspectionLayer with rules and a server name.
    pub fn new(rules: CompiledAllowedPathes, server_name: impl Into<String>) -> Self {
        Self {
            rules: Arc::new(rules),
            server_name: Arc::new(server_name.into()),
        }
    }
}

impl<S> Layer<S> for InspectionLayer {
    type Service = InspectionService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        InspectionService {
            inner,
            allowed_pathes: self.rules.clone(),
            server_name: Arc::clone(&self.server_name),
        }
    }
}

#[derive(Clone)]
pub struct InspectionService<S> {
    inner: S,
    allowed_pathes: Arc<CompiledAllowedPathes>,
    server_name: Arc<String>,
}

use server::ServiceRespBody;
impl<S, ReqBody> Service<Request<ReqBody>> for InspectionService<S>
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
        // Extracts the method, path, and query string.
        // Check if the request is allowed via the is_allowed function.
        let method = req.method().as_str().to_uppercase();
        let uri = req.uri().clone();
        let path = uri.path().to_string();
        let query = uri.query().unwrap_or("").to_string();
        let allow = self.allowed_pathes.is_allowed(&method, &path, &query);
        let server_name = Arc::clone(&self.server_name);

        if allow {
            // If the request matches one of the allowed regex patterns
            let mut inner = self.inner.clone();
            Box::pin(async move { inner.call(req).await })
        } else {
            // if not allowed:
            // Log the blocked attempt.
            // Return a 403 Forbidden response with a simple body.
            tracing::warn!(
                "{}: Blocked request: {} {}?{}",
                server_name,
                method,
                path,
                query
            );

            #[cfg(feature = "boxed_body")]
            let body: ServiceRespBody =
                Full::new(Bytes::from("Request does not match allowed patterns"))
                    .map_err(SrvError::from)
                    .boxed();
            #[cfg(not(feature = "boxed_body"))]
            let body: ServiceRespBody =
                Full::new(Bytes::from("Request does not match allowed patterns"));
            let response = Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(body)
                .expect("Failed to build response");
            Box::pin(async move { Ok(response) })
        }
    }
}
