use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode, body::Incoming, http::uri::Uri};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use tower::Service;
use tracing::trace;

use server::ServiceRespBody;
use server::SrvError;

use crate::configuration::ServerConfig; // BoxBody<Bytes, SrvError>

/// The `RouterService` is a Tower-compatible HTTP service that performs
/// prefix-based routing of incoming requests to different backend URIs.
/// It wraps a Hyper client, applies routing rules, and forwards requests
/// to the matching backend, rewriting the request URI as needed.
#[derive(Clone, Debug)]
pub struct RouterService {
    /// Hyper client instance with HTTPS support.
    client: Client<
        hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        ServiceRespBody,
    >,
    /// Vector of routing rules: (path prefix, backend URI), sorted by prefix length (longest first).
    rules: Arc<Vec<(String, Uri)>>, // (prefix, backend_uri)
    /// The server name (for logging and diagnostics).
    server_name: String,
}

impl RouterService {
    /// Constructs a new `RouterService`.
    ///
    /// # Arguments
    ///
    /// * `routes` - Optional routing table mapping path prefixes to backend URI strings.
    /// * `server_name` - Name of the server for logging.
    ///
    /// # Returns
    ///
    /// Returns a fully initialized RouterService.
    pub fn new(config: &ServerConfig, server_name: impl Into<String>) -> Self {

        let routes=config.rev_routes.clone();
        let server_name = server_name.into();

        // Build HTTPS connector with native root certificates.
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_native_roots()
            .expect("no native root CA certificates found")
            .https_or_http()
            .enable_http1()
            .build();

        // Construct a Hyper client with the HTTPS connector.
        let client: Client<
            hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
            ServiceRespBody,
        > = Client::builder(TokioExecutor::new()).build(https);

        // Process and sort routing rules by prefix length (descending).
        let mut rules_vec: Vec<_> = match routes {
            Some(map) => map
                .into_iter()
                .filter_map(|(prefix, uri_str)| match uri_str.parse::<Uri>() {
                    Ok(uri) => Some((prefix, uri)),
                    Err(e) => {
                        tracing::warn!(
                            "{server_name}: Invalid URI in routing rules ({}): {}",
                            prefix,
                            e
                        );
                        None
                    }
                })
                .collect(),
            None => Vec::new(),
        };
        // Ensure longest prefixes are checked first for correct routing.
        rules_vec.sort_by(|(a, _), (b, _)| b.len().cmp(&a.len()));

        RouterService {
            client,
            rules: Arc::new(rules_vec),
            server_name,
        }
    }
}

impl Service<Request<Incoming>> for RouterService {
    type Response = Response<ServiceRespBody>;
    type Error = SrvError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    /// Checks if the service is ready to accept a request.
    /// Always returns ready (this service is always ready).
    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        //
        trace!("poll_ready im router");
        Poll::Ready(Ok(()))
    }

    /// Handles an incoming HTTP request, applies routing rules, and forwards the
    /// request to the corresponding backend using the Hyper client.
    ///
    /// # Arguments
    ///
    /// * `request` - The incoming HTTP request.
    ///
    /// # Returns
    ///
    /// Returns a future that resolves to the proxied response from the backend,
    /// or an error response if no routing rule matches.
    fn call(&mut self, request: Request<Incoming>) -> Self::Future {
        //trace!("call im router");
        let rules = Arc::clone(&self.rules);
        let client = self.client.clone();
        let server_name = self.server_name.clone();

        Box::pin(async move {
            let (request_parts, request_body) = request.into_parts();
            let request_path = request_parts.uri.path();

            // Prioritized rule match (sorted longest first for prefix matching).
            // Ensures for example /api matches /api, /api/v1, but not /apis
            let target_uri = rules
                .iter()
                .find(|(prefix, _)| {
                    request_path == prefix
                        || (request_path.starts_with(prefix)
                            && request_path.chars().nth(prefix.len()) == Some('/'))
                })
                .map(|(_, uri)| uri.clone());

            let target_uri = match target_uri {
                Some(uri) => uri,
                None => {
                    // No matching backend found; respond with 400 Bad Request.
                    tracing::warn!("{server_name}: NO MATCHING BACKEND FOR PATH: {request_path}");

                    #[cfg(feature = "boxed_body")]
                    let body: ServiceRespBody = Full::new(Bytes::from("No matching backend"))
                        .map_err(SrvError::from)
                        .boxed();
                    #[cfg(not(feature = "boxed_body"))]
                    let body: ServiceRespBody = Full::new(Bytes::from("No matching backend"));
                    let mut response = Response::new(body);
                    *response.status_mut() = StatusCode::BAD_REQUEST;
                    return Ok(response);
                }
            };

            // Construct a new URI by combining the target backend base with the request's path/query.
            let response_uri = {
                let mut target_uri_parts = target_uri.into_parts();
                target_uri_parts.path_and_query = request_parts.uri.path_and_query().cloned();
                Uri::from_parts(target_uri_parts)
            };

            let mut response_parts = request_parts;
            response_parts.uri = match response_uri {
                Ok(uri) => uri,
                Err(_) => {
                    // URI parts construction failed; respond with 400 Bad Request.
                    tracing::warn!("{server_name}: INVALID URI PARTS: {}", response_parts.uri);
                    #[cfg(feature = "boxed_body")]
                    let body: ServiceRespBody = Full::new(Bytes::from("Invalid Request Uri"))
                        .map_err(SrvError::from)
                        .boxed();
                    #[cfg(not(feature = "boxed_body"))]
                    let body: ServiceRespBody = Full::new(Bytes::from("Invalid Request Uri"));
                    let mut response = Response::new(body);
                    *response.status_mut() = StatusCode::BAD_REQUEST;
                    return Ok(response);
                }
            };

            // Always use HTTP/1.1 for backend requests.
            response_parts.version = hyper::Version::HTTP_11;
            // Optional: update the Host header to match the backend (commented out).
            // response_parts.headers.insert(
            //     hyper::header::HOST,
            //     hyper::header::HeaderValue::from_str(&response_parts.uri.authority().unwrap().to_string())
            //         .unwrap(),
            // );

            trace!("{server_name}: Forwarding request to: {:?}", response_parts);

            // Prepare the request body, handling boxed/non-boxed bodies via feature flag.
            #[cfg(feature = "boxed_body")]
            let body: ServiceRespBody = request_body.map_err(SrvError::from).boxed();
            #[cfg(not(feature = "boxed_body"))]
            let body = Full::new(request_body.collect().await?.to_bytes());

            // Build the forwarded request to send to the backend.
            let forwarded_request: Request<ServiceRespBody> =
                Request::from_parts(response_parts, body);

            // Forward the request to the matched backend.
            let response = client.request(forwarded_request).await?;
            trace!("{server_name}: router response: {:?}", response);

            // Adapt the backend response body as needed by feature.
            #[cfg(feature = "boxed_body")]
            {
                let response: Response<ServiceRespBody> =
                    response.map(|b| b.map_err(SrvError::from).boxed());
                return Ok(response);
            }
            #[cfg(not(feature = "boxed_body"))]
            {
                let (parts, body) = response.into_parts();
                let bytes = body.collect().await?.to_bytes();
                let response: Response<ServiceRespBody> =
                    Response::from_parts(parts, Full::new(bytes));
                return Ok(response);
            }
        })
    }
}
