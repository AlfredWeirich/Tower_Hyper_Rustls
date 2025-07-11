use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::Bytes;
use http_body_util::Full;

#[cfg(feature = "boxed_body")]
use http_body_util::BodyExt;

use hyper::{Request, Response, StatusCode};
use tower::{Layer, Service};
use tracing::error;

use server::ServiceRespBody;

#[cfg(feature = "boxed_body")]
use server::SrvError;

use jsonwebtoken::DecodingKey; // <-- ADDED

use common::{Claims, load_decoding_keys, verify_jwt};

#[derive(Clone)]
pub struct JwtAuthLayer {
    decoding_keys: Arc<Vec<DecodingKey>>,
    server_name: Arc<String>,
}

impl JwtAuthLayer {
    #[allow(dead_code)]
    pub fn new(key_files: Vec<String>, server_name: impl Into<String>) -> Self {
        let decoding_keys = load_decoding_keys(&key_files);

        Self {
            decoding_keys: Arc::new(decoding_keys),
            server_name: Arc::new(server_name.into()),
        }
    }
}

impl<S> Layer<S> for JwtAuthLayer {
    type Service = JwtAuthService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        JwtAuthService {
            inner,
            decoding_keys: self.decoding_keys.clone(),
            server_name: Arc::clone(&self.server_name),
        }
    }
}

#[derive(Clone)]
pub struct JwtAuthService<S> {
    inner: S,
    decoding_keys: Arc<Vec<DecodingKey>>,
    server_name: Arc<String>,
}

impl<S, ReqBody> Service<Request<ReqBody>> for JwtAuthService<S>
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

    fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
        let mut inner = self.inner.clone();
        let decoding_keys = self.decoding_keys.clone();
        let server_name = Arc::clone(&self.server_name);

        Box::pin(async move {
            // extract the token string from the request's Authorization header
            let token = req
                .headers()
                .get("Authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.strip_prefix("Bearer "))
                .map(str::trim);

            // If a valid token is found, it's verified against the public keys.
            // If successful, the parsed claims are attached to the request (via req.extensions_mut()),
            // making them accessible to downstream layers or handlers.
            match token {
                Some(token) => match verify_jwt(token, &decoding_keys) {
                    Ok(_claims) => {
                        req.extensions_mut().insert::<Claims>(_claims);
                        inner.call(req).await
                    }
                    Err(e) => {
                        error!("{}: Invalid JWT: {:?}", server_name, e);
                        unauthorized_response()
                    }
                },
                None => {
                    error!("{}: Missing or invalid Authorization header", server_name);
                    unauthorized_response()
                }
            }
        })
    }
}

fn unauthorized_response<T>() -> Result<Response<ServiceRespBody>, T> {
    #[cfg(feature = "boxed_body")]
    let body: ServiceRespBody = Full::new(Bytes::from("Unauthorized"))
        .map_err(SrvError::from)
        .boxed();
    #[cfg(not(feature = "boxed_body"))]
    let body: ServiceRespBody = Full::new(Bytes::from("Unauthorized"));

    let mut resp: Response<ServiceRespBody> = Response::new(body);
    *resp.status_mut() = StatusCode::UNAUTHORIZED;
    Ok(resp)
}
