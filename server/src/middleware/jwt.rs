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
use server::SrvError; // BoxBody<Bytes, SrvError>

use jsonwebtoken::DecodingKey; // <-- ADDED

use crate::utils::{Claims, load_decoding_keys, verify_jwt};

#[derive(Clone)]
pub struct JwtAuthLayer {
    decoding_keys: Arc<Vec<DecodingKey>>,
    server_name: Arc<String>,
}

impl JwtAuthLayer {
    #[allow(dead_code)]
    pub fn new(key_files: Vec<String>, server_name: impl Into<String>) -> Self {
        // Load all keys ONCE at startup!
        // let decoding_keys: Vec<DecodingKey> = key_files
        //     .into_iter()
        //     .map(|file| {
        //         let pem = std::fs::read(file).expect("Failed to read public key file");
        //         DecodingKey::from_rsa_pem(&pem).expect("Failed to parse RSA public key")
        //     })
        //     .collect();
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
            let token = req
                .headers()
                .get("Authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.strip_prefix("Bearer "))
                .map(str::trim);

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

/* use std::{
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
use server::SrvError; // BoxBody<Bytes, SrvError>

use crate::utils::{verify_jwt, Claims};

#[derive(Clone)]
pub struct JwtAuthLayer {
    public_keys: Arc<Vec<String>>,
    server_name: Arc<String>,
}

impl JwtAuthLayer {
    #[allow(dead_code)]
    pub fn new(public_keys: Vec<String>, server_name: impl Into<String>) -> Self {
        Self {
            public_keys: Arc::new(public_keys),
            server_name: Arc::new(server_name.into()),
        }
    }
}

impl<S> Layer<S> for JwtAuthLayer {
    type Service = JwtAuthService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        JwtAuthService {
            inner,
            public_keys: self.public_keys.clone(),
            server_name: Arc::clone(&self.server_name),
        }
    }
}

#[derive(Clone)]
pub struct JwtAuthService<S> {
    inner: S,
    public_keys: Arc<Vec<String>>,
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
        let public_keys = self.public_keys.clone();
        let server_name = Arc::clone(&self.server_name);

        Box::pin(async move {
            let token = req
                .headers()
                .get("Authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.strip_prefix("Bearer "))
                .map(str::trim);

            match token {
                Some(token) => match verify_jwt(token, &public_keys) {
                    Ok(_claims) => {
                        // let now = std::time::SystemTime::now()
                        //     .duration_since(std::time::UNIX_EPOCH)
                        //     .unwrap()
                        //     .as_secs();

                        // let expires_in = _claims.exp.saturating_sub(now as usize);

                        // tracing::trace!(
                        //     "{}: JWT verified: {:?}, expires in: {} seconds",
                        //     server_name,
                        //     _claims,
                        //     expires_in
                        // );

                        // only needd if we want to have the Claims in the request for further use
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
 */
