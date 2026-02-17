//! # JWT Authentication Middleware
//!
//! Validates incoming requests against one or more Ed25519 public keys,
//! extracts the [`Claims`](common::Claims) payload, and maps the contained
//! OID strings to internal [`UserRole`](crate::configuration::UserRole)
//! values.
//!
//! ## Request Flow
//!
//! 1. Extract the `Authorization: Bearer <token>` header.
//! 2. Verify the JWT signature against a list of [`DecodingKey`]s (supports
//!    key rotation / multiple issuers).
//! 3. Map the custom `oids` claim entries to [`UserRole`] variants using the
//!    global configuration's OID→role table.
//! 4. Inject both the raw [`Claims`] and the resolved `Vec<UserRole>` into
//!    the request's [extensions](hyper::Request::extensions) for downstream
//!    layers to consume (e.g. the logger, the router's RBAC check).
//!
//! If the token is missing or invalid, a **401 Unauthorized** response is
//! returned immediately without forwarding the request.

// [dependencies]
// josekit = "0.10" # Prüfe die aktuellste Version auf crates.io

// === Standard Library ===
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

// === External Crates ===
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode};
use jsonwebtoken::DecodingKey;
use tower::{Layer, Service};
use tracing::error;

// === Internal Modules ===
use crate::{ServiceRespBody, SrvError};
use common::{Claims, load_decoding_keys, verify_jwt};

/// A Tower [`Layer`] for JWT-based Authentication.
///
/// This layer prepares a [`JwtAuthService`] with the necessary decoding keys
/// and server identification.
#[derive(Clone)]
pub struct JwtAuthLayer {
    /// Pre-loaded Ed25519 decoding keys shared across all service clones.
    /// Wrapped in `Arc` because `DecodingKey` is not `Clone`-cheap.
    decoding_keys: Arc<Vec<DecodingKey>>,
    /// Server name label for tracing/logging.
    server_name: &'static str,
}

impl JwtAuthLayer {
    /// Creates a new `JwtAuthLayer`.
    ///
    /// # Arguments
    /// * `key_files` - A list of paths to PEM-encoded public keys used for token verification.
    /// * `server_name` - A static string identifying the server for logging purposes.
    #[allow(dead_code)]
    pub fn new(key_files: Vec<String>, server_name: &'static str) -> Self {
        let decoding_keys = load_decoding_keys(&key_files);

        Self {
            decoding_keys: Arc::new(decoding_keys),
            server_name: server_name,
        }
    }
}

impl<S> Layer<S> for JwtAuthLayer {
    type Service = JwtAuthService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        JwtAuthService {
            inner,
            decoding_keys: self.decoding_keys.clone(),
            server_name: self.server_name,
        }
    }
}

/// A Tower [`Service`] that validates JWTs and maps claims to roles.
///
/// On success the service injects two extensions into the request:
/// * `Claims` — the raw decoded JWT payload.
/// * `Vec<UserRole>` — the mapped internal roles.
///
/// On failure it short-circuits with a 401 response.
#[derive(Clone)]
pub struct JwtAuthService<S> {
    /// The next service in the middleware chain.
    inner: S,
    /// Arc-shared list of decoding keys for signature verification.
    decoding_keys: Arc<Vec<DecodingKey>>,
    /// Server name label for tracing/logging.
    server_name: &'static str,
}

impl<S, ReqBody> Service<Request<ReqBody>> for JwtAuthService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ServiceRespBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    ReqBody: Send + 'static,
{
    type Response = Response<ServiceRespBody>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    /// Delegates back-pressure to the inner service.
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    /// Extracts, validates, and processes the JWT from the `Authorization` header.
    ///
    /// ## Happy Path
    ///
    /// 1. Strips the `Bearer ` prefix from the `Authorization` header.
    /// 2. Calls [`verify_jwt`] , which tries every decoding key until one
    ///    succeeds (supporting key rotation).
    /// 3. Maps each OID in the claims to a [`UserRole`](crate::configuration::UserRole)
    ///    via the global config. If no specific roles are matched, defaults to
    ///    `UserRole::Guest`.
    /// 4. Inserts the raw `Claims` and the `Vec<UserRole>` into the request
    ///    extensions.
    /// 5. Forwards the enriched request to the inner service.
    ///
    /// ## Error Path
    ///
    /// Returns **401 Unauthorized** if:
    /// * The `Authorization` header is missing.
    /// * The token cannot be verified by any of the configured keys.
    fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
        let mut inner = self.inner.clone();
        let decoding_keys = self.decoding_keys.clone();
        let server_name = self.server_name;
        tracing::trace!("{}: Processing JWT Authentication", server_name);

        Box::pin(async move {
            // Extract the token from the "Authorization: Bearer <token>" header.
            let token = req
                .headers()
                .get("Authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.strip_prefix("Bearer "))
                .map(str::trim);

            match token {
                Some(token_str) => match verify_jwt(token_str, &decoding_keys) {
                    Ok(claims) => {
                        // --- Role Mapping Logic ---
                        // Expert Note: We map custom OIDs (extracted from the JWT) to internal UserRoles.
                        // This allows the rest of the application to work with strongly-typed roles
                        // instead of raw OID strings.
                        let config = crate::configuration::Config::global();

                        let mut roles: Vec<crate::configuration::UserRole> = claims
                            .oids
                            .iter()
                            .map(|suffix| config.map_oid_to_role(suffix))
                            // Filter out Guest initially to determine if we have higher-privileged roles.
                            .filter(|role| *role != crate::configuration::UserRole::Guest)
                            .collect();

                        // Default to Guest if no specific roles were identified.
                        if roles.is_empty() {
                            roles.push(crate::configuration::UserRole::Guest);
                        }

                        tracing::trace!("{}: JWT Roles mapped: {:?}", server_name, roles);

                        // Inject both the raw claims and the mapped roles into request extensions
                        // for downstream middleware and handlers to consume.
                        req.extensions_mut().insert::<Claims>(claims);
                        req.extensions_mut()
                            .insert::<Vec<crate::configuration::UserRole>>(roles);

                        inner.call(req).await
                    }
                    Err(e) => {
                        error!("{}: Invalid JWT: {:?}", server_name, e);
                        unauthorized_response()
                    }
                },
                None => {
                    error!("{}: Missing Authorization header", server_name);
                    unauthorized_response()
                }
            }
        })
    }
}

/// Helper function to create a standardized **401 Unauthorized** response.
///
/// Generic over the error type `T` so it can be used in any `Result<Response, T>`
/// context — the `Ok` variant is always returned, making the error type irrelevant.
fn unauthorized_response<T>() -> Result<Response<ServiceRespBody>, T> {
    let body: ServiceRespBody = Full::new(Bytes::from("Unauthorized"))
        .map_err(SrvError::from)
        .boxed();

    let mut resp: Response<ServiceRespBody> = Response::new(body);
    *resp.status_mut() = StatusCode::UNAUTHORIZED;
    Ok(resp)
}
