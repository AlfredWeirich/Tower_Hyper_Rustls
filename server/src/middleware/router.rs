//! # Reverse-Proxy Routing Service
//!
//! This module implements a Tower [`Service`] that acts as a **reverse proxy**.
//! Incoming HTTP requests are matched against a set of configured route prefixes,
//! then forwarded to the corresponding upstream (backend) server.
//!
//! ## Key responsibilities
//! - **Prefix-based routing** – Uses the [`matchit`] crate's radix-tree router
//!   for O(1)-ish path matching with wildcard support.
//! - **URI rewriting** – Translates the client-facing path into the upstream path
//!   while preserving any trailing segments and query parameters.
//! - **Role-based access control (RBAC)** – Optionally restricts routes to
//!   specific [`UserRole`]s extracted earlier in the middleware stack.
//! - **Hop-by-hop header stripping** – Removes connection-level headers that
//!   must not be forwarded according to RFC 7230 §6.1.
//! - **mTLS / JWT authentication toward upstream** – Configures the outgoing
//!   TLS client with optional client certificates or injects a JWT bearer token.

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
use hyper::{
    Request, Response, StatusCode, header,
    http::uri::{PathAndQuery, Uri},
};
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use matchit::Router;
use tower::Service;
use tracing::{error, warn};

// === Internal Modules ===
use crate::{
    ServiceRespBody, SrvBody, SrvError,
    configuration::{AuthenticationMethod, ParsedRoute, ServerConfig, UserRole},
};
use common::{build_root_store, build_tls_client_config};

/// HTTP hop-by-hop headers that **must not** be forwarded by a proxy.
///
/// These headers describe properties of the immediate connection between
/// two HTTP peers and are meaningless to the upstream backend. Stripping
/// them is required by RFC 7230, Section 6.1.
///
/// The list includes both standard headers recognized by Hyper and two
/// non-standard but widely-used headers (`keep-alive`, `proxy-connection`)
/// that some legacy clients/proxies still set.
static HOP_BY_HOP_HEADERS: [header::HeaderName; 9] = [
    header::CONNECTION,
    header::PROXY_AUTHENTICATE,
    header::PROXY_AUTHORIZATION,
    header::TE,
    header::TRAILER,
    header::TRANSFER_ENCODING,
    header::UPGRADE,
    header::HeaderName::from_static("keep-alive"),
    header::HeaderName::from_static("proxy-connection"),
];

/// A Tower [`Service`] that implements **reverse-proxy routing**.
///
/// `RouterService` owns a shared, immutable radix-tree router (from the
/// [`matchit`] crate) and a pooled HTTPS client. For every incoming request
/// it:
///
/// 1. Extracts the client IP and sets the `X-Real-IP` header.
/// 2. Looks up the request path in the router to find the matching
///    [`ParsedRoute`] configuration.
/// 3. Enforces **role-based access control** if the route has restricted
///    `allowed_roles`.
/// 4. Rewrites the URI to point at the upstream backend, preserving
///    sub-path segments and query parameters.
/// 5. Strips hop-by-hop headers, sets the `Host` header to the upstream
///    authority, and optionally injects a JWT bearer token.
/// 6. Forwards the request via the pooled HTTPS client and streams the
///    backend response back to the caller.
///
/// # Cloning
///
/// `RouterService` is cheaply cloneable: the router is behind an [`Arc`]
/// and the Hyper [`Client`] uses an internal connection pool with atomic
/// reference counting.
#[derive(Clone)]
pub struct RouterService {
    /// Hyper legacy [`Client`] used to forward requests to upstream services.
    ///
    /// Configured with a `rustls`-backed HTTPS connector that optionally
    /// presents a client certificate (mTLS). The client maintains an internal
    /// connection pool with a configurable idle timeout.
    client: Client<
        hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        ServiceRespBody,
    >,

    /// Shared radix-tree router mapping URL prefixes to [`ParsedRoute`] configs.
    ///
    /// Wrapped in [`Arc`] so that all cloned `RouterService` instances share
    /// the same routing table without duplication.
    router: Arc<Router<ParsedRoute>>,

    /// Reference to the global, leaked [`ServerConfig`].
    ///
    /// Used at request time only for the server name (logging / diagnostics).
    config: &'static ServerConfig,

    /// Pre-formatted `Bearer <token>` header value, ready to be inserted
    /// into outgoing requests when JWT-based upstream authentication is enabled.
    ///
    /// `None` when no JWT is configured for this server instance.
    jwt_token: Option<header::HeaderValue>,
}

impl RouterService {
    /// Constructs a new `RouterService` from the application configuration.
    ///
    /// The constructor performs three main setup steps:
    ///
    /// 1. **Route registration** – Iterates over [`ServerConfig::parsed_routes`]
    ///    and inserts each prefix **twice** into the `matchit` router:
    ///    once as an exact match and once with a `/*rest` wildcard so that
    ///    sub-paths are also captured.
    /// 2. **HTTPS client setup** – Builds a `rustls` client config using the
    ///    configured root CA certificate and, when mTLS is required, the
    ///    client certificate + key pair. The resulting connector supports
    ///    both HTTP/1.1 and HTTP/2 over TLS.
    /// 3. **JWT preparation** – If a JWT string is present in the router
    ///    params, it is pre-formatted into a `Bearer <token>` header value
    ///    that can be cloned cheaply at request time.
    ///
    /// # Arguments
    ///
    /// * `config` – A `'static` reference to the [`ServerConfig`] that
    ///   contains routing rules, TLS material, and upstream authentication
    ///   settings.
    ///
    /// # Panics
    ///
    /// Panics if `config.router_params` is `None`, which indicates a
    /// programming error in the configuration parser—this service must
    /// only be created for server instances that have routing enabled.
    pub fn new(config: &'static ServerConfig) -> Self {
        let router_params = config
            .router_params
            .as_ref()
            .expect("Router params missing");

        // ── 1. Router initialization ──────────────────────────────────
        // Build a `matchit::Router` from the parsed routes. Each route is
        // registered with both an exact prefix and a wildcard variant so
        // that e.g. `/api` matches requests to `/api`, `/api/`, and
        // `/api/foo/bar`.
        let mut router = Router::new();
        for route_data in &config.parsed_routes {
            let prefix = &route_data.prefix;
            // Exact-prefix entry (e.g. `/api`).
            let _ = router.insert(prefix, route_data.clone());

            // Wildcard entry (e.g. `/api/*rest`). The `*rest` parameter
            // captures everything after the prefix, which we later append
            // to the upstream URI during URI reconstruction (step 4 in `call`).
            let wildcard_path = if prefix.ends_with('/') {
                format!("{}*rest", prefix)
            } else {
                format!("{}/*rest", prefix)
            };

            if let Err(e) = router.insert(&wildcard_path, route_data.clone()) {
                warn!(
                    "{}: Failed to insert wildcard route {}: {}",
                    config.name, wildcard_path, e
                );
            }
        }
        let router = Arc::new(router);

        // ── 2. HTTPS client configuration ─────────────────────────────
        // The client is backed by `rustls` and supports both HTTP/1.1 and
        // HTTP/2.  When the upstream requires mutual TLS (mTLS), a client
        // certificate and private key are loaded into the TLS config.
        let client = {
            // Load the CA root store used to validate upstream server certs.
            let root_store = build_root_store(&router_params.ssl_root_certificate);
            let is_mtls = router_params.authentication == AuthenticationMethod::ClientCert;

            // Conditionally attach client-certificate material for mTLS.
            let tls_client_config = if is_mtls {
                build_tls_client_config(
                    root_store,
                    router_params.ssl_client_certificate.as_deref(),
                    router_params.ssl_client_key.as_deref(),
                )
            } else {
                build_tls_client_config(root_store, None, None)
            };

            // Build the HTTPS connector and attach it to a pooled Hyper
            // `Client`. The idle-timeout prevents stale connections from
            // lingering indefinitely in the pool.
            let https_connector = hyper_rustls::HttpsConnectorBuilder::new()
                .with_tls_config(tls_client_config)
                .https_or_http()
                .enable_http1()
                .enable_http2()
                .build();

            Client::builder(TokioExecutor::new())
                .pool_idle_timeout(std::time::Duration::from_secs(90))
                .build(https_connector)
        };

        // ── 3. JWT bearer token preparation ───────────────────────────
        // Pre-format the `Authorization: Bearer …` header value so it can
        // be cheaply cloned into each forwarded request.
        let jwt_token = router_params
            .jwt
            .as_ref()
            .and_then(|t| header::HeaderValue::from_str(&format!("Bearer {}", t)).ok());

        RouterService {
            client,
            router,
            config,
            jwt_token,
        }
    }
}

// ─── Tower Service Implementation ────────────────────────────────────────────
//
// Implementing `Service<Request<SrvBody>>` makes `RouterService` usable as a
// layer in a Tower service stack. The associated types define that:
//   - Responses carry a boxed, error-mapped body (`ServiceRespBody`).
//   - Errors are unified under `SrvError`.
//   - The future is heap-allocated (`Pin<Box<…>>`) because it must be `Send`
//     and has an opaque, async-block type.

impl Service<Request<SrvBody>> for RouterService {
    type Response = Response<ServiceRespBody>;
    type Error = SrvError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    /// Indicates readiness to accept the next request.
    ///
    /// Always returns [`Poll::Ready(Ok(()))`] because the service is
    /// stateless with respect to back-pressure — the underlying Hyper
    /// client handles connection-pool pressure internally.
    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    /// Processes a single incoming request through the reverse-proxy pipeline.
    ///
    /// The processing happens in five clearly separated stages inside the
    /// returned future:
    ///
    /// 1. **IP address management** – Extracts the client's socket address
    ///    from the request extensions (set by the connection handler) and
    ///    injects it as an `X-Real-IP` header so the upstream can see the
    ///    original client IP.
    /// 2. **Route lookup** – Matches the request path against the radix-tree
    ///    router. Returns `404 Not Found` if no route matches.
    /// 3. **RBAC enforcement** – If the matched route has `allowed_roles`,
    ///    compares them against the `Vec<UserRole>` stored in the request
    ///    extensions. Returns `403 Forbidden` when unauthorized.
    /// 4. **URI reconstruction** – Builds the upstream URI by combining the
    ///    backend's base URI with the captured `*rest` sub-path and the
    ///    original query string.
    /// 5. **Header management & forwarding** – Strips hop-by-hop headers,
    ///    sets the `Host` header to the upstream authority, optionally
    ///    injects the JWT bearer token, and dispatches the request through
    ///    the pooled HTTPS client. A backend connection failure is mapped
    ///    to `502 Bad Gateway`.
    ///
    /// # Arguments
    ///
    /// * `req` – The inbound HTTP request with a [`SrvBody`] body type.
    ///
    /// # Returns
    ///
    /// A pinned, boxed future resolving to:
    /// - `Ok(Response)` – either the upstream response or a synthetic error
    ///   response (404 / 403 / 502).
    /// - `Err(SrvError)` – only on internal errors such as URI construction
    ///   failures.
    fn call(&mut self, req: Request<SrvBody>) -> Self::Future {
        // Clone the cheaply-clonable handles so they can move into the
        // `async` block without borrowing `self`.
        let router = Arc::clone(&self.router);
        let client = self.client.clone();
        let server_name = self.config.name.as_str();
        let jwt_token = self.jwt_token.clone();

        Box::pin(async move {
            // Decompose the request into its head (`parts`) and body so
            // we can freely mutate headers, URI, and extensions.
            let (mut parts, body) = req.into_parts();

            // ── Stage 1: IP Address Management ───────────────────────
            // The `ConnectionHandler` layer stores the peer's `SocketAddr`
            // in the request extensions. We extract it and propagate the
            // client IP as `X-Real-IP` so upstream services know the true
            // origin of the request.
            if let Some(addr) = parts.extensions.get::<std::net::SocketAddr>() {
                let ip_str = addr.ip().to_string();
                if let Ok(hv) = header::HeaderValue::from_str(&ip_str) {
                    parts.headers.insert("X-Real-IP", hv);
                }
                // X-Forwarded-For logic
            }

            // ── Stage 2: Route Lookup ────────────────────────────────
            // Query the radix-tree router with the request path. The
            // `matchit::Match` returned on success contains:
            //   - `value` → the `ParsedRoute` with upstream URI, allowed
            //                roles, prefix, etc.
            //   - `params` → captured wildcard segments (e.g. `rest`).
            let path = parts.uri.path();
            let matched = match router.at(path) {
                Ok(m) => m,
                Err(_) => return Ok(build_error_response("Not Found", StatusCode::NOT_FOUND)),
            };
            let route_info = matched.value;

            // ── Stage 3: Role-Based Access Control (RBAC) ────────────
            // If the route defines `allowed_roles`, we check whether the
            // user possesses at least one of them. The roles are stored as
            // `Arc<Vec<UserRole>>` in the request extensions, populated
            // earlier by the `ConnectionHandler` from the client certificate
            // OIDs or another authentication mechanism.
            if !route_info.allowed_roles.is_empty() {
                // We look for the Vec<UserRole> that the ConnectionHandler set in the request extensions.
                let user_roles = parts.extensions.get::<Arc<Vec<UserRole>>>();

                let is_authorized = match user_roles {
                    Some(roles) => roles.iter().any(|r| route_info.allowed_roles.contains(r)),
                    None => false,
                };

                if !is_authorized {
                    warn!(
                        "{}: Forbidden for roles {:?} at {}",
                        server_name, user_roles, path
                    );
                    return Ok(build_error_response("Forbidden", StatusCode::FORBIDDEN));
                }
            }

            // ── Stage 4: URI Reconstruction ──────────────────────────
            // Build the full upstream path-and-query string by:
            //   a) Starting with the backend base path (trailing `/` trimmed).
            //   b) Appending the captured `*rest` wildcard segment, if any.
            //   c) Appending the original query string, if present.
            // Finally, we reassemble a `Uri` using the upstream's scheme
            // and authority combined with the newly constructed path+query.
            let backend_base_uri = &route_info.upstream_uri;
            let mut pq_string = String::with_capacity(64);
            pq_string.push_str(backend_base_uri.path().trim_end_matches('/'));

            // Append the sub-path captured by the `*rest` wildcard param.
            if let Some(rest) = matched.params.get("rest") {
                if !rest.starts_with('/') {
                    pq_string.push('/');
                }
                pq_string.push_str(rest);
            } else if pq_string.is_empty() {
                // Ensure the path is never empty — at minimum it is `/`.
                pq_string.push('/');
            }

            // Preserve the original query string verbatim.
            if let Some(query) = parts.uri.query() {
                pq_string.push('?');
                pq_string.push_str(query);
            }

            // Re-assemble the URI from the upstream's scheme + authority
            // and the freshly built path-and-query.
            let mut uri_parts = backend_base_uri.clone().into_parts();
            uri_parts.path_and_query = Some(
                pq_string
                    .parse::<PathAndQuery>()
                    .map_err(|e| SrvError::from(format!("Invalid PathAndQuery: {e}")))?,
            );

            parts.uri = Uri::from_parts(uri_parts)
                .map_err(|e| SrvError::from(format!("URI Build Error: {e}")))?;

            // ── Stage 5: Header Management & Forwarding ──────────────
            // Strip all hop-by-hop headers that are meaningful only for
            // the client-to-proxy leg (RFC 7230 §6.1).
            for h in &HOP_BY_HOP_HEADERS {
                parts.headers.remove(h);
            }

            // Set the `Host` header to the upstream's authority so that
            // virtual-host routing on the backend works correctly.
            if let Some(auth) = parts.uri.authority() {
                if let Ok(host_val) = header::HeaderValue::from_str(auth.as_str()) {
                    parts.headers.insert(header::HOST, host_val);
                }
            }

            // Inject the pre-formatted JWT bearer token when configured.
            if let Some(hv) = jwt_token {
                parts.headers.insert(header::AUTHORIZATION, hv);
            }

            // Box-erase the request body so it matches the client's
            // expected body type (`ServiceRespBody`), then re-assemble
            // the proxy request from parts + body.
            let boxed_body: ServiceRespBody = body.map_err(SrvError::from).boxed();
            let proxy_req = Request::from_parts(parts, boxed_body);

            // Dispatch the request to the upstream backend and stream the
            // response back. On failure, return a synthetic 502 Bad Gateway
            // instead of propagating the error — the client should receive
            // a well-formed HTTP response even when the backend is unreachable.
            match client.request(proxy_req).await {
                Ok(res) => {
                    let (res_parts, res_body) = res.into_parts();
                    Ok(Response::from_parts(
                        res_parts,
                        res_body.map_err(SrvError::from).boxed(),
                    ))
                }
                Err(e) => {
                    error!("{}: Backend connection failed: {}", server_name, e);
                    Ok(build_error_response("Bad Gateway", StatusCode::BAD_GATEWAY))
                }
            }
        })
    }
}

/// Builds a minimal synthetic HTTP error response.
///
/// Used to return well-formed error pages to the client without depending
/// on any upstream backend (e.g. for 404, 403, or 502 situations).
///
/// # Arguments
///
/// * `msg`    – A static string that becomes the response body (e.g. `"Not Found"`).
/// * `status` – The HTTP status code to set on the response.
///
/// # Panics
///
/// Panics if the `Response::builder()` fails, which can only happen if
/// an invalid status code is supplied — all call-sites use well-known constants.
fn build_error_response(msg: &'static str, status: StatusCode) -> Response<ServiceRespBody> {
    let body = Full::new(Bytes::from(msg)).map_err(SrvError::from).boxed();
    Response::builder()
        .status(status)
        .body(body)
        .expect("Response builder failed")
}
