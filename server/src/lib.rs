//! # Server Library Crate Root
//!
//! This module defines the **core types** and the [`ConnectionHandler`] that
//! together form the backbone of the reverse-proxy server.
//!
//! ## Contents
//!
//! | Item | Purpose |
//! |------|---------|
//! | [`SrvBody`] / [`ServiceRespBody`] | Unified, boxed HTTP body type used throughout the service stack. |
//! | [`BoxedCloneService`] | A type-erased, cloneable Tower service – the fully assembled middleware pipeline. |
//! | [`H3Body`] | Adapter that bridges an HTTP/3 (QUIC) receive stream into a [`http_body::Body`]. |
//! | [`ConnectionHandler`] | Per-connection glue: injects client metadata (IP, roles) and security headers. |
//!
//! ## Module re-exports
//!
//! The crate publicly exposes four sub-modules:
//! - [`configuration`] – TOML-driven server configuration and route parsing.
//! - [`error`] – The unified [`SrvError`] error type.
//! - [`middleware`] – Tower layers (logging, Alt-Svc, JWT, routing, …).
//! - [`tls_conf`] – TLS acceptor construction for `rustls`.

use bytes::Buf;
use core::net::SocketAddr;
use futures::Stream;
use http_body_util::{BodyExt, combinators::BoxBody};
use hyper::{
    Request, Response,
    body::{Bytes, Incoming},
};
// use pin_project::pin_project;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tower::Service;
use tower::util::BoxCloneService;

// ── Public Modules ───────────────────────────────────────────────────────────

/// Server configuration, route parsing, and role definitions.
pub mod configuration;
/// Unified error type ([`SrvError`]) used across all layers.
pub mod error;
/// Tower middleware layers (logging, Alt-Svc header injection, routing, …).
pub mod middleware;
/// TLS acceptor and `rustls` configuration helpers.
pub mod tls_conf;
pub use error::SrvError;

// ── Type Aliases ─────────────────────────────────────────────────────────────

/// The canonical body type flowing through the Tower service stack.
///
/// A boxed, dynamically-dispatched HTTP body whose data chunks are [`Bytes`]
/// and whose error type is [`SrvError`]. Using a single body type across all
/// middleware avoids generic-parameter explosion.
pub type SrvBody = BoxBody<Bytes, SrvError>;

/// Alias for response bodies – identical to [`SrvBody`] for symmetry.
///
/// Having a separate alias makes it easy to diverge later (e.g. if response
/// bodies need different constraints) without touching every signature.
pub type ServiceRespBody = SrvBody;

/// A fully assembled, type-erased, **cloneable** Tower service.
///
/// This is the end product of stacking all middleware layers. It accepts a
/// `Request<SrvBody>` and produces a `Response<ServiceRespBody>`. Because it
/// is clone-able, it can be shared across connections via cheap `Arc`-based
/// cloning internally.
pub type BoxedCloneService = BoxCloneService<Request<SrvBody>, Response<ServiceRespBody>, SrvError>;

// ── HTTP/3 Body Adapter ──────────────────────────────────────────────────────

/// The concrete receive-stream type from the `h3` + `h3_quinn` stack.
///
/// We use `RecvStream` (not `BidiStream`) because the request/response
/// halves are split: the server reads from `RecvStream` and writes to a
/// separate `SendStream`.
type H3RecvStream = h3::server::RequestStream<h3_quinn::RecvStream, bytes::Bytes>;

/// Adapter that presents an HTTP/3 QUIC receive stream as an [`http_body::Body`].
///
/// Hyper's service stack expects bodies to implement [`http_body::Body`], but
/// the `h3` crate exposes data through an async [`Stream`]. `H3Body` bridges
/// the two by wrapping the stream in a pinned, heap-allocated box and
/// delegating [`Body::poll_frame`] to [`Stream::poll_next`].
///
/// # Construction
///
/// Created via [`H3Body::new`], which takes ownership of an [`H3RecvStream`]
/// and internally builds a [`futures::stream::unfold`] that repeatedly calls
/// [`recv_data()`](h3::server::RequestStream::recv_data) until EOF or error.
pub struct H3Body {
    /// The underlying async stream of body frames, type-erased and pinned.
    ///
    /// Each item is a `Result<Frame<Bytes>, SrvError>`. The stream yields
    /// `None` on EOF and `Some(Err(…))` on transport errors.
    inner: Pin<Box<dyn Stream<Item = Result<http_body::Frame<Bytes>, SrvError>> + Send + Sync>>,
}

impl H3Body {
    /// Creates a new `H3Body` by converting an HTTP/3 receive stream into
    /// an async [`Stream`] of body frames.
    ///
    /// Internally uses [`futures::stream::unfold`] to drive the `h3`
    /// receive loop:
    /// - **`Ok(Some(bytes))`** – a chunk of data arrived; copy it into a
    ///   contiguous [`Bytes`] buffer and wrap it in a [`http_body::Frame`].
    /// - **`Ok(None)`** – the peer has finished sending (EOF); end the stream.
    /// - **`Err(e)`** – a transport-level error occurred; surface it as
    ///   [`SrvError`] and let the consumer decide how to handle it.
    ///
    /// # Arguments
    ///
    /// * `stream` – The HTTP/3 receive stream obtained after splitting the
    ///   bidirectional QUIC stream.
    pub fn new(stream: H3RecvStream) -> Self {
        let s = futures::stream::unfold(stream, |mut s| async move {
            match s.recv_data().await {
                Ok(Some(mut bytes)) => {
                    let frame = http_body::Frame::data(bytes.copy_to_bytes(bytes.remaining()));
                    Some((Ok(frame), s))
                }
                Ok(None) => None, // EOF
                Err(e) => Some((Err(SrvError::from(e.to_string())), s)),
            }
        });

        Self { inner: Box::pin(s) }
    }
}

/// [`http_body::Body`] implementation for [`H3Body`].
///
/// Delegates frame polling directly to the inner async stream. Because the
/// stream already yields `Result<Frame<Bytes>, SrvError>`, no additional
/// transformation is needed — this is a thin forwarding impl.
impl http_body::Body for H3Body {
    type Data = Bytes;
    type Error = SrvError;

    /// Polls the underlying QUIC receive stream for the next body frame.
    ///
    /// Returns:
    /// - `Poll::Ready(Some(Ok(frame)))` – a data frame is available.
    /// - `Poll::Ready(Some(Err(e)))` – a transport error occurred.
    /// - `Poll::Ready(None)` – the body has been fully received (EOF).
    /// - `Poll::Pending` – no data available yet; the waker is registered.
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        self.inner.as_mut().poll_next(cx)
    }
}

// ── Connection Handler ───────────────────────────────────────────────────────

use crate::configuration::UserRole;
use std::sync::Arc;

/// Per-connection bridge between the network transport and the application's
/// Tower service stack.
///
/// A `ConnectionHandler` is created once per accepted TLS connection and is
/// then cloned for every HTTP request that arrives on that connection (HTTP/2
/// multiplexes many requests over a single connection).
///
/// # Responsibilities
///
/// 1. **Client metadata injection** – Stores the peer's [`SocketAddr`] and
///    resolved [`UserRole`]s, and attaches them as request extensions so
///    downstream middleware (e.g. the router's RBAC check) can access them.
/// 2. **Security header enforcement** – Appends a set of hardened HTTP
///    response headers (HSTS, CSP, etc.) to **every** response, regardless
///    of what the upstream backend or middleware returns.
/// 3. **Body type bridging** – Converts Hyper's native [`Incoming`] body
///    into the unified [`SrvBody`] type expected by the service stack.
///
/// # Cloning
///
/// `ConnectionHandler` is cheaply cloneable: the inner service uses
/// [`BoxCloneService`] (internally `Arc`-based) and the role list is
/// wrapped in an [`Arc`].
pub struct ConnectionHandler {
    /// The fully assembled middleware + routing pipeline, type-erased and
    /// cloneable so it can be shared across all requests on this connection.
    inner_service: BoxedCloneService,

    /// The remote peer's socket address (IP + port), used to populate
    /// `X-Real-IP` and for logging/diagnostics.
    client_addr: SocketAddr,

    /// Pre-computed user roles derived from the client certificate's OIDs.
    ///
    /// Wrapped in [`Arc`] so that cloning the handler for each request on
    /// the same connection is a cheap pointer bump instead of a `Vec` copy.
    /// Defaults to `[UserRole::Guest]` when no recognized OID is found.
    client_roles: Arc<Vec<UserRole>>,
}

impl ConnectionHandler {
    /// Creates a new `ConnectionHandler`, performing the **OID → Role mapping**
    /// once at connection establishment time.
    ///
    /// The mapping is intentionally done here — not per-request — because it
    /// involves a global config lookup and allocation. Doing it once and
    /// sharing the result via [`Arc`] avoids repeated work for every request
    /// on the same connection.
    ///
    /// # Arguments
    ///
    /// * `service` – The boxed, cloneable Tower service stack.
    /// * `addr`    – The remote peer's socket address.
    /// * `oids`    – OID strings extracted from the client's X.509 certificate.
    ///              Each OID is mapped to a [`UserRole`] via the global config.
    ///
    /// # Role resolution logic
    ///
    /// 1. Map every OID to a [`UserRole`] using [`Config::map_oid_to_role`].
    /// 2. Filter out [`UserRole::Guest`] (the default/fallback role).
    /// 3. If no meaningful roles remain, fall back to `[UserRole::Guest]`.
    pub fn new(service: BoxedCloneService, addr: SocketAddr, oids: Vec<String>) -> Self {
        // 1. Perform the expensive mapping ONCE per connection
        let config = crate::configuration::Config::global();
        let roles: Vec<UserRole> = oids
            .iter()
            .map(|oid| config.map_oid_to_role(oid))
            .filter(|role| *role != UserRole::Guest)
            .collect();

        // If you need Guest as fallback, handle it here
        let final_roles = if roles.is_empty() {
            vec![UserRole::Guest]
        } else {
            roles
        };

        Self {
            inner_service: service,
            client_addr: addr,
            client_roles: Arc::new(final_roles),
        }
    }

    /// Creates a `ConnectionHandler` that **reuses** an already-resolved
    /// role list.
    ///
    /// This is the preferred constructor when handling a second (or Nth)
    /// request on the same connection, because the roles were already
    /// computed during the first [`ConnectionHandler::new`] call.
    ///
    /// # Arguments
    ///
    /// * `service` – The boxed, cloneable Tower service stack.
    /// * `addr`    – The remote peer's socket address.
    /// * `roles`   – A shared, pre-computed role vector (cheap `Arc` clone).
    pub fn new_shared(
        service: BoxedCloneService,
        addr: SocketAddr,
        roles: Arc<Vec<UserRole>>, // Pass roles, not OIDs
    ) -> Self {
        Self {
            inner_service: service,
            client_addr: addr,
            client_roles: roles,
        }
    }

    /// Processes a single HTTP request through the full middleware pipeline.
    ///
    /// This method **consumes** `self`, which side-steps `Send` / `Sync`
    /// issues that would arise if we held a `&mut self` across `.await`
    /// points. Callers typically clone the handler first.
    ///
    /// # Processing steps
    ///
    /// 1. **Inject client IP** – Inserts the [`SocketAddr`] into the request
    ///    extensions so downstream layers (e.g. the router) can set
    ///    `X-Real-IP`.
    /// 2. **Inject user roles** – Clones the [`Arc<Vec<UserRole>>`] into the
    ///    request extensions (zero-cost pointer bump). The router's RBAC
    ///    check reads these roles later.
    /// 3. **Dispatch** – Forwards the enriched request to the inner service
    ///    stack and awaits its response.
    /// 4. **Security headers** – Appends hardened response headers that must
    ///    apply universally, regardless of upstream or middleware behavior:
    ///    - `Strict-Transport-Security` (HSTS, 2 years)
    ///    - `X-Content-Type-Options: nosniff`
    ///    - `Content-Security-Policy: default-src 'none'`
    ///    - `Cache-Control: no-store`
    ///
    /// # Arguments
    ///
    /// * `req` – The inbound request with a [`SrvBody`] (already box-erased).
    ///
    /// # Errors
    ///
    /// Returns `Err(SrvError)` if the inner service stack returns an error.
    pub async fn handle(
        mut self,
        mut req: Request<SrvBody>,
    ) -> Result<Response<ServiceRespBody>, SrvError> {
        req.extensions_mut().insert(self.client_addr);

        // 2. Zero-cost injection. Just cloning the Arc pointer.
        req.extensions_mut().insert(self.client_roles.clone());

        let mut resp = self.inner_service.call(req).await?;

        // === Security Response Headers ===
        // Injected at the ConnectionHandler level so they apply to ALL responses,
        // regardless of middleware configuration. Cannot be accidentally disabled.
        let headers = resp.headers_mut();
        headers.insert(
            // HSTS: Forces browsers to use HTTPS for 2 years, preventing
            // TLS downgrade attacks on the initial plaintext request.
            hyper::header::STRICT_TRANSPORT_SECURITY,
            "max-age=63072000; includeSubDomains".parse().unwrap(),
        );
        headers.insert(
            // Prevents MIME-type sniffing: browsers must trust the declared
            // Content-Type, blocking attacks that rely on content misinterpretation.
            hyper::header::X_CONTENT_TYPE_OPTIONS,
            "nosniff".parse().unwrap(),
        );
        // headers.insert(
        //     /*Tells browsers: "Don't embed this page in a frame, iframe, or object." This prevents clickjacking attacks where an attacker puts your site inside a hidden iframe on their site to trick users into clicking things they didn't mean to click. */
        //     hyper::header::X_FRAME_OPTIONS,
        //     "DENY".parse().unwrap());
        headers.insert(
            // CSP `default-src 'none'`: the most restrictive Content Security
            // Policy — no external resources (scripts, images, etc.) may load.
            // Ideal for a pure API that only returns JSON/data.
            hyper::header::CONTENT_SECURITY_POLICY,
            "default-src 'none'".parse().unwrap(),
        );
        headers.insert(
            // Prevents caching of dynamic API responses so clients always
            // receive fresh data and sensitive information is not stored
            // in browser/proxy caches.
            hyper::header::CACHE_CONTROL,
            "no-store".parse().unwrap(),
        );

        Ok(resp)
    }
}

// ── Hyper Service Implementation ─────────────────────────────────────────────
//
// This is the entry point that Hyper's HTTP/1.1 and HTTP/2 connection drivers
// call for every incoming request. It adapts the native `Incoming` body type
// to our unified `SrvBody` and delegates to `ConnectionHandler::handle`.

impl hyper::service::Service<Request<Incoming>> for ConnectionHandler {
    type Response = Response<ServiceRespBody>;
    type Error = SrvError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    /// Called by Hyper's connection driver for each incoming HTTP request.
    ///
    /// Performs three steps:
    /// 1. **Decompose** the request into head (`parts`) and body.
    /// 2. **Box-erase** the [`Incoming`] body into a [`SrvBody`] so it is
    ///    compatible with the Tower service stack.
    /// 3. **Clone** `self` and spawn the actual processing inside a pinned
    ///    future, because `Service::call` takes `&self` but
    ///    [`ConnectionHandler::handle`] consumes `self` for `Send` safety.
    fn call(&self, req: Request<Incoming>) -> Self::Future {
        let (parts, body) = req.into_parts();
        let boxed_body = body.map_err(SrvError::from).boxed();
        let req = Request::from_parts(parts, boxed_body);
        let this = self.clone();
        Box::pin(async move { this.handle(req).await })
    }
}

/// Manual [`Clone`] implementation for [`ConnectionHandler`].
///
/// All fields are cheaply cloneable:
/// - `inner_service` – [`BoxCloneService`] clones via an internal `Arc`.
/// - `client_addr` – [`SocketAddr`] is `Copy`.
/// - `client_roles` – [`Arc<Vec<UserRole>>`] is a pointer bump.
impl Clone for ConnectionHandler {
    fn clone(&self) -> Self {
        Self {
            inner_service: self.inner_service.clone(),
            client_addr: self.client_addr,
            client_roles: self.client_roles.clone(),
        }
    }
}
