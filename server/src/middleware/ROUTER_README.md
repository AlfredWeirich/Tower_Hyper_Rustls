# RouterService — Reverse-Proxy Routing

> **File:** [`router.rs`](./router.rs)

A Tower `Service` that acts as a **configurable reverse proxy**.
Incoming HTTP requests are matched against prefix-based routes and forwarded to upstream backend servers, with built-in RBAC, URI rewriting, and hop-by-hop header management.

---

## Architecture

```
                              ┌──────────────────┐
   Client Request ──────────► │  RouterService   │
                              │                  │
                              │  1. Extract IP   │
                              │  2. Route Lookup │
                              │  3. RBAC Check   │
                              │  4. Rewrite URI  │
                              │  5. Strip Headers│
                              │  6. Forward      │──────► Upstream Backend
                              └──────────────────┘
                                       │
                                       ▼
                              Response streamed
                              back to client
```

## Features

| Feature | Description |
|---------|-------------|
| **Prefix Routing** | Uses [`matchit`](https://docs.rs/matchit) radix-tree router for efficient O(1)-ish path matching with wildcard support (`{*rest}`). |
| **URI Rewriting** | Translates client-facing paths to upstream paths, preserving trailing segments and query parameters. |
| **RBAC** | Routes can restrict access to specific `UserRole`s (`Admin`, `Operator`, `Viewer`, `Guest`). Roles are injected by the `ConnectionHandler` or `JwtAuthService` earlier in the stack. |
| **Hop-by-Hop Header Stripping** | Removes connection-level headers (`Connection`, `Transfer-Encoding`, `Upgrade`, etc.) per RFC 7230 §6.1. |
| **Upstream Authentication** | Supports **mTLS** (client certificate) or **JWT bearer token** injection toward backends. |
| **Connection Pooling** | Uses Hyper's built-in pooled `Client` for efficient connection reuse to upstream servers. |

## Request Processing Pipeline

Each incoming request passes through six stages inside the `call()` method:

1. **IP Address Management** — Extracts the client socket address from request extensions and sets `X-Real-IP`.
2. **Route Lookup** — Matches the request path against the radix-tree router. Returns `404 Not Found` on miss.
3. **RBAC Enforcement** — If the matched route has `allowed_roles`, verifies the client's roles (from request extensions). Returns `403 Forbidden` on denial.
4. **URI Reconstruction** — Builds the upstream URI from the matched route's `upstream_uri`, the captured wildcard suffix, and the original query string.
5. **Header Management** — Strips hop-by-hop headers, sets `Host` to the upstream authority, and optionally injects an `Authorization: Bearer <token>` header.
6. **Forwarding** — Sends the rewritten request via the pooled HTTPS client and streams the response back. Returns `502 Bad Gateway` on upstream failure.

## Configuration (TOML)

Routes are defined in `Config.toml` under each `[[Server]]` block:

```toml
[[Server]]
name = "proxy"
service = "Router"

[Server.RouterParams]
protocol = "https"                              # Upstream protocol
authentication = "JWT"                          # or "ClientCert", "None"
ssl_root_certificate = "certs/upstream-ca.pem"  # Verify upstream TLS
jwt = "jwt/upstream-token.jwt"                  # Bearer token file
# ssl_client_certificate = "..."               # For mTLS to upstream
# ssl_client_key = "..."

[Server.ReverseRoutes."/api"]
upstream = "127.0.0.1:8080"
allowed_roles = ["Admin", "Operator"]

[Server.ReverseRoutes."/public"]
upstream = "127.0.0.1:8081"
# allowed_roles omitted → unrestricted access
```

### Route Matching

Routes are sorted by **descending prefix length** during `ServerConfig::finalize()`, ensuring the most specific prefix always wins. The `matchit` router registers each prefix with a `{*rest}` wildcard catch-all:

```
/api/v1/{*rest}   →  upstream_a
/api/{*rest}      →  upstream_b
/{*rest}          →  upstream_c
```

## Struct & API Reference

### `RouterService`

```rust
#[derive(Clone)]
pub struct RouterService {
    client:    Client<HttpsConnector<HttpConnector>, ServiceRespBody>,
    router:    Arc<Router<ParsedRoute>>,
    config:    &'static ServerConfig,
    jwt_token: Option<HeaderValue>,
}
```

| Field | Purpose |
|-------|---------|
| `client` | Pooled Hyper HTTP client with Rustls connector (optional mTLS). |
| `router` | `Arc`-wrapped `matchit::Router` for zero-copy shared routing. |
| `config` | Static reference to the server configuration (used for logging). |
| `jwt_token` | Pre-formatted `Bearer <token>` value for upstream JWT auth. |

### Key Methods

| Method | Description |
|--------|-------------|
| `new(config)` | Constructs the router, registers all routes, builds the TLS client. Panics if no `RouterParams` are configured. |
| `poll_ready()` | Always returns `Ready` — back-pressure is handled by the Hyper connection pool. |
| `call(req)` | Processes one request through the 6-stage pipeline described above. |

### `build_error_response()`

A helper function that builds minimal synthetic HTTP error responses (404, 403, 502) without depending on any upstream backend.

## Error Handling

| Situation | HTTP Status | Logged? |
|-----------|-------------|---------|
| No matching route prefix | `404 Not Found` | `warn!` |
| Client lacks required role | `403 Forbidden` | `warn!` with client roles |
| Upstream connection failure | `502 Bad Gateway` | `error!` with details |
| URI construction failure | `SrvError` propagated | Via `?` operator |

## Cloning & Performance

`RouterService` is **cheaply cloneable**:

- The `Router<ParsedRoute>` is wrapped in `Arc` — cloning only increments the reference count.
- The Hyper `Client` uses an internal atomic-reference-counted connection pool.
- The `jwt_token` is a small `Option<HeaderValue>` that clones in O(1).

This makes it safe to clone once per connection in the TCP/UDP accept loops without performance concerns.

## Dependencies

| Crate | Usage |
|-------|-------|
| [`matchit`](https://docs.rs/matchit) | Radix-tree URL router |
| [`hyper`](https://docs.rs/hyper) + [`hyper-util`](https://docs.rs/hyper-util) | HTTP client & request/response types |
| [`hyper-rustls`](https://docs.rs/hyper-rustls) | TLS connector for the upstream client |
| [`tower`](https://docs.rs/tower) | `Service` trait implementation |
| [`bytes`](https://docs.rs/bytes) + [`http-body-util`](https://docs.rs/http-body-util) | Body manipulation |
| [`tracing`](https://docs.rs/tracing) | Structured logging |
