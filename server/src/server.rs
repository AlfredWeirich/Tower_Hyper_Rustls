//! # Server Binary — Entry Point & Lifecycle
//!
//! This is the main executable for the server application. It orchestrates:
//!
//! 1. **Configuration loading** via [`Config::init`].
//! 2. **Tokio runtime creation** with a configurable number of worker threads.
//! 3. **Tracing / logging setup** (stdout + optional rolling-file appender).
//! 4. **Per-server task spawning** — each `[[Server]]` block in `Config.toml`
//!    becomes an independent Tokio task.
//! 5. **Dual-stack listeners** — HTTPS servers accept both TCP (HTTP/1.1 + H2)
//!    and UDP (HTTP/3 via QUIC) on the **same port**.
//! 6. **Graceful shutdown** on `Ctrl-C` using a shared [`CancellationToken`].
//!
//! ## Architecture Overview
//!
//! ```text
//! main()
//!   └─ main_async()                       (tokio runtime)
//!       ├─ start_single_server(server_A)  (spawned task)
//!       │   ├─ build_service_stack()
//!       │   └─ run_dual_stack()
//!       │       ├─ run_tcp_listener()     (HTTP/1.1, H2)
//!       │       └─ run_udp_listener()     (H3/QUIC)
//!       ├─ start_single_server(server_B)
//!       │   └─ …
//!       └─ Ctrl-C handler → CancellationToken
//! ```
//!
//! ## Example `curl` Invocations
//!
//! ```bash
//! # HTTP/2 + mTLS + help endpoint
//! curl -v --http2 \
//!   --cert client_certs/client.cert.pem \
//!   --key  client_certs/client.key.pem \
//!   --cacert server_certs/self_signed/myca.pem \
//!   https://192.168.178.175:1337/help
//!
//! # HTTP/3 + JWT + JSON PUT
//! echo '{"status": "updated"}' | curl -v --http3 -X PUT \
//!   --cert client_certs/client.cert.pem \
//!   --key  client_certs/client.key.pem \
//!   --cacert server_certs/self_signed/myca.pem \
//!   -H "Authorization: Bearer $(cat ./jwt/token1.jwt)" \
//!   -H "Content-Type: application/json" \
//!   --data-binary @- https://192.168.178.175:1337/
//! ```

// tokio console: https://tokio.rs/tokio/topics/tracing-next-steps

/// Optimization 1
/// Use mimalloc as the global allocator for reduced contention
/// under heavy multi-threaded workloads (5–15% throughput gain).
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

// === Standard Library ===
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

// === External Crates ===
use anyhow::{Context, Error};
use hyper::Request;
use hyper_util::rt::TokioIo;
use tokio::{net::TcpListener, runtime::Builder};

use tokio_util::sync::CancellationToken;
use tower::{Layer, ServiceExt, limit::ConcurrencyLimit};
use tracing::{error, info, trace};
use tracing_appender::{non_blocking::WorkerGuard, rolling::RollingFileAppender};
use tracing_subscriber::{EnvFilter, Registry, fmt, layer::SubscriberExt};

// === Internal Modules ===
use server::configuration::UserRole;
use server::{
    BoxedCloneService, ConnectionHandler,
    configuration::{
        AuthenticationMethod, CompiledAllowedPathes, Config, MiddlewareLayer, Protocol,
        ServerConfig, ServiceType,
    },
    middleware::{
        CountingLayer, DelayLayer, EchoService, InspectionLayer, JwtAuthLayer, LoggerLayer,
        MaxPayloadLayer, RouterService, SimpleRateLimiterLayer, TimingLayer,
        TokenBucketRateLimiterLayer,
        alt_svc::AltSvcLayer,
        compression::{SrvCompressionLayer, SrvDecompressionLayer},
    },
    tls_conf::{extract_oids_from_cert, tls_config},
};

use http_body_util::BodyExt;
use hyper::{Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioTimer};
use hyper_util::server::conn::auto;
use rustls::ServerConfig as RustlsServerConfig;
use server::H3Body;
use std::sync::Mutex;

///    Main entry point for the server application.
///
/// This function is the "synchronous" wrapper that starts the program.
/// It performs the following steps:
/// 1. **Parse Arguments**: Looks for a configuration file path (default: `Config.toml`).
/// 2. **Load Configuration**: Reads and parses the global settings.
/// 3. **Setup Logging**: Initializes the tracing system to see what the server is doing.
/// 4. **Build Runtime**: Starts the Tokio runtime, which is the engine that drives all asynchronous tasks.
/// 5. **Start Server**: Launches the main asynchronous loop.
fn main() -> Result<(), Error> {
    let arg = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "Config.toml".to_string());

    // This installs 'ring' as the default provider for the entire process.
    // Ensure you have the 'ring' feature enabled in rustls (usually default).
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    // Initialize the global configuration from the provided file.
    // This uses a OnceLock pattern for safe, global read access.
    let config = Config::init(&arg)?;

    // Determine the number of Tokio worker threads. Defaults to 2x logical CPUs if not specified.
    let tokio_threads = config.tokio_threads.unwrap_or_else(|| num_cpus::get());

    // Setup the tracing/logging system (stdout and optional file appender).
    // Use _guard to keep the non-blocking appender alive until the end of main.
    let _tracing_guard = setup_tracing(config.log_dir.as_deref())?;

    info!("Configuration loaded from: {}", arg);
    trace!("Full Config: {:#?}", config);

    // Build the high-performance multi-threaded Tokio runtime.
    let runtime = Builder::new_multi_thread()
        .worker_threads(tokio_threads)
        .enable_all()
        .build()
        .context("Failed to build Tokio runtime")?;

    // Block the main thread on the execution of the asynchronous server loop.
    runtime.block_on(main_async(config))
}

/// The asynchronous main loop that manages multiple server instances.
///
/// Think of this as the "Mission Control" center.
/// - It reads the list of servers from the config.
/// - For each enabled server, it launches a separate, independent task (green thread).
/// - It listens for a "Shutdown Signal" (like pressing Ctrl+C).
/// - It ensures all servers stop gracefully before the program exits.
async fn main_async(config: Arc<Config>) -> Result<(), Error> {
    let mut server_join_set = tokio::task::JoinSet::new();

    // Map: port -> (CancellationToken, Arc<ServerConfig>, Arc<Mutex<BoxedCloneService>>)
    let mut active_servers: std::collections::HashMap<
        u16,
        (
            CancellationToken,
            Arc<ServerConfig>,
            Arc<Mutex<BoxedCloneService>>,
        ),
    > = std::collections::HashMap::new();

    // Iterate through all configured servers and spawn tasks for those that are enabled.
    for server_config in &config.servers {
        if !server_config.enabled {
            continue;
        }

        let cancel_token = CancellationToken::new();
        let server_config_arc = Arc::new(server_config.clone());

        let service_stack = match build_service_stack(&server_config_arc) {
            Ok(svc) => svc,
            Err(e) => {
                error!(
                    "{}: Failed to build initial service stack: {:?}",
                    server_config.name, e
                );
                continue;
            }
        };
        let dynamic_stack = Arc::new(Mutex::new(service_stack));

        active_servers.insert(
            server_config.port,
            (
                cancel_token.clone(),
                server_config_arc.clone(),
                dynamic_stack.clone(),
            ),
        );

        server_join_set.spawn(async move {
            start_single_server(server_config_arc, cancel_token, dynamic_stack).await;
        });
    }

    let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;

    // Wait for a shutdown signal or handle configuration reloads
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("Shutdown signal received (Ctrl+C). Starting graceful shutdown...");
                break;
            }
            _ = sighup.recv() => {
                info!("Received SIGHUP, initiating hot-reload...");

                // 1. Reload configuration from disk
                // Config::init reads the file and returns the new Arc<Config>.
                // It also updates the globally available rustls CertifiedKeys (via ArcSwap)
                // so that DynamicCertResolver instantly gets the new certificates.
                let new_config = match Config::init("Config.toml") {
                    Ok(c) => c,
                    Err(e) => {
                        error!("Failed to reload config on SIGHUP, ignoring: {:?}", e);
                        continue;
                    }
                };

                info!("Successfully parsed new Config.toml");
                let mut next_active_servers = std::collections::HashMap::new();

                // 2. Diff and manage listeners
                for new_server in &new_config.servers {
                    if !new_server.enabled { continue; }

                    let needs_restart = match active_servers.get(&new_server.port) {
                        None => true, // New listener on this port
                        Some((_, old_server, _)) => {
                            // Restart listener if fundamental binding parameters changed
                            old_server.ip != new_server.ip || old_server.protocol != new_server.protocol
                        }
                    };

                    if needs_restart {
                        info!("Starting new listener for '{}' on port {}", new_server.name, new_server.port);
                        let cancel_token = CancellationToken::new();
                        let server_config_arc = Arc::new(new_server.clone());

                        let service_stack = match build_service_stack(&server_config_arc) {
                            Ok(svc) => svc,
                            Err(e) => {
                                error!("{}: Failed to build service stack: {:?}", new_server.name, e);
                                continue;
                            }
                        };
                        let dynamic_stack = Arc::new(Mutex::new(service_stack));

                        next_active_servers.insert(
                            new_server.port,
                            (cancel_token.clone(), server_config_arc.clone(), dynamic_stack.clone()),
                        );

                        server_join_set.spawn(async move {
                            start_single_server(server_config_arc, cancel_token, dynamic_stack).await;
                        });
                    } else {
                        // Keep listener alive!
                        // Removing from active_servers so we know which ones to drop later
                        let (old_token, _, dynamic_stack) = active_servers.remove(&new_server.port).unwrap();
                        let server_config_arc = Arc::new(new_server.clone());

                        // Rebuild service stack for new config
                        if let Ok(new_svc) = build_service_stack(&server_config_arc) {
                            *dynamic_stack.lock().unwrap() = new_svc;
                            info!("Hot-swapped service stack for '{}' on port {}", new_server.name, new_server.port);
                        } else {
                            error!("Failed to rebuild service stack for '{}', keeping old stack", new_server.name);
                        }

                        next_active_servers.insert(new_server.port, (old_token, server_config_arc, dynamic_stack));
                    }
                }

                // 3. Stop drained/removed listeners
                for (port, (token, old_server, _)) in active_servers.drain() {
                    info!("Stopping listener for '{}' on port {}", old_server.name, port);
                    token.cancel();
                }

                active_servers = next_active_servers;
                info!("Hot-reload complete.");
            }
        }
    }

    // Cancel all running listeners on graceful shutdown
    for (_, (token, _, _)) in active_servers {
        token.cancel();
    }

    // Await the completion of all spawned server tasks.
    while let Some(res) = server_join_set.join_next().await {
        if let Err(e) = res {
            error!("Server task panicked or failed prematurely: {:?}", e);
        }
    }

    info!("All servers shut down cleanly.");
    Ok(())
}

/// Starts a single server instance (HTTP or HTTPS/H3) based on the provided configuration.
///
/// This is where the specific instructions for one server (one port) are executed.
///
/// # The Process:
/// 1. **Resolve IP**: Finds the IP address to listen on.
/// 2. **Build Stack**: Assembles the "chain of command" (middleware) that will handle each request.
/// 3. **Check Protocol**:
///    - **HTTPS**: Starts a "Dual Stack" listener. accessible via TCP (traditional web) AND UDP (modern HTTP/3).
///    - **HTTP**: Starts a simple TCP listener for plaintext traffic.
async fn start_single_server(
    server_config: Arc<ServerConfig>,
    cancel_token: CancellationToken,
    dynamic_stack: Arc<Mutex<BoxedCloneService>>,
) {
    if server_config.service == ServiceType::Router {
        if let Some(router_params) = &server_config.router_params {
            let root_store = common::build_root_store(&router_params.ssl_root_certificate);
            let is_mtls = router_params.authentication == AuthenticationMethod::ClientCert;
            let tls_client_config = if is_mtls {
                common::build_tls_client_config(
                    root_store,
                    router_params.ssl_client_certificate.as_deref(),
                    router_params.ssl_client_key.as_deref(),
                )
            } else {
                common::build_tls_client_config(root_store, None, None)
            };

            let pool_config = common::client::ClientPoolConfig {
                idle_timeout: Some(Duration::from_secs(90)),
                max_idle_per_host: Some(1024),
                http2_only: false,
            };

            let client = common::client::build_hyper_client(tls_client_config, pool_config);

            let jwt_token = router_params
                .jwt
                .as_ref()
                .and_then(|t| hyper::header::HeaderValue::from_str(&format!("Bearer {}", t)).ok());

            let proto_str = match router_params.protocol {
                Protocol::Https => "https",
                Protocol::Http => "http",
            };

            for route in &server_config.parsed_routes {
                let interval = route.target.active_health_check_interval;
                if interval > 0 {
                    for (idx, node) in route.target.upstreams.iter().enumerate() {
                        let client = client.clone();
                        let token = cancel_token.clone();
                        let uri_str = format!(
                            "{}://{}/health",
                            proto_str,
                            node.uri.authority().unwrap().as_str()
                        );
                        let uri = uri_str.parse::<hyper::Uri>().unwrap();
                        let server_name = server_config.static_name.unwrap_or("unknown");
                        let interval_dur = Duration::from_secs(interval);
                        let target_arc = route.target.clone();
                        let auth_header = jwt_token.clone();

                        tokio::spawn(async move {
                            let mut ticker = tokio::time::interval(interval_dur);
                            // Set tick behavior so it doesn't burst if delayed
                            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                            loop {
                                tokio::select! {
                                    _ = token.cancelled() => break,
                                    _ = ticker.tick() => {
                                        let mut req_builder = Request::builder()
                                            .method(hyper::Method::GET)
                                            .uri(uri.clone());

                                        if let Some(ref header_val) = auth_header {
                                            req_builder = req_builder.header(hyper::header::AUTHORIZATION, header_val.clone());
                                        }

                                        let req = req_builder
                                            .body(http_body_util::Empty::<bytes::Bytes>::new().map_err(|e| match e {}).boxed())
                                            .unwrap();
                                        match client.request(req).await {
                                            Ok(resp) if resp.status() == StatusCode::OK => {
                                                if !target_arc.upstreams[idx].is_alive.load(std::sync::atomic::Ordering::Relaxed) {
                                                    trace!("{}: Health check recovered '{}'", server_name, uri);
                                                    target_arc.upstreams[idx].is_alive.store(true, std::sync::atomic::Ordering::Relaxed);
                                                }
                                            }
                                            Err(e) => {
                                                if target_arc.upstreams[idx].is_alive.load(std::sync::atomic::Ordering::Relaxed) {
                                                    trace!("{}: Health check failed for '{}': {}", server_name, uri, e);
                                                    target_arc.upstreams[idx].is_alive.store(false, std::sync::atomic::Ordering::Relaxed);
                                                }
                                            }
                                            Ok(resp) => {
                                                if target_arc.upstreams[idx].is_alive.load(std::sync::atomic::Ordering::Relaxed) {
                                                    trace!("{}: Health check failed status {} for '{}'", server_name, resp.status(), uri);
                                                    target_arc.upstreams[idx].is_alive.store(false, std::sync::atomic::Ordering::Relaxed);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        });
                    }
                }
            }
        }
    }

    let server_addr = match server_config.get_server_ip() {
        Ok(addr) => addr,
        Err(e) => {
            error!("{}: Failed to resolve IP: {:?}", server_config.name, e);
            return;
        }
    };

    info!(
        "{}: Listening on {} ({:?})",
        server_config.name, server_addr, server_config.protocol
    );

    // === HTTPS / DUAL STACK PATH ===
    if server_config.protocol == Protocol::Https {
        let tls_config: RustlsServerConfig = match build_rustls_config(server_config.as_ref()) {
            Ok(cfg) => cfg,
            Err(e) => {
                error!("{}: TLS Setup Error: {:?}", server_config.name, e);
                return;
            }
        };

        if let Err(e) = run_dual_stack(
            server_addr,
            tls_config,
            dynamic_stack,
            cancel_token,
            server_config.static_name.expect("missing static_name"),
        )
        .await
        {
            error!(
                "{}: HTTPS/Dual Stack Server crashed: {:?}",
                server_config.name, e
            );
        }
    } else {
        // === HTTP (PLAINTEXT) FALLBACK ===
        // Your original logic for plaintext HTTP only
        let listener = match TcpListener::bind(server_addr).await {
            Ok(l) => l,
            Err(e) => {
                error!("{}: HTTP Bind failed: {}", server_config.name, e);
                return;
            }
        };

        loop {
            tokio::select! {
                _ = cancel_token.cancelled() => break,
                res = listener.accept() => {
                    match res {
                        Ok((stream, peer_addr)) => {
                            let svc = dynamic_stack.lock().unwrap().clone(); // fresh stack per connection
                            let conn_token = cancel_token.clone();
                            tokio::spawn(async move {
                                let handler = ConnectionHandler::new(svc, peer_addr, Vec::new());
                                let mut builder = auto::Builder::new(TokioExecutor::new());
                                // Timeout: drop clients that take too long to send HTTP/1 headers
                                builder.http1()
                                    .timer(TokioTimer::new())
                                    .header_read_timeout(Duration::from_secs(10));
                                // Timeout: detect dead HTTP/2 connections via keep-alive pings
                                builder
                                    .http2()
                                    .timer(TokioTimer::new())
                                    .initial_stream_window_size(1024 * 1024)
                                    .max_concurrent_streams(1024)
                                    .max_pending_accept_reset_streams(Some(16384))
                                    .keep_alive_interval(Some(Duration::from_secs(30)))
                                    .keep_alive_timeout(Duration::from_secs(10));
                                let conn = builder
                                    .serve_connection(TokioIo::new(stream), handler);
                                let mut conn = std::pin::pin!(conn);
                                tokio::select! {
                                    res = conn.as_mut() => { let _ = res; },
                                    _ = conn_token.cancelled() => {
                                        conn.as_mut().graceful_shutdown();
                                        let _ = conn.await;
                                    }
                                }
                            });
                        }
                        Err(e) => error!("{}: HTTP Accept error: {}", server_config.name, e),
                    }
                }
            }
        }
    }
}

/// Builds the service stack for a given server configuration.
///
/// This function takes a `ServerConfig` and constructs a `BoxedCloneService`
/// by applying a series of middleware layers defined in the configuration.
/// It also ensures that if an `InspectionLayer` is used, the `compiled_allowed_pathes`
/// are correctly provided.
///
/// # Arguments
/// * `config` - A static reference to the `ServerConfig` for which to build the service stack.
///
/// # Returns
/// A `Result` which is `Ok` containing a `BoxedCloneService` if successful,
/// or an `Error` if the service stack cannot be built (e.g., missing compiled paths).
fn build_service_stack(server_config: &Arc<ServerConfig>) -> Result<BoxedCloneService, Error> {
    let layers = server_config.layers.build_middleware_layers()?;

    // Ensure compiled paths are available.
    // While the InspectionLayer will also validate this, checking here provides
    // an early configuration error if the paths are missing when needed.
    let compiled_allowed_pathes =
        server_config
            .compiled_allowed_pathes
            .as_ref()
            .context(format!(
                "Server '{}': Compiled paths missing",
                server_config.name
            ))?;

    let base_service = match server_config.service {
        ServiceType::Echo => {
            EchoService::new(server_config.static_name.expect("static_name missing")).boxed_clone()
        }
        ServiceType::Router => RouterService::new(server_config.clone()).boxed_clone(),
    };

    Ok(apply_layers(
        base_service, // The core service (Echo or Router) handling the request
        layers,
        server_config.static_name.expect("static_name missing"),
        compiled_allowed_pathes.clone(),
        server_config.port,
    ))
}

/// Applies the configured middleware layers to the base service.
///
/// This function builds the final service stack by wrapping the base service with each middleware layer
/// defined in the configuration. The layers are applied in reverse order (outside-in execution flow),
/// so the first layer in the list is the outermost wrapper.
///
/// # Arguments
///
/// * `service` - The base service (e.g., Echo or Router) to wrap.
/// * `layers` - A list of middleware layers to apply.
/// * `server_name` - The name of the server, used for logging and metrics.
/// * `compiled_allowed_pathes` - Pre-compiled regex paths for the inspection layer (if used).
/// * `server_port` - The port the server listens on, used for `Alt-Svc` headers.
///
/// # Returns
///
/// A `BoxedCloneService` representing the full middleware stack ready to handle requests.
fn apply_layers(
    service: BoxedCloneService,
    layers: Vec<MiddlewareLayer>,
    server_name: &'static str,
    compiled_allowed_pathes: Arc<CompiledAllowedPathes>,
    server_port: u16, // <--- Add this argument
) -> BoxedCloneService {
    layers
        .into_iter()
        .rev()
        .fold(service, |svc, layer| match layer {
            MiddlewareLayer::Timing => TimingLayer::new(server_name).layer(svc).boxed_clone(),
            MiddlewareLayer::Counter => CountingLayer::new(server_name).layer(svc).boxed_clone(),
            MiddlewareLayer::Logger => LoggerLayer::new(server_name).layer(svc).boxed_clone(),
            MiddlewareLayer::Inspection => {
                InspectionLayer::new(compiled_allowed_pathes.clone(), server_name)
                    .layer(svc)
                    .boxed_clone()
            }
            MiddlewareLayer::Delay(micros) => {
                DelayLayer::new(Duration::from_micros(micros), server_name)
                    .layer(svc)
                    .boxed_clone()
            }
            MiddlewareLayer::JwtAuth(keys) => JwtAuthLayer::new(keys, server_name)
                .layer(svc)
                .boxed_clone(),
            MiddlewareLayer::RateLimiter(server::configuration::RateLimiter::Simple(cfg)) => {
                let dur = Duration::from_secs_f32(1.0 / cfg.requests_per_second as f32);
                SimpleRateLimiterLayer::new(dur, server_name)
                    .layer(svc)
                    .boxed_clone()
            }
            MiddlewareLayer::RateLimiter(server::configuration::RateLimiter::TokenBucket(cfg)) => {
                TokenBucketRateLimiterLayer::new(
                    cfg.max_capacity,
                    cfg.refill,
                    Duration::from_micros(cfg.duration_micros),
                    server_name,
                )
                .layer(svc)
                .boxed_clone()
            }
            MiddlewareLayer::ConcurrencyLimit(max_requests) => {
                // Here we directly use the extracted usize value
                ConcurrencyLimit::new(svc, max_requests).boxed_clone()
            }
            MiddlewareLayer::Compression => SrvCompressionLayer::new(server_name)
                .layer(svc)
                .boxed_clone(),
            MiddlewareLayer::Decompression(max_bytes) => {
                SrvDecompressionLayer::new(server_name, max_bytes)
                    .layer(svc)
                    .boxed_clone()
            }
            MiddlewareLayer::MaxPayload(max_bytes) => MaxPayloadLayer::new(max_bytes, server_name)
                .layer(svc)
                .boxed_clone(),
            MiddlewareLayer::AltSvc => {
                // We use the actual running port of the server
                AltSvcLayer::new(server_port).layer(svc).boxed_clone()
            }
        })
}

// === Refactored run_dual_stack ===

/// Runs a dual-stack server supporting both TCP (HTTP/1.1, HTTP/2) and UDP (HTTP/3).
///
/// # What is "Dual Stack"?
/// Modern web servers often need to speak two different "languages" on the transport layer:
/// 1. **TCP (Transmission Control Protocol)**: The traditional, reliable way to send data. Used for HTTP/1.1 and HTTP/2.
/// 2. **UDP (User Datagram Protocol)**: A faster, but less strict way to send data. Used for HTTP/3 (QUIC).
///
/// This function starts TWO listeners on the same port: one for TCP and one for UDP.
pub async fn run_dual_stack(
    server_addr: SocketAddr,
    tls_config: RustlsServerConfig,
    dynamic_stack: Arc<Mutex<BoxedCloneService>>,
    cancel_token: CancellationToken,
    server_name: &'static str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let arc_tls_config = Arc::new(tls_config);

    // We need two tokens for the two listeners
    let tcp_cancel_token = cancel_token.clone();
    let udp_cancel_token = cancel_token; // move the original

    // 1. TCP Listener (HTTP/1.1 & HTTP/2)
    let tcp_handle = run_tcp_listener(
        server_addr,
        arc_tls_config.clone(),
        dynamic_stack.clone(),
        tcp_cancel_token,
        server_name,
    );

    // 2. UDP Listener (HTTP/3)
    let udp_handle = run_udp_listener(
        server_addr,
        arc_tls_config,
        dynamic_stack,
        udp_cancel_token,
        server_name,
    );

    // Wait for both listeners to finish (shutdown signal)
    let _ = tokio::join!(tcp_handle, udp_handle);
    Ok(())
}

/// Runs the TCP listener for HTTPS traffic (supporting HTTP/1.1 and HTTP/2).
///
/// # How it works:
/// 1. **Bind**: Reserves the port for TCP connections.
/// 2. **Accept**: Waits for a client (like a browser) to connect.
/// 3. **Handshake**: Performs the TLS "secret handshake" to encrypt the connection.
/// 4. **Identify**: Checks the client's certificate for special IDs (OIDs) to know who they are.
/// 5. **Serve**: Starts a task to handle the requests using `hyper` (the HTTP engine).
async fn run_tcp_listener(
    server_addr: SocketAddr,
    tls_config: Arc<RustlsServerConfig>,
    dynamic_stack: Arc<Mutex<BoxedCloneService>>,
    cancel_token: CancellationToken,
    server_name: &'static str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let tcp_listener = TcpListener::bind(server_addr).await?;
    let acceptor = tokio_rustls::TlsAcceptor::from(tls_config);

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = cancel_token.cancelled() => break,
                res = tcp_listener.accept() => {
                    if let Ok((stream, peer_addr)) = res {
                        // Optimization 2
                        // Disable Nagle's algorithm — send small responses immediately
                        // instead of waiting to batch them. Critical for low-latency APIs.
                        let _ = stream.set_nodelay(true);
                        let acceptor = acceptor.clone();
                        let dynamic_stack = dynamic_stack.clone();
                        tokio::spawn(async move {
                            trace!("{}: TCP Connection accepted", server_name);
                            // Timeout: abort TLS handshakes that stall (Slowloris protection)
                            let tls_result = tokio::time::timeout(
                                Duration::from_secs(10),
                                acceptor.accept(stream),
                            ).await;
                            match tls_result {
                                Ok(Ok(tls_stream)) => {
                                    // --- TCP OID EXTRACTION ---
                                    let (_, session) = tls_stream.get_ref();
                                    let certs = session.peer_certificates();

                                    let client_oids = certs
                                        .and_then(|c| c.first())
                                        .map(|cert| extract_oids_from_cert(cert.as_ref()))
                                        .unwrap_or_default();

                                    let svc = dynamic_stack.lock().unwrap().clone(); // fresh stack
                                    // Use the standard constructor which wraps Vec in Arc
                                    let handler = ConnectionHandler::new(svc, peer_addr, client_oids);

                                    let mut builder = auto::Builder::new(TokioExecutor::new());
                                    // Timeout: drop clients that take too long to send HTTP/1 headers
                                    builder.http1()
                                    .timer(TokioTimer::new())
                                    .header_read_timeout(Duration::from_secs(10));
                                    // Timeout: detect dead HTTP/2 connections via keep-alive pings
                                    builder
                                        .http2()
                                        .timer(TokioTimer::new())
                                        .initial_stream_window_size(1024 * 1024)
                                        .max_concurrent_streams(1024)
                                        .max_pending_accept_reset_streams(Some(16384))
                                        .keep_alive_interval(Some(Duration::from_secs(30)))
                                        .keep_alive_timeout(Duration::from_secs(10));
                                    let _ = builder
                                        .serve_connection(TokioIo::new(tls_stream), handler)
                                        .await;
                                }
                                Ok(Err(e)) => {
                                    error!("{}: TLS Handshake failed: {}", server_name, e);
                                }
                                Err(_) => {
                                    trace!("{}: TLS Handshake timed out for {}", server_name, peer_addr);
                                }
                            }
                        });
                    }
                }
            }
        }
    });

    Ok(())
}

/// Runs the UDP listener for HTTP/3 traffic using QUIC (via `quinn` and `h3`).
///
/// # What is QUIC?
/// QUIC is a new transport protocol that runs on top of UDP. It's designed to be faster and more secure than TCP+TLS.
///
/// # Key Steps:
/// 1. **Config**: Sets up specific settings for QUIC (like telling clients "I speak h3").
/// 2. **Bind**: Reserves the port for UDP packets.
/// 3. **Listen**: Waits for QUIC packets to arrive.
/// 4. **Handle**: When a connection forms, it hands it off to `handle_h3_connection`.
async fn run_udp_listener(
    server_addr: SocketAddr,
    tls_config: Arc<RustlsServerConfig>,
    dynamic_stack: Arc<Mutex<BoxedCloneService>>,
    cancel_token: CancellationToken,
    server_name: &'static str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Determine if we need to modify the TLS config for QUIC (ALPN)
    // Quinn expects explicit "h3" ALPN
    let mut quic_tls_models = rustls::ServerConfig::clone(&tls_config);
    quic_tls_models.alpn_protocols = vec![b"h3".to_vec()];

    let quic_config = quinn::crypto::rustls::QuicServerConfig::try_from(quic_tls_models)
        .map_err(|e| format!("TLS Config Error for QUIC: {e}"))?;

    let mut quinn_server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_config));

    // Optimization 3
    // Tune QUIC transport for higher throughput (defaults are conservative)
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_uni_streams(1024u32.into());
    transport.max_concurrent_bidi_streams(1024u32.into());
    // Aggressively tune flow control windows to prevent stream resets under high load
    transport.receive_window(128_000_000u32.into());
    transport.send_window(128_000_000u64);
    transport.stream_receive_window(16_000_000u32.into());
    // Timeout: close idle QUIC connections after 30 seconds
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(Duration::from_secs(30)).unwrap(),
    ));
    transport.keep_alive_interval(Some(Duration::from_secs(10)));
    quinn_server_config.transport_config(Arc::new(transport));

    // Bind UDP socket
    let endpoint = quinn::Endpoint::server(quinn_server_config, server_addr)?;

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = cancel_token.cancelled() => break,
                res = endpoint.accept() => {
                    if let Some(conn) = res {
                        trace!("{}: UDP Connection accepted", server_name);
                        let dynamic_stack = dynamic_stack.clone();

                        tokio::spawn(async move {
                            if let Err(e) = handle_h3_connection(conn, dynamic_stack, server_name).await {
                                error!("{}: H3 Connection Error: {:?}", server_name, e);
                            }
                        });
                    } else {
                        break; // Endpoint closed
                    }
                }
            }
        }
    });

    Ok(())
}

/// Handles a single HTTP/3 (QUIC) connection.
///
/// Unlike TCP where the OS handles the connection mostly, here we have to do a bit more work.
///
/// # Work Flow:
/// 1. **Connect**: Finishes establishing the QUIC connection.
/// 2. **Verify**: Checks who the client is (using their certificate) - **Just once** for the whole connection!
/// 3. **Loop**: Enters a loop where it waits for individual "Streams" (Requests).
///    - In HTTP/3, one connection can carry MANY requests at the same time.
/// 4. **Serve**: Passes each request to our `ConnectionHandler`.
async fn handle_h3_connection(
    connecting: quinn::Incoming,
    dynamic_stack: Arc<Mutex<BoxedCloneService>>,
    #[allow(unused_variables)] server_name: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // 1. Establish QUIC connection
    let connection = connecting.await?;
    let peer_addr = connection.remote_address();

    // 2. Extract OIDs (Strings)
    let mut oids = Vec::new();
    if let Some(identity) = connection.peer_identity() {
        if let Some(certs) =
            identity.downcast_ref::<Vec<rustls_pki_types::CertificateDer<'static>>>()
        {
            for c in certs {
                oids.extend(extract_oids_from_cert(c.as_ref()));
            }
        }
    }

    // --- OPTIMIZATION START ---
    // Convert OIDs (Strings) to Roles (Enums) ONCE for the whole connection.
    let config = Config::global();
    let mut roles: Vec<UserRole> = oids
        .iter()
        .map(|oid| config.map_oid_to_role(oid))
        .filter(|role| *role != UserRole::Guest)
        .collect();

    if roles.is_empty() {
        roles.push(UserRole::Guest);
    }

    // Wrap the ROLES in Arc, not the OIDs.
    let shared_roles = Arc::new(roles);
    // --- OPTIMIZATION END ---

    // 3. HTTP/3 Connection Setup
    let h3_conn = h3_quinn::Connection::new(connection);
    let mut h3_server: h3::server::Connection<h3_quinn::Connection, bytes::Bytes> =
        h3::server::Connection::new(h3_conn).await?;

    // --- MUTEX OPTIMIZATION ---
    // Lock the Mutex ONCE per QUIC connection, not per HTTP/3 request stream!
    // The underlying Tower service handles its own cheap lock-free cloning.
    let base_svc = dynamic_stack.lock().unwrap().clone();

    // 4. Request Loop
    loop {
        match h3_server.accept().await {
            Ok(Some(resolver)) => {
                // Cheap lock-free clone per QUIC stream
                let svc = base_svc.clone();
                // Cheap clone of the already calculated roles
                let roles_for_req = shared_roles.clone();

                tokio::spawn(async move {
                    match resolver.resolve_request().await {
                        Ok((req, stream)) => {
                            let (mut sender, receiver) = stream.split();

                            // Pass the ROLES to new_shared
                            let handler =
                                ConnectionHandler::new_shared(svc, peer_addr, roles_for_req);

                            let (parts, _) = req.into_parts();
                            let body = H3Body::new(receiver);
                            let hyper_req = Request::from_parts(parts, body.boxed());

                            if let Ok(res) = handler.handle(hyper_req).await {
                                let (res_parts, mut res_body) = res.into_parts();

                                if sender
                                    .send_response(Response::from_parts(res_parts, ()))
                                    .await
                                    .is_ok()
                                {
                                    while let Some(frame) = res_body.frame().await {
                                        if let Ok(data) = frame.unwrap().into_data() {
                                            if sender.send_data(data).await.is_err() {
                                                break;
                                            }
                                        }
                                    }
                                    let _ = sender.finish().await;
                                }
                            }
                        }
                        Err(e) => error!("H3 Request Error: {e}"),
                    }
                });
            }
            Ok(None) => break,
            Err(_e) => break,
        }
    }
    Ok(())
}
// async fn handle_h3_connection(
//     connecting: quinn::Incoming,
//     service_stack: BoxedCloneService,
//     server_name: &str,
// ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//     // 1. Establish QUIC connection
//     let connection = connecting.await?;
//     let peer_addr = connection.remote_address();

//     // 2. Extract OIDs ONCE per connection
//     let mut oids = Vec::new();
//     if let Some(identity) = connection.peer_identity() {
//         if let Some(certs) =
//             identity.downcast_ref::<Vec<rustls_pki_types::CertificateDer<'static>>>()
//         {
//             for c in certs {
//                 oids.extend(extract_oids_from_cert(c.as_ref()));
//             }
//         } else {
//             error!(
//                 "{}: QUIC Identity present but downcast failed.",
//                 server_name
//             );
//         }
//     }

//     // Wrap OIDs in Arc for cheap sharing across requests on this connection
//     let shared_oids = Arc::new(oids);

//     // 3. HTTP/3 Connection Setup
//     let h3_conn = h3_quinn::Connection::new(connection);
//     let mut h3_server = h3::server::Connection::new(h3_conn).await?;

//     // 4. Request Loop
//     loop {
//         match h3_server.accept().await {
//             Ok(Some(resolver)) => {
//                 let svc = service_stack.clone();
//                 let oids = shared_oids.clone(); // Cheap Arcc clone

//                 tokio::spawn(async move {
//                     match resolver.resolve_request().await {
//                         Ok((req, stream)) => {
//                             let (mut sender, receiver) = stream.split();

//                             // Use the new_shared constructor for existing Arc
//                             let handler = ConnectionHandler::new_shared(svc, peer_addr, oids);

//                             let (parts, _) = req.into_parts();
//                             let body = H3Body::new(receiver);
//                             let hyper_req = Request::from_parts(parts, body.boxed());

//                             if let Ok(res) = handler.handle(hyper_req).await {
//                                 let (res_parts, mut res_body) = res.into_parts();

//                                 if sender
//                                     .send_response(Response::from_parts(res_parts, ()))
//                                     .await
//                                     .is_ok()
//                                 {
//                                     while let Some(frame) = res_body.frame().await {
//                                         if let Ok(data) = frame.unwrap().into_data() {
//                                             if sender.send_data(data).await.is_err() {
//                                                 break;
//                                             }
//                                         }
//                                     }
//                                     let _ = sender.finish().await;
//                                 }
//                             }
//                         }
//                         Err(e) => error!("H3 Request Error: {e}"),
//                     }
//                 });
//             }
//             Ok(None) => break, // Connection closed by client
//             Err(e) => {
//                 trace!("H3 Connection closed: {e}");
//                 break;
//             }
//         }
//     }
//     Ok(())
// }

/// Helper function to build the Rustls server configuration.
///
/// It loads the server's certificate chain and private key.
/// If client certificate authentication (mTLS) is enabled, it also loads the client CA roots.
fn build_rustls_config(config: &ServerConfig) -> Result<RustlsServerConfig, Error> {
    let server_certs = config.server_certs.as_ref().context(format!(
        "{}: HTTPS enabled but no server_certs",
        config.name
    ))?;

    let client_certs = if config.authentication == AuthenticationMethod::ClientCert {
        Some(
            config
                .client_certs
                .as_deref()
                .context("mTLS enabled but no client_certs")?,
        )
    } else {
        None
    };

    // Use your existing tls_config function
    let tls_config = tls_config(
        config.static_name.expect("static_name missing"),
        server_certs,
        client_certs,
        config.authentication == AuthenticationMethod::ClientCert,
    )?;

    Ok(tls_config)
}

// --- Logging Setup ---

/// Configures the global tracing subscriber for logging.
///
/// # Arguments
///
/// * `log_dir` - An optional directory path. If provided, logs will also be written to rolling files
///               in this directory (rotated daily). If `None`, logs are written only to stdout.
///
/// By default, it uses the `RUST_LOG` environment variable filter (defaulting to "info").
fn setup_tracing(log_dir: Option<&str>) -> Result<Option<WorkerGuard>, Error> {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let stdout_layer = fmt::layer().with_ansi(true);

    if let Some(dir) = log_dir {
        let file_appender = RollingFileAppender::builder()
            .rotation(tracing_appender::rolling::Rotation::DAILY)
            .filename_prefix("app")
            .filename_suffix("log")
            .build(dir)?;

        // PERFORMANCE FIX: Use non_blocking wrapper
        let (non_blocking_appender, _guard) = tracing_appender::non_blocking(file_appender);

        // Note: You must hold `_guard` until the end of main(),
        // or logs might be dropped on shutdown.
        // You might need to change the function signature to return the guard.

        let file_layer = fmt::layer()
            .with_ansi(false)
            .with_writer(non_blocking_appender);

        let subscriber = Registry::default()
            .with(env_filter)
            .with(stdout_layer)
            .with(file_layer);

        tracing::subscriber::set_global_default(subscriber)?;

        // Return the guard so it's not dropped
        return Ok(Some(_guard));
    } else {
        let subscriber = Registry::default().with(env_filter).with(stdout_layer);
        tracing::subscriber::set_global_default(subscriber)?;
        Ok(None)
    }
}
