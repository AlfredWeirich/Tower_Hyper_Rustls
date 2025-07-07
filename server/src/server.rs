// === External Crates ===
use anyhow::Error;
use tracing::{Subscriber, error, trace};
use tracing_appender::rolling::RollingFileAppender;
use tracing_subscriber::{EnvFilter, Registry, fmt, layer::SubscriberExt};

// === Standard Library ===
use core::net::SocketAddr;
use std::{io, sync::Arc, time::Duration};

// === Tokio: Async Runtime, I/O, and Networking ===
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
    runtime::Builder,
};

// === Hyper & Hyper Util ===
use hyper_util::{rt::TokioIo, service::TowerToHyperService};

// === Tower (Middleware, Service) ===
use tower::{Layer, ServiceExt};

// === TLS/Rustls ===
use tokio_rustls::TlsAcceptor;

// === Application Modules ===
// Middleware
mod middleware;
use middleware::{
    CountingLayer, DelayLayer, EchoService, InspectionLayer, JwtAuthLayer, RouterService,
    SimpleLoggerLayer, SimpleRateLimiterLayer, TimingLayer, TokenBucketRateLimiterLayer,
};

// TLS Configuration
mod tls_conf;
use tls_conf::tls_config;

// Server Configuration
mod configuration;
use configuration::{
    ClientCertConfig, CompiledAllowedPathes, Config, MiddlewareLayer, RateLimiter,
    ServerCertConfig, ServerConfig, get_configuration,
};

// Utilities
mod utils;

// === Type Alias ===
// These are type aliases for ergonomics, not repeated here for brevity.
use server::BoxedCloneService;
use server::BoxedHyperService;

/// Main program entry point.
///
/// Responsibilities:
/// - Parses command-line arguments for config file location
/// - Loads configuration
/// - Initializes tracing/logging
/// - Starts the Tokio runtime with configured worker threads
/// - Executes the async server startup logic
///
/// Returns:
/// - `Ok(())` on successful exit
/// - `Err(anyhow::Error)` if any stage fails
///
/// === Notes to test the server ===
/// Sample curl commands to test the server (mTLS, HTTP/1.1, HTTP/2):
/// curl -v --http2 --cert client_certs/client.cert.pem --key client_certs/client.key.pem https://www.aweirich.eu:1337/help
/// curl -v --http1.1 --cert client.cert.pem --key client.key.pem https://www.aweirich.eu:443/help
/// curl -v --http1.1 --cert client.cert.pem --key client.key.pem http://www.aweirich.eu:443/help
/// curl -v https://www.aweirich.eu:1337   -H "Authorization: Bearer $(cat ./jwt/token1.jwt)"
/// wrk -t8 -c128 -d10s  https://192.168.178.31:1337
fn main() -> Result<(), anyhow::Error> {
    // Read config file path from the first CLI argument or use a default.
    let arg = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "Config.toml".to_string());

    // Load application configuration.
    let config = get_configuration(&arg)?;

    // Decide how many Tokio worker threads to spawn.
    let tokio_threads = config.tokio_threads.unwrap_or(num_cpus::get() * 2);

    // Set up structured tracing/logging (file or stdout, based on config).
    setup_tracing(config.log_dir.as_deref())?;
    trace!("Configuration from: {}", arg);
    trace!("Servers Config: {:#?}", config);

    // Build a multi-threaded Tokio runtime for async execution.
    let runtime = Builder::new_multi_thread()
        .worker_threads(tokio_threads)
        .enable_all()
        .build()
        .unwrap();

    // Block on async main logic.
    runtime.block_on(main_async(config))
}

/// Asynchronous server orchestration logic.
///
/// - Iterates over all configured servers
/// - For each enabled server, spawns a Tokio task to start it
/// - Never exits (blocks forever), so all servers remain running
///
/// Params:
/// - `config`: The application-wide configuration (parsed from file)
///
/// Returns:
/// - Always returns `Ok(())` (unless server task panics), as this function never completes.
async fn main_async(config: Config) -> Result<(), anyhow::Error> {
    for server_config in config.servers {
        match server_config.enabled {
            Some(true) => { /* continue below */ }
            _ => {
                trace!("{}: Server is disabled, skipping", server_config.name);
                continue;
            }
        }
        let server_config = Arc::new(server_config);

        // Start each enabled server on its own async task/thread.
        tokio::spawn(async move {
            start_single_server(server_config.clone()).await;
        });
    }
    // Block forever (until killed)
    futures::future::pending::<()>().await;

    Ok(())
}

/// Starts a single server instance.
///
/// - Resolves bind address and opens a TCP listener
/// - Configures TLS if enabled
/// - Builds middleware/service stack (via Tower)
/// - Accepts incoming TCP connections in a loop
/// - For each new connection, spawns a task to handle the client session
///
/// Params:
/// - `server_config`: Shared reference to the per-server configuration
async fn start_single_server(server_config: Arc<ServerConfig>) {
    // Step 1: Resolve server bind address
    let addr = match server_config.get_server_ip() {
        Ok(addr) => {
            trace!("{}: Binding to address: {}", server_config.name, addr);
            addr
        }
        Err(e) => {
            error!("Failed to resolve IP: {:?}", e);
            return;
        }
    };

    // Step 2: Bind TCP listener (will fail if port is taken, etc)
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("Failed to bind: {:?}", e);
            return;
        }
    };

    // Step 3: If TLS is enabled, set up an acceptor
    let tls_acceptor = match build_tls_acceptor(&server_config) {
        Ok(opt) => opt.map(Arc::new),
        Err(e) => {
            error!("TLS error: {:?}", e);
            return;
        }
    };
    let tls_acceptor = Arc::new(tls_acceptor);

    // Step 4: Build the Tower service/middleware stack
    let service_stack = match build_service_stack(&server_config) {
        Ok(svc) => TowerToHyperService::new(svc),
        Err(e) => {
            error!("Failed to build service: {:?}", e);
            return;
        }
    };

    // Step 5: Accept new TCP clients in an infinite loop
    loop {
        let (stream, peer_addr) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                error!("Accept failed: {:?}", e);
                continue;
            }
        };

        let server_config = server_config.clone();
        let tls_acceptor = tls_acceptor.clone();
        let service_stack = service_stack.clone();

        // Spawn new task for each connection to avoid blocking.
        tokio::spawn(async move {
            handle_connection(
                stream,
                peer_addr,
                server_config,
                service_stack,
                tls_acceptor,
            )
            .await;
        });
    }
}

/// Handles a single accepted client connection.
///
/// - If TLS is required, upgrades to TLS and dispatches to HTTP/1 or HTTP/2 handler (using ALPN)
/// - Otherwise, handles plain HTTP/1.1
///
/// Params:
/// - `stream`: The accepted TCP stream
/// - `ip_addr`: Client socket address (for logging)
/// - `config`: Server config
/// - `service`: Tower service stack wrapped for Hyper
/// - `tls_acceptor`: TLS acceptor if enabled, else None
async fn handle_connection(
    stream: TcpStream,
    ip_addr: SocketAddr,
    config: Arc<ServerConfig>,
    service: TowerToHyperService<BoxedCloneService>,
    tls_acceptor: Arc<Option<Arc<TlsAcceptor>>>,
) {
    if !config.use_tls() {
        trace!("{}: Handling HTTP", config.name);
        if let Err(e) = handle_http1_connection(stream, service).await {
            error!("{}: HTTP error: {:?} / {}", config.name, e, ip_addr);
        }
        return;
    }

    // If we reach here, TLS is expected
    let Some(ref acceptor) = *tls_acceptor else {
        error!("{}: TLS expected but no acceptor configured.", config.name);
        return;
    };

    // Begin TLS handshake
    match acceptor.accept(stream).await {
        Ok(tls_stream) => {
            // Extract ALPN protocol (http/1.1 vs h2) after handshake
            let alpn = tls_stream
                .get_ref()
                .1
                .alpn_protocol()
                .map(|proto| std::str::from_utf8(proto).unwrap_or("").to_owned());

            // Route to appropriate HTTP handler
            if let Err(err) = handle_https_connection(tls_stream, service, alpn).await {
                if config.use_client_cert() {
                    error!(
                        "{}: mTLS connection error: {:?} / {}",
                        config.name, err, ip_addr
                    );
                } else {
                    error!("{}: HTTPS error: {:?} / {}", config.name, err, ip_addr);
                }
            }
        }
        Err(e) => {
            error!("{}: TLS handshake failed: {:?}", config.name, e);
        }
    }
}

/// Builds a TLS acceptor if TLS is enabled in config.
///
/// Returns:
/// - `Ok(Some(TlsAcceptor))` if TLS enabled and configured correctly
/// - `Ok(None)` if TLS is not enabled
/// - `Err(_)` if configuration error (missing certs, invalid config)
fn build_tls_acceptor(config: &ServerConfig) -> Result<Option<TlsAcceptor>, anyhow::Error> {
    if !config.use_tls() {
        return Ok(None);
    }
    let require_client_auth = config.use_client_cert();
    let server_certs = get_server_certs(config);
    let client_certs = if require_client_auth {
        get_client_certs(config)
    } else {
        None
    };
    setup_tls(
        &config.name,
        server_certs,
        client_certs,
        require_client_auth,
    )
    .map(Some)
}

/// Loads and builds a TlsAcceptor based on provided cert configs.
///
/// Params:
/// - `server_name`: Identifier for logging
/// - `server_certs`: Server's certificate/key configuration
/// - `client_certs`: Client certificate(s), if mTLS enabled
/// - `require_client_auth`: Whether to require mTLS
/// Returns:
/// - Ok(TlsAcceptor) or error
pub fn setup_tls(
    server_name: &str,
    server_certs: &ServerCertConfig,
    client_certs: Option<&[ClientCertConfig]>,
    require_client_auth: bool,
) -> Result<TlsAcceptor, Error> {
    let tls_config = tls_config(server_name, server_certs, client_certs, require_client_auth)?;
    Ok(TlsAcceptor::from(Arc::new(tls_config)))
}

/// Constructs the Tower service stack for this server, composing all middleware layers.
///
/// - Reads the configured middleware stack
/// - Creates the base service (Echo or Router)
/// - Applies all middleware layers in order
/// - Returns boxed, cloneable service compatible with Hyper
///
/// Params:
/// - `config`: Server config (defines middleware, allowed paths, etc)
/// Returns:
/// - Ok(BoxedCloneService) or error (if layer fails to build)
fn build_service_stack(config: &ServerConfig) -> Result<BoxedCloneService, Error> {
    let layers = config.build_middleware_layers()?;
    let compiled_routes = config.compiled_allowed_pathes.clone().unwrap();

    let service_name = config.service.as_str();
    let server_name = config.name.as_str();
    let base_service = match service_name {
        "Echo" => EchoService::new(server_name).boxed_clone(),
        "Router" => RouterService::new(config.rev_routes.clone(), server_name).boxed_clone(),
        _ => {
            error!("Unknown service name: {}", service_name);
            EchoService::new(server_name).boxed_clone()
        }
    };

    Ok(apply_layers(
        base_service,
        layers,
        server_name,
        Arc::new(compiled_routes),
    ))
}

/// Applies all middleware layers to a base service in order, returning the fully stacked service.
///
/// Supported middleware types:
/// - Timing, Counter, Logger, RateLimiter (simple/token-bucket), Delay, JWT auth, Inspection
///
/// Params:
/// - `service`: The initial base service (usually Echo/Router)
/// - `layers`: List of middleware layers to apply, in order
/// - `server_name`: For logging/context
/// - `compiled_routes`: Allowed/recognized routes (for inspection layer)
///
/// Returns:
/// - The fully composed boxed service
fn apply_layers(
    service: BoxedCloneService,
    layers: Vec<MiddlewareLayer>,
    server_name: &str,
    compiled_routes: Arc<CompiledAllowedPathes>,
) -> BoxedCloneService {
    // Fold all layers in order, wrapping service at each step
    layers.into_iter().fold(service, |svc, layer| match layer {
        MiddlewareLayer::Timing => {
            trace!("{}: Timing middleware enabled", server_name);
            TimingLayer::new(server_name).layer(svc).boxed_clone()
        }
        MiddlewareLayer::Counter => {
            trace!("{}: Counter middleware enabled", server_name);
            CountingLayer::new(server_name).layer(svc).boxed_clone()
        }

        MiddlewareLayer::SimpleLogger => {
            trace!("{}: Logger middleware enabled", server_name);
            SimpleLoggerLayer::new(server_name).layer(svc).boxed_clone()
        }
        MiddlewareLayer::RateLimiter(RateLimiter::Simple(cfg)) => {
            trace!("{}: SimpleRateLimiter middleware enabled", server_name);
            let dur = Duration::from_secs_f32(1. / cfg.requests_per_second as f32);
            SimpleRateLimiterLayer::new(dur, server_name)
                .layer(svc)
                .boxed_clone()
        }
        MiddlewareLayer::Delay(cfg) => {
            trace!(
                "{}: Delay middleware enabled: {:?}",
                server_name, cfg.delay_micros
            );
            let dur = Duration::from_micros(cfg.delay_micros);
            DelayLayer::new(dur, server_name).layer(svc).boxed_clone()
        }
        MiddlewareLayer::JwtAuth(cfg) => {
            trace!("{}: JWT middleware enabled: {:?}", server_name, cfg);
            JwtAuthLayer::new(cfg, server_name).layer(svc).boxed_clone()
        }
        MiddlewareLayer::RateLimiter(RateLimiter::TokenBucket(cfg)) => {
            trace!("{}: TokenBucketRateLimiter middleware enabled", server_name);
            TokenBucketRateLimiterLayer::new(
                cfg.max_capacity,
                cfg.refill,
                Duration::from_micros(cfg.duration_micros),
                server_name,
            )
            .layer(svc)
            .boxed_clone()
        }
        MiddlewareLayer::Inspection => {
            trace!("{}: Inspection middleware enabled", server_name);
            InspectionLayer::new((*compiled_routes).clone(), server_name)
                .layer(svc)
                .boxed_clone()
        }
    })
}

/// Handles an incoming HTTP/2 connection, dispatching requests to the provided service.
///
/// Params:
/// - `stream`: Any AsyncRead+AsyncWrite stream (plain or TLS-wrapped)
/// - `service`: Hyper-compatible Tower service
///
/// Returns:
/// - Ok(()) on clean session close
/// - Err(hyper::Error) on I/O/service error
pub async fn handle_http2_connection<I>(
    stream: I,
    service: BoxedHyperService,
) -> Result<(), hyper::Error>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Use Hyper's HTTP/2 server connection builder (Tokio executor)
    hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
        .serve_connection(TokioIo::new(stream), service)
        .await
}

/// Handles a TLS-wrapped connection: determines negotiated protocol and dispatches to HTTP/2 or HTTP/1 handler as needed.
///
/// - Reads ALPN result to pick protocol.
/// - Falls back to HTTP/1.1 if ALPN is missing or unknown.
///
/// Params:
/// - `tls_stream`: TLS session (must implement AsyncRead/AsyncWrite)
/// - `service`: Hyper-compatible Tower service
/// - `alpn`: Optionally, the negotiated protocol (as string)
///
/// Returns:
/// - Ok(()) on successful completion
/// - Err(io::Error) if the handshake/protocol is unsupported or errors
pub async fn handle_https_connection<I>(
    tls_stream: I,
    service: BoxedHyperService,
    alpn: Option<String>,
) -> Result<(), io::Error>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Dispatch based on ALPN protocol string.
    match alpn.as_deref() {
        Some("h2") => handle_http2_connection(tls_stream, service)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Hyper error: {}", e))),
        Some("http/1.1") | Some("http/1.0") | None => handle_http1_connection(tls_stream, service)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Hyper error: {}", e))),
        Some(other) => {
            // Unsupported protocol (could log, reject, or fallback)
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("Unsupported ALPN protocol: {}", other),
            ))
        }
    }
}

/// Handles a plain HTTP/1.1 connection, dispatching to the provided Tower service stack.
///
/// Params:
/// - `stream`: AsyncRead+AsyncWrite stream (plain or TLS-wrapped)
/// - `service`: Hyper-compatible Tower service
///
/// Returns:
/// - Ok(()) on clean close
/// - Err(hyper::Error) on connection or service error
pub async fn handle_http1_connection<I>(
    stream: I,
    service: BoxedHyperService,
) -> Result<(), hyper::Error>
where
    I: AsyncRead + AsyncWrite + Unpin,
{
    // hyper::server::conn::http1 only serves HTTP/1.x
    let res = hyper::server::conn::http1::Builder::new()
        .serve_connection(TokioIo::new(stream), service)
        .await;
    res
}

/// Sets up structured tracing/logging.
///
/// - Configures stdout logging, and optionally file logging (if a directory is given)
/// - Loads log filter level from environment variable `RUST_LOG` or defaults to "info"
/// - Uses `tracing-subscriber` to register a global subscriber
///
/// Params:
/// - `log_dir`: Optional directory for rolling log file output
/// Returns:
/// - Ok(()) or error if setup fails
fn setup_tracing(log_dir: Option<&str>) -> Result<(), Error> {
    let env_filter = EnvFilter::try_from_default_env().or_else(|_| EnvFilter::try_new("info"))?;

    // stdout layer
    let stdout_layer = fmt::layer().with_ansi(true).with_writer(std::io::stdout);

    // Build a boxed subscriber
    let subscriber: Box<dyn Subscriber + Send + Sync> = match log_dir {
        Some(dir) => {
            let file_appender: RollingFileAppender =
                tracing_appender::rolling::daily(dir, "app.log");

            let file_layer = fmt::layer().with_ansi(false).with_writer(file_appender);

            Box::new(
                Registry::default()
                    .with(env_filter)
                    .with(stdout_layer)
                    .with(file_layer),
            )
        }
        None => Box::new(Registry::default().with(env_filter).with(stdout_layer)),
    };

    // Set global subscriber
    tracing::subscriber::set_global_default(subscriber)?;

    Ok(())
}

/// Utility: Gets the server's certificate config from server config.
/// - Panics/aborts if not set but TLS is enabled, to prevent silent misconfiguration.
fn get_server_certs<'a>(config: &'a ServerConfig) -> &'a ServerCertConfig {
    config.server_certs.as_ref().unwrap_or_else(|| {
        error!(
            "{}: TLS is enabled but no [server_certs] provided",
            config.name
        );
        std::process::exit(1);
    })
}

/// Utility: Gets the client certificate config for mTLS from server config.
/// - Panics/aborts if mTLS is enabled but certs missing.
fn get_client_certs<'a>(config: &'a ServerConfig) -> Option<&'a [ClientCertConfig]> {
    match config.client_certs.as_ref() {
        Some(certs) if !certs.is_empty() => Some(certs.as_slice()),
        _ => {
            error!(
                "{}: mTLS is enabled but no [[client_certs]] provided",
                config.name
            );
            std::process::exit(1);
        }
    }
}
