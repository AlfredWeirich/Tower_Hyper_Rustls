use std::time::Instant;

use anyhow::Context;
use anyhow::Error;
use bytes::Bytes;
use clap::{Parser, ValueEnum};

use futures::StreamExt;
use futures::stream::FuturesUnordered;

use http_body_util::{BodyExt, Full};
use hyper::{Request, http::uri::Uri};
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use rustls::{ClientConfig, RootCertStore};
use tracing::{error, trace};

use server::utils;

// On MacOs:
// sudo sysctl -w kern.maxfiles=65536
// sudo sysctl -w kern.maxfilesperproc=65536
// sudo ulimit -n 65536
//
// Example to run the client
// RUST_LOG=client=trace cargo run -p client --bin=client -- --ca="./server_certs/self_signed/myca.pem" -p / -j ./jwt/token1.jwt -s jwt -i 800
//
// RUST_LOG=client=trace cargo run -p client --bin=client --release -- --ca="./server_certs/self_signed/myca.pem" -p / -c ./client_certs/test1_crl/client1.cert.pem -k ./client_certs/test1_crl/client1.key.pem  -s mtls -i 65000

/// Entrypoint: parse CLI, validate, build client, and launch parallel requests.
#[tokio::main]
async fn main() -> Result<(), Error> {
    //console_subscriber::init();
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();
    validate_cli(&cli);

    // read JWT token if jwt is specified
    let jwt_token = read_jwt(&cli);

    // build a https or http client based on the protocol
    // and build the URI from the CLI input
    let client = build_client(&cli);
    let uri = build_uri(&cli);

    // Launch N requests in parallel and print throughput
    let concurrency = cli.num_parallel as usize; // Tune this with parameter --num_parallel; Maybe 100, maybe 500 depending on your machine/network
    let total_requests = cli.num_req as usize; // Send this many total requests

    let mut futs = FuturesUnordered::new();
    let start = Instant::now();
    let mut completed = 0;
    let mut launched = 0;

    // Kick off up to `concurrency` (cli.num_parallel) requests to start
    let first_batch = std::cmp::min(concurrency, total_requests);
    for _ in 0..first_batch {
        futs.push(do_request(&client, &cli, jwt_token.as_deref(), uri.clone())); // fut has now a len() of first_batch
        launched += 1;
    }

    // Now poll futures, and for each completed one, launch a new until we reach total_requests
    while completed < total_requests {
        if let Some(res) = futs.next().await {
            // futs have the size concurrency
            completed += 1;
            match res {
                Ok(_) => {}
                Err(e) => error!("Request failed: {e}"),
            }

            if launched < total_requests {
                futs.push(do_request(&client, &cli, jwt_token.as_deref(), uri.clone()));
                launched += 1;
            }
        }
    }

    let duration = start.elapsed();
    let mean = total_requests as f64 / duration.as_secs_f64();
    trace!(
        "\nDuration: {}ms with {} total requests at concurrency {}\nMean requests per second: {mean:.0}  --> per request: {:.1}us",
        duration.as_millis(),
        total_requests,
        concurrency,
        1000000. / mean
    );

    Ok(())
}

/// Command-line arguments for configuring the client.
#[derive(Parser, Debug)]
#[clap(author, version, about)]
struct Cli {
    #[clap(short = 'i', long, default_value_t = 10)]
    num_req: u16,
    #[clap(long, default_value_t = 128)]
    num_parallel: u16,
    #[clap(short = 's', long, value_enum, default_value_t = Protocol::Https)]
    security: Protocol,
    #[clap(short = 'r', long, value_name = "Root ca")]
    ca: Option<String>,
    #[clap(long, short = 'j', value_name = "jwt file")]
    jwt: Option<String>,
    #[clap(short = 'c', long, value_name = "client cert")]
    cert: Option<String>,
    #[clap(short = 'k', long, value_name = "client-key")]
    key: Option<String>,
    #[clap(
        short = 'm',
        long,
        default_value = "GET",
        value_name = "request method"
    )]
    method: String,
    #[clap(short = 'u', long, default_value = "192.168.178.31:1337")]
    uri: String,
    #[clap(long, short = 'p', default_value = "/", value_name = "request path")]
    path: String,
}

/// Supported protocols.
#[derive(Debug, Clone, ValueEnum, PartialEq)]
enum Protocol {
    Http,
    Https,
    Jwt,
    Mtls,
}

/// Enum to hold either an HTTP or HTTPS client.
enum MultiProtocolClient {
    Http(Client<hyper_util::client::legacy::connect::HttpConnector, Full<Bytes>>),
    Https(
        Client<
            hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
            Full<Bytes>,
        >,
    ),
}

impl MultiProtocolClient {
    /// Dispatch request based on client type.
    pub async fn request(
        &self,
        req: Request<Full<Bytes>>,
    ) -> Result<hyper::Response<hyper::body::Incoming>, hyper_util::client::legacy::Error> {
        match self {
            MultiProtocolClient::Http(client) => client.request(req).await,
            MultiProtocolClient::Https(client) => client.request(req).await,
        }
    }
}

/// Validate CLI arguments according to the protocol requirements.
fn validate_cli(cli: &Cli) {
    match cli.security {
        Protocol::Https => {
            if cli.ca.is_none() {
                // error!("--ca <Root ca> must be set for HTTPS");
                // std::process::exit(1);
            }
        }
        Protocol::Jwt => {
            if cli.ca.is_none() {
                // error!("--ca <Root ca> must be set for JWT");
                // std::process::exit(1);
            }
            if cli.jwt.is_none() {
                error!("--jwt <jwt file> must be set for JWT");
                std::process::exit(1);
            }
        }
        Protocol::Mtls => {
            if cli.ca.is_none() {
                // error!("--ca <Root ca> must be set for mTLS");
                // std::process::exit(1);
            }
            if cli.cert.is_none() || cli.key.is_none() {
                error!("--cert <client cert> and --key <client-key> must be set for mTLS");
                std::process::exit(1);
            }
        }
        Protocol::Http => {}
    }
}

/// Build a root certificate store from system and custom roots.
fn build_root_store(ca_path: &Option<String>) -> RootCertStore {
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    match ca_path {
        Some(path) => {
            let root_cert = utils::load_certs(path, "mtlsclient");
            root_store.add_parsable_certificates(root_cert);
        }
        None => {}
    }
    root_store
}

/// Create a rustls ClientConfig, with or without mTLS.
fn build_tls_config(
    root_store: RootCertStore,
    cert: Option<&str>,
    key: Option<&str>,
) -> ClientConfig {
    match (cert, key) {
        (Some(cert_path), Some(key_path)) => {
            let certs = utils::load_certs(cert_path, "mtlsclient");
            let key = utils::load_single_key(key_path, "mtlsclient");
            ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_client_auth_cert(certs, key)
                .expect("Failed to build client config")
        }
        _ => ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    }
}

/// Build the appropriate HTTP(S) client based on the protocol.
fn build_client(cli: &Cli) -> MultiProtocolClient {
    match cli.security {
        Protocol::Http => {
            let client = Client::builder(TokioExecutor::new()).build_http::<Full<Bytes>>();
            MultiProtocolClient::Http(client)
        }
        Protocol::Https | Protocol::Jwt => {
            let root_store = build_root_store(&cli.ca);
            let config = build_tls_config(root_store, None, None);
            let https = hyper_rustls::HttpsConnectorBuilder::new()
                .with_tls_config(config)
                .https_only()
                .enable_http1()
                .build();
            let client = Client::builder(TokioExecutor::new()).build(https);
            MultiProtocolClient::Https(client)
        }
        Protocol::Mtls => {
            let root_store = build_root_store(&cli.ca);
            let config = build_tls_config(root_store, cli.cert.as_deref(), cli.key.as_deref());
            let https = hyper_rustls::HttpsConnectorBuilder::new()
                .with_tls_config(config)
                .https_only()
                .enable_http1()
                .build();
            let client = Client::builder(TokioExecutor::new()).build(https);
            MultiProtocolClient::Https(client)
        }
    }
}

/// Reads a JWT token from the provided file, if applicable.
fn read_jwt(cli: &Cli) -> Option<String> {
    if let Protocol::Jwt = cli.security {
        let path = cli.jwt.as_ref().unwrap();
        Some(
            std::fs::read_to_string(path)
                .expect("Failed to read JWT")
                .trim()
                .to_string(),
        )
    } else {
        None
    }
}

/// Build the full request URI based on the protocol and user input.
fn build_uri(cli: &Cli) -> Uri {
    let scheme = match cli.security {
        Protocol::Https | Protocol::Mtls | Protocol::Jwt => "https",
        Protocol::Http => "http",
    };
    let uri = format!("{}://{}{}", scheme, cli.uri, cli.path);
    let uri = uri.parse().expect("Invalid URI");
    trace!("Built URI: {}", uri);
    uri
}

/// Send a single request, set Authorization if JWT, and return the response body as String.
async fn do_request(
    client: &MultiProtocolClient,
    cli: &Cli,
    jwt_token: Option<&str>,
    uri: Uri,
) -> Result<String, Error> {
    let mut builder = Request::builder()
        .method(cli.method.to_uppercase().as_str())
        .uri(&uri);

    if cli.security == Protocol::Jwt {
        if let Some(token) = jwt_token {
            builder = builder.header("Authorization", format!("Bearer {token}"));
        }
    }

    let request = builder
        .body(Full::new(Bytes::from_static(b"Hello, World!")))
        .expect("Failed to build request");

    // trace!("Request: {:#?}", request);

    let response = client.request(request).await?;
    let status = response.status();

    // If you want non-2xx to be errors:
    if !status.is_success() {
        // Collect the response body for debugging (optional)
        let (_parts, body) = response.into_parts();
        let body_bytes = body
            .collect()
            .await
            .context("Failed to read error response body")?
            .to_bytes();
        let body_str = String::from_utf8_lossy(&body_bytes);
        return Err(anyhow::anyhow!(
            "Request to {uri} failed with status {status}: {body_str}"
        ));
    }

    // Collect body and handle errors
    let (_parts, body) = response.into_parts();
    let body_bytes = body
        .collect()
        .await
        .context("Failed to read response body")?
        .to_bytes();

    // Parse body as UTF-8, error if invalid
    let body_str =
        String::from_utf8(body_bytes.to_vec()).context("Response body was not valid UTF-8")?;

    Ok(body_str)
}
