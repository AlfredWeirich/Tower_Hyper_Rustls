//! # gRPC Echo Client
//!
//! A Tonic-based gRPC client for the server's Echo service. Demonstrates how
//! to build a Hyper + Rustls HTTPS client, attach mTLS or JWT credentials,
//! and invoke a unary RPC call.
//!
//! ## Usage
//!
//! ```bash
//! cargo run -p client --bin=grpc_client -- -s mtls \
//!   --ca server_certs/self_signed/myca.pem \
//!   -c client_certs/client.cert.pem \
//!   -k client_certs/client.key.pem
//! ```
//!
//! > **Note:** This binary is a scaffold / example. The `EchoClient` and
//! > `EchoRequest` types referenced below must be generated from a `.proto`
//! > definition via `tonic-build` before this will compile.

// === Standard Library ===
use std::time::Instant;

// === External Crates ===
use anyhow::{Context, Error};
use bytes::Bytes;
use clap::{Parser, ValueEnum};
use futures::{StreamExt, stream::FuturesUnordered};
use http_body_util::{BodyExt, Full};
use hyper::{Request, http::uri::Uri};
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use tracing::{error, trace};

// === Internal Modules ===
use common;

/// The main entry point for the gRPC client.
/// It initializes tracing, parses CLI arguments, and executes the client logic.
#[tokio::main]
async fn main() -> Result<(), Error> {
    // Initialize logging/tracing
    // console_subscriber::init(); // Optional: used for tokio console debugging
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    // Validate the provided CLI parameters based on the selected protocol
    validate_cli(&cli);

    // Optional: Retrieve JWT token from file if security protocol requires it
    let _jwt_token = read_jwt(&cli);

    // Construct the networking client (Hyper-based) with appropriate TLS/Auth settings
    let client = build_client(&cli);

    // Placeholder URI and Client - this demonstrates how to use the generated EchoClient
    // with a specific origin and the configured Hyper client.
    let uri = Uri::from_static("https://example.com");
    let mut client = EchoClient::with_origin(client, uri);

    // Construct a standard gRPC Request
    let request = tonic::Request::new(EchoRequest {
        message: "hello".into(),
    });

    // Execute the RPC and await the response
    let response = client.unary_echo(request).await?;

    println!("RESPONSE={response:?}");

    Ok(())
}

/// Command-line arguments for configuring the client.
#[derive(Parser, Debug)]
#[clap(author, version, about)]
struct Cli {
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
    #[clap(short = 'u', long, default_value = "192.168.178.31:1337")]
    uri: String,
    // #[clap(long, short = 'p', default_value = "/", value_name = "request path")]
    // path: String,
}

/// Supported protocols.
#[derive(Debug, Clone, ValueEnum, PartialEq)]
enum Protocol {
    Http,
    Https,
    Jwt,
    Mtls,
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

fn build_client(cli: &Cli) -> Client<common::client::HttpsConnector<HttpConnector>, Full<Bytes>> {
    let root_store = common::build_root_store(&cli.ca);
    let tls_client_config = match cli.security {
        Protocol::Http | Protocol::Https | Protocol::Jwt => {
            common::build_tls_client_config(root_store, None, None)
        }
        Protocol::Mtls => {
            common::build_tls_client_config(root_store, cli.cert.as_deref(), cli.key.as_deref())
        }
    };

    let pool_config = common::client::ClientPoolConfig {
        idle_timeout: None,
        max_idle_per_host: Some(1024),
        http2_only: false,
    };

    common::client::build_hyper_client(tls_client_config, pool_config)
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

// /// Build the full request URI based on the protocol and user input.
// fn build_uri(cli: &Cli) -> Uri {
//     let scheme = match cli.security {
//         Protocol::Https | Protocol::Mtls | Protocol::Jwt => "https",
//         Protocol::Http => "http",
//     };
//     let uri = format!("{}://{}{}", scheme, cli.uri, cli.path);
//     let uri = uri.parse().expect("Invalid URI");
//     trace!("Built URI: {}", uri);
//     uri
// }
