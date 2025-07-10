use std::sync::Arc;
//use hyper::server;
#[allow(unused_imports)]
use tracing::{error, info, trace, warn};

// TLS / Rustls types
use rustls::ServerConfig as RustlsServerConfig;
use rustls_pki_types::{CertificateRevocationListDer, pem::PemObject};

use crate::ClientCertConfig;
use crate::configuration::ServerCertConfig;

use crate::utils::{load_certs, load_single_key};
use anyhow::Error;

/// Builds and returns a Rustls `ServerConfig` with mutual TLS (mTLS) support.
///
/// This function loads server certificates and keys for use in TLS communication,
/// and configures a client certificate verifier using a provided CA bundle.
/// The resulting configuration enforces client authentication using mTLS.
///
/// # Parameters
///
/// - `server_name`: Identifier for tracing/logging context (usually the hostname).
/// - `server_cert_config`: Contains file paths to the server certificate and private key.
/// - `client_ca_configs`: Optional list of client CA configs. Required if client authentication is enabled.
/// - `require_client_auth`: Whether to enforce mTLS (client certificate verification).
///
/// # Returns
///
/// Returns a fully configured [`ServerConfig`](rustls::ServerConfig) that can be used to run
/// a secure TLS server with (optional) client certificate verification.
///
/// # Errors
///
/// Returns an error if any certificate or private key file fails to load, is malformed, or if
/// configuration cannot be completed.
///
/// # Panics
///
/// This function will panic only if a `.expect()` is triggered inside a utility function
/// (not expected if `load_certs`/`load_single_key` are implemented with Result).
pub fn tls_config(
    server_name: &str,
    server_cert_config: &ServerCertConfig,
    client_ca_configs: Option<&[ClientCertConfig]>,
    require_client_auth: bool,
) -> Result<RustlsServerConfig, Error> {
    // === Load server certificate and private key ===
    // Loads PEM-encoded certificates and private key from provided paths.
    let server_certs = load_certs(&server_cert_config.ssl_certificate, server_name);
    trace!("{}: Server certificates loaded successfully.", server_name);

    let server_key = load_single_key(&server_cert_config.ssl_certificate_key, server_name);
    trace!("{}: Server private key loaded successfully.", server_name);

    // Create a fresh Rustls config builder (TLS 1.3 by default)
    let config_builder = rustls::ServerConfig::builder();

    // Determine if client authentication (mTLS) is required
    let config = if require_client_auth {
        // === mTLS: Load client CA roots and (optional) CRLs for client certificate verification ===
        let mut root_store = rustls::RootCertStore::empty();

        // Ensure client CA configs are provided if mTLS is enabled
        let client_certs = client_ca_configs.ok_or_else(|| {
            Error::msg(format!(
                "{server_name}: Client certs required for mTLS, but none provided.",
            ))
        })?;

        // Collect Certificate Revocation Lists (CRLs) if specified in client CA configs
        let mut crls: Vec<CertificateRevocationListDer<'_>> = Vec::new();
        for config in client_certs {
            // Load one or more CA certs for this config
            let ca_certs = load_certs(&config.ssl_client_ca, server_name);
            for ca in ca_certs {
                // Add each CA cert to the root store
                root_store
                    .add(ca)
                    .map_err(|e| Error::msg(format!("{server_name}: Failed to add CA: {e}")))?;
                trace!("{server_name}: Added CA from {}", config.ssl_client_ca);
            }
            // Optionally load and add a CRL for certificate revocation checks
            if let Some(ref crl_path) = config.ssl_client_crl {
                let crl = CertificateRevocationListDer::from_pem_file(crl_path)?;
                trace!("{server_name}: Added CRL from {crl_path}");
                crls.push(crl);
            }
        }

        // Build a WebPKI-based client certificate verifier with loaded root CAs and CRLs
        let client_verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store))
            .with_crls(crls)
            .allow_unknown_revocation_status()
            .build()
            .map_err(|e| {
                Error::msg(format!(
                    "{server_name}: Failed to build client verifier: {e}",
                ))
            })?;

        // Attach verifier and server certificates to the config builder
        config_builder
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(server_certs, server_key)
            .map_err(|e| Error::msg(format!("{server_name}: Invalid cert/key: {e}")))?
    } else {
        // No client authentication; set up HTTPS only
        config_builder
            .with_no_client_auth()
            .with_single_cert(server_certs, server_key)
            .map_err(|e| Error::msg(format!("{server_name}: Invalid cert/key: {e}")))?
    };

    let mut config = config;
    // Enable ALPN for HTTP/2 and HTTP/1.1 support
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    trace!(
        "{}: {} server TLS configuration completed.",
        server_name,
        if require_client_auth { "mTLS" } else { "HTTPS" }
    );

    Ok(config)
}
