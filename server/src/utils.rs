#[allow(unused_imports)]
use tracing::{error, info, trace, warn};

// TLS / Rustls types
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use anyhow::Error;
use jsonwebtoken::{DecodingKey, Validation, decode, decode_header};
use serde::{Deserialize, Serialize};

/// Loads a list of DER-encoded certificates from a specified file path.
///
/// This function reads a PEM-formatted file containing one or more X.509 certificates,
/// parses them into DER format, and returns them as a vector.
///
/// # Arguments
///
/// * `path` - A string slice representing the file path to the certificate file.
/// * `server_name` - Used for logging and tracing context.
///
/// # Returns
///
/// * A `Vec<CertificateDer>` containing all valid certificates found in the file.
///
/// # Panics
///
/// * If the file cannot be opened or read.
/// * If the contents cannot be parsed as valid PEM certificates.
pub fn load_certs(path: &str, server_name: &str) -> Vec<CertificateDer<'static>> {
    // Attempt to read the entire certificate file
    let data = std::fs::read(path).unwrap_or_else(|_| {
        error!("{}: Failed to read {}", server_name, path);
        panic!("{}: Failed to read {}", server_name, path);
    });

    // Parse the certificates from PEM-encoded input and collect them into a vector
    rustls_pemfile::certs(&mut &data[..])
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|_| {
            error!("{}: Invalid cert in {}", server_name, path);
            panic!("{}: Invalid cert in {}", server_name, path);
        })
}

/// Loads a single private key from a file, expecting it to be in PKCS#8 format.
///
/// This function reads a PEM-formatted file and extracts the first available private key,
/// returning it in DER format.
///
/// # Arguments
///
/// * `path` - A string slice that represents the file path to the private key file.
/// * `server_name` - Used for logging and tracing context.
///
/// # Returns
///
/// * A `PrivateKeyDer` representing the first valid private key found.
///
/// # Panics
///
/// * If the file cannot be read.
/// * If the file contains no valid private keys.
/// * If the keys cannot be parsed properly.
pub fn load_single_key(path: &str, server_name: &str) -> PrivateKeyDer<'static> {
    // Read the private key file contents into memory
    let key_data = std::fs::read(path).unwrap_or_else(|_| {
        error!("{}: Failed to read {}", server_name, path);
        panic!("{}: Failed to read {}", server_name, path);
    });

    // Attempt to parse one or more private keys in PKCS#8 format
    let mut keys = rustls_pemfile::pkcs8_private_keys(&mut &key_data[..])
        .map(|res| {
            res.map(PrivateKeyDer::from)
                .expect("Invalid private key format")
        })
        .collect::<Vec<_>>();

    // Ensure exactly one key is used; log and panic if none, warn if multiple
    match keys.len() {
        0 => {
            error!("{}: No private key found in server key file", server_name);
            panic!("{}: No private key found in server key file", server_name);
        }
        1 => {
            trace!("{}: Single private key loaded successfully.", server_name);
        }
        _ => {
            warn!(
                "{}: Multiple private keys found, using the first one",
                server_name
            );
        }
    }

    // Return the first parsed key
    keys.remove(0)
}

/// JWT Claims payload for authentication and authorization.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    /// Subject identifier (usually user ID or account ID)
    pub sub: String,
    /// Expiration time (as UTC timestamp)
    pub exp: usize,
    // Extend with additional custom claims as needed
}

/// Loads a set of RSA decoding keys from a list of PEM file paths.
///
/// Used for supporting JWT validation (e.g., for key rotation or multiple issuers).
///
/// # Arguments
///
/// * `key_paths` - Slice of strings with each entry a PEM file path containing an RSA public key.
///
/// # Returns
///
/// * Vector of `DecodingKey` loaded and parsed from each file.
///
/// # Panics
///
/// * If a file cannot be read or is not a valid RSA public key PEM.
pub fn load_decoding_keys(key_paths: &[String]) -> Vec<DecodingKey> {
    key_paths
        .iter()
        .map(|path| {
            let pem = std::fs::read(path).expect("Failed to read key file");
            DecodingKey::from_rsa_pem(&pem).expect("Failed to parse key")
        })
        .collect()
}

/// Attempts to verify a JWT against a set of decoding keys, returning the claims if successful.
///
/// This function supports verification using multiple keys, enabling scenarios such as
/// seamless key rotation. The first key to successfully verify the token will be used.
///
/// # Arguments
///
/// * `token` - JWT token string to verify.
/// * `decoding_keys` - Slice of decoding keys to attempt verification with.
///
/// # Returns
///
/// * `Ok(Claims)` if the token is valid and successfully verified by any key.
/// * `Err` if none of the provided keys can verify the token.
///
/// # Errors
///
/// Returns an error if all keys fail to validate the JWT or if the token format is invalid.
pub fn verify_jwt(token: &str, decoding_keys: &[DecodingKey]) -> Result<Claims, Error> {
    // Parse the header to determine algorithm and check token format
    let header = decode_header(token)?;
    let alg = header.alg;
    let validation = Validation::new(alg);

    // Try verifying the JWT with each decoding key
    for key in decoding_keys {
        if let Ok(data) = decode::<Claims>(token, key, &validation) {
            return Ok(data.claims);
        }
    }
    Err(Error::msg("JWT verification failed with all keys"))
}

use rustls::{ClientConfig, RootCertStore};
/// Create a rustls ClientConfig, with or without mTLS.
pub fn build_tls_client_config(
    root_store: RootCertStore,
    cert: Option<&str>,
    key: Option<&str>,
) -> ClientConfig {
    match (cert, key) {
        (Some(cert_path), Some(key_path)) => {
            let certs = load_certs(cert_path, "mtlsclient");
            let key = load_single_key(key_path, "mtlsclient");
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

/// Build a root certificate store from system and custom roots.
pub fn build_root_store(ca_path: &Option<String>) -> RootCertStore {
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    match ca_path {
        Some(path) => {
            let root_cert = load_certs(path, "mtlsclient");
            root_store.add_parsable_certificates(root_cert);
        }
        None => {}
    }
    root_store
}
