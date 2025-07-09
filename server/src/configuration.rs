use anyhow::Error;
use local_ip_address::local_ip;
use regex::Regex;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;

// ===================
//    Root Config
// ===================

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(rename = "Server")]
    pub servers: Vec<ServerConfig>,
    // number of threads for Tokio to use for the server, if not set, it defaults to the number of CPU cores
    pub tokio_threads: Option<usize>,
    // the directory where the logs are stored, if not set, logging is only to stdout
    pub log_dir: Option<String>,
}

// ===================
//    Server Config
// ===================

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    // any name to identify server, no further meaning
    pub name: String,
    // ip and port the server is listening
    pub ip: String,
    pub port: u16,
    // is this server enabled
    pub enabled: Option<bool>,

    // the final service, can be Echo or Router, all others default to Echo
    pub service: String,

    // protocol to use, can be http or https
    // if https, server_certs are needed
    pub protocol: String,

    // authentication method, can be empty, jwt or clientcert
    // if empty, no authentication is used
    // if jwt, the JWT public keys are used to verify the JWT tokens, a JWT layer must be enabled, and the JWT public keys must be configured. the protocol should be HTTPS
    // if clientcert, the client certificates are used to authenticate the clients. client_certs must be configured. The protocol must be HTTPS
    pub authentication: Option<String>,

    // the path to the Server certificates in case of HTTPS
    // if the protocol is HTTPS, this must be defined
    // if the protocol is HTTP, this may be not set
    #[serde(rename = "server_certs")]
    pub server_certs: Option<ServerCertConfig>,

    // Path to Client certificates in case of authentication = "ClientCert"
    // if authentication is "ClientCert", this must be defined
    #[serde(rename = "client_certs")]
    pub client_certs: Option<Vec<ClientCertConfig>>,

    // the layers to get configured for the server, if empty, only the final service is used
    // if not empty, the layers are applied in the order they are defined
    #[serde(rename = "Layers")]
    pub layers: Layers,

    // only for the "Inspection layer", the regex to match the request path
    // if inspection layer is enabled, this should be defined
    #[serde(rename = "AllowedPathes")]
    pub allowed_pathes: Option<AllowedPathes>,

    // only for the end-service router.
    // if router is configured, this should be defined
    #[serde(rename = "ReverseRoutes")]
    pub rev_routes: Option<HashMap<String, String>>, // prefix -> backend_uri

    #[serde(rename = "RouterParams")]
    pub router_params: Option<RouterParams>,

    #[serde(skip)]
    pub compiled_allowed_pathes: Option<CompiledAllowedPathes>,
}

#[derive(Debug, Deserialize, Clone)]
// the router service is also a HTTP/HTTPS-client for sending requests
// so we must configure a client
pub struct RouterParams {
    // http or https, defaults to http
    pub protocoll: Option<String>,
    // mTLS or JWT or None
    // in case of not None, we need HTTPS
    pub authentication: Option<String>,
    // in case of https, we need a root cert
    pub ssl_root_certificate: Option<String>,
    // in case of auth==JWT, we need HTTPS an a JWT
    pub jwt: Option<String>,
    // in case of mTLS, we need HTTPS and the client certificates
    pub ssl_client_certificate: Option<String>,
    pub ssl_client_key: Option<String>,
}
impl RouterParams {
    pub fn validate(&self, server_name: &str) -> Result<(), Error> {
        let protocol = self.protocoll.as_deref().unwrap_or("http").to_lowercase();

        if protocol != "http" && protocol != "https" {
            return Err(Error::msg(format!(
                "Server '{}': invalid protocol '{}'. Must be 'http' or 'https'",
                server_name, protocol
            )));
        }

        // If protocol is https, root cert must be defined
        if protocol == "https" && self.ssl_root_certificate.is_none() {
            return Err(Error::msg(format!(
                "Server '{}': protocol is 'https' but [RouterParams.sss_root_certificate] is missing",
                server_name
            )));
        }

        let auth = self.authentication.as_deref().unwrap_or("").to_lowercase();

        match auth.as_str() {
            "" => {} // No authentication – fine
            "jwt" => {
                if protocol != "https" {
                    return Err(Error::msg(format!(
                        "Server '{}': JWT authentication requires 'https' protocol",
                        server_name
                    )));
                }
                if self.jwt.is_none() {
                    return Err(Error::msg(format!(
                        "Server '{}': JWT authentication requires [RouterParams.jwt]",
                        server_name
                    )));
                }
            }
            "mtls" => {
                if protocol != "https" {
                    return Err(Error::msg(format!(
                        "Server '{}': mTLS authentication requires 'https' protocol",
                        server_name
                    )));
                }
                if self.ssl_client_certificate.is_none() || self.ssl_client_key.is_none() {
                    return Err(Error::msg(format!(
                        "Server '{}': mTLS requires [RouterParams.ssl_client_certificate] and [ssl_client_key]",
                        server_name
                    )));
                }
            }
            other => {
                return Err(Error::msg(format!(
                    "Server '{}': unknown authentication method '{}'. Use '', 'JWT' or 'mTLS'",
                    server_name, other
                )));
            }
        }

        Ok(())
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerCertConfig {
    pub ssl_certificate: String,
    pub ssl_certificate_key: String,
}

// the servers client_ca and crl in case of mTLS
#[derive(Debug, Deserialize, Clone)]
pub struct ClientCertConfig {
    pub ssl_client_ca: String,
    pub sl_client_crl: Option<String>,
}

impl ServerConfig {
    pub fn get_server_ip(&self) -> Result<SocketAddr, Error> {
        let ip_str = if self.ip == "local" {
            local_ip()?.to_string()
        } else {
            self.ip.clone()
        };
        let addr = format!("{}:{}", ip_str, self.port);
        addr.parse()
            .map_err(|e| Error::msg(format!("Invalid server address: {}", e)))
    }

    pub fn use_tls(&self) -> bool {
        self.protocol.eq_ignore_ascii_case("https")
    }

    pub fn use_client_cert_auth(&self) -> bool {
        self.authentication
            .as_ref()
            .map(|a| a.eq_ignore_ascii_case("clientcert"))
            .unwrap_or(false)
    }

    // pub fn use_jwt_auth(&self) -> bool {
    //     self.authentication
    //         .as_ref()
    //         .map(|a| a.eq_ignore_ascii_case("jwt"))
    //         .unwrap_or(false)
    // }

    pub fn init_compiled_allowed_pathes(&mut self) -> Result<(), Error> {
        self.compiled_allowed_pathes = Some(CompiledAllowedPathes::from_raw(&self.allowed_pathes)?);
        Ok(())
    }

    pub fn build_middleware_layers(&self) -> Result<Vec<MiddlewareLayer>, Error> {
        self.layers.build_middleware_layers()
    }
    pub fn normalize_router_protocol(&mut self) {
        if let Some(params) = self.router_params.as_mut() {
            match params.protocoll.as_deref() {
                Some("http") | Some("https") => {} // valid
                Some(other) => {
                    tracing::warn!(
                        "Server '{}': Invalid router protocol '{}', defaulting to 'http'",
                        self.name,
                        other
                    );
                    params.protocoll = Some("http".to_string());
                }
                None => {
                    params.protocoll = Some("http".to_string());
                }
            }
        }
    }
}

// ===================
//    Layers
// ===================

#[derive(Debug, Deserialize, Clone)]
pub struct Layers {
    pub enabled: Vec<LayerSpec>,

    #[serde(rename = "RateLimiter")]
    pub rate_limiter_config: Option<SimpleRateLimiterConfig>,

    #[serde(rename = "TokenBucketRateLimiter")]
    pub token_bucket_config: Option<TokenBucketRateLimiterConfig>,

    #[serde(rename = "Delay")]
    pub delay_config: Option<DelayConfig>,

    #[serde(rename = "JWT")]
    pub jwt_config: Option<JwtAuthConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct JwtAuthConfig {
    pub jwt_public_keys: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum LayerSpec {
    Timing,
    Counter,
    Logger,
    RateLimiter(RateLimiterType),
    Delay,
    Inspection,
    JwtAuth,
}

impl<'de> Deserialize<'de> for LayerSpec {
    fn deserialize<D>(deserializer: D) -> Result<LayerSpec, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "Timing" => Ok(LayerSpec::Timing),
            "Counter" => Ok(LayerSpec::Counter),
            "Logger" => Ok(LayerSpec::Logger),
            "Delay" => Ok(LayerSpec::Delay),
            "Inspection" => Ok(LayerSpec::Inspection),
            "JwtAuth" | "JWT" => Ok(LayerSpec::JwtAuth),
            other if other.starts_with("RateLimiter:") => match &other["RateLimiter:".len()..] {
                "Simple" => Ok(LayerSpec::RateLimiter(RateLimiterType::Simple)),
                "TokenBucket" => Ok(LayerSpec::RateLimiter(RateLimiterType::TokenBucket)),
                _ => Err(serde::de::Error::custom(format!(
                    "Unknown rate limiter: {}",
                    other
                ))),
            },
            _ => Err(serde::de::Error::custom(format!("Unknown layer: {}", s))),
        }
    }
}

#[derive(Debug, Clone)]
pub enum MiddlewareLayer {
    Timing,
    Counter,
    Logger,
    RateLimiter(RateLimiter),
    Delay(DelayConfig),
    Inspection,
    JwtAuth(Vec<String>),
}

#[derive(Debug, Clone)]
pub enum RateLimiter {
    Simple(SimpleRateLimiterConfig),
    TokenBucket(TokenBucketRateLimiterConfig),
}

#[derive(Debug, Clone)]
pub enum RateLimiterType {
    Simple,
    TokenBucket,
}

impl Layers {
    pub fn build_middleware_layers(&self) -> Result<Vec<MiddlewareLayer>, Error> {
        let mut result = Vec::new();
        for layer in &self.enabled {
            match layer {
                LayerSpec::Timing => result.push(MiddlewareLayer::Timing),
                LayerSpec::Counter => result.push(MiddlewareLayer::Counter),
                LayerSpec::Logger => result.push(MiddlewareLayer::Logger),
                LayerSpec::Delay => {
                    let cfg = self
                        .delay_config
                        .as_ref()
                        .ok_or_else(|| Error::msg("Missing [Layers.Delay]"))?;
                    result.push(MiddlewareLayer::Delay(cfg.clone()));
                }
                LayerSpec::Inspection => result.push(MiddlewareLayer::Inspection),
                LayerSpec::RateLimiter(RateLimiterType::Simple) => {
                    let cfg = self
                        .rate_limiter_config
                        .as_ref()
                        .ok_or_else(|| Error::msg("Missing [Layers.RateLimiter]"))?;
                    result.push(MiddlewareLayer::RateLimiter(RateLimiter::Simple(
                        cfg.clone(),
                    )));
                }
                LayerSpec::RateLimiter(RateLimiterType::TokenBucket) => {
                    let cfg = self
                        .token_bucket_config
                        .as_ref()
                        .ok_or_else(|| Error::msg("Missing [Layers.TokenBucketRateLimiter]"))?;
                    result.push(MiddlewareLayer::RateLimiter(RateLimiter::TokenBucket(
                        cfg.clone(),
                    )));
                }
                LayerSpec::JwtAuth => {
                    let cfg = self
                        .jwt_config
                        .as_ref()
                        .ok_or_else(|| Error::msg("Missing [Layers.JWT] for JwtAuth layer"))?;
                    result.push(MiddlewareLayer::JwtAuth(cfg.jwt_public_keys.clone()));
                }
            }
        }
        Ok(result)
    }
}

// ===================
//    Supporting Configs
// ===================

#[derive(Debug, Deserialize, Clone)]
pub struct SimpleRateLimiterConfig {
    pub requests_per_second: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TokenBucketRateLimiterConfig {
    pub max_capacity: usize,
    pub refill: usize,
    pub duration_micros: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DelayConfig {
    pub delay_micros: u64,
}

// ===================
//    Allowed Routes
// ===================

#[derive(Debug, Deserialize, Clone)]
pub struct AllowedPathes {
    #[serde(rename = "GET")]
    pub get: Option<HashMap<String, Vec<String>>>,
    #[serde(rename = "POST")]
    pub post: Option<HashMap<String, Vec<String>>>,
    #[serde(rename = "PUT")]
    pub put: Option<HashMap<String, Vec<String>>>,
    #[serde(rename = "DELETE")]
    pub delete: Option<HashMap<String, Vec<String>>>,
}

#[derive(Debug, Clone)]
pub struct CompiledAllowedPathes {
    pub get: HashMap<String, Vec<Regex>>,
    pub post: HashMap<String, Vec<Regex>>,
    pub put: HashMap<String, Vec<Regex>>,
    pub delete: HashMap<String, Vec<Regex>>,
}

impl CompiledAllowedPathes {
    pub fn from_raw(routes: &Option<AllowedPathes>) -> Result<Self, Error> {
        fn compile(
            map: &Option<HashMap<String, Vec<String>>>,
        ) -> Result<HashMap<String, Vec<Regex>>, Error> {
            let mut compiled = HashMap::new();
            if let Some(map) = map {
                for (k, patterns) in map {
                    let regexes = patterns
                        .iter()
                        .map(|p| {
                            Regex::new(p).map_err(|e| Error::msg(format!("Invalid regex: {}", e)))
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    compiled.insert(k.clone(), regexes);
                }
            }
            Ok(compiled)
        }

        Ok(Self {
            get: compile(&routes.as_ref().and_then(|r| r.get.clone()))?,
            post: compile(&routes.as_ref().and_then(|r| r.post.clone()))?,
            put: compile(&routes.as_ref().and_then(|r| r.put.clone()))?,
            delete: compile(&routes.as_ref().and_then(|r| r.delete.clone()))?,
        })
    }
    pub fn is_allowed(&self, method: &str, path: &str, query: &str) -> bool {
        let full_path = if query.is_empty() {
            path.to_string()
        } else {
            format!("{}?{}", path, query)
        };

        let map = match method {
            "GET" => &self.get,
            "POST" => &self.post,
            "PUT" => &self.put,
            "DELETE" => &self.delete,
            _ => return false,
        };

        map.get(path)
            .map(|regexes| regexes.iter().any(|r| r.is_match(&full_path)))
            .unwrap_or(false)
    }
}

// ===================
//    Config Loader
// ===================

pub fn get_configuration(config_file: &str) -> Result<Config, Error> {
    let toml_str = fs::read_to_string(config_file)?;
    let mut config: Config = toml::from_str(&toml_str)?;

    // do some checks on parameters for each of the servers
    for server in config.servers.iter_mut() {
        // if service layer is router, we need router_params
        if server.service.eq_ignore_ascii_case("Router") {
            let params = server.router_params.as_ref().ok_or_else(|| {
                Error::msg(format!(
                    "Server '{}' uses service = 'Router' but [RouterParams] is missing",
                    server.name
                ))
            })?;

            params.validate(&server.name)?;
        }
        // set default for router client protokoll
        server.normalize_router_protocol();

        // for the inspection layer: the allowed pathes regex must be pre-compiled
        server.init_compiled_allowed_pathes()?;

        // in case of TLS, we need server certificates
        if server.use_tls() && server.server_certs.is_none() {
            return Err(Error::msg(format!(
                "Server '{}' uses HTTPS but [server_certs] is missing",
                server.name
            )));
        }

        match server.authentication.as_deref() {
            Some("JWT") => {
                let jwt = server.layers.jwt_config.as_ref();
                if jwt.is_none() || jwt.unwrap().jwt_public_keys.is_empty() {
                    return Err(Error::msg(format!(
                        "Server '{}' uses JWT but [Layers.JWT] is missing or empty",
                        server.name
                    )));
                }

                let jwt_enabled = server
                    .layers
                    .enabled
                    .iter()
                    .any(|layer| matches!(layer, LayerSpec::JwtAuth));

                if !jwt_enabled {
                    return Err(Error::msg(format!(
                        "Server '{}' uses JWT authentication but 'JwtAuth' is not in the [Layers.enabled] list",
                        server.name
                    )));
                }
            }
            Some("ClientCert") => {
                if server.client_certs.as_ref().is_none_or(|v| v.is_empty()) {
                    return Err(Error::msg(format!(
                        "Server '{}' uses ClientCert but [[client_certs]] is missing or empty",
                        server.name
                    )));
                }
            }
            _ => {}
        }
    }

    Ok(config)
}
