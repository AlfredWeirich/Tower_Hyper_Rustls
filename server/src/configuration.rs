// configuration.rs

use anyhow::Error;
use hyper::Uri;
use local_ip_address::local_ip;
use regex::Regex;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(rename = "Server")]
    pub servers: Vec<ServerConfig>,
    pub tokio_threads: Option<usize>,
    pub log_dir: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub name: String,
    pub ip: String,
    pub port: u16,
    pub enabled: Option<bool>,

    #[serde(default)]
    pub service: ServiceType,

    #[serde(default)]
    pub protocol: Protocol,

    #[serde(default)]
    pub authentication: AuthenticationMethod,

    #[serde(rename = "server_certs")]
    pub server_certs: Option<ServerCertConfig>,

    #[serde(rename = "client_certs")]
    pub client_certs: Option<Vec<ClientCertConfig>>,

    #[serde(rename = "Layers")]
    pub layers: Layers,

    #[serde(rename = "AllowedPathes")]
    pub allowed_pathes: Option<AllowedPathes>,

    #[serde(rename = "ReverseRoutes")]
    pub rev_routes: Option<HashMap<String, String>>,

    #[serde(rename = "RouterParams")]
    pub router_params: Option<RouterParams>,

    #[serde(skip)]
    pub parsed_routes: Vec<(String, Uri)>,

    #[serde(skip)]
    pub compiled_allowed_pathes: Option<CompiledAllowedPathes>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Http,
    Https,
}

impl Default for Protocol {
    fn default() -> Self {
        Protocol::Http
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum ServiceType {
    Echo,
    Router,
}

impl Default for ServiceType {
    fn default() -> Self {
        ServiceType::Echo
    }
}
impl ServiceType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ServiceType::Echo => "Echo",
            ServiceType::Router => "Router",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum AuthenticationMethod {
    #[serde(alias = "", alias = "None")]
    None,
    Jwt,
    ClientCert,
}

impl Default for AuthenticationMethod {
    fn default() -> Self {
        AuthenticationMethod::None
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct RouterParams {
    pub protocol: Option<String>,
    pub authentication: Option<String>,
    pub ssl_root_certificate: Option<String>,
    pub jwt: Option<String>,
    pub ssl_client_certificate: Option<String>,
    pub ssl_client_key: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerCertConfig {
    pub ssl_certificate: String,
    pub ssl_certificate_key: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ClientCertConfig {
    pub ssl_client_ca: String,
    pub ssl_client_crl: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Layers {
    pub enabled: Vec<String>,

    #[serde(rename = "RateLimiter")]
    pub rate_limiter_config: Option<SimpleRateLimiterConfig>,

    #[serde(rename = "TokenBucketRateLimiter")]
    pub token_bucket_config: Option<TokenBucketRateLimiterConfig>,

    #[serde(rename = "Delay")]
    pub delay_config: Option<DelayConfig>,

    #[serde(rename = "JWT")]
    pub jwt_config: Option<JwtAuthConfig>,

    #[serde(rename = "ConcurrencyLimit")]
    pub concurrency_limit_config: Option<ConcurrencyLimitConfig>,
}
#[derive(Debug, Deserialize, Clone)]
pub struct ConcurrencyLimitConfig {
    pub max_concurrent_requests: usize,
}

#[derive(Debug, Deserialize, Clone)]
pub struct JwtAuthConfig {
    pub jwt_public_keys: Vec<String>,
}

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

impl ServerConfig {
    pub fn get_server_ip(&self) -> Result<SocketAddr, Error> {
        let ip_str = if self.ip == "local" {
            local_ip()?.to_string()
        } else {
            self.ip.clone()
        };
        let addr = format!("{}:{}", ip_str, self.port);
        addr.parse()
            .map_err(|e| Error::msg(format!("Invalid server address: {e}")))
    }

    pub fn use_tls(&self) -> bool {
        self.protocol == Protocol::Https
    }

    pub fn use_client_cert_auth(&self) -> bool {
        self.authentication == AuthenticationMethod::ClientCert
    }

    pub fn init_compiled_allowed_pathes(&mut self) -> Result<(), Error> {
        self.compiled_allowed_pathes = Some(CompiledAllowedPathes::from_raw(&self.allowed_pathes)?);
        Ok(())
    }

    pub fn normalize_router_protocol(&mut self) {
        if let Some(params) = self.router_params.as_mut() {
            match params.protocol.as_deref() {
                Some("http") | Some("https") => {}
                Some(other) => {
                    tracing::warn!(
                        "Server '{}': Invalid router protocol '{}', defaulting to 'http'",
                        self.name,
                        other
                    );
                    params.protocol = Some("http".to_string());
                }
                None => {
                    params.protocol = Some("http".to_string());
                }
            }
        }
    }

    pub fn validate_and_normalize_router(&mut self) -> Result<(), Error> {
        if self.service == ServiceType::Router {
            let params = self.router_params.as_ref().ok_or_else(|| {
                Error::msg(format!(
                    "Server '{}' uses service = 'Router' but [RouterParams] is missing",
                    self.name
                ))
            })?;

            let protocol = params.protocol.as_deref().unwrap_or("http").to_lowercase();

            if protocol != "http" && protocol != "https" {
                return Err(Error::msg(format!(
                    "Server '{}': invalid protocol '{}'. Must be 'http' or 'https'",
                    self.name, protocol
                )));
            }

            if protocol == "https" && params.ssl_root_certificate.is_none() {
                return Err(Error::msg(format!(
                    "Server '{}': protocol is 'https' but [RouterParams.ssl_root_certificate] is missing",
                    self.name
                )));
            }

            match params
                .authentication
                .as_deref()
                .unwrap_or("")
                .to_lowercase()
                .as_str()
            {
                "" => {}
                "jwt" => {
                    if protocol != "https" {
                        return Err(Error::msg(format!(
                            "Server '{}': JWT authentication requires 'https' protocol",
                            self.name
                        )));
                    }
                    if params.jwt.is_none() {
                        return Err(Error::msg(format!(
                            "Server '{}': JWT authentication requires [RouterParams.jwt]",
                            self.name
                        )));
                    }
                }
                "mtls" => {
                    if protocol != "https" {
                        return Err(Error::msg(format!(
                            "Server '{}': mTLS authentication requires 'https' protocol",
                            self.name
                        )));
                    }
                    if params.ssl_client_certificate.is_none() || params.ssl_client_key.is_none() {
                        return Err(Error::msg(format!(
                            "Server '{}': mTLS requires [ssl_client_certificate] and [ssl_client_key]",
                            self.name
                        )));
                    }
                }
                other => {
                    return Err(Error::msg(format!(
                        "Server '{}': unknown authentication method '{}'. Use '', 'JWT' or 'mTLS'",
                        self.name, other
                    )));
                }
            }

            self.normalize_router_protocol();
        }
        Ok(())
    }

    pub fn init_parsed_routes(&mut self) -> Result<(), Error> {
        let mut rules_vec = match &self.rev_routes {
            Some(map) => {
                let proto = self
                    .router_params
                    .as_ref()
                    .and_then(|p| p.protocol.as_deref())
                    .unwrap_or("http");

                map.iter()
                    .filter_map(|(prefix, host_port)| {
                        let full_uri = format!("{proto}://{host_port}");
                        match full_uri.parse::<Uri>() {
                            Ok(uri) => Some((prefix.clone(), uri)),
                            Err(e) => {
                                tracing::warn!("{}: Invalid URI ({}): {}", self.name, full_uri, e);
                                None
                            }
                        }
                    })
                    .collect::<Vec<_>>()
            }
            None => Vec::new(),
        };

        rules_vec.sort_by(|(a, _), (b, _)| b.len().cmp(&a.len()));
        self.parsed_routes = rules_vec;
        Ok(())
    }

    pub fn finalize(&mut self) -> Result<(), Error> {
        self.validate_and_normalize_router()?;
        self.init_compiled_allowed_pathes()?;
        self.init_parsed_routes()?;
        self.validate_tls_requirements()?;
        self.validate_auth_requirements()?;
        Ok(())
    }

    fn validate_tls_requirements(&self) -> Result<(), Error> {
        if self.use_tls() && self.server_certs.is_none() {
            return Err(Error::msg(format!(
                "Server '{}' uses HTTPS but [server_certs] is missing",
                self.name
            )));
        }
        Ok(())
    }

    fn validate_auth_requirements(&self) -> Result<(), Error> {
        match self.authentication {
            AuthenticationMethod::Jwt => {
                let jwt = self.layers.jwt_config.as_ref();
                if jwt.is_none() || jwt.unwrap().jwt_public_keys.is_empty() {
                    return Err(Error::msg(format!(
                        "Server '{}' uses JWT but [Layers.JWT] is missing or empty",
                        self.name
                    )));
                }

                let jwt_enabled = self.layers.enabled.iter().any(|layer| {
                    layer.eq_ignore_ascii_case("JwtAuth") || layer.eq_ignore_ascii_case("JWT")
                });

                if !jwt_enabled {
                    return Err(Error::msg(format!(
                        "Server '{}' uses JWT authentication but 'JwtAuth' is not in the [Layers.enabled] list",
                        self.name
                    )));
                }
            }
            AuthenticationMethod::ClientCert => {
                if self.client_certs.as_ref().map_or(true, |v| v.is_empty()) {
                    return Err(Error::msg(format!(
                        "Server '{}' uses ClientCert but [[client_certs]] is missing or empty",
                        self.name
                    )));
                }
            }
            _ => {}
        }
        Ok(())
    }
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
                            Regex::new(p).map_err(|e| Error::msg(format!("Invalid regex: {e}")))
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
            format!("{path}?{query}")
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

pub fn get_configuration(config_file: &str) -> Result<&'static Config, Error> {
    let toml_str = fs::read_to_string(config_file)?;
    let mut config: Config = toml::from_str(&toml_str)?;

    for server in config.servers.iter_mut() {
        server.finalize()?;
    }

    config.set_static_config();
    Ok(Config::get_static_config())
}

static mut STAT_CONFIG: *const Config = std::ptr::null();

impl Config {
    fn set_static_config(self) {
        unsafe {
            STAT_CONFIG = Box::into_raw(Box::new(self));
        }
    }

    fn get_static_config() -> &'static Config {
        unsafe { &*STAT_CONFIG }
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
    ConcurrencyLimit(ConcurrencyLimitConfig),
}

#[derive(Debug, Clone)]
pub enum RateLimiter {
    Simple(SimpleRateLimiterConfig),
    TokenBucket(TokenBucketRateLimiterConfig),
}

pub enum RateLimiterType {
    Simple,
    TokenBucket,
}

impl Layers {
    pub fn build_middleware_layers(&self) -> Result<Vec<MiddlewareLayer>, Error> {
        let mut result = Vec::with_capacity(10);

        for layer in &self.enabled {
            match layer.as_str() {
                "Timing" => result.push(MiddlewareLayer::Timing),
                "Counter" => result.push(MiddlewareLayer::Counter),
                "Logger" => result.push(MiddlewareLayer::Logger),
                "Delay" => {
                    let cfg = self
                        .delay_config
                        .as_ref()
                        .ok_or_else(|| Error::msg("Missing [Layers.Delay]"))?;
                    result.push(MiddlewareLayer::Delay(cfg.clone()));
                }
                "Inspection" => result.push(MiddlewareLayer::Inspection),
                "JwtAuth" | "JWT" => {
                    let cfg = self
                        .jwt_config
                        .as_ref()
                        .ok_or_else(|| Error::msg("Missing [Layers.JWT]"))?;
                    result.push(MiddlewareLayer::JwtAuth(cfg.jwt_public_keys.clone()));
                }
                s if s == "RateLimiter:Simple" => {
                    let cfg = self
                        .rate_limiter_config
                        .as_ref()
                        .ok_or_else(|| Error::msg("Missing [Layers.RateLimiter]"))?;
                    result.push(MiddlewareLayer::RateLimiter(RateLimiter::Simple(
                        cfg.clone(),
                    )));
                }
                s if s == "RateLimiter:TokenBucket" => {
                    let cfg = self
                        .token_bucket_config
                        .as_ref()
                        .ok_or_else(|| Error::msg("Missing [Layers.TokenBucketRateLimiter]"))?;
                    result.push(MiddlewareLayer::RateLimiter(RateLimiter::TokenBucket(
                        cfg.clone(),
                    )));
                }
                "ConcurrencyLimit" => {
                    let cfg = self
                        .concurrency_limit_config
                        .as_ref()
                        .ok_or_else(|| Error::msg("Missing [Layers.ConcurrencyLimit]"))?;
                    result.push(MiddlewareLayer::ConcurrencyLimit(cfg.clone()));
                }
                other => return Err(Error::msg(format!("Unknown layer type: {}", other))),
            }
        }

        Ok(result)
    }
}
