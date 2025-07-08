# Server Configuration README

This document explains the settings available in your server configuration file, provides example snippets, and outlines what each section does.

---

## Global Options

- **tokio_threads**: Number of threads for the Tokio runtime.  
  _Default_: Number of CPU cores  * 2

  _Example:_  
  ```toml
  # tokio_threads=32
  ```
- **log_dir**: Directory for log files. If not set, logs go to stdout only.  
  _Example:_  
  ```toml
  # log_dir="log"
  ```

---

## Server Definition

Each server is defined in a `[[Server]]` section. You can define multiple servers.

### Example

```toml
[[Server]]
name = "echo_test"
ip = "local"
port = 1337
enabled = true
protocol = "HTTPS"
service = "Echo"
```

- **name**: Any identifier for the server.
- **ip**: IP address or "local" for localhost.
- **port**: Port number to listen on.
- **enabled**: Whether this server instance is active.
- **protocol**: Either "HTTP" or "HTTPS".
- **service**: Service type; "Echo" or "Router".

---

## Authentication

- **authentication**:  
  - `"ClientCert"`: Use client certificate (mTLS)  
  - `"JWT"`: Use JWT tokens (works with HTTPS)  
  - `""` (empty): No authentication

```toml
# authentication = "ClientCert"
# authentication = "JWT"
```

---

## Reverse Routing (Router Service Only)

Defines reverse proxy paths for a Router service.

```toml
[Server.ReverseRoutes]
"/help" = "https://192.168.178.31:1338"
"/static" = "http://192.168.178.31:1339"
"/api" = "http://192.168.178.31:1330"
```

---

## TLS/SSL Certificates

Required for HTTPS servers.

```toml
[Server.server_certs]
ssl_certificate = "./server_certs/self_signed/fullchain_self.pem"
ssl_certificate_key  = "./server_certs/self_signed/privkey_self.pem"
```

---

## Client Certificates (for mTLS)

Can define multiple CA certificates.  
If a CRL is used, only that CA is allowed.

```toml
[[Server.client_certs]]
ssl_client_certificate   = "./client_certs/test1_crl/ca.cert.pem"
ssl_crl = "./client_certs/test1_crl/ca.crl.pem"
```

---

## Layers

Layers add middleware features like logging, rate limiting, JWT checks, etc.

```toml
[Server.Layers]
enabled = []
```

### Layer Options

- **Counter**
- **Delay**
- **Inspection**
- **Logger**
- **Timing**
- **JWT**
- **RateLimiter:Simple**
- **RateLimiter:TokenBucket**

Enable as a list, e.g.:
```toml
enabled = ["Counter", "Logger", "Timing", "Inspection", "JWT", "RateLimiter:Simple"]
```

---

### JWT Keys (if using JWT authentication)

```toml
[Server.Layers.JWT]
jwt_public_keys = ["./jwt/public_key.pem"]
```

---

### Simple Rate Limiter

```toml
[Server.Layers.RateLimiter]
requests_per_second = 500000
```

---

### Token Bucket Rate Limiter

```toml
[Server.Layers.TokenBucketRateLimiter]
max_capacity = 15
refill = 8
duration_micros = 1000
```

---

### Delay Layer

```toml
[Server.Layers.Delay]
delay_micros = 1
```

---

## Allowed Paths for Inspection Layer

Control allowed request patterns per HTTP method.

```toml
[Server.AllowedPathes.GET]
"/" = ["^/?$", "^/\\?name=.*$"]
"/help" = ["^/help\\??(topic=.*)?$"]
"/helpx" = ["^/helpx\\??(topic=.*)?$"]
"/name" = ["^/name\\??id=\\d+$"]

[Server.AllowedPathes.POST]
"/" = ["^/?$", "^/\\?id=\\d+$"]
"/name" = ["^/name\\??name=[a-zA-Z]+$"]
"/address" = ["^/address\\??city=[a-zA-Z]+$"]

[Server.AllowedPathes.PUT]
"/" = ["^/?$", "^/\\?id=\\d+$"]
```

---

## Multiple Servers

Add additional `[[Server]]` sections as needed.

```toml
[[Server]]
name = "base_service"
ip = "192.168.178.31"
port = 1338
protocol = "HTTPS"
service = "Echo"
enabled = false

[Server.server_certs]
ssl_certificate = "./server_certs/self_signed/fullchain_self.pem"
ssl_certificate_key  = "./server_certs/self_signed/privkey_self.pem"

[Server.Layers]
enabled = ["Logger","Timing"]

[Server.Layers.Delay]
delay_micros = 250
```

---

## Notes

- All sections starting with `#` are comments.
- If a value is not set, defaults are typically used (see comments in the file).
- You can duplicate or remove sections to fit your needs.

---

## Quick Start

1. Copy `config.toml.example` to `config.toml`
2. Adjust the parameters as shown above for your setup.
3. Start the server with your preferred method.

---
