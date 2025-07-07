# Rust Hyper + Rustls + Tower Server

A modern, performant HTTP server written in Rust with full async support, leveraging:

- **Hyper** (HTTP/1.1 and HTTP/2, async)
- **Rustls** (TLS and mTLS, no OpenSSL runtime dependency)
- **Tower** (composable middleware stack)
- **Tokio** (multithreaded async runtime)
- **Configurable via TOML** (`Config.toml`)
- **Structured logging** (to stdout and/or files)
- **JWT and Client Certificate authentication**
- **Dynamic reverse routing and flexible service composition**

---

## ✨ Features

- HTTP/1.1 and HTTP/2 (ALPN)
- TLS/mTLS (with server & client certs, and optional CRL)
- Middleware layers: logging, timing, JWT auth, rate limiting, inspection, artificial delay
- Easily configurable: enable/disable features and servers via `Config.toml`
- Per-path reverse proxy routing via Router
- Clean modular Rust code
- Tracing/logging to stdout or daily rolling files

---

## 🗂️ Structure

- `src/server.rs` - Main entry point (see examples in this README)
- `src/middleware/` - Custom Tower middleware (e.g., logging, timing, JWT, inspection)
- `src/tls_conf.rs` - Rustls/TLS configuration and loading logic
- `src/configuration.rs` - Config file parsing and struct definitions
- `Config.toml` - Main configuration file (see below)

---

## ⚙️ Prerequisites

- Rust (edition = "2024")
- Your certificates for TLS/mTLS (see `Config.toml` for file paths)
- For mTLS, client CA cert and (optionally) CRL

---

## 📦 Build & Run

```sh
# Clone repo
git clone <repo-url>
cd server

# Build release binary
cargo build --release

# Prepare your certificates and edit Config.toml as needed
# Run the server
./target/release/server Config.toml
# If no argument given, defaults to Config.toml in current directory

