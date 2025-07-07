# Rust Hyper Async Client

A fast, async HTTP/HTTPS/JWT/mTLS benchmarking client using [hyper](https://github.com/hyperium/hyper), [tower](https://github.com/tower-rs/tower), [rustls](https://github.com/rustls/rustls), and [clap](https://github.com/clap-rs/clap).

Supports **concurrent** requests, JWT authentication, mTLS (mutual TLS), and flexible command-line arguments.

---

## Features

- **Async** & highly concurrent via `tokio`
- **HTTP/HTTPS/JWT/mTLS** support
- **Custom CA roots & client certs** for secure connections
- **Parallelism**: set both total and concurrent request numbers
- **Simple CLI** with strong validation and clear error messages
- **JWT Bearer Auth** for easy API testing
- **Metrics**: reports total duration and mean RPS

---

## Requirements

- **Rust** 1.75+ (for modern async & dependency versions)
- Linux/macOS (for high file descriptor/concurrency support)
- See [System Tuning](#system-tuning) for high concurrency tips

---

## Installation

```sh
git clone <your-repo>
cd <your-repo>
cargo build --release
```

---

## Usage

```sh
cargo run -p client --bin=client -- [OPTIONS]
```

### CLI Options

| Option          | Short | Long             | Description                                     | Default                  |
|-----------------|-------|------------------|-------------------------------------------------|--------------------------|
| Number of reqs  | `-i`  | `--num-req`      | Number of requests to send                      | 10                       |
| Parallel reqs   |       | `--num-parallel` | Number of concurrent requests                   | 128                      |
| Protocol        | `-s`  | `--security`     | Protocol: `http`, `https`, `jwt`, `mtls`        | `https`                  |
| CA cert         | `-r`  | `--ca`           | Root CA for TLS                                 | _(required for TLS)_     |
| JWT file        | `-j`  | `--jwt`          | JWT token file for JWT mode                     | _(required for JWT)_     |
| Client cert     | `-c`  | `--cert`         | Client certificate for mTLS                     | _(required for mTLS)_    |
| Client key      | `-k`  | `--key`          | Client private key for mTLS                     | _(required for mTLS)_    |
| HTTP Method     | `-m`  | `--method`       | HTTP method (`GET`, `POST`, etc.)               | `GET`                    |
| Host:port       | `-u`  | `--uri`          | Host and port (e.g. `192.168.178.31:1337`)      | `192.168.178.31:1337`    |
| Request path    | `-p`  | `--path`         | URL path                                        | `/`                      |

---

## Examples

**HTTPS with self-signed CA:**

```sh
RUST_LOG=client=trace \
cargo run -p client --bin=client -- \
  --ca="./server_certs/self_signed/myca.pem" -p / -s https -i 800
```

**JWT Auth:**

```sh
RUST_LOG=client=trace \
cargo run -p client --bin=client -- \
  --ca="./server_certs/self_signed/myca.pem" -p / -j ./jwt/token1.jwt -s jwt -i 800
```

**mTLS (mutual TLS):**

```sh
RUST_LOG=client=trace \
cargo run -p client --bin=client --release -- \
  --ca="./server_certs/self_signed/myca.pem" \
  -p / -c ./client_certs/client1.cert.pem -k ./client_certs/client1.key.pem \
  -s mtls -i 65000
```

---

## System Tuning

For high concurrency (thousands of requests), increase file descriptors:

```sh
sudo sysctl -w kern.maxfiles=65536
sudo sysctl -w kern.maxfilesperproc=65536
ulimit -n 65536
```

---

## How It Works

- **Protocols:** Choose between HTTP, HTTPS, JWT Bearer (with HTTPS), or mutual TLS.
- **Concurrency:** Launches up to N requests in parallel, keeps concurrency steady until total number sent.
- **TLS:** Uses `rustls` for modern TLS, custom CA support, and optional mTLS with client cert/key.
- **JWT:** Reads token from file, adds as Bearer header.
- **Metrics:** Reports duration and mean requests per second at end.
- **Error Handling:** Clear messages if required parameters (e.g. CA, JWT, mTLS certs) are missing.

---

## Example System Output

<details>
<summary>Sample Run Output</summary>

```
Duration: 750ms with 800 total requests at concurrency 128
Mean requests per second: 1066  --> per request: 937.7us
```

</details>

---

## Dependencies

- [hyper](https://crates.io/crates/hyper)
- [hyper-util](https://crates.io/crates/hyper-util)
- [hyper-rustls](https://crates.io/crates/hyper-rustls)
- [tower](https://crates.io/crates/tower)
- [rustls](https://crates.io/crates/rustls)
- [clap](https://crates.io/crates/clap)
- [tokio](https://crates.io/crates/tokio)
- [anyhow](https://crates.io/crates/anyhow)
- [tracing](https://crates.io/crates/tracing)
- [bytes](https://crates.io/crates/bytes)
- [futures](https://crates.io/crates/futures)
- [http-body-util](https://crates.io/crates/http-body-util)

---

## Notes

- Make sure your target server is listening on the port and protocol you specify.
- For mTLS and custom CAs, ensure certificate paths are correct.
- The request body is currently hardcoded as `"Hello, World!"`. Change in code as needed.

---

## TODO

- Add support for custom request bodies (e.g., POST data)
- Support for HTTP/2 or HTTP/3
- JSON response parsing
- Progress bars and nicer CLI UX

---

## Contribution

PRs and issues welcome! Please file bugs or suggestions.

---

## License

MIT or Apache-2.0

---

## Author

Your Name/Org

---
