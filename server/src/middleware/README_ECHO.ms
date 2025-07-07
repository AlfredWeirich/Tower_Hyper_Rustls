# What Does EchoService Do?

`EchoService` is a simple HTTP service built with Tower and Hyper in Rust.  
Here’s what it does:

- **GET /**  
  Responds with `"Echo!"`

- **GET /help**  
  Responds with a help message that includes the server's name.

- **POST /** and **PUT /**  
  Reads the request body and echoes it back as the response body.

- **Any other path or method**  
  Responds with HTTP 404 and body `"Not Found"`.

---

## Key Points

- It is a Tower `Service`, so you can combine it with other middleware and layers.
- Logging is done via `tracing`, so you can track requests in your logs.
- The server name is customizable (set via `EchoService::new(name)`).
- Designed to plug into a Hyper server, with or without TLS (via Rustls).

---

## In Short

- **It’s a minimal echo web server**: you send it something, it sends it right back—unless you hit `/` or `/help`.
