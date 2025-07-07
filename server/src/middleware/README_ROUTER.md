# What Does RouterService Do?

`RouterService` is a routing HTTP service built with Tower and Hyper in Rust.  
Here’s what it does:

- **Routes Incoming Requests**  
  Matches each HTTP request’s path and method, then delegates handling to the appropriate inner service (like `EchoService`, static file handlers, API endpoints, etc).

- **Custom Per-Route Logic**  
  Allows you to define different behaviors or middleware per route—for example, one service for `/api/*`, another for `/static/*`, and so on.

- **404 Handling**  
  If no route matches, responds with HTTP 404 and a customizable "Not Found" body.

---

## Key Points

- **Composes Multiple Services**: You can register multiple handlers/services, each for a specific path or method.
- **Tower-Compatible**: Fully compatible with other Tower middleware, layers, and services.
- **Easy to Extend**: Add new routes/services by updating the route table or match logic.
- **Logging**: Typically uses `tracing` for logging route matches and misses.
- **Central Dispatch**: Acts as the "traffic cop," sending each request to the right code path.

---

## In Short

- **It’s a request router**:  
  It takes incoming HTTP requests and sends them to the right handler/service based on the URL path and method.
