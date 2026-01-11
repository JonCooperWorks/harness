# Rust std::net Polyfill for WASM Plugins

This polyfill provides `std::net::TcpStream`, `std::net::UdpSocket`, ICMP functionality, and an HTTP client for WASM plugins running in the harness system. It wraps the harness host's TCP, UDP, ICMP, and HTTP functions to provide standard Rust networking APIs.

## Features

- **Drop-in replacement** for `std::net::TcpStream` and `std::net::UdpSocket` in WASM environments
- **Standard Rust API** - implements `Read`, `Write`, and standard networking methods
- **Automatic connection management** - connections are closed on drop
- **Buffered reading** - efficiently handles partial reads and data buffering
- **TCP, UDP, and ICMP support** - all three protocols are fully supported
- **HTTP client with reqwest-like API** - properly handles all headers including multiple `Set-Cookie` headers

## Usage

Add the polyfill as a dependency in your `Cargo.toml`:

```toml
[dependencies]
harness-wasi-sockets = { path = "../../polyfill" }
```

Then use it in your plugin:

### TCP Example

```rust
use harness_wasi_sockets::TcpStream;
use std::io::{Read, Write};

// Connect to a remote host
let mut stream = TcpStream::connect("127.0.0.1:6000")?;

// Write data
stream.write_all(b"Hello, world!")?;

// Read data
let mut buf = [0u8; 1024];
let n = stream.read(&mut buf)?;
println!("Received {} bytes", n);

// Connection is automatically closed when stream goes out of scope
```

### UDP Example

```rust
use harness_wasi_sockets::UdpSocket;

// Connect to a remote host
let socket = UdpSocket::connect("127.0.0.1:6000")?;

// Send a datagram
socket.send(b"Hello, UDP!")?;

// Receive a datagram
let mut buf = [0u8; 1024];
let (n, addr) = socket.recv_from(&mut buf)?;
println!("Received {} bytes from {}", n, addr);
```

### ICMP Example

```rust
use harness_wasi_sockets::IcmpSocket;

// Create an ICMP socket
let socket = IcmpSocket::new();

// Send an ICMP echo request
socket.send("8.8.8.8", b"Hello, ICMP!", 1)?;

// Receive ICMP response
let response = socket.recv(5000)?;
println!("Received from {}: type={}, code={}", response.source, response.icmp_type, response.code);
if let Some(seq) = response.seq {
    println!("Sequence number: {}", seq);
}
```

## API

### `TcpStream::connect<A: ToSocketAddrs>(addr: A) -> io::Result<TcpStream>`

Opens a TCP connection to a remote host. The `addr` parameter can be:
- A string like `"127.0.0.1:6000"` or `"localhost:8080"`
- A `SocketAddr`

### `TcpStream::shutdown(&self, how: Shutdown) -> io::Result<()>`

Shuts down the read, write, or both halves of the connection. Currently closes the connection entirely.

### `TcpStream::peer_addr(&self) -> io::Result<SocketAddr>`

Returns the socket address of the remote peer. **Not yet implemented** - returns an error.

### `TcpStream::local_addr(&self) -> io::Result<SocketAddr>`

Returns the socket address of the local half. **Not yet implemented** - returns an error.

### `Read` and `Write` traits

The `TcpStream` implements `std::io::Read` and `std::io::Write`, allowing you to use all standard Rust I/O operations:

```rust
use std::io::{Read, Write, BufRead, BufReader};

let mut stream = TcpStream::connect("127.0.0.1:6000")?;
let mut reader = BufReader::new(&mut stream);
let mut line = String::new();
reader.read_line(&mut line)?;
```

## UDP API

### `UdpSocket::connect<A: ToSocketAddrs>(addr: A) -> io::Result<UdpSocket>`

Connects a UDP socket to a remote address. The `addr` parameter can be:
- A string like `"127.0.0.1:6000"` or `"localhost:8080"`
- A `SocketAddr`

### `UdpSocket::send(&self, buf: &[u8]) -> io::Result<usize>`

Sends data on this socket to the remote address to which it is connected.

### `UdpSocket::recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)>`

Receives a single datagram message on the socket. Returns the number of bytes read and the address from whence the message came.

### `UdpSocket::recv(&self, buf: &mut [u8]) -> io::Result<usize>`

Receives a single datagram message on the socket. Returns only the number of bytes read.

### `UdpSocket::peer_addr(&self) -> io::Result<SocketAddr>`

Returns the socket address of the remote peer this socket was connected to.

### `UdpSocket::local_addr(&self) -> io::Result<SocketAddr>`

Returns the socket address of the local half. **Not yet implemented** - returns an error.

## ICMP API

> **Note:** ICMP functions require raw socket access, which typically requires root/administrator privileges or the `CAP_NET_RAW` capability on Linux. Without elevated privileges, ICMP operations will fail silently.

### `IcmpSocket::new() -> IcmpSocket`

Creates a new ICMP socket for sending and receiving ICMP packets.

### `IcmpSocket::send(&self, target: &str, payload: &[u8], seq: u16) -> io::Result<()>`

Sends an ICMP echo request packet to the specified target.

- `target` - Target IP address (e.g., "8.8.8.8")
- `payload` - Payload data to send in the ICMP packet
- `seq` - Sequence number for the ICMP packet

### `IcmpSocket::recv(&self, timeout_ms: u32) -> io::Result<IcmpResponse>`

Receives an ICMP packet with the specified timeout.

- `timeout_ms` - Timeout in milliseconds

Returns an `IcmpResponse` containing:
- `source` - Source address of the ICMP packet
- `icmp_type` - ICMP type
- `code` - ICMP code
- `id` - ICMP echo ID (if echo packet)
- `seq` - ICMP echo sequence number (if echo packet)
- `data` - ICMP payload data

## How It Works

The polyfill wraps the harness host's TCP and UDP functions:

### TCP Functions

1. **`tcp_connect(addr_offset: u64) -> u32`** - Establishes a TCP connection
   - Takes a pointer to a null-terminated address string in plugin memory
   - Returns a connection ID (non-zero on success, 0 on error)

2. **`tcp_send(conn_id: u32, data_offset: u64, data_len: u64) -> u32`** - Sends data
   - Takes connection ID, pointer to data, and data length
   - Returns number of bytes sent (0 on error)

3. **`tcp_recv(conn_id: u32, max_len: u32) -> u64`** - Receives data
   - Takes connection ID and maximum length to read
   - Returns memory offset to received data (0 if no data available)

4. **`tcp_close(conn_id: u32)`** - Closes the connection

### UDP Functions

1. **`udp_connect(addr_offset: u64) -> u32`** - Connects a UDP socket
   - Takes a pointer to a null-terminated address string in plugin memory
   - Returns a connection ID (non-zero on success, 0 on error)

2. **`udp_send(conn_id: u32, data_offset: u64, data_len: u64) -> u32`** - Sends a datagram
   - Takes connection ID, pointer to data, and data length
   - Returns number of bytes sent (0 on error)

3. **`udp_recv(conn_id: u32, max_len: u32) -> u64`** - Receives a datagram
   - Takes connection ID and maximum length to read
   - Returns memory offset to received data (0 if no data available)

4. **`udp_close(conn_id: u32)`** - Closes the connection

### ICMP Functions

1. **`icmp_send(target_offset: u64, payload_offset: u64, payload_len: u64, seq: u16) -> u32`** - Sends an ICMP packet
   - Takes pointer to target address string, pointer to payload data, payload length, and sequence number
   - Returns 1 on success, 0 on failure

2. **`icmp_recv(timeout_ms: u32) -> u64`** - Receives an ICMP packet
   - Takes timeout in milliseconds
   - Returns memory offset to JSON response (0 if timeout or error)
   - The JSON contains: `{"source": "...", "type": 0, "code": 0, "id": 1, "seq": 1, "data": [...]}`

The polyfill uses Extism's `Memory` API to allocate and manage memory for addresses and data, ensuring compatibility with the harness host's memory model.

## Limitations

- **IPv6 support** - IPv6 addresses are parsed but may not work correctly with the host
- **`peer_addr()` and `local_addr()`** - `local_addr()` not implemented (host doesn't provide this information)
- **Partial shutdown** - TCP `shutdown()` currently closes the entire connection
- **Non-blocking I/O** - All operations are blocking with timeouts handled by the host
- **UDP connection mode** - UDP sockets must be connected via `connect()` before use (connectionless mode not supported)
- **ICMP permissions** - ICMP operations require raw socket access, which typically requires root/administrator privileges or the `CAP_NET_RAW` capability on Linux. Without elevated privileges, ICMP operations will fail silently.
- **ICMP response format** - ICMP responses are returned as JSON, not raw packets

## Migration from Raw Host Functions

If you're currently using raw host functions in your plugin:

**Before:**
```rust
extern "C" {
    fn tcp_connect(addr_offset: u64) -> u32;
    fn tcp_send(conn_id: u32, data_offset: u64, data_len: u64) -> u32;
    fn tcp_recv(conn_id: u32, max_len: u32) -> u64;
    fn tcp_close(conn_id: u32);
}

// Manual memory management
let addr_mem = Memory::new(&target_addr)?;
let conn_id = unsafe { tcp_connect(addr_mem.offset()) };
// ... more manual code
```

**After:**
```rust
use harness_wasi_sockets::TcpStream;
use std::io::Write;

// Automatic memory management
let mut stream = TcpStream::connect(&target_addr)?;
stream.write_all(&data)?;
// Connection automatically closed on drop
```

### ICMP Example

**Before:**
```rust
extern "C" {
    fn icmp_send(target_offset: u64, payload_offset: u64, payload_len: u64, seq: u32) -> u32;
    fn icmp_recv(timeout_ms: u32) -> u64;
}

// Manual memory management and JSON parsing
let target_mem = Memory::new(&target)?;
let payload_mem = Memory::new(&payload)?;
let result = unsafe { icmp_send(target_mem.offset(), payload_mem.offset(), payload.len() as u64, 1) };
// ... manual JSON parsing
```

**After:**
```rust
use harness_wasi_sockets::IcmpSocket;

// Automatic memory management and JSON parsing
let socket = IcmpSocket::new();
socket.send("8.8.8.8", b"Hello", 1)?;
let response = socket.recv(5000)?;
// Response is automatically parsed into structured data
```

## Building

The polyfill is built as part of your plugin:

```bash
cargo build --target wasm32-wasip1 --release
```

No separate build step is required - it's compiled into your plugin binary.

## HTTP Client

The polyfill includes an HTTP client with a reqwest-like API that uses Go's `net/http` on the host side. This properly handles all HTTP headers, including multiple `Set-Cookie` headers, which solves limitations of extism's built-in HTTP API.

### Features

- **Proper header handling** - All headers including multiple `Set-Cookie` headers are properly extracted
- **Reqwest-like API** - Familiar API similar to the popular `reqwest` crate
- **JSON support** - Built-in JSON serialization/deserialization
- **Synchronous API** - Blocking requests for simplicity
- **Uses Go's net/http** - Battle-tested HTTP implementation on the host side

### Usage

```rust
use harness_wasi_sockets::Client;

// Create a new HTTP client
let client = Client::new();

// GET request
let response = client.get("https://example.com").send()?;
println!("Status: {}", response.status());
let body = response.text()?;

// POST request with JSON
use serde_json::json;

let response = client.post("https://api.example.com/data")
    .header("Authorization", "Bearer token123")
    .json(&json!({"key": "value"}))
    .send()?;

let data: Value = response.json()?;

// POST request with raw body
let response = client.post("https://api.example.com/upload")
    .header("Content-Type", "text/plain")
    .body(b"Hello, world!".to_vec())
    .send()?;

// Access headers (properly handles multiple headers with same name)
if let Some(cookies) = response.header("Set-Cookie") {
    for cookie in cookies {
        println!("Cookie: {}", cookie);
    }
}

// Get all headers
let headers = response.headers();
for (name, values) in headers {
    println!("{}: {:?}", name, values);
}
```

### API Reference

#### `Client`

The main HTTP client type.

##### Methods

- **`Client::new() -> Client`** - Creates a new HTTP client
- **`Client::get(url: &str) -> RequestBuilder`** - Creates a GET request builder
- **`Client::post(url: &str) -> RequestBuilder`** - Creates a POST request builder
- **`Client::put(url: &str) -> RequestBuilder`** - Creates a PUT request builder
- **`Client::delete(url: &str) -> RequestBuilder`** - Creates a DELETE request builder
- **`Client::patch(url: &str) -> RequestBuilder`** - Creates a PATCH request builder

#### `RequestBuilder`

A builder for constructing HTTP requests.

##### Methods

- **`header(name: &str, value: &str) -> RequestBuilder`** - Adds a header to the request
- **`json<T: Serialize>(body: &T) -> RequestBuilder`** - Sets the request body as JSON (automatically sets `Content-Type: application/json`)
- **`body(body: Vec<u8>) -> RequestBuilder`** - Sets the request body as raw bytes
- **`send() -> Result<Response>`** - Sends the request and returns the response

#### `Response`

An HTTP response.

##### Methods

- **`status() -> u16`** - Returns the HTTP status code
- **`status_is_success() -> bool`** - Returns `true` if status is 200-299
- **`headers() -> &HeaderMap`** - Returns a reference to the header map
- **`header(name: &str) -> Option<&Vec<String>>`** - Gets all values for a header name (case-insensitive)
- **`text() -> Result<String>`** - Returns the response body as a string
- **`bytes() -> &[u8]`** - Returns the response body as raw bytes
- **`json<T: Deserialize>() -> Result<T>`** - Deserializes the response body as JSON

#### `HeaderMap`

A type alias for `HashMap<String, Vec<String>>` that stores multiple values per header name.

This allows proper handling of headers like `Set-Cookie` that can appear multiple times in a response.

### How It Works

The HTTP client uses a host function that calls Go's `net/http`:

1. **Request building** - The Rust code builds a request with method, URL, headers, and body
2. **Host function call** - The request is serialized to JSON and passed to the `http_request` host function
3. **Go net/http execution** - The host function uses Go's `net/http` to make the actual HTTP request
4. **Response parsing** - The response (status, headers, body) is returned as JSON and parsed into Rust types

This approach ensures that all headers, including multiple `Set-Cookie` headers, are properly handled by Go's battle-tested HTTP implementation.

### Migration from extism-pdk HTTP API

**Before (extism-pdk):**
```rust
use extism_pdk::*;

let mut req = HttpRequest::new("https://example.com")
    .with_method("GET")
    .with_header("Cookie", "session=abc123");

let res = http::request::<Vec<u8>>(&req, None)?;
let body = String::from_utf8_lossy(&res.body()).to_string();

// Problem: Only one Set-Cookie header is accessible
for (key, value) in res.headers() {
    if key.to_lowercase() == "set-cookie" {
        // Only gets one Set-Cookie header even if server sent multiple
    }
}
```

**After (HTTP client polyfill):**
```rust
use harness_wasi_sockets::Client;

let client = Client::new();
let response = client.get("https://example.com")
    .header("Cookie", "session=abc123")
    .send()?;

let body = response.text()?;

// Solution: All Set-Cookie headers are accessible
if let Some(cookies) = response.header("Set-Cookie") {
    for cookie in cookies {
        // Gets ALL Set-Cookie headers from the server
        println!("Cookie: {}", cookie);
    }
}
```

### Limitations

- **Synchronous only** - All requests are blocking (no async support)
- **10 second timeout** - Requests timeout after 10 seconds
- **Redirects are followed** - Up to 10 redirects are followed automatically (as per Go's default)
- **Base64 body encoding** - Response bodies are base64-encoded in transport (handled transparently)
