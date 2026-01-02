# Rust std::net Polyfill for WASM Plugins

This polyfill provides `std::net::TcpStream`, `std::net::UdpSocket`, and ICMP functionality for WASM plugins running in the harness system. It wraps the harness host's TCP, UDP, and ICMP functions to provide a standard Rust networking API.

## Features

- **Drop-in replacement** for `std::net::TcpStream` and `std::net::UdpSocket` in WASM environments
- **Standard Rust API** - implements `Read`, `Write`, and standard networking methods
- **Automatic connection management** - connections are closed on drop
- **Buffered reading** - efficiently handles partial reads and data buffering
- **TCP, UDP, and ICMP support** - all three protocols are fully supported

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
- **ICMP permissions** - ICMP operations may require elevated privileges on some systems
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

