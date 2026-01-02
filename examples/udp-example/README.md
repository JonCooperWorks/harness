# UDP Example Plugin

A simple example plugin that demonstrates UDP networking using the `harness-wasi-sockets` polyfill.

## Building

```bash
cargo build --target wasm32-wasip1 --release
```

The compiled WASM will be at: `target/wasm32-wasip1/release/udp_example_plugin.wasm`

## Usage

This plugin sends a UDP datagram to a target host and optionally receives a response.

### Arguments

- `target` (required, string): Target host IP address (e.g., "127.0.0.1")
- `port` (required, integer): Target port number (e.g., 6000)
- `message` (optional, string): Message to send (defaults to "Hello, UDP!")

### Example

```bash
# Test locally using the test script
./test-udp.sh

# Or use the harness system (see below)
```

## Testing Locally

A simple test script is provided to test the plugin without the full harness encryption/signing workflow:

```bash
./test-udp.sh
```

This will:
1. Load the compiled WASM plugin
2. Send a UDP datagram to `localhost:6000`
3. Display the result

## How It Works

This plugin demonstrates:

1. **UDP Socket Creation** - Uses `UdpSocket::connect()` from the polyfill
2. **Sending Datagrams** - Uses `socket.send()` to send data
3. **Receiving Responses** - Uses `socket.recv_from()` to receive data

The polyfill provides a standard `std::net::UdpSocket`-compatible API that wraps the harness host's UDP functions.

## See Also

- [`polyfill/README.md`](../../polyfill/README.md) - Complete polyfill documentation
- [`../cve-2025-3243/`](../cve-2025-3243/) - TCP example using the polyfill

