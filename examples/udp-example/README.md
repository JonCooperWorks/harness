# UDP Example Plugin

A simple example plugin that demonstrates UDP networking using the `harness-wasi-sockets` polyfill.

## Building

```bash
cargo build --target wasm32-wasip1 --release
```

The compiled WASM will be at: `target/wasm32-wasip1/release/udp_example_plugin.wasm`

## Encrypting, Signing, and Running

### Option 1: Direct Encryption

```bash
# First, encrypt the plugin (Exploit Owner)
./bin/encrypt \
  -plugin examples/udp-example/target/wasm32-wasip1/release/udp_example_plugin.wasm \
  -type wasm \
  -harness-key harness_public.pem \
  -target-key target_public.pem \
  -exploit-keystore-key "exploit-key" \
  -output examples/udp-example/udp-example.encrypted

# Then, sign with execution arguments (Target)
./bin/sign \
  -file examples/udp-example/udp-example.encrypted \
  -target-keystore-key "target-key" \
  -exploit-key exploit_public.pem \
  -harness-key harness_public.pem \
  -args '{"target":"127.0.0.1","port":6000,"message":"Hello, UDP!"}' \
  -output examples/udp-example/udp-example.approved

# Finally, execute the plugin (Harness)
./bin/harness \
  -file examples/udp-example/udp-example.approved \
  -harness-keystore-key "harness-key" \
  -target-key target_public.pem \
  -exploit-key exploit_public.pem
```

### Option 2: Store First, Then Encrypt

```bash
# First, store the plugin (Exploit Owner) - encrypts to your own key
./bin/store \
  -plugin examples/udp-example/target/wasm32-wasip1/release/udp_example_plugin.wasm \
  -type wasm \
  -harness-key harness_public.pem \
  -exploit-keystore-key "exploit-key" \
  -output examples/udp-example/udp-example.wasm.stored

# Later, encrypt from stored file (Exploit Owner)
./bin/encrypt \
  -plugin examples/udp-example/udp-example.wasm.stored \
  -type wasm \
  -harness-key harness_public.pem \
  -target-key target_public.pem \
  -exploit-keystore-key "exploit-key" \
  -output examples/udp-example/udp-example.encrypted

# Then, sign with execution arguments (Target)
./bin/sign \
  -file examples/udp-example/udp-example.encrypted \
  -target-keystore-key "target-key" \
  -exploit-key exploit_public.pem \
  -harness-key harness_public.pem \
  -args '{"target":"127.0.0.1","port":6000,"message":"Hello, UDP!"}' \
  -output examples/udp-example/udp-example.approved

# Finally, execute the plugin (Harness)
./bin/harness \
  -file examples/udp-example/udp-example.approved \
  -harness-keystore-key "harness-key" \
  -target-key target_public.pem \
  -exploit-key exploit_public.pem
```

## Plugin Storage

The harness system makes no assumptions about how you store your exploit plugins. You can use any storage infrastructure you prefer (S3, databases, file systems, etc.). The system is designed to be compatible with existing infrastructure.

If you don't have storage infrastructure set up, the `store` command provides an easy option that works within the existing cryptosystem:

- **Stored files** (`.stored` extension) are encrypted to the exploit owner's key, giving you full control
- Only you (the exploit owner) can decrypt stored files using your `exploit-keystore-key`
- The `encrypt` command automatically detects stored files and can re-encrypt them for targets
- Stored files use the same encryption format as regular encrypted files, just encrypted to your key instead of the target's key

The `store` command is optional - you can use any storage mechanism you prefer. The `encrypt` command accepts both raw plugin binaries and stored files transparently.

## Arguments

- `target` (required, string): Target host IP address (e.g., "127.0.0.1")
- `port` (required, integer): Target port number (e.g., 6000)
- `message` (optional, string): Message to send (defaults to "Hello, UDP!")

### Example Usage

```bash
-args '{"target":"127.0.0.1","port":6000,"message":"Hello, UDP!"}'
```

## How It Works

This plugin demonstrates UDP networking by:

1. **UDP Socket Creation** - Uses `UdpSocket::connect()` from the polyfill to establish a connection to the target host
2. **Sending Datagrams** - Uses `socket.send()` to send a UDP datagram with the specified message
3. **Receiving Responses** - Uses `socket.recv_from()` to receive any response from the target

The polyfill provides a standard `std::net::UdpSocket`-compatible API that wraps the harness host's UDP functions. The polyfill allows plugins to use standard Rust networking APIs while running in WASM environments. See [`polyfill/README.md`](../../polyfill/README.md) for more information.

## See Also

- [`polyfill/README.md`](../../polyfill/README.md) - Complete polyfill documentation
- [`../cve-2025-3243/`](../cve-2025-3243/) - TCP example using the polyfill
