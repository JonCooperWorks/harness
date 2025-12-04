# Get IP Plugin

An example WASM plugin that fetches IP information from ipconfig.io using Extism PDK.

## Building

```bash
cargo build --target wasm32-wasip1 --release
```

The compiled WASM will be at: `target/wasm32-wasip1/release/get_ip_plugin.wasm`

## Encrypting, Signing, and Running

```bash
# First, encrypt the plugin (Exploit Owner)
./bin/encrypt \
  -plugin examples/get-ip/target/wasm32-wasip1/release/get_ip_plugin.wasm \
  -type wasm \
  -harness-key harness_public.pem \
  -target-key target_public.pem \
  -exploit-keystore-key "exploit-key" \
  -output get-ip-plugin.encrypted

# Then, sign with execution arguments (Target)
./bin/sign \
  -file get-ip-plugin.encrypted \
  -target-keystore-key "target-key" \
  -exploit-key exploit_public.pem \
  -harness-key harness_public.pem \
  -args '{}' \
  -output get-ip-plugin.approved

# Finally, execute the plugin (Harness)
./bin/harness \
  -file get-ip-plugin.approved \
  -harness-keystore-key "harness-key" \
  -target-key target_public.pem \
  -exploit-key exploit_public.pem
```

## Features

- Uses Extism PDK for plugin development
- Makes HTTP requests to fetch IP information
- Returns JSON with IP address, location, and other details

This serves as a template for creating WASM plugins that work with the Harness system.
