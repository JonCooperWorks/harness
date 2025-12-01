# Get IP Plugin

An example WASM plugin that fetches IP information from ipconfig.io using Extism PDK.

## Building

```bash
cargo build --target wasm32-wasip1 --release
```

The compiled WASM will be at: `target/wasm32-wasip1/release/get_ip_plugin.wasm`

## Signing and Running

```bash
# Sign the plugin using keystore
./bin/sign \
  -plugin examples/get-ip/target/wasm32-wasip1/release/get_ip_plugin.wasm \
  -type wasm \
  -name get-ip-plugin \
  -president-keystore-key "president-key" \
  -harness-key harness_public.pem \
  -output get-ip-plugin.encrypted

# Run the plugin using keystore
./bin/harness \
  -file get-ip-plugin.encrypted \
  -keystore-key "harness-key" \
  -president-key president_public.pem \
  -args '{}'
```

## Features

- Uses Extism PDK for plugin development
- Makes HTTP requests to fetch IP information
- Returns JSON with IP address, location, and other details

This serves as a template for creating WASM plugins that work with the Harness system.
