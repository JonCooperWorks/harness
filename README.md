# Harness - Secure Plugin System

A cross-platform Go program that securely loads and executes encrypted WASM plugins with cryptographic signature verification.

## Features

- **Cryptographic Security**: ECDSA signature verification and AES-256 encryption
- **Cross-Platform**: Works on macOS, Linux, and Windows
- **WASM Plugins**: Supports WebAssembly plugins via wazero runtime
- **OS Keystore Integration**: Secure key storage using platform keystores
- **Memory-Based Loading**: Plugins loaded directly from memory

## Building

```bash
# Build all utilities
go build -o bin/genkeys ./cmd/genkeys
go build -o bin/sign ./cmd/sign
go build -o bin/harness ./cmd/harness
go build -o bin/verify ./cmd/verify
```

## Quick Start

### 1. Generate Keys

Generate keys for the president (who signs plugins) and the harness (who executes them):

```bash
# Generate president's keys (for signing)
./bin/genkeys -private president_private.pem -public president_public.pem

# Generate harness keys (for decryption)
./bin/genkeys -private harness_private.pem -public harness_public.pem
```

### 2. Create a WASM Plugin

Create a WASM module that exports the required functions:
- `name()` - returns the plugin name
- `description()` - returns the plugin description
- `json_schema()` - returns the JSON schema for arguments
- `execute(args_ptr, args_len)` - executes the plugin with JSON arguments

See the WASM loader implementation for details on the expected interface.

### 3. Sign and Encrypt Plugin

The president signs and encrypts the plugin:

```bash
./bin/sign \
  -plugin my-plugin.wasm \
  -type wasm \
  -name my-plugin \
  -president-key president_private.pem \
  -harness-key harness_public.pem \
  -output my-plugin.encrypted
```

### 4. Verify Plugin (Optional)

Verify the encrypted plugin without executing it:

```bash
./bin/verify \
  -file my-plugin.encrypted \
  -key harness_private.pem \
  -president-key president_public.pem
```

### 5. Execute Plugin

Run the harness to load and execute the plugin:

```bash
./bin/harness \
  -file my-plugin.encrypted \
  -key harness_private.pem \
  -president-key president_public.pem \
  -args '{"message":"Hello","count":1}'
```

## Using OS Keystore

Instead of storing keys in files, you can use the OS keystore:

### macOS Keychain

```bash
# Store key in Keychain (manual step - use keychain access or keyring library)
# Then use:
./bin/harness \
  -file my-plugin.encrypted \
  -keystore-key "harness-key-id" \
  -president-key president_public.pem \
  -args '{}'
```

### Linux Keyring

Similar process using the Linux keyring (libsecret).

### Windows Credential Store

Similar process using Windows Credential Manager.

## Architecture

### Cryptographic Flow

1. **Signing** (President):
   - Generate symmetric key (AES-256)
   - Encrypt plugin data with symmetric key
   - Encrypt symmetric key with harness's public key (ECDH)
   - Sign metadata + encrypted data with president's private key (ECDSA)

2. **Verification & Decryption** (Harness):
   - Verify signature with president's public key
   - Decrypt symmetric key with harness's private key (ECDH)
   - Decrypt plugin data with symmetric key (AES-256)

### Plugin Interface

All plugins must implement:

```go
type Plugin interface {
    Name() string
    Description() string
    JSONSchema() string
    Execute(ctx context.Context, args json.RawMessage) (interface{}, error)
}
```

## Example: Test Plugin

A simple test plugin is included in `plugin/test/`:

```bash
# Sign a WASM plugin
./bin/sign \
  -plugin my-plugin.wasm \
  -type wasm \
  -name test-plugin \
  -president-key president_private.pem \
  -harness-key harness_public.pem \
  -output test-plugin.encrypted

# Execute it
./bin/harness \
  -file test-plugin.encrypted \
  -key harness_private.pem \
  -president-key president_public.pem \
  -args '{"message":"Hello World","count":3}'
```

## Platform Notes

- **WASM Plugins**: Supported on all platforms via the wazero runtime
- **Keystore**: Platform-specific implementations for secure key storage

## Security Considerations

- Private keys should be stored securely (use OS keystore when possible)
- President's public key should be distributed securely
- Encrypted plugins can be distributed over insecure channels
- Signature verification ensures plugin authenticity
- Encryption ensures plugin confidentiality

## License

[Your License Here]

