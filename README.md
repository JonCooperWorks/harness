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

Generate keys for the president (who signs plugins) and the harness (who executes them). **Private keys are stored in the OS keystore and never written to disk.**

```bash
# Generate president's keys (for signing)
# Private key stored in keystore, only public key written to disk
./bin/genkeys -keystore-key "president-key" -public president_public.pem

# Generate harness keys (for decryption)
# Private key stored in keystore, only public key written to disk
./bin/genkeys -keystore-key "harness-key" -public harness_public.pem

# List all keys in keystore
./bin/listkeys
```

**Note**: If you have existing PEM private key files, you can import them into the keystore:

```bash
# Import existing private key into keystore
./bin/genkeys -import president_private.pem -keystore-key "president-key" -public president_public.pem
./bin/genkeys -import harness_private.pem -keystore-key "harness-key" -public harness_public.pem

# After importing, you can safely delete the PEM files
```

### 2. Create a WASM Plugin

Create a WASM module that exports the required functions:
- `name()` - returns the plugin name
- `description()` - returns the plugin description
- `json_schema()` - returns the JSON schema for arguments
- `execute(args_ptr, args_len)` - executes the plugin with JSON arguments

See the WASM loader implementation for details on the expected interface.

### 3. Sign and Encrypt Plugin

The president signs and encrypts the plugin using a key from the keystore:

```bash
./bin/sign \
  -plugin my-plugin.wasm \
  -type wasm \
  -name my-plugin \
  -president-keystore-key "president-key" \
  -harness-key harness_public.pem \
  -output my-plugin.encrypted
```

### 4. Verify Plugin (Optional)

Verify the encrypted plugin without executing it:

```bash
./bin/verify \
  -file my-plugin.encrypted \
  -keystore-key "harness-key" \
  -president-key president_public.pem
```

### 5. Execute Plugin

Run the harness to load and execute the plugin using a key from the keystore:

```bash
./bin/harness \
  -file my-plugin.encrypted \
  -keystore-key "harness-key" \
  -president-key president_public.pem \
  -args '{"message":"Hello","count":1}'
```

## OS Keystore Integration

**All private keys are stored in the OS keystore and never written to disk.** This provides secure key storage using platform-native security features.

### Key Management

**Generate new keys** (recommended):

```bash
# Generate a new key pair, store private key in keystore, output only public key
./bin/genkeys \
  -keystore-key "harness-key" \
  -public harness_public.pem
```

**Import existing PEM keys** (migration):

```bash
# Import an existing private key file into the keystore
./bin/genkeys \
  -import existing_private.pem \
  -keystore-key "harness-key" \
  -public harness_public.pem

# After importing, you can safely delete the PEM file
```

**List keys in keystore**:

```bash
# List all key IDs stored in the keystore
./bin/listkeys
```

### Using Keys from Keystore

All commands support keystore-based keys:

```bash
# Sign a plugin using keystore
./bin/sign \
  -plugin my-plugin.wasm \
  -president-keystore-key "president-key" \
  -harness-key harness_public.pem \
  -output my-plugin.encrypted

# Verify a plugin using keystore
./bin/verify \
  -file my-plugin.encrypted \
  -keystore-key "harness-key" \
  -president-key president_public.pem

# Execute a plugin using keystore
./bin/harness \
  -file my-plugin.encrypted \
  -keystore-key "harness-key" \
  -president-key president_public.pem \
  -args '{}'
```

### Platform Support

- **macOS**: Uses Keychain Access (service: `harness`)
  - Default: Uses login keychain (unlocked when logged in, fewer prompts)
  - Custom: Set `HARNESS_KEYCHAIN="harness-keys"` to use custom keychain
  - Example: `export HARNESS_KEYCHAIN="harness-keys"` before running commands
- **Linux**: Uses libsecret/keyring (service: `harness`)
- **Windows**: Uses Credential Manager (service: `harness`)

**macOS Keychain Configuration:**
- **Default (recommended)**: No environment variable = uses login keychain (fewer password prompts)
- **Custom keychain**: Set `export HARNESS_KEYCHAIN="harness-keys"` to use the custom "harness-keys" keychain
- Note: If you have existing keys in "harness-keys", set the environment variable to access them

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

## Example: Using a WASM Plugin

```bash
# Sign a WASM plugin using keystore
./bin/sign \
  -plugin my-plugin.wasm \
  -type wasm \
  -name my-plugin \
  -president-keystore-key "president-key" \
  -harness-key harness_public.pem \
  -output my-plugin.encrypted

# Execute it using keystore
./bin/harness \
  -file my-plugin.encrypted \
  -keystore-key "harness-key" \
  -president-key president_public.pem \
  -args '{"message":"Hello World","count":3}'
```

## Platform Notes

- **WASM Plugins**: Supported on all platforms via the wazero runtime
- **Keystore**: Platform-specific implementations for secure key storage

## Security Considerations

- **Private keys are stored in OS keystore** - never written to disk
- President's public key should be distributed securely
- Encrypted plugins can be distributed over insecure channels
- Signature verification ensures plugin authenticity
- Encryption ensures plugin confidentiality
- File-based private keys (`-key` flag) are deprecated and only supported for migration purposes

## License

[Your License Here]

