# Harness - Secure Plugin System

A cross-platform Go program that securely loads and executes encrypted WASM plugins with cryptographic signature verification.

## Features

- **Cryptographic Security**: ECDSA signature verification and AES-256 encryption
- **Cross-Platform**: Works on macOS, Linux, and Windows
- **WASM Plugins**: Supports WebAssembly plugins via Extism SDK
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

Create a WASM module using the Extism Plugin Development Kit (PDK). The plugin must export the following functions:

- `name()` - returns the plugin name as a string
- `description()` - returns the plugin description as a string
- `json_schema()` - returns the JSON schema for arguments as a string
- `execute()` - executes the plugin with JSON arguments and returns JSON result

See the [Plugin API](#plugin-api) section below for detailed documentation on how to implement these functions.

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

### Encrypted File Format Specification

The encrypted plugin file is a binary format with the following structure:

```
[signature_length:4 bytes][signature][metadata_length:4 bytes][metadata][encrypted_symmetric_key][encrypted_plugin_data]
```

#### File Layout

| Field | Size | Description |
|-------|------|-------------|
| `signature_length` | 4 bytes | Big-endian uint32: length of signature in bytes |
| `signature` | variable | ASN.1 DER-encoded ECDSA signature (R, S values) |
| `metadata_length` | 4 bytes | Big-endian uint32: length of metadata JSON in bytes |
| `metadata` | variable | JSON object containing encryption metadata |
| `encrypted_symmetric_key` | variable | Encrypted AES-256 symmetric key (see format below) |
| `encrypted_plugin_data` | variable | Encrypted plugin payload (see format below) |

#### Signature Format

- **Algorithm**: ECDSA with P-256 curve
- **Encoding**: ASN.1 DER format
- **Signed Data**: SHA-256 hash of `metadata || encrypted_symmetric_key || encrypted_plugin_data`
- **Purpose**: Ensures authenticity and integrity of the encrypted plugin

#### Metadata Format (JSON)

```json
{
  "symmetric_key_len": <integer>,
  "plugin_data_len": <integer>,
  "algorithm": "ECDSA-P256+AES-256-GCM"
}
```

- `symmetric_key_len`: Length in bytes of the `encrypted_symmetric_key` field
- `plugin_data_len`: Length in bytes of the `encrypted_plugin_data` field
- `algorithm`: Cryptographic algorithm identifier (currently `"ECDSA-P256+AES-256-GCM"`)

#### Encrypted Symmetric Key Format

The symmetric key is encrypted using ECDH key exchange and AES-256-GCM:

```
[ephemeral_public_key:65 bytes][nonce:12 bytes][ciphertext+tag:variable]
```

| Field | Size | Description |
|-------|------|-------------|
| `ephemeral_public_key` | 65 bytes | Uncompressed ECDSA public key: `0x04 || X (32 bytes) || Y (32 bytes)` |
| `nonce` | 12 bytes | Random nonce for AES-GCM encryption |
| `ciphertext+tag` | variable | AES-256-GCM encrypted symmetric key (32 bytes) + authentication tag (16 bytes) |

**Encryption Process:**
1. Generate ephemeral ECDSA key pair (same curve as harness public key)
2. Compute shared secret via ECDH: `shared_secret = ECDH(ephemeral_private, harness_public)`
3. Derive AES-256 key: `aes_key = SHA256(shared_secret)`
4. Encrypt symmetric key with AES-256-GCM using the derived key
5. Prepend ephemeral public key and nonce to the ciphertext

#### Encrypted Plugin Data Format

The plugin payload is encrypted using AES-256-GCM:

```
[nonce:12 bytes][ciphertext+tag:variable]
```

| Field | Size | Description |
|-------|------|-------------|
| `nonce` | 12 bytes | Random nonce for AES-GCM encryption |
| `ciphertext+tag` | variable | AES-256-GCM encrypted payload JSON + authentication tag (16 bytes) |

**Payload Format (JSON, after decryption):**

```json
{
  "type": <uint8>,
  "name": "<string>",
  "data": "<base64-encoded-bytes>"
}
```

- `type`: Plugin type (0 = WASM)
- `name`: Plugin name identifier
- `data`: Base64-encoded plugin binary data (e.g., WASM module). Go's `encoding/json` automatically base64-encodes `[]byte` fields when marshaling.

**Encryption Process:**
1. Create JSON payload from plugin type, name, and binary data
2. Encrypt payload JSON with AES-256-GCM using the symmetric key
3. Prepend nonce to the ciphertext

#### Security Properties

- **Confidentiality**: Plugin data encrypted with AES-256-GCM
- **Authenticity**: ECDSA signature verifies plugin origin
- **Integrity**: GCM authentication tags detect tampering
- **Forward Secrecy**: Ephemeral keys used for symmetric key encryption
- **Key Exchange**: ECDH provides secure key derivation without key material in metadata

### Plugin API

Harness uses the **Extism SDK** for WASM plugin execution. Plugins must be written using the **Extism Plugin Development Kit (PDK)** and export the following functions:

#### Required Exported Functions

1. **`name()`** - Returns the plugin name
   - Input: None
   - Output: String containing the plugin name

2. **`description()`** - Returns a description of what the plugin does
   - Input: None
   - Output: String containing the plugin description

3. **`json_schema()`** - Returns the JSON schema for plugin arguments
   - Input: None
   - Output: String containing a JSON schema that describes the expected input arguments

4. **`execute()`** - Executes the plugin with the provided arguments
   - Input: JSON object (as bytes) containing the plugin arguments
   - Output: JSON object (as bytes) containing the plugin result

#### Plugin Development

Plugins are developed using the Extism PDK, which provides:
- **Input/Output handling**: Use `extism_pdk::input()` to read JSON arguments and `extism_pdk::output()` or return values to write results
- **HTTP requests**: Access to HTTP client functionality for making external API calls
- **WASI support**: Full WASI capabilities for file I/O, networking, etc.

#### Example Plugin (Rust)

```rust
use extism_pdk::*;
use serde_json::Value;

#[plugin_fn]
pub fn name() -> FnResult<String> {
    Ok("my-plugin".to_string())
}

#[plugin_fn]
pub fn description() -> FnResult<String> {
    Ok("A plugin that does something useful".to_string())
}

#[plugin_fn]
pub fn json_schema() -> FnResult<String> {
    Ok(r#"{"type":"object","properties":{"message":{"type":"string"}}}"#.to_string())
}

#[plugin_fn]
pub fn execute() -> FnResult<Json<Value>> {
    // Read input JSON args
    let input: Json<Value> = input()?;
    
    // Process the input...
    
    // Return JSON result
    Ok(Json(serde_json::json!({"result": "success"})))
}
```

#### Plugin Types

**Note**: Harness currently only supports WASM plugins. Go plugins are not supported. All plugins must be compiled to WebAssembly using the `wasm32-wasip1` target.

#### Plugin Interface (Go)

The internal Go interface that WASM plugins implement:

```go
type Plugin interface {
    Name() string
    Description() string
    JSONSchema() string
    Execute(ctx context.Context, args json.RawMessage) (interface{}, error)
}
```

This interface is implemented by the WASM loader, which translates between the Go interface and the Extism SDK calls to the WASM module.

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

- **WASM Plugins**: Supported on all platforms via the Extism SDK (which uses wazero internally)
- **Keystore**: Platform-specific implementations for secure key storage
- **Plugin Types**: Only WASM plugins are supported. Go plugins are not supported.

## Security Considerations

- **Private keys are stored in OS keystore** - never written to disk
- President's public key should be distributed securely
- Encrypted plugins can be distributed over insecure channels
- Signature verification ensures plugin authenticity
- Encryption ensures plugin confidentiality
- File-based private keys (`-key` flag) are deprecated and only supported for migration purposes
