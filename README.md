# Harness - Dual-Authorization Exploit Execution System

A cryptographically secure system for storing, transporting, approving, and executing sensitive payloads including zero-day exploits and high-risk penetration testing tools. Harness enforces **dual-authorization** through cryptographic signatures and encryption, ensuring that exploits cannot be executed without explicit approval from both the principal (firm leadership) and the client.

## Purpose

Harness is designed for offensive security teams and penetration testers who need to:

- **Store and transport sensitive exploits** including zero-days, proof-of-concepts, and custom payloads
- **Enforce authorization boundaries** preventing unauthorized execution
- **Maintain chain-of-custody** with cryptographic proof of approval
- **Protect exploit confidentiality** during transit and storage
- **Meet compliance requirements** for CREST, ISO 27001, SOC2, and PCI penetration testing standards

### Dual-Authorization Model

Harness implements a two-party authorization system:

1. **Principal Authorization**: Firm leadership (principal) cryptographically signs and encrypts the exploit payload using their private key. This signature proves the exploit has been reviewed and approved by authorized personnel.

2. **Client Authorization**: The client must possess the harness private key (stored in OS keystore) to decrypt and execute the exploit. Without this key, execution is cryptographically impossible. Possession of the harness key represents explicit client approval.

3. **Execution**: The harness verifies both authorizations before execution:
   - Verifies the principal's signature (proves principal approval)
   - Requires the client's private key to decrypt (proves client approval)
   - Only executes if both conditions are met

**Result**: A pentester cannot execute an exploit unless both the principal has signed it AND the client has provided their decryption key (representing approval).

## Threat Model & Rationale

### Threats Addressed

1. **Rogue Pentester Modification**: Prevents pentesters from modifying payloads after signing. The principal's signature covers the entire encrypted payload, making tampering detectable.

2. **Unauthorized Execution**: Ensures exploits cannot be executed without client authorization. The client's private key (harness key) is required for decryption, and without it, execution is impossible.

3. **Exploit Confidentiality**: Protects exploit code from exposure during transit or storage. Payloads are encrypted with AES-256-GCM, and the symmetric key is encrypted using ECDH with the client's public key.

4. **Chain-of-Custody**: Provides cryptographic proof of who approved what and when. Signatures are non-repudiable and verifiable.

5. **Compliance Violations**: Helps meet regulatory requirements by enforcing authorization boundaries and maintaining audit trails.

### Why WASM Sandboxing?

Exploit payloads are executed within WebAssembly (WASM) sandboxes for:

- **Deterministic Execution**: WASM provides predictable, reproducible execution environments across platforms
- **Sandboxing**: Isolated execution prevents exploits from affecting the host system
- **No Filesystem Exposure**: WASM modules cannot directly access the host filesystem without explicit host function grants
- **Controlled Syscalls**: Only explicitly granted host functions are available, preventing unauthorized system access
- **Cross-Platform Reproducibility**: Same exploit behavior across macOS, Linux, and Windows
- **Memory Safety**: WASM's memory model prevents buffer overflows and memory corruption attacks on the host

## High-Level Workflow

```
┌─────────────┐
│  Principal  │
│ (Firm Lead)  │
└──────┬──────┘
       │
       │ 1. Signs exploit with principal private key
       │ 2. Encrypts exploit with AES-256-GCM
       │ 3. Encrypts symmetric key with client's public key (ECDH)
       │
       ▼
┌─────────────────────────┐
│  Encrypted Exploit File  │
│  (signed + encrypted)    │
└──────┬──────────────────┘
       │
       │ Distributed to client
       │
       ▼
┌─────────────┐
│   Client    │
└──────┬──────┘
       │
       │ 4. Provides harness private key (client approval)
       │
       ▼
┌─────────────┐
│   Harness   │
└──────┬──────┘
       │
       │ 5. Verifies principal signature ✓
       │ 6. Decrypts with client private key ✓
       │ 7. Loads WASM payload
       │ 8. Executes in sandbox
       │
       ▼
┌─────────────┐
│  Execution  │
│   Result    │
└─────────────┘
```

### Workflow Steps

1. **Principal → Signs + Encrypts Exploit**
   - Principal reviews and approves the exploit
   - Signs the encrypted payload with principal's private key (ECDSA)
   - Encrypts exploit with AES-256-GCM
   - Encrypts symmetric key with client's public key (ECDH)

2. **Client → Approves + Signs**
   - Client reviews the exploit and approves execution
   - Client provides harness private key (stored in OS keystore)
   - This key represents cryptographic approval

3. **Harness → Verifies Both → Decrypts → Executes**
   - Verifies principal's signature (proves principal approval)
   - Decrypts symmetric key using client's private key (proves client approval)
   - Decrypts exploit payload
   - Loads WASM module into sandbox
   - Executes with provided arguments

## Dual Signatures Explained

### Principal Signature

- **Purpose**: Proves the exploit has been reviewed and approved by firm leadership
- **Algorithm**: ECDSA with P-256 curve
- **What it signs**: SHA-256 hash of `metadata || encrypted_symmetric_key || encrypted_plugin_data`
- **Verification**: Harness verifies this signature before decryption
- **If missing**: Execution fails immediately with "signature verification failed"

### Client Authorization (Harness Key)

- **Purpose**: Proves the client has approved execution of the exploit
- **Mechanism**: The symmetric key is encrypted with the client's public key (ECDH)
- **Requirement**: Client must provide harness private key to decrypt
- **Storage**: Private key stored in OS keystore (Keychain/Credential Manager/libsecret)
- **If missing**: Decryption is cryptographically impossible, execution cannot proceed

### Execution Requirements

Execution is **cryptographically impossible** without both:

1. ✓ Valid principal signature (verified with principal's public key)
2. ✓ Client's harness private key (required for decryption)

Both conditions must be met. Missing either authorization results in immediate failure.

## Features

- **Cryptographic Security**: ECDSA signature verification and AES-256-GCM encryption
- **Cross-Platform**: Works on macOS, Linux, and Windows
- **WASM Sandboxing**: Exploit payloads executed in isolated WebAssembly sandboxes via Extism SDK
- **OS Keystore Integration**: Private keys stored securely using platform-native keystores
- **Memory-Based Loading**: Exploits loaded directly from memory, never written to disk unencrypted
- **Dual-Authorization**: Requires both principal signature and client key for execution

## Building

```bash
# Build all utilities
go build -o bin/genkeys ./cmd/genkeys
go build -o bin/sign ./cmd/sign
go build -o bin/harness ./cmd/harness
go build -o bin/verify ./cmd/verify
go build -o bin/listkeys ./cmd/listkeys
```

## Quick Start

### 1. Generate Keys

Generate keys for the principal (who signs exploits) and the client (who approves execution). **Private keys are stored in the OS keystore and never written to disk.**

```bash
# Generate principal's keys (for signing exploits)
# Private key stored in keystore, only public key written to disk
./bin/genkeys -keystore-key "principal-key" -public principal_public.pem

# Generate client's harness keys (for decryption/approval)
# Private key stored in keystore, only public key written to disk
./bin/genkeys -keystore-key "client-harness-key" -public client_harness_public.pem

# List all keys in keystore
./bin/listkeys
```

**Note**: If you have existing PEM private key files, you can import them into the keystore:

```bash
# Import existing private key into keystore
./bin/genkeys -import principal_private.pem -keystore-key "principal-key" -public principal_public.pem
./bin/genkeys -import client_harness_private.pem -keystore-key "client-harness-key" -public client_harness_public.pem

# After importing, you can safely delete the PEM files
```

### 2. Create a WASM Exploit Payload

Create a WASM module using the Extism Plugin Development Kit (PDK). The exploit must export the following functions:

- `name()` - returns the exploit name as a string
- `description()` - returns the exploit description as a string
- `json_schema()` - returns the JSON schema for arguments as a string
- `execute()` - executes the exploit with JSON arguments and returns JSON result

See the [Plugin API](#plugin-api) section below for detailed documentation on how to implement these functions.

### 3. Principal Signs and Encrypts Exploit

The principal signs and encrypts the exploit using their keystore key and the client's public key:

```bash
./bin/sign \
  -plugin exploit.wasm \
  -type wasm \
  -name "cve-2024-xxxx-exploit" \
  -president-keystore-key "principal-key" \
  -harness-key client_harness_public.pem \
  -output exploit.encrypted
```

### 4. Client Verifies Exploit (Optional)

The client can verify the encrypted exploit without executing it:

```bash
./bin/verify \
  -file exploit.encrypted \
  -keystore-key "client-harness-key" \
  -president-key principal_public.pem
```

### 5. Execute Exploit (Requires Both Authorizations)

The harness verifies both authorizations and executes the exploit:

```bash
./bin/harness \
  -file exploit.encrypted \
  -keystore-key "client-harness-key" \
  -president-key principal_public.pem \
  -args '{"target":"192.168.1.100","port":443}'
```

**Note**: Execution requires:
- ✓ Valid principal signature (verified with `principal_public.pem`)
- ✓ Client's harness private key (from keystore `client-harness-key`)

Without both, execution fails cryptographically.

## OS Keystore Integration

**All private keys are stored in the OS keystore and never written to disk.** This provides secure key storage using platform-native security features.

### Key Management

**Generate new keys** (recommended):

```bash
# Generate a new key pair, store private key in keystore, output only public key
./bin/genkeys \
  -keystore-key "client-harness-key" \
  -public client_harness_public.pem
```

**Import existing PEM keys** (migration):

```bash
# Import an existing private key file into the keystore
./bin/genkeys \
  -import existing_private.pem \
  -keystore-key "client-harness-key" \
  -public client_harness_public.pem

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
# Principal signs an exploit using keystore
./bin/sign \
  -plugin exploit.wasm \
  -president-keystore-key "principal-key" \
  -harness-key client_harness_public.pem \
  -output exploit.encrypted

# Client verifies an exploit using keystore
./bin/verify \
  -file exploit.encrypted \
  -keystore-key "client-harness-key" \
  -president-key principal_public.pem

# Execute an exploit using keystore (requires both authorizations)
./bin/harness \
  -file exploit.encrypted \
  -keystore-key "client-harness-key" \
  -president-key principal_public.pem \
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

1. **Signing** (Principal):
   - Generate symmetric key (AES-256)
   - Encrypt exploit payload with symmetric key (AES-256-GCM)
   - Encrypt symmetric key with client's public key (ECDH)
   - Sign metadata + encrypted data with principal's private key (ECDSA)

2. **Verification & Decryption** (Harness):
   - Verify principal's signature with principal's public key
   - Decrypt symmetric key with client's private key (ECDH)
   - Decrypt exploit payload with symmetric key (AES-256-GCM)
   - Load WASM module into sandbox
   - Execute with provided arguments

### Encrypted File Format Specification

The encrypted exploit file is a binary format with the following structure:

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
| `encrypted_plugin_data` | variable | Encrypted exploit payload (see format below) |

#### Signature Format

- **Algorithm**: ECDSA with P-256 curve
- **Encoding**: ASN.1 DER format
- **Signed Data**: SHA-256 hash of `metadata || encrypted_symmetric_key || encrypted_plugin_data`
- **Purpose**: Ensures authenticity and integrity of the encrypted exploit
- **Authorization**: Proves principal has reviewed and approved the exploit

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
1. Generate ephemeral ECDSA key pair (same curve as client public key)
2. Compute shared secret via ECDH: `shared_secret = ECDH(ephemeral_private, client_public)`
3. Derive AES-256 key: `aes_key = SHA256(shared_secret)`
4. Encrypt symmetric key with AES-256-GCM using the derived key
5. Prepend ephemeral public key and nonce to the ciphertext

**Authorization**: Only the client with the harness private key can decrypt this symmetric key, representing client approval.

#### Encrypted Exploit Data Format

The exploit payload is encrypted using AES-256-GCM:

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

- `type`: Exploit type (0 = WASM)
- `name`: Exploit name identifier
- `data`: Base64-encoded exploit binary data (e.g., WASM module). Go's `encoding/json` automatically base64-encodes `[]byte` fields when marshaling.

**Encryption Process:**
1. Create JSON payload from exploit type, name, and binary data
2. Encrypt payload JSON with AES-256-GCM using the symmetric key
3. Prepend nonce to the ciphertext

#### Security Properties

- **Confidentiality**: Exploit data encrypted with AES-256-GCM
- **Authenticity**: ECDSA signature verifies exploit origin and principal approval
- **Integrity**: GCM authentication tags detect tampering
- **Forward Secrecy**: Ephemeral keys used for symmetric key encryption
- **Key Exchange**: ECDH provides secure key derivation without key material in metadata
- **Dual Authorization**: Requires both principal signature and client key for execution

## Plugin API

Harness uses the **Extism SDK** for WASM exploit execution. Exploit payloads must be written using the **Extism Plugin Development Kit (PDK)** and export the following functions:

### Required Exported Functions

1. **`name()`** - Returns the exploit name
   - Input: None
   - Output: String containing the exploit name

2. **`description()`** - Returns a description of what the exploit does
   - Input: None
   - Output: String containing the exploit description

3. **`json_schema()`** - Returns the JSON schema for exploit arguments
   - Input: None
   - Output: String containing a JSON schema that describes the expected input arguments

4. **`execute()`** - Executes the exploit with the provided arguments
   - Input: JSON object (as bytes) containing the exploit arguments
   - Output: JSON object (as bytes) containing the exploit result

### Exploit Development

Exploits are developed using the Extism PDK, which provides:
- **Input/Output handling**: Use `extism_pdk::input()` to read JSON arguments and `extism_pdk::output()` or return values to write results
- **HTTP requests**: Access to HTTP client functionality for making external API calls
- **WASI support**: Full WASI capabilities for file I/O, networking, etc. (subject to host function grants)

### Example Exploit (Rust)

```rust
use extism_pdk::*;
use serde_json::Value;

#[plugin_fn]
pub fn name() -> FnResult<String> {
    Ok("cve-2024-xxxx-exploit".to_string())
}

#[plugin_fn]
pub fn description() -> FnResult<String> {
    Ok("Exploits CVE-2024-XXXX vulnerability".to_string())
}

#[plugin_fn]
pub fn json_schema() -> FnResult<String> {
    Ok(r#"{"type":"object","properties":{"target":{"type":"string"},"port":{"type":"integer"}}}"#.to_string())
}

#[plugin_fn]
pub fn execute() -> FnResult<Json<Value>> {
    // Read input JSON args
    let input: Json<Value> = input()?;
    
    // Extract target and port from args
    let target = input.0["target"].as_str().unwrap();
    let port = input.0["port"].as_u64().unwrap();
    
    // Execute exploit logic...
    
    // Return JSON result
    Ok(Json(serde_json::json!({
        "status": "success",
        "target": target,
        "port": port
    })))
}
```

### Exploit Types

**Note**: Harness currently only supports WASM exploits. Go plugins are not supported. All exploit payloads must be compiled to WebAssembly using the `wasm32-wasip1` target.

### Plugin Interface (Go)

The internal Go interface that WASM exploits implement:

```go
type Plugin interface {
    Name() string
    Description() string
    JSONSchema() string
    Execute(ctx context.Context, args json.RawMessage) (interface{}, error)
}
```

This interface is implemented by the WASM loader, which translates between the Go interface and the Extism SDK calls to the WASM module.

## Example: Using a WASM Exploit

```bash
# Principal signs a WASM exploit using keystore
./bin/sign \
  -plugin exploit.wasm \
  -type wasm \
  -name "cve-2024-xxxx-exploit" \
  -president-keystore-key "principal-key" \
  -harness-key client_harness_public.pem \
  -output exploit.encrypted

# Execute it using keystore (requires both authorizations)
./bin/harness \
  -file exploit.encrypted \
  -keystore-key "client-harness-key" \
  -president-key principal_public.pem \
  -args '{"target":"192.168.1.100","port":443}'
```

## Platform Notes

- **WASM Exploits**: Supported on all platforms via the Extism SDK (which uses wazero internally)
- **Keystore**: Platform-specific implementations for secure key storage
- **Exploit Types**: Only WASM exploits are supported. Go plugins are not supported.

## Legal & Compliance

Harness helps penetration testing teams meet compliance requirements for:

- **CREST**: Enforces authorization boundaries and maintains audit trails
- **ISO 27001**: Provides cryptographic controls for information security
- **SOC2**: Demonstrates access controls and authorization enforcement
- **PCI DSS**: Meets penetration testing requirements for secure execution

### Authorization Boundaries

Harness enforces authorization boundaries by:

- Requiring explicit principal approval (cryptographic signature)
- Requiring explicit client approval (possession of harness private key)
- Preventing unauthorized modification (signature verification)
- Maintaining chain-of-custody (cryptographic proof of approval)

### Liability Protections

The dual-authorization model provides liability protections by:

- Proving both parties approved execution (non-repudiable signatures)
- Preventing unauthorized execution (cryptographic enforcement)
- Maintaining audit trails (verifiable signatures and keystore access logs)
- Enforcing sandboxed execution (WASM isolation)

## Security Considerations

- **Private keys are stored in OS keystore** - never written to disk
- Principal's public key should be distributed securely
- Encrypted exploits can be distributed over insecure channels
- Signature verification ensures exploit authenticity and principal approval
- Encryption ensures exploit confidentiality
- Client authorization is enforced cryptographically (harness key required)
- WASM sandboxing prevents exploits from affecting the host system
- File-based private keys (`-key` flag) are deprecated and only supported for migration purposes

## License

[Your License Here]
