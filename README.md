# Harness - Dual-Authorization Exploit Execution System

A cryptographically secure system for storing, transporting, approving, and executing sensitive payloads including zero-day exploits and high-risk penetration testing tools. Harness enforces **dual-authorization** through cryptographic encryption and signatures, ensuring exploits cannot be executed without explicit approval from both the principal (firm leadership) and the client (President).

## Purpose

For offensive security teams and penetration testers who need to:
- Store and transport sensitive exploits (zero-days, PoCs, custom payloads)
- Enforce authorization boundaries preventing unauthorized execution
- Maintain chain-of-custody with cryptographic proof of approval
- Protect exploit confidentiality during transit and storage
- Meet compliance requirements (CREST, ISO 27001, SOC2, PCI)

### Dual-Authorization Model

**Nobody can run an exploit unilaterally:**

1. **Principal** encrypts exploit with pentester's public key (has exploit, cannot authorize)
2. **Client** signs execution arguments + expiration (has authorization, cannot decrypt)
3. **Pentester** verifies signature, decrypts, executes (needs both authorizations + valid expiration)

**Result**: Execution requires principal encryption (control of payload) AND client signature (control of authorization).

## Threat Model

### Threats Addressed

1. **Unauthorized Execution**: Client signature on arguments + expiration required; execution cryptographically impossible without it
2. **Exploit Confidentiality**: AES-256-GCM encryption with ECDH key exchange
3. **Chain-of-Custody**: Non-repudiable cryptographic proof of approval
4. **Stale Approvals**: Signed expiration timestamps prevent execution of old approvals
5. **Compliance Violations**: Enforces authorization boundaries and maintains audit trails

### Replay Attacks & Time-Limited Authorization

**Replays are intentionally allowed** within expiration window (default: 72h). Penetration testing requires multiple verification runs; time-limited expiration provides control mechanism.

**Cryptographic Evidence**: System provides proof of:
- Which exploit was received (encrypted with pentester's public key)
- Which target was authorized (client-signed arguments)
- When authorization expires (signed expiration timestamp)

**Custom Decryptor Risk**: Mitigate by running exploits on locked-down, monitored hosts where custom decryptors cannot be deployed. Cryptographic evidence still shows exploit access even if execution is bypassed.

### Why WASM Sandboxing?

- Deterministic, reproducible execution across platforms
- Provides isolation boundaries to reduce host system impact
- Limited filesystem exposure (subject to host function grants)
- Controlled syscalls (only explicitly granted host functions)
- Memory safety helps prevent buffer overflows and memory corruption

**Note**: WASM sandboxing provides security boundaries but is not a perfect isolation mechanism. Vulnerabilities in the WASM runtime, host function implementations, or the underlying system can still pose risks. Always run exploits on isolated, monitored systems.

## Workflow

```
Principal → Encrypts exploit with pentester's public key + creates args
    ↓
Client → Signs args + expiration (cannot decrypt)
    ↓
Pentester → Verifies signature, decrypts, executes in WASM sandbox
```

### Steps

1. **Principal**: Encrypts WASM payload with pentester's public key (ECDH + AES-256-GCM), creates execution arguments. Does NOT sign.
2. **Client**: Signs expiration + execution arguments with private key (ECDSA). Cannot decrypt exploit.
3. **Pentester**: Verifies expiration, verifies client signature, decrypts with private key, loads WASM directly into sandbox, executes with signed args.

## Authorization Model

### Principal Encryption (Exploit Payload)
- **Algorithm**: ECDH key exchange + AES-256-GCM
- **Purpose**: Authorizes pentester to decrypt (by encrypting with their public key)
- **Storage**: Encrypted exploits stored in stockpile (reusable, unsigned)
- **If missing**: Execution fails cryptographically

### Client Signature (Execution Arguments + Expiration)
- **Algorithm**: ECDSA with P-256 curve
- **Signed Data**: SHA-256 hash of `expiration (8 bytes) || execution_arguments_json`
- **Purpose**: Proves client approval of targeting parameters and expiration
- **Storage**: Private key in OS keystore (Keychain/Credential Manager/libsecret)
- **If missing**: Execution fails immediately

### Execution Requirements

Execution is **cryptographically impossible** without all:
1. ✓ Exploit encrypted with pentester's public key
2. ✓ Valid client signature on expiration + execution arguments
3. ✓ Expiration has not passed

### Keystore Interface

Go interface ([`crypto/keystore/Keystore`](crypto/keystore/interface.go)) provides cryptographic operations without exposing private keys, allowing hardware-backed or cloud-based key storage:

```go
type Keystore interface {
	GetPublicKey(keyID string) (*ecdsa.PublicKey, error)
	Sign(keyID string, hash []byte) ([]byte, error)
	DecryptSymmetricKey(keyID string, encryptedKey []byte) ([]byte, error)
	SetPrivateKey(keyID string, privateKey *ecdsa.PrivateKey) error
	ListKeys() ([]string, error)
}
```

**Platform Implementations:**
- **macOS**: Keychain Access (extensible to Secure Enclave)
- **Linux**: libsecret/keyring (extensible to TPM/cloud KMS)
- **Windows**: Credential Manager (extensible to TPM/Windows Key Storage Provider)

### Adding New Keystore Implementations

Harness uses a **registry pattern** for keystore implementations, allowing you to add support for new platforms or keystore backends without modifying core code.

**Steps to add a new keystore:**

1. **Implement the `Keystore` interface** in a new file (e.g., `crypto/keystore/cloudkms.go`):

```go
package keystore

import "crypto/ecdsa"

// CloudKMSKeystore implements Keystore for cloud KMS
type CloudKMSKeystore struct {
    // ... your implementation fields
}

// NewCloudKMSKeystore creates a new cloud KMS keystore
func NewCloudKMSKeystore() (Keystore, error) {
    // ... initialization logic
    return &CloudKMSKeystore{}, nil
}

// Implement all Keystore interface methods...
func (k *CloudKMSKeystore) GetPublicKey(keyID string) (*ecdsa.PublicKey, error) { ... }
func (k *CloudKMSKeystore) Sign(keyID string, hash []byte) ([]byte, error) { ... }
// ... etc
```

2. **Register the implementation** in an `init()` function:

```go
func init() {
    RegisterKeystore("cloudkms", NewCloudKMSKeystore)
    // Or register for a specific platform:
    RegisterKeystore("linux", NewCloudKMSKeystore) // Override default Linux keystore
}
```

3. **Use the registry** - The factory automatically uses registered implementations:

```go
// In factory.go, NewKeystore() automatically looks up the registered factory
// for runtime.GOOS, or you can manually get a factory:
factory, err := GetKeystoreFactory("cloudkms")
if err != nil {
    return nil, err
}
keystore, err := factory()
```

**Registry API:**
- `RegisterKeystore(platform string, factory KeystoreFactory)` - Register a keystore factory
- `GetKeystoreFactory(platform string) (KeystoreFactory, error)` - Get a factory by platform
- `ListRegisteredPlatforms() []string` - List all registered platforms

The registry is thread-safe and implementations register themselves automatically when imported.

## Features

- **Cryptographic Security**: ECDSA signatures, AES-256-GCM encryption
- **Cross-Platform**: macOS, Linux, Windows
- **WASM Sandboxing**: Execution isolation via Extism SDK (provides security boundaries, not perfect isolation)
- **OS Keystore Integration**: Private keys never written to disk
- **Memory-Based Loading**: Exploits loaded directly from memory
- **Dual-Authorization**: Requires principal encryption + client signature

## Building

```bash
go build -o bin/genkeys ./cmd/genkeys
go build -o bin/encrypt ./cmd/encrypt
go build -o bin/sign ./cmd/sign
go build -o bin/harness ./cmd/harness
go build -o bin/verify ./cmd/verify
go build -o bin/listkeys ./cmd/listkeys
```

## Quick Start

### 1. Generate Keys

**Private keys stored in OS keystore, never written to disk:**

```bash
# Generate client keys (signs execution arguments)
./bin/genkeys -keystore-key "client-key" -public client_public.pem

# Generate pentester keys (decrypts and executes)
./bin/genkeys -keystore-key "pentester-key" -public pentester_public.pem

# List all keys
./bin/listkeys
```

**Import existing PEM keys:**
```bash
./bin/genkeys -import client_private.pem -keystore-key "client-key" -public client_public.pem
./bin/genkeys -import pentester_private.pem -keystore-key "pentester-key" -public pentester_public.pem
# After importing, safely delete PEM files
```

### 2. Create WASM Exploit Payload

Create WASM module using Extism PDK. Must export:
- `name()` - exploit name (string)
- `description()` - exploit description (string)
- `json_schema()` - JSON schema for arguments (string)
- `execute()` - executes with JSON args, returns JSON result

See [Plugin API](#plugin-api) section for details.

### 3. Encrypt Exploit

```bash
./bin/encrypt \
  -plugin exploit.wasm \
  -type wasm \
  -name "cve-2024-xxxx-exploit" \
  -harness-key pentester_public.pem \
  -output exploit.encrypted
```

### 4. Client Signs Execution Arguments

```bash
./bin/sign \
  -file exploit.encrypted \
  -client-keystore-key "client-key" \
  -args '{"target":"192.168.1.100","port":443}' \
  -expiration 72h \
  -output exploit.approved
```

**Expiration**: Default `72h` (3 days). Signed with arguments, cannot be tampered. Examples: `24h`, `168h` (1 week), `30m`.

### 5. Execute Exploit

```bash
./bin/harness \
  -file exploit.approved \
  -keystore-key "pentester-key" \
  -signature-key client_public.pem
```

**Execution requires all three:**
- ✓ Exploit encrypted with pentester's public key
- ✓ Valid client signature on encrypted payload hash + expiration + execution arguments
- ✓ Expiration has not passed

Arguments are automatically extracted from approved package (signed by client). Cannot override or change arguments.

## Execution Logging

All commands log cryptographic operations to stderr for audit trails and security analysis. Logs are prefixed with command-specific tags and include SHA256 hashes of critical data.

### Encryption Logs (`cmd/encrypt`)

```
[ENCRYPTION LOG] <timestamp>
[ENCRYPTION LOG] Plaintext Exploit Hash (SHA256): <hash>
[ENCRYPTION LOG] Pentester Public Key Hash (SHA256): <hash>
```

- **Plaintext Exploit Hash**: SHA256 of the original exploit binary before encryption
- **Pentester Public Key Hash**: SHA256 of the pentester's public key used for encryption

### Signing Logs (`cmd/sign`)

```
[SIGNING LOG] <timestamp>
[SIGNING LOG] Encrypted Payload Hash (SHA256): <hash>
[SIGNING LOG] Client Public Key Hash (SHA256): <hash>
```

- **Encrypted Payload Hash**: SHA256 of the encrypted payload being signed
- **Client Public Key Hash**: SHA256 of the client's public key used for signing

### Verification Logs (`cmd/verify`)

```
[VERIFICATION LOG] <timestamp>
[VERIFICATION LOG] Encrypted Payload Hash (SHA256): <hash>
[VERIFICATION LOG] Client Signature Hash (SHA256): <hash>
[VERIFICATION LOG] Client Public Key Hash (SHA256): <hash>
[VERIFICATION LOG] Pentester Public Key Hash (SHA256): <hash>
```

- **Encrypted Payload Hash**: SHA256 of the encrypted payload that was verified
- **Client Signature Hash**: SHA256 of the ASN.1 DER-encoded client signature
- **Client Public Key Hash**: SHA256 of the client's public key used for verification
- **Pentester Public Key Hash**: SHA256 of the pentester's public key used for decryption

### Execution Logs (`cmd/harness`)

```
[EXECUTION LOG] <timestamp>
[EXECUTION LOG] Plugin Type: <type>
[EXECUTION LOG] Plugin Name: <name>
[EXECUTION LOG] Exploit Binary Hash (SHA256): <hash>
[EXECUTION LOG] Execution Arguments: <args>
[EXECUTION LOG] Client Signature Hash (SHA256): <hash>
[EXECUTION LOG] Client Public Key Hash (SHA256): <hash>
[EXECUTION LOG] Pentester Public Key Hash (SHA256): <hash>
```

- **Exploit Binary Hash**: SHA256 of the decrypted exploit binary that was executed
- **Execution Arguments**: The JSON arguments that were executed with
- **Client Signature Hash**: SHA256 of the verified client signature
- **Client Public Key Hash**: SHA256 of the client's public key used for verification
- **Pentester Public Key Hash**: SHA256 of the pentester's public key used for decryption

**Note**: All logs are written to stderr, so they won't interfere with JSON output on stdout. This provides a complete audit trail of cryptographic operations, key usage, and execution details for compliance and security analysis.

## OS Keystore Integration

**All private keys stored in OS keystore, never written to disk.**

### Key Management

```bash
# Generate new key pair
./bin/genkeys -keystore-key "client-key" -public client_public.pem

# Import existing PEM key
./bin/genkeys -import existing_private.pem -keystore-key "client-key" -public client_public.pem

# List keys
./bin/listkeys
```

### Platform Support

- **macOS**: Keychain Access (service: `harness`)
  - Default: Login keychain (unlocked when logged in, fewer prompts)
  - Custom: `export HARNESS_KEYCHAIN="harness-keys"`
  - Reduce prompts: Trust app in Keychain Access → "Always allow access"
- **Linux**: libsecret/keyring (service: `harness`)
- **Windows**: Credential Manager (service: `harness`)

## Architecture

### Cryptographic Flow

1. **Encrypting Exploit** (Principal):
   - Generate AES-256 symmetric key
   - Encrypt payload with symmetric key (AES-256-GCM)
   - Encrypt symmetric key with pentester's public key (ECDH)
   - Write encrypted file (no signature)

2. **Signing Arguments** (Client):
   - Set expiration (default: 3 days)
   - Hash encrypted payload
   - Sign encrypted payload hash + expiration + execution arguments (ECDSA)
   - Append version, signature, expiration, arguments to encrypted file

3. **Verification & Execution** (Pentester):
   - Read version field (must be 1)
   - Verify expiration not passed
   - Hash encrypted payload
   - Verify client signature on encrypted payload hash + expiration + arguments
   - Decrypt symmetric key with private key (ECDH)
   - Decrypt exploit data with symmetric key (AES-256-GCM)
   - Log execution details (args, exploit hash)
   - Load WASM directly into sandbox
   - Execute with signed arguments

### Encrypted File Format Specification

The encrypted exploit file format (after client signing) is:

```
[version:1 byte][metadata_length:4 bytes][metadata][encrypted_symmetric_key][encrypted_plugin_data][client_sig_len:4 bytes][client_sig][expiration:8 bytes][args_len:4 bytes][args_json]
```

#### File Layout

| Field | Size | Description |
|-------|------|-------------|
| `version` | 1 byte | Format version (must be 1). Includes encrypted payload hash in signature. |
| `metadata_length` | 4 bytes | Big-endian uint32: length of metadata JSON in bytes |
| `metadata` | variable | JSON object containing encryption metadata |
| `encrypted_symmetric_key` | variable | Encrypted AES-256 symmetric key (see format below) |
| `encrypted_plugin_data` | variable | Encrypted exploit payload (see format below) |
| `client_sig_len` | 4 bytes | Big-endian uint32: length of client signature in bytes |
| `client_sig` | variable | ASN.1 DER-encoded ECDSA signature (R, S values) |
| `expiration` | 8 bytes | Big-endian uint64: Unix timestamp (seconds) when payload expires |
| `args_len` | 4 bytes | Big-endian uint32: length of arguments JSON in bytes |
| `args_json` | variable | JSON object containing execution arguments |

#### Client Signature Format

- **Algorithm**: ECDSA with P-256 curve
- **Encoding**: ASN.1 DER format
- **Signed Data**: SHA-256 hash of `SHA256(encrypted_payload) (32 bytes) || expiration (8 bytes) || args_json`
- **Purpose**: Ensures authenticity and integrity of the encrypted payload, execution arguments, and expiration
- **Authorization**: Proves client has reviewed and approved the specific exploit payload, targeting parameters, and expiration time

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
1. Generate ephemeral ECDSA key pair (same curve as pentester public key)
2. Compute shared secret via ECDH: `shared_secret = ECDH(ephemeral_private, pentester_public)`
3. Derive AES-256 key: `aes_key = SHA256(shared_secret)`
4. Encrypt symmetric key with AES-256-GCM using the derived key
5. Prepend ephemeral public key and nonce to the ciphertext

**Note**: The symmetric key is encrypted with the pentester's public key, allowing the pentester to decrypt and execute. The client separately signs the execution arguments + expiration to approve targeting.

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

- `type`: Exploit type identifier (string, e.g., "wasm", "python")
- `name`: Exploit name identifier
- `data`: Base64-encoded exploit binary data (e.g., WASM module). Go's `encoding/json` automatically base64-encodes `[]byte` fields when marshaling.

**Encryption Process:**
1. Create JSON payload from exploit type, name, and binary data
2. Encrypt payload JSON with AES-256-GCM using the symmetric key
3. Prepend nonce to the ciphertext

#### Security Properties

- **Confidentiality**: AES-256-GCM encryption
- **Authenticity**: ECDSA signature verifies arguments + expiration approval
- **Integrity**: GCM authentication tags detect tampering
- **Forward Secrecy**: Ephemeral keys for symmetric key encryption
- **Key Exchange**: ECDH secure key derivation
- **Dual Authorization**: Requires principal encryption + client signature

## Plugin API

Harness uses **Extism SDK** for WASM execution. Exploits must use **Extism PDK** and export:

### Required Exported Functions

1. **`name()`** → exploit name (string)
2. **`description()`** → exploit description (string)
3. **`json_schema()`** → JSON schema for arguments (string)
4. **`execute()`** → executes with JSON args, returns JSON result

### Exploit Development

Extism PDK provides:
- Input/Output handling (`extism_pdk::input()`, `extism_pdk::output()`)
- HTTP client functionality
- WASI support (file I/O, networking, subject to host function grants)

### Example Exploit (Rust)

```rust
use extism_pdk::*;x
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
    let input: Json<Value> = input()?;
    let target = input.0["target"].as_str().unwrap();
    let port = input.0["port"].as_u64().unwrap();
    
    // Execute exploit logic...
    
    Ok(Json(serde_json::json!({
        "status": "success",
        "target": target,
        "port": port
    })))
}
```

### Plugin Interface (Go)

Harness is engine-agnostic and supports multiple plugin formats through a unified interface. The WASM loader ([`plugin/wasm/loader.go`](plugin/wasm/loader.go)) is one such implementation that translates between the Go interface and Extism SDK calls to WASM modules compiled to `wasm32-wasip1` target.

```go
type Plugin interface {
    Name() string
    Description() string
    JSONSchema() string
    Execute(ctx context.Context, args json.RawMessage) (interface{}, error)
}
```

**Extensibility**: You can add support for other plugin formats (e.g., Go plugins, Python scripts, native binaries) by creating an implementation of this interface. 

### Adding New Plugin Loader Implementations

Harness uses a **registry pattern** for plugin loaders, allowing you to add support for new plugin formats without modifying any core code or constants. Each loader registers itself with a string identifier, just like keystore implementations.

**Steps to add a new plugin loader:**

1. **Create a new file** in the `plugin` package (e.g., `plugin/python.go`):

```go
package plugin

import (
    "context"
    "encoding/json"
    // ... your imports
)

func init() {
    // Register with a string identifier - no constants needed!
    RegisterLoader("python", func() (Loader, error) {
        return NewPythonLoader()
    })
}

// PythonLoader loads Python script plugins
type PythonLoader struct {
    // ... your implementation fields
}

// NewPythonLoader creates a new Python loader
func NewPythonLoader() (*PythonLoader, error) {
    // ... initialization logic
    return &PythonLoader{}, nil
}

// Load implements the Loader interface
func (pl *PythonLoader) Load(data []byte, name string) (Plugin, error) {
    // ... load and return a Plugin implementation
    return &PythonPlugin{...}, nil
}
```

2. **Implement the `Plugin` interface** for your plugin type:

```go
// PythonPlugin implements Plugin
type PythonPlugin struct {
    name string
    // ... other fields
}

func (p *PythonPlugin) Name() string { ... }
func (p *PythonPlugin) Description() string { ... }
func (p *PythonPlugin) JSONSchema() string { ... }
func (p *PythonPlugin) Execute(ctx context.Context, args json.RawMessage) (interface{}, error) { ... }
```

3. **Use the new plugin type** - The loader automatically uses registered implementations:

```go
// Payload Type is now a string identifier
payload := &crypto.Payload{
    Type: "python",  // Use the same string identifier you registered with
    Name: "my-script",
    Data: scriptBytes,
}
plugin, err := plugin.LoadPlugin(payload)
```

**Registry API:**
- `RegisterLoader(typeIdentifier string, factory LoaderFactory)` - Register a loader factory with a string identifier
- `GetLoaderFactory(typeIdentifier string) (LoaderFactory, error)` - Get a factory by type identifier
- `ListRegisteredPluginTypes() []string` - List all registered plugin type identifiers



## Example: Using a WASM Exploit

```bash
# Principal encrypts exploit
./bin/encrypt \
  -plugin exploit.wasm \
  -type wasm \
  -name "cve-2024-xxxx-exploit" \
  -harness-key pentester_public.pem \
  -output exploit.encrypted

# Client signs execution arguments
./bin/sign \
  -file exploit.encrypted \
  -client-keystore-key "client-key" \
  -args '{"target":"192.168.1.100","port":443}' \
  -expiration 72h \
  -output exploit.approved

# Pentester executes (requires both authorizations)
./bin/harness \
  -file exploit.approved \
  -keystore-key "pentester-key" \
  -signature-key client_public.pem
```

## Platform Notes

- **WASM Exploits**: Supported on all platforms via Extism SDK (wazero internally)
- **Keystore**: Platform-specific implementations for secure key storage
- **Exploit Types**: Only WASM exploits supported (no Go plugins)

## Legal & Compliance

Helps meet compliance requirements:
- **CREST**: Authorization boundaries and audit trails
- **ISO 27001**: Cryptographic controls for information security
- **SOC2**: Access controls and authorization enforcement
- **PCI DSS**: Penetration testing requirements

### Authorization Boundaries

- Explicit principal encryption (control of exploit availability)
- Explicit client approval (signature on arguments + expiration)
- Prevents unauthorized modification (signature verification)
- Maintains chain-of-custody (cryptographic proof)

### Liability Protections

- Non-repudiable proof both parties approved execution
- Cryptographic enforcement prevents unauthorized execution
- Verifiable audit trails (signatures and keystore access logs)
- Sandboxed execution (WASM isolation boundaries)

## Security Considerations

- Private keys stored in OS keystore (never written to disk)
- Public keys should be distributed securely
- Encrypted exploits can be distributed over insecure channels
- Client signature verification ensures arguments + expiration approval
- Encryption ensures exploit confidentiality
- WASM sandboxing provides isolation boundaries to reduce host system impact
