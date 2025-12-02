# Harness - Dual-Authorization Exploit Execution System

A cryptographically secure system for storing, transporting, approving, and executing sensitive payloads including zero-day exploits and high-risk penetration testing tools. Harness enforces **dual-authorization** through cryptographic encryption and signatures, ensuring exploits cannot be executed without explicit approval from both the exploit owner (who encrypts the exploit) and the target (who signs execution arguments).

**Documentation**: [pkg.go.dev/github.com/joncooperworks/harness](https://pkg.go.dev/github.com/joncooperworks/harness)

Harness can be used as a library, and the `cmd/...` packages are examples demonstrating how to integrate it into your own applications. You can deploy harness in various environments (AWS Lambda, containers, isolated VMs) to further limit access to payloads and enforce additional execution boundaries.

## Purpose

For offensive security teams and penetration testers who need to:
- Store and transport sensitive exploits (zero-days, PoCs, custom payloads)
- Enforce authorization boundaries preventing unauthorized execution
- Maintain chain-of-custody with cryptographic proof of approval
- Protect exploit confidentiality during transit and storage
- Meet compliance requirements (CREST, ISO 27001, SOC2, PCI)

### Dual-Authorization Model

**Nobody can run an exploit unilaterally:**

1. **Exploit Owner** encrypts exploit with harness (pentester) public key and signs encrypted payload (has exploit, cannot authorize execution)
2. **Target** signs execution arguments + expiration (has authorization, cannot decrypt exploit)
3. **Harness (Pentester)** verifies signatures, decrypts, executes (needs both authorizations + valid expiration)

**Result**: Execution requires exploit owner encryption + signature (control of payload) AND target signature (control of authorization).

## Threat Model

### Threats Addressed

1. **Unauthorized Execution**: Target signature on arguments + expiration required
2. **Exploit Confidentiality**: AES-256-GCM encryption with X25519 key exchange
3. **Chain-of-Custody**: Non-repudiable cryptographic proof of approval
4. **Stale Approvals**: Signed expiration timestamps prevent execution of old approvals
5. **Compliance Violations**: Enforces authorization boundaries and maintains audit trails

### Replay Attacks & Time-Limited Authorization

**Replays are intentionally allowed** within expiration window (default: 72h). Penetration testing requires multiple verification runs; time-limited expiration provides control mechanism.

**Cryptographic Evidence**: System provides proof of:
- Which exploit was received (encrypted with harness public key)
- Which target was authorized (target-signed arguments)
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
Exploit Owner → Encrypts exploit with harness public key + signs encrypted payload
    ↓
Target → Signs execution args + expiration (cannot decrypt exploit)
    ↓
Harness → Verifies both signatures, decrypts, executes in WASM sandbox
```

### Steps

1. **Exploit Owner**: Encrypts WASM payload with harness public key (X25519 + AES-256-GCM), signs encrypted payload hash with Ed25519.
2. **Target**: Signs expiration + execution arguments with private key (Ed25519). Cannot decrypt exploit.
3. **Harness (Pentester)**: Verifies expiration, verifies both exploit owner and target signatures, decrypts with private key, loads WASM directly into sandbox, executes with signed args.

## Authorization Model
>....                                                                                                     
  -target-keystore-key target-key \
  -file plugin.encrypted \
  -output plugin.approved \
  -harness-key harness_public.pem \
&& ./bin/verify \
  -file plugin.approved \
  -harness-keystore-key harness-key \
  -target-key target_public.pem \
  -exploit-key exploit_public.pem \
&& ./bin/harness \
  -file plugin.approved \
  -harness-keystore-key harness-key \
  -target-key target_public.pem \
  -exploit-key exploit_public.pem
{"time":"2025-12-02T20:36:46.141478Z","level":"INFO","msg":"encryption log","timestamp":"2025-12-02T20:36:46Z","exploit_owner_signature_hash_sha256":"30811a6e1d74797b9132f32adea5cf785b12fc7715c261ae927997a5e381d216","exploit_owner_public_key_hash_sha256":"0ecdbb984e42071abdd3e75e473c36208b0252ef57beb8e9d8cf24d19c50280e","harness_public_key_hash_sha256":"1fc9ce7352378f4ad16ea7c5141cbe98a8c6526894b6a9000bbae42b4b072051"}
Plugin encrypted successfully:
  Input: /Users/jonathan/Development/harness/examples/get-ip/target/wasm32-wasip1/release/get_ip_plugin.wasm
  Output: plugin.encrypted
  Type: wasm
  Name: ip-check-plugin

Next step: Sign the encrypted file with ./bin/sign
{"time":"2025-12-02T20:36:51.157895Z","level":"INFO","msg":"signing log","timestamp":"2025-12-02T20:36:51Z","encrypted_payload_hash_sha256":"9840f71059652f4881f110b948f2e7b1982495bbef02936fd99b37d16e894718","target_public_key_hash_sha256":"8af5420e2826e673e3b74067a3a8e3738dd768d766301adbd51676608d45dd4f"}
Arguments signed successfully:
  Input: plugin.encrypted
  Output: plugin.approved
  Expiration: 2025-12-05T20:36:46Z (Fri, 05 Dec 2025 20:36:46 GMT)
{"time":"2025-12-02T20:36:58.158333Z","level":"INFO","msg":"verification log","timestamp":"2025-12-02T20:36:58Z","encrypted_payload_hash_sha256":"06bb157736d06e451e9a43eb2612083c6ebfd2ac76c77039c8be15c9fbebbafd","exploit_owner_signature_hash_sha256":"30811a6e1d74797b9132f32adea5cf785b12fc7715c261ae927997a5e381d216","exploit_owner_public_key_hash_sha256":"0ecdbb984e42071abdd3e75e473c36208b0252ef57beb8e9d8cf24d19c50280e","target_signature_hash_sha256":"5a20602b64d4fe6375727f8d650d97633edc244da904931a3dc4bab552c9f79c","target_public_key_hash_sha256":"8af5420e2826e673e3b74067a3a8e3738dd768d766301adbd51676608d45dd4f","harness_public_key_hash_sha256":"1fc9ce7352378f4ad16ea7c5141cbe98a8c6526894b6a9000bbae42b4b072051"}
✓ Target signature on arguments verified successfully
✓ Plugin decrypted successfully

Plugin details:
  Type: wasm
  Name: ip-check-plugin
  Data size: 270167 bytes
  Note: WASM plugin ready to execute
{"time":"2025-12-02T20:37:04.020531Z","level":"INFO","msg":"execution log","timestamp":"2025-12-02T20:37:04Z","encrypted_payload_hash_sha256":"06bb157736d06e451e9a43eb2612083c6ebfd2ac76c77039c8be15c9fbebbafd","plugin_type":"wasm","plugin_name":"ip-check-plugin","exploit_binary_hash_sha256":"c30694d83806cebd605870c91aa1c13d745d96a1880a6d1928ebd69c8b302e04","exploit_owner_signature_hash_sha256":"30811a6e1d74797b9132f32adea5cf785b12fc7715c261ae927997a5e381d216","exploit_owner_public_key_hash_sha256":"0ecdbb984e42071abdd3e75e473c36208b0252ef57beb8e9d8cf24d19c50280e","target_signature_hash_sha256":"5a20602b64d4fe6375727f8d650d97633edc244da904931a3dc4bab552c9f79c","target_public_key_hash_sha256":"8af5420e2826e673e3b74067a3a8e3738dd768d766301adbd51676608d45dd4f","harness_public_key_hash_sha256":"1fc9ce7352378f4ad16ea7c5141cbe98a8c6526894b6a9000bbae42b4b072051"}
{
  "ip_info": {
    "asn": "AS15502",
    "asn_org": "Vodafone Ireland Limited",
    "city": "Dublin",
    "country": "Ireland",
    "country_eu": true,
    "country_iso": "IE",
    "ip": "109.77.60.252",
    "ip_decimal": 1833778428,
    "latitude": 53.3382,
    "longitude": -6.2591,
    "region_code": "L",
    "region_name": "Leinster",
    "time_zone": "Europe/Dublin",
    "user_agent": {
      "product": "Go-http-client",
      "raw_value": "Go-http-client/2.0",
      "version": "2.0"
    },
    "zip_code": "D02"
  },
  "received_args": {
    "hello": "world"
  }
}
### Exploit Owner Encryption + Signature (Exploit Payload)
- **Algorithm**: X25519 key exchange + AES-256-GCM for encryption, Ed25519 for signature
- **Purpose**: Encrypts exploit for harness (by encrypting with harness public key) and signs encrypted payload hash
- **Storage**: Encrypted exploits stored in stockpile (reusable, signed by exploit owner)
- **If missing**: Execution fails cryptographically

### Target Signature (Execution Arguments + Expiration)
- **Algorithm**: Ed25519
- **Signed Data**: SHA-256 hash of `encrypted_payload_hash (32 bytes) || expiration (8 bytes) || encrypted_arguments`
- **Purpose**: Proves target approval of targeting parameters and expiration
- **Storage**: Private key in OS keystore (Keychain/Credential Manager/libsecret)
- **If missing**: Execution fails immediately

### Execution Requirements

Execution is **cryptographically impossible** without all:
1. ✓ Exploit encrypted with harness public key
2. ✓ Valid exploit owner signature on encrypted payload hash (verified before decryption)
3. ✓ Valid target signature on encrypted payload hash + expiration + execution arguments
4. ✓ Expiration has not passed

### Keystore Interface

Go interface ([`crypto/keystore/Keystore`](crypto/keystore/interface.go)) provides cryptographic operations without exposing private keys, allowing hardware-backed or cloud-based key storage:

```go
type Keystore interface {
	GetPublicKey(keyID string) (ed25519.PublicKey, error)
	Sign(keyID string, hash []byte) ([]byte, error)
	DecryptWithContext(keyID string, encryptedKey []byte, context string) ([]byte, error)
	SetPrivateKey(keyID string, privateKey ed25519.PrivateKey) error
	ListKeys() ([]string, error)
}
```

**Sign**: Returns a raw Ed25519 signature (64 bytes, fixed size).

**DecryptWithContext**: Decrypts data encrypted via X25519 with a specific HKDF context string. The `context` parameter specifies the HKDF context used for key derivation:
- `"harness-symmetric-key-v1"` for decrypting symmetric keys
- `"harness-args-v1"` for decrypting execution arguments

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

import "crypto/ed25519"

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
func (k *CloudKMSKeystore) GetPublicKey(keyID string) (ed25519.PublicKey, error) { ... }
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

- **Cryptographic Security**: Ed25519 signatures, X25519 key exchange, AES-256-GCM encryption
- **Cross-Platform**: macOS, Linux, Windows
- **WASM Sandboxing**: Execution isolation via [Extism SDK](https://extism.org/) (provides security boundaries, not perfect isolation)
- **OS Keystore Integration**: Private keys never written to disk
- **Memory-Based Loading**: Exploits loaded directly from memory
- **Dual-Authorization**: Requires principal encryption + client signature
- **Pluggable keystores and plugin environments**: bring your own keystore or exploit framework

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
# Generate target keys (signs execution arguments)
./bin/genkeys -keystore-key "target-key" -public target_public.pem

# Generate harness (pentester) keys (decrypts and executes)
./bin/genkeys -keystore-key "harness-key" -public harness_public.pem

# Generate exploit owner keys (encrypts and signs exploit payload)
./bin/genkeys -keystore-key "exploit-key" -public exploit_public.pem

# List all keys
./bin/listkeys
```

**Import existing PEM keys:**
```bash
./bin/genkeys -import target_private.pem -keystore-key "target-key" -public target_public.pem
./bin/genkeys -import harness_private.pem -keystore-key "harness-key" -public harness_public.pem
./bin/genkeys -import exploit_private.pem -keystore-key "exploit-key" -public exploit_public.pem
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
  -harness-key harness_public.pem \
  -exploit-keystore-key "exploit-key" \
  -output exploit.encrypted
```

**Plugin Name**: The plugin name is automatically loaded from the plugin (via the `name()` function).

**Exploit Owner Signature**: The exploit owner signs the encrypted payload hash, providing cryptographic proof that the exploit owner has reviewed and approved the encrypted exploit payload.

### 4. Target Signs Execution Arguments

```bash
./bin/sign \
  -file exploit.encrypted \
  -target-keystore-key "target-key" \
  -harness-key harness_public.pem \
  -args '{"target":"192.168.1.100","port":443}' \
  -expiration 72h \
  -output exploit.approved
```

**Argument Encryption**: Arguments are encrypted with the harness public key (X25519 + AES-256-GCM) before signing, ensuring only the harness can read them. The target signs the encrypted arguments along with the encrypted payload hash and expiration.

**Expiration**: Default `72h` (3 days). Signed with encrypted arguments, cannot be tampered. Examples: `24h`, `168h` (1 week), `30m`.

### 5. Execute Exploit

```bash
./bin/harness \
  -file exploit.approved \
  -harness-keystore-key "harness-key" \
  -target-key target_public.pem \
  -exploit-key exploit_public.pem
```

**Execution requires all four:**
- ✓ Exploit encrypted with harness public key
- ✓ Valid exploit owner signature on encrypted payload hash (verified before decryption)
- ✓ Valid target signature on encrypted payload hash + expiration + execution arguments
- ✓ Expiration has not passed

Arguments are automatically extracted from approved package (signed by target). Cannot override or change arguments.

## Execution Logging

All commands log cryptographic operations to stderr in JSON format for audit trails and security analysis. Logs include ISO 8601 timestamps, log levels, and SHA256 hashes of critical data.

### Encryption Logs (`cmd/encrypt`)

```json
{
  "time": "2025-12-02T20:36:46.141478Z",
  "level": "INFO",
  "msg": "encryption log",
  "timestamp": "2025-12-02T20:36:46Z",
  "exploit_owner_signature_hash_sha256": "30811a6e1d74797b9132f32adea5cf785b12fc7715c261ae927997a5e381d216",
  "exploit_owner_public_key_hash_sha256": "0ecdbb984e42071abdd3e75e473c36208b0252ef57beb8e9d8cf24d19c50280e",
  "harness_public_key_hash_sha256": "1fc9ce7352378f4ad16ea7c5141cbe98a8c6526894b6a9000bbae42b4b072051"
}
```

- **time**: ISO 8601 timestamp with nanosecond precision
- **level**: Log level (INFO, ERROR)
- **msg**: Log message identifier ("encryption log")
- **timestamp**: ISO 8601 timestamp (seconds precision)
- **exploit_owner_signature_hash_sha256**: SHA256 of the Ed25519 signature (64 bytes) on the encrypted payload hash
- **exploit_owner_public_key_hash_sha256**: SHA256 of the exploit owner's public key used for signing
- **harness_public_key_hash_sha256**: SHA256 of the harness public key used for encryption

### Signing Logs (`cmd/sign`)

```json
{
  "time": "2025-12-02T20:36:51.157895Z",
  "level": "INFO",
  "msg": "signing log",
  "timestamp": "2025-12-02T20:36:51Z",
  "encrypted_payload_hash_sha256": "9840f71059652f4881f110b948f2e7b1982495bbef02936fd99b37d16e894718",
  "target_public_key_hash_sha256": "8af5420e2826e673e3b74067a3a8e3738dd768d766301adbd51676608d45dd4f"
}
```

- **time**: ISO 8601 timestamp with nanosecond precision
- **level**: Log level (INFO, ERROR)
- **msg**: Log message identifier ("signing log")
- **timestamp**: ISO 8601 timestamp (seconds precision)
- **encrypted_payload_hash_sha256**: SHA256 of the encrypted payload being signed
- **target_public_key_hash_sha256**: SHA256 of the target's public key used for signing

### Verification Logs (`cmd/verify`)

```json
{
  "time": "2025-12-02T20:36:58.158333Z",
  "level": "INFO",
  "msg": "verification log",
  "timestamp": "2025-12-02T20:36:58Z",
  "encrypted_payload_hash_sha256": "06bb157736d06e451e9a43eb2612083c6ebfd2ac76c77039c8be15c9fbebbafd",
  "exploit_owner_signature_hash_sha256": "30811a6e1d74797b9132f32adea5cf785b12fc7715c261ae927997a5e381d216",
  "exploit_owner_public_key_hash_sha256": "0ecdbb984e42071abdd3e75e473c36208b0252ef57beb8e9d8cf24d19c50280e",
  "target_signature_hash_sha256": "5a20602b64d4fe6375727f8d650d97633edc244da904931a3dc4bab552c9f79c",
  "target_public_key_hash_sha256": "8af5420e2826e673e3b74067a3a8e3738dd768d766301adbd51676608d45dd4f",
  "harness_public_key_hash_sha256": "1fc9ce7352378f4ad16ea7c5141cbe98a8c6526894b6a9000bbae42b4b072051"
}
```

- **time**: ISO 8601 timestamp with nanosecond precision
- **level**: Log level (INFO, ERROR)
- **msg**: Log message identifier ("verification log")
- **timestamp**: ISO 8601 timestamp (seconds precision)
- **encrypted_payload_hash_sha256**: SHA256 of the encrypted payload that was verified
- **exploit_owner_signature_hash_sha256**: SHA256 of the Ed25519 signature (64 bytes)
- **exploit_owner_public_key_hash_sha256**: SHA256 of the exploit owner's public key used for verification
- **target_signature_hash_sha256**: SHA256 of the Ed25519 signature (64 bytes)
- **target_public_key_hash_sha256**: SHA256 of the target's public key used for verification
- **harness_public_key_hash_sha256**: SHA256 of the harness public key used for decryption

### Execution Logs (`cmd/harness`)

```json
{
  "time": "2025-12-02T20:37:04.020531Z",
  "level": "INFO",
  "msg": "execution log",
  "timestamp": "2025-12-02T20:37:04Z",
  "encrypted_payload_hash_sha256": "06bb157736d06e451e9a43eb2612083c6ebfd2ac76c77039c8be15c9fbebbafd",
  "plugin_type": "wasm",
  "plugin_name": "ip-check-plugin",
  "exploit_binary_hash_sha256": "c30694d83806cebd605870c91aa1c13d745d96a1880a6d1928ebd69c8b302e04",
  "exploit_owner_signature_hash_sha256": "30811a6e1d74797b9132f32adea5cf785b12fc7715c261ae927997a5e381d216",
  "exploit_owner_public_key_hash_sha256": "0ecdbb984e42071abdd3e75e473c36208b0252ef57beb8e9d8cf24d19c50280e",
  "target_signature_hash_sha256": "5a20602b64d4fe6375727f8d650d97633edc244da904931a3dc4bab552c9f79c",
  "target_public_key_hash_sha256": "8af5420e2826e673e3b74067a3a8e3738dd768d766301adbd51676608d45dd4f",
  "harness_public_key_hash_sha256": "1fc9ce7352378f4ad16ea7c5141cbe98a8c6526894b6a9000bbae42b4b072051"
}
```

- **time**: ISO 8601 timestamp with nanosecond precision
- **level**: Log level (INFO, ERROR)
- **msg**: Log message identifier ("execution log")
- **timestamp**: ISO 8601 timestamp (seconds precision)
- **encrypted_payload_hash_sha256**: SHA256 of the encrypted payload (matches the hash signed by target and logged in sign/verify commands)
- **plugin_type**: Type of plugin executed (e.g., "wasm")
- **plugin_name**: Name of the plugin extracted from the plugin itself
- **exploit_binary_hash_sha256**: SHA256 of the decrypted exploit binary that was executed
- **exploit_owner_signature_hash_sha256**: SHA256 of the verified exploit owner signature
- **exploit_owner_public_key_hash_sha256**: SHA256 of the exploit owner's public key used for verification
- **target_signature_hash_sha256**: SHA256 of the verified target signature
- **target_public_key_hash_sha256**: SHA256 of the target's public key used for verification
- **harness_public_key_hash_sha256**: SHA256 of the harness public key used for decryption

**Note**: All logs are written to stderr in JSON format, so they won't interfere with JSON output on stdout. This provides a complete audit trail of cryptographic operations, key usage, and execution details for compliance and security analysis. The JSON format makes it easy to parse and analyze logs programmatically.

## OS Keystore Integration

**All private keys stored in OS keystore, never written to disk.**

### Key Management

```bash
# Generate new key pair
./bin/genkeys -keystore-key "target-key" -public target_public.pem

# Import existing PEM key
./bin/genkeys -import existing_private.pem -keystore-key "target-key" -public target_public.pem

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

1. **Encrypting Exploit** (Exploit Owner):
   - Generate AES-256 symmetric key
   - Encrypt payload with symmetric key (AES-256-GCM)
   - Encrypt symmetric key with harness public key (X25519)
   - Sign encrypted payload hash with exploit owner's private key (Ed25519)
   - Write encrypted file with exploit owner signature

2. **Signing Arguments** (Target):
   - Set expiration (default: 3 days)
   - Encrypt execution arguments with harness public key (X25519 + AES-256-GCM)
   - Hash encrypted payload
   - Sign encrypted payload hash + expiration + encrypted arguments (Ed25519)
   - Append signature, expiration, encrypted arguments to encrypted file

3. **Verification & Execution** (Harness):
   - Read magic bytes and version field (must be "HARN" and version 1)
   - Extract exploit owner signature
   - Verify exploit owner signature on encrypted payload hash BEFORE decryption
   - Verify expiration not passed
   - Hash encrypted payload
   - Verify target signature on encrypted payload hash + expiration + arguments
   - Decrypt symmetric key with harness private key (X25519)
   - Decrypt exploit data with symmetric key (AES-256-GCM)
   - Log execution details (exploit hash, signatures)
   - Load WASM directly into sandbox
   - Execute with signed arguments

### Encrypted File Format Specification

The encrypted exploit file format (after target signing) is:

```
[magic:4 bytes][version:1 byte][flags:1 byte][file_length:4 bytes][exploit_owner_sig_len:4 bytes][exploit_owner_sig][metadata_length:4 bytes][metadata][encrypted_symmetric_key][encrypted_plugin_data][target_sig_len:4 bytes][target_sig][expiration:8 bytes][args_len:4 bytes][encrypted_args]
```

#### File Layout

| Field | Size | Description |
|-------|------|-------------|
| `magic` | 4 bytes | Magic bytes identifier: `0x48 0x41 0x52 0x4E` ("HARN") for file type detection |
| `version` | 1 byte | Format version (must be 1). Includes exploit owner signature and encrypted payload hash in signatures. |
| `flags` | 1 byte | Reserved flags byte (currently 0, reserved for future use) |
| `file_length` | 4 bytes | Big-endian uint32: total file size in bytes (set to 0 in encrypted files, updated by sign command) |
| `exploit_owner_sig_len` | 4 bytes | Big-endian uint32: length of exploit owner signature in bytes (must be 64) |
| `exploit_owner_sig` | 64 bytes | Ed25519 signature signing the encrypted payload hash |
| `metadata_length` | 4 bytes | Big-endian uint32: length of metadata JSON in bytes |
| `metadata` | variable | JSON object containing encryption metadata |
| `encrypted_symmetric_key` | variable | Encrypted AES-256 symmetric key (see format below) |
| `encrypted_plugin_data` | variable | Encrypted exploit payload (see format below) |
| `target_sig_len` | 4 bytes | Big-endian uint32: length of target signature in bytes (must be 64) |
| `target_sig` | 64 bytes | Ed25519 signature |
| `expiration` | 8 bytes | Big-endian uint64: Unix timestamp (seconds) when payload expires |
| `args_len` | 4 bytes | Big-endian uint32: length of encrypted arguments in bytes |
| `encrypted_args` | variable | Encrypted arguments (X25519 + AES-256-GCM format: [ephemeral_x25519_public_key:32][nonce:12][ciphertext+tag]) |

#### Exploit Owner Signature Format

- **Algorithm**: Ed25519
- **Encoding**: Raw 64-byte signature (fixed size)
- **Signed Data**: SHA-256 hash of the encrypted payload: `SHA256([metadata_length:4][metadata][encrypted_symmetric_key][encrypted_plugin_data])`
- **Purpose**: Ensures authenticity and integrity of the encrypted payload
- **Authorization**: Proves exploit owner has reviewed and approved the specific encrypted payload
- **Security**: Verified BEFORE decryption to prevent decryption of invalid payloads

#### Target Signature Format

- **Algorithm**: Ed25519
- **Encoding**: Raw 64-byte signature (fixed size)
- **Signed Data**: SHA-256 hash of `SHA256(encrypted_payload) (32 bytes) || expiration (8 bytes) || encrypted_args`
- **Purpose**: Ensures authenticity and integrity of the encrypted payload, execution arguments, and expiration
- **Authorization**: Proves target has reviewed and approved the specific exploit payload, targeting parameters, and expiration time

#### Metadata Format (JSON)

```json
{
  "symmetric_key_len": <integer>,
  "plugin_data_len": <integer>,
  "algorithm": "Ed25519+X25519+AES-256-GCM"
}
```

- `symmetric_key_len`: Length in bytes of the `encrypted_symmetric_key` field
- `plugin_data_len`: Length in bytes of the `encrypted_plugin_data` field
- `algorithm`: Cryptographic algorithm identifier (currently `"Ed25519+X25519+AES-256-GCM"`)

#### Encrypted Symmetric Key Format

The symmetric key is encrypted using X25519 key exchange and AES-256-GCM:

```
[ephemeral_x25519_public_key:32 bytes][nonce:12 bytes][ciphertext+tag:variable]
```

| Field | Size | Description |
|-------|------|-------------|
| `ephemeral_x25519_public_key` | 32 bytes | X25519 public key (Montgomery curve format) |
| `nonce` | 12 bytes | Random nonce for AES-GCM encryption |
| `ciphertext+tag` | variable | AES-256-GCM encrypted symmetric key (32 bytes) + authentication tag (16 bytes) |

**Encryption Process:**
1. Generate ephemeral Ed25519 key pair
2. Convert Ed25519 keys to X25519 format for key exchange
3. Compute shared secret via X25519: `shared_secret = X25519(ephemeral_private, harness_public)`
4. Derive AES-256 key using HKDF-SHA256: `aes_key = HKDF-SHA256(shared_secret, context, 32)` where context is "harness-symmetric-key-v1" for symmetric keys or "harness-args-v1" for arguments
5. Encrypt symmetric key with AES-256-GCM using the derived key
6. Prepend ephemeral X25519 public key and nonce to the ciphertext

**Note**: The symmetric key is encrypted with the harness public key, allowing the harness to decrypt and execute. The target separately signs the execution arguments + expiration to approve targeting.

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
- **Authenticity**: Ed25519 signatures verify arguments + expiration approval
- **Integrity**: GCM authentication tags detect tampering
- **Forward Secrecy**: Ephemeral keys for symmetric key encryption
- **Key Exchange**: X25519 secure key derivation with HKDF-SHA256 for key derivation
- **Deterministic Signatures**: Ed25519 signatures are deterministic (no randomness needed)
- **Fixed Signature Size**: Ed25519 signatures are always 64 bytes (simpler than variable-length ASN.1)
- **Deterministic Parsing**: File format uses explicit deterministic forward parsing (no heuristics)
- **Metadata Limits**: Hard limit of 10KB enforced on metadata size
- **Dual Authorization**: Requires exploit owner encryption + signature and target signature
- **File Type Detection**: Magic bytes ("HARN") enable quick file type identification
- **File Length Validation**: Total file length field enables early validation of file completeness

## Plugin API

Harness uses **[Extism SDK](https://extism.org/)** for WASM execution. Exploits must use **[Extism PDK](https://extism.org/docs/quickstart/plugin-quickstart)** and export:

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

Harness is engine-agnostic and supports multiple plugin formats through a unified interface. The WASM loader ([`plugin/wasm/loader.go`](plugin/wasm/loader.go)) is one such implementation that translates between the Go interface and [Extism SDK](https://extism.org/) calls to WASM modules compiled to `wasm32-wasip1` target.

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
# Exploit owner encrypts exploit and signs encrypted payload hash
./bin/encrypt \
  -plugin exploit.wasm \
  -type wasm \
  -harness-key harness_public.pem \
  -exploit-keystore-key "exploit-key" \
  -output exploit.encrypted

# Target signs execution arguments (arguments are encrypted with harness public key)
./bin/sign \
  -file exploit.encrypted \
  -target-keystore-key "target-key" \
  -harness-key harness_public.pem \
  -args '{"target":"192.168.1.100","port":443}' \
  -expiration 72h \
  -output exploit.approved

# Harness executes (requires exploit owner signature, target signature, and valid expiration)
./bin/harness \
  -file exploit.approved \
  -harness-keystore-key "harness-key" \
  -target-key target_public.pem \
  -exploit-key exploit_public.pem
```

## Platform Notes

- **WASM Exploits**: Supported on all platforms via [Extism SDK](https://extism.org/) (wazero internally)
- **Keystore**: Platform-specific implementations for secure key storage
- **Exploit Types**: Only WASM exploits supported (no Go plugins)

## Legal & Compliance

Helps meet compliance requirements:
- **CREST**: Authorization boundaries and audit trails
- **ISO 27001**: Cryptographic controls for information security
- **SOC2**: Access controls and authorization enforcement
- **PCI DSS**: Penetration testing requirements

### Authorization Boundaries

- Explicit exploit owner encryption + signature (control of exploit availability)
- Explicit target approval (signature on arguments + expiration)
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
- Target signature verification ensures arguments + expiration approval
- Exploit owner signature verification ensures payload authenticity
- Encryption ensures exploit confidentiality
- WASM sandboxing provides isolation boundaries to reduce host system impact
