# Harness - Dual-Authorization Exploit Execution System

A cryptographically secure system for storing, transporting, approving, and executing sensitive payloads including zero-day exploits and high-risk penetration testing tools. Harness enforces **dual-authorization** through cryptographic encryption and signatures, ensuring that exploits cannot be executed without explicit approval from both the principal (firm leadership) and the client (President).

## Purpose

Harness is designed for offensive security teams and penetration testers who need to:

- **Store and transport sensitive exploits** including zero-days, proof-of-concepts, and custom payloads
- **Enforce authorization boundaries** preventing unauthorized execution
- **Maintain chain-of-custody** with cryptographic proof of approval
- **Protect exploit confidentiality** during transit and storage
- **Meet compliance requirements** for CREST, ISO 27001, SOC2, and PCI penetration testing standards

### Dual-Authorization Model

Harness implements a two-party authorization system where **nobody can run an exploit unilaterally**:

1. **Principal Authorization**: Firm leadership (principal) encrypts exploit payloads with the pentester's public key. The principal has the exploit but **cannot authorize its use** - they only encrypt it. The exploit remains confidential until execution.

2. **Client Authorization**: The client (President) receives the encrypted payload along with execution arguments (targeting information). The client cryptographically signs the arguments and expiration, proving approval of the specific targeting parameters. The client has **authorization power but not the exploit** - they can approve usage but cannot decrypt or execute.

3. **Execution**: The pentester receives the encrypted payload with client-signed arguments and executes:
   - Verifies the client's signature on the execution arguments + expiration (proves client approval of targeting)
   - Decrypts the exploit using their private key (pentester can decrypt because principal encrypted it for them)
   - Executes in WASM sandbox without prior knowledge of exploit details

**Result**: A pentester cannot execute an exploit unless:
- ✓ The principal encrypted it with the pentester's public key (principal authorization - they have the exploit)
- ✓ The client signed the execution arguments + expiration (client authorization - they approve usage)

Both parties must act: principal encrypts (has exploit, no authorization), client signs args (has authorization, no exploit), pentester executes (can decrypt, needs both).

## Threat Model & Rationale

### Threats Addressed

1. **Unauthorized Execution**: Ensures exploits cannot be executed without client authorization. The client's signature on execution arguments + expiration is required, and without it, execution is cryptographically impossible.

2. **Exploit Confidentiality**: Protects exploit code from exposure during transit or storage. Payloads are encrypted with AES-256-GCM, and the symmetric key is encrypted using ECDH with the pentester's public key.

3. **Chain-of-Custody**: Provides cryptographic proof of who approved what and when. Signatures are non-repudiable and verifiable.

4. **Stale Approvals**: Expiration timestamps prevent execution of old approvals. The expiration is cryptographically signed along with arguments, ensuring it cannot be tampered with.

5. **Compliance Violations**: Helps meet regulatory requirements by enforcing authorization boundaries and maintaining audit trails.

### Replay Attacks & Time-Limited Authorization

**Replays are intentionally allowed** within the expiration window. This design recognizes that penetration testing engagements require multiple verification runs and retesting across different phases. The time-limited expiration (default: 72 hours) provides the control mechanism rather than preventing replays entirely.

**Cryptographic Evidence**: The system provides cryptographic evidence that a pentester received an exploit for a specific target (via the client-signed execution arguments). This creates an audit trail - pentesters cannot run off with exploits undetected, as there is cryptographic proof of:
- Which exploit they received (encrypted with their public key)
- Which target they were authorized to test (client-signed arguments)
- When the authorization expires (signed expiration timestamp)

**Custom Decryptor Risk**: A pentester could theoretically create a custom decryptor that unwraps the payload without executing it through the harness. This risk can be mitigated by:
- Running exploits on a **locked-down and monitored exploit host** where custom decryptors cannot be deployed
- Monitoring for unauthorized decryption attempts
- The cryptographic evidence still shows they received the exploit, even if they bypass execution

**Key Point**: The system provides cryptographic evidence of exploit access and target authorization, creating accountability even if execution is bypassed. The time-limited expiration balances operational flexibility (allowing retesting) with security controls (preventing indefinite access).

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
│ (Firm Lead) │
└──────┬──────┘
       │
       │ 1. Encrypts exploit with pentester's public key
       │ 2. Creates execution arguments (targeting info)
       │    (Principal has exploit but cannot authorize)
       │
       ▼
┌─────────────────────────┐
│  Encrypted Payload + Args │
│  (no signature - unsigned) │
└──────┬──────────────────┘
       │
       │ Sent to client for approval
       │
       ▼
┌─────────────┐
│   Client    │
│ (President) │
└──────┬──────┘
       │
       │ 3. Reviews encrypted payload and arguments
       │ 4. Signs arguments + expiration with client private key
       │    (Client has authorization but not exploit)
       │ 5. Returns approved payload to pentester
       │
       ▼
┌─────────────┐
│  Pentester  │
└──────┬──────┘
       │
       │ 6. Verifies client signature on arguments + expiration ✓
       │ 7. Decrypts exploit with pentester private key ✓
       │ 8. Loads WASM payload (never sees plaintext)
       │ 9. Executes in sandbox with signed args
       │
       ▼
┌─────────────┐
│  Execution  │
│   Result    │
└─────────────┘
```

### Workflow Steps

1. **Principal → Encrypts Exploit**
   - Principal reviews and encrypts the exploit WASM payload
   - Encrypts exploit with pentester's public key (ECDH + AES-256-GCM)
   - Creates execution arguments (targeting information: IPs, ports, etc.)
   - **Principal does NOT sign** - they have the exploit but cannot authorize its use
   - Sends encrypted payload + arguments to client

2. **Client → Signs Arguments + Expiration**
   - Client (President) reviews the encrypted payload and execution arguments
   - Client signs the expiration timestamp + execution arguments with their private key (ECDSA)
   - This signature proves client approval of the specific targeting parameters and expiration time
   - **Client cannot decrypt** - they have authorization power but not the exploit
   - Client returns the approved payload (with signed arguments + expiration) to the pentester

3. **Pentester → Verifies Client Signature → Decrypts → Executes**
   - Verifies expiration has not passed (reject if expired)
   - Verifies client's signature on expiration + execution arguments (proves client approval)
   - Decrypts exploit using pentester's private key (principal authorized them via encryption)
   - Loads WASM module directly into sandbox (pentester never sees plaintext exploit)
   - Executes with client-signed arguments

**Key Point**: Nobody can run an exploit unilaterally. Principal encrypts (has exploit, no authorization), client signs args+expiration (has authorization, no exploit), pentester executes (can decrypt, needs both authorizations and valid expiration).

## Authorization Model Explained

### Principal Encryption (Exploit Payload)

- **Purpose**: Principal encrypts the exploit with the pentester's public key, authorizing the pentester to decrypt
- **Algorithm**: ECDH key exchange + AES-256-GCM encryption
- **What it encrypts**: The exploit WASM payload (symmetric key encrypted with pentester's public key)
- **Authorization**: By encrypting with pentester's public key, principal authorizes the pentester to decrypt
- **Storage**: Encrypted exploits are stored in the firm's stockpile (reusable, unsigned)
- **If missing**: Pentester cannot decrypt - execution fails cryptographically

### Client Signature (Execution Arguments + Expiration)

- **Purpose**: Proves the client (President) has approved the specific targeting parameters and expiration time for execution
- **Algorithm**: ECDSA with P-256 curve
- **What it signs**: SHA-256 hash of `expiration (8 bytes) || execution_arguments_json`
- **Verification**: Pentester verifies this signature before execution
- **Storage**: Client's private key stored in OS keystore via the `Keystore` interface (Keychain/Credential Manager/libsecret)
- **If missing**: Execution fails immediately - cannot proceed without client approval of targeting

### Execution Requirements

Execution is **cryptographically impossible** without all of the following:

1. ✓ Exploit encrypted with pentester's public key (principal authorization - they have the exploit)
2. ✓ Valid client signature on expiration + execution arguments (client authorization - they approve usage)
3. ✓ Expiration has not passed (time-based authorization - prevents stale approvals)

All conditions must be met. Missing any results in immediate failure. **Nobody can run an exploit unilaterally** - principal has exploit but no authorization, client has authorization but no exploit, pentester can decrypt but needs both authorizations and valid expiration.

### Keystore Interface

The keystore is implemented as a Go interface (`crypto/keystore/Keystore`) that provides platform-specific implementations:
- **macOS**: Keychain Access
- **Linux**: libsecret/keyring
- **Windows**: Credential Manager

This abstraction allows secure, platform-native key storage without exposing private keys to disk.

## Features

- **Cryptographic Security**: ECDSA signature verification and AES-256-GCM encryption
- **Cross-Platform**: Works on macOS, Linux, and Windows
- **WASM Sandboxing**: Exploit payloads executed in isolated WebAssembly sandboxes via Extism SDK
- **OS Keystore Integration**: Private keys stored securely using platform-native keystores
- **Memory-Based Loading**: Exploits loaded directly from memory, never written to disk unencrypted
- **Dual-Authorization**: Requires both principal encryption (control of payload) and client signature (control of authorization)

## Building

```bash
# Build all utilities
go build -o bin/genkeys ./cmd/genkeys
go build -o bin/encrypt ./cmd/encrypt
go build -o bin/sign ./cmd/sign
go build -o bin/harness ./cmd/harness
go build -o bin/verify ./cmd/verify
go build -o bin/listkeys ./cmd/listkeys
```

## Quick Start

### 1. Generate Keys

Generate keys for the client (who signs execution arguments) and the pentester (who executes). **Private keys are stored in the OS keystore and never written to disk.**

```bash
# Generate client's keys (for signing execution arguments)
# Private key stored in keystore, only public key written to disk
./bin/genkeys -keystore-key "client-key" -public client_public.pem

# Generate pentester's keys (for decrypting and executing exploits)
# Private key stored in keystore, only public key written to disk
./bin/genkeys -keystore-key "pentester-key" -public pentester_public.pem

# List all keys in keystore
./bin/listkeys
```

**Note**: If you have existing PEM private key files, you can import them into the keystore:

```bash
# Import existing private key into keystore
./bin/genkeys -import client_private.pem -keystore-key "client-key" -public client_public.pem
./bin/genkeys -import pentester_private.pem -keystore-key "pentester-key" -public pentester_public.pem

# After importing, you can safely delete the PEM files
```

### 2. Create a WASM Exploit Payload

Create a WASM module using the Extism Plugin Development Kit (PDK). The exploit must export the following functions:

- `name()` - returns the exploit name as a string
- `description()` - returns the exploit description as a string
- `json_schema()` - returns the JSON schema for arguments as a string
- `execute()` - executes the exploit with JSON arguments and returns JSON result

See the [Plugin API](#plugin-api) section below for detailed documentation on how to implement these functions.

### 3. Encrypt Exploit

Principal encrypts the exploit using the pentester's public key:

```bash
./bin/encrypt \
  -plugin exploit.wasm \
  -type wasm \
  -name "cve-2024-xxxx-exploit" \
  -harness-key pentester_public.pem \
  -output exploit.encrypted
```

### 4. Client Signs Execution Arguments

Client receives the encrypted payload and execution arguments, then signs the arguments + expiration (client has authorization but not the exploit):

```bash
./bin/sign \
  -file exploit.encrypted \
  -client-keystore-key "client-key" \
  -args '{"target":"192.168.1.100","port":443}' \
  -expiration 72h \
  -output exploit.approved
```

**Expiration**: The `-expiration` flag sets how long the payload remains valid. Default is `72h` (3 days). The expiration is cryptographically signed along with the arguments, ensuring it cannot be tampered with. Examples:
- `-expiration 24h` - expires in 24 hours
- `-expiration 168h` - expires in 1 week
- `-expiration 30m` - expires in 30 minutes

### 5. Execute Exploit (Requires Both Authorizations)

Pentester verifies client signature and decrypts with their private key. Arguments are automatically extracted from the approved package:

```bash
./bin/harness \
  -file exploit.approved \
  -keystore-key "pentester-key" \
  -signature-key client_public.pem
```

**Note**: Execution requires:
- ✓ Exploit encrypted with pentester's public key (principal authorization - they have the exploit)
- ✓ Valid client signature on expiration + execution arguments (client authorization - they approve usage)
- ✓ Expiration has not passed (time-based authorization)

The execution arguments are automatically extracted from the approved package (signed by the client). You cannot override or change the arguments - they must match what the client signed.

Without all three, execution fails cryptographically. **Nobody can run an exploit unilaterally**.

## OS Keystore Integration

**All private keys are stored in the OS keystore and never written to disk.** The keystore is implemented as a Go interface (`crypto/keystore/Keystore`) that provides platform-specific implementations for secure key storage using platform-native security features.

### Key Management

**Generate new keys** (recommended):

```bash
# Generate a new key pair, store private key in keystore, output only public key
./bin/genkeys \
  -keystore-key "client-key" \
  -public client_public.pem
```

**Import existing PEM keys** (one-time import into keystore):

```bash
# Import an existing private key file into the keystore
./bin/genkeys \
  -import existing_private.pem \
  -keystore-key "client-key" \
  -public client_public.pem

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
# Principal encrypts exploit with pentester's public key
./bin/encrypt \
  -plugin exploit.wasm \
  -harness-key pentester_public.pem \
  -output exploit.encrypted

# Client signs execution arguments using keystore
./bin/sign \
  -file exploit.encrypted \
  -client-keystore-key "client-key" \
  -args '{"target":"192.168.1.100","port":443}' \
  -expiration 72h \
  -output exploit.approved

# Pentester executes exploit using keystore (requires both authorizations)
# Arguments are automatically extracted from the approved package
./bin/harness \
  -file exploit.approved \
  -keystore-key "pentester-key" \
  -signature-key client_public.pem
```

### Platform Support

- **macOS**: Uses Keychain Access (service: `harness`)
  - Default: Uses login keychain (unlocked when logged in, fewer prompts)
  - Custom: Set `HARNESS_KEYCHAIN="harness-keys"` to use custom keychain
  - Example: `export HARNESS_KEYCHAIN="harness-keys"` before running commands
- **Linux**: Uses libsecret/keyring (service: `harness`)
- **Windows**: Uses Credential Manager (service: `harness`)

**macOS Keychain Configuration:**
- **Default (recommended)**: No environment variable = uses login keychain (unlocked when logged in, no password prompts)
- **Custom keychain**: Set `export HARNESS_KEYCHAIN="harness-keys"` to use the custom "harness-keys" keychain
- **Reducing password prompts**: 
  - Use the default login keychain (no `HARNESS_KEYCHAIN` set) for automatic unlocking
  - Trust the application in Keychain Access: Open Keychain Access → Find "harness" → Right-click → Get Info → Check "Always allow access to this item"
  - If you see two password prompts, the first is to unlock the keychain, the second is for key access - trusting the application eliminates the second prompt

## Architecture

### Cryptographic Flow

1. **Encrypting Exploit** (Principal, Encrypt command):
   - Generate symmetric key (AES-256)
   - Encrypt exploit payload with symmetric key (AES-256-GCM)
   - Encrypt symmetric key with pentester's public key (ECDH)
   - Create metadata and write encrypted file (without signature)
   - Store in exploit stockpile (reusable, unsigned)
   - **Principal does NOT sign** - they have the exploit but cannot authorize its use

2. **Signing Arguments** (Client, Sign command):
   - Client receives encrypted payload and execution arguments
   - Client sets expiration time (default: 3 days from signing)
   - Client signs expiration + execution arguments with client's private key (ECDSA)
   - Append client signature, expiration timestamp, and arguments to encrypted file
   - Return approved payload to pentester
   - **Client cannot decrypt** - they have authorization power but not the exploit

3. **Verification & Execution** (Pentester, Harness):
   - Verify expiration has not passed (reject if expired)
   - Verify client's signature on expiration + execution arguments
   - Decrypt symmetric key with pentester's private key (ECDH)
   - Decrypt exploit data with symmetric key (AES-256-GCM)
   - Load WASM module directly into sandbox (pentester never sees plaintext)
   - Execute with client-signed arguments

### Encrypted File Format Specification

The encrypted exploit file format (after client signing) is:

```
[metadata_length:4 bytes][metadata][encrypted_symmetric_key][encrypted_plugin_data][client_sig_len:4 bytes][client_sig][expiration:8 bytes][args_len:4 bytes][args_json]
```

#### File Layout

| Field | Size | Description |
|-------|------|-------------|
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
- **Signed Data**: SHA-256 hash of `expiration (8 bytes) || args_json`
- **Purpose**: Ensures authenticity and integrity of the execution arguments and expiration
- **Authorization**: Proves client has reviewed and approved the specific targeting parameters and expiration time

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

- `type`: Exploit type (0 = WASM)
- `name`: Exploit name identifier
- `data`: Base64-encoded exploit binary data (e.g., WASM module). Go's `encoding/json` automatically base64-encodes `[]byte` fields when marshaling.

**Encryption Process:**
1. Create JSON payload from exploit type, name, and binary data
2. Encrypt payload JSON with AES-256-GCM using the symmetric key
3. Prepend nonce to the ciphertext

#### Security Properties

- **Confidentiality**: Exploit data encrypted with AES-256-GCM
- **Authenticity**: Client's ECDSA signature verifies execution arguments and expiration approval
- **Integrity**: GCM authentication tags detect tampering
- **Forward Secrecy**: Ephemeral keys used for symmetric key encryption
- **Key Exchange**: ECDH provides secure key derivation without key material in metadata
- **Dual Authorization**: Requires both principal encryption (control of payload) and client signature (control of authorization)

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
# Principal encrypts WASM exploit with pentester's public key
./bin/encrypt \
  -plugin exploit.wasm \
  -type wasm \
  -name "cve-2024-xxxx-exploit" \
  -harness-key pentester_public.pem \
  -output exploit.encrypted

# Client signs execution arguments using keystore
./bin/sign \
  -file exploit.encrypted \
  -client-keystore-key "client-key" \
  -args '{"target":"192.168.1.100","port":443}' \
  -expiration 72h \
  -output exploit.approved

# Pentester executes it using keystore (requires both authorizations)
# Arguments are automatically extracted from the approved package
./bin/harness \
  -file exploit.approved \
  -keystore-key "pentester-key" \
  -signature-key client_public.pem
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

- Requiring explicit principal encryption (control of which exploit is available)
- Requiring explicit client approval (signature on execution arguments + expiration)
- Preventing unauthorized modification (signature verification)
- Maintaining chain-of-custody (cryptographic proof of approval)

### Liability Protections

The dual-authorization model provides liability protections by:

- Proving both parties approved execution (non-repudiable signatures and encryption)
- Preventing unauthorized execution (cryptographic enforcement)
- Maintaining audit trails (verifiable signatures and keystore access logs)
- Enforcing sandboxed execution (WASM isolation)

## Security Considerations

- **Private keys are stored in OS keystore** - never written to disk
- Public keys should be distributed securely
- Encrypted exploits can be distributed over insecure channels
- Client signature verification ensures execution arguments and expiration approval
- Encryption ensures exploit confidentiality
- Client authorization is enforced cryptographically (signature on execution arguments + expiration required)
- WASM sandboxing prevents exploits from affecting the host system
