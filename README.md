# Harness - Dual-Authorization Exploit Execution System

A cryptographically secure system for storing, transporting, approving, and executing sensitive payloads including zero-day exploits and high-risk penetration testing tools. Harness enforces **dual-authorization** through cryptographic encryption and signatures, ensuring exploits cannot be executed without explicit approval from both the exploit owner (who encrypts the exploit) and the target (who signs execution arguments).

**Documentation**: [pkg.go.dev/github.com/joncooperworks/harness](https://pkg.go.dev/github.com/joncooperworks/harness)  
**Protocol Specification**: [docs/RFC.md](docs/RFC.md) - HCEEP (Harness Cryptographic Execution Envelope Protocol)

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

1. **Exploit Owner** encrypts exploit and signs encrypted payload (has exploit, cannot authorize execution)
2. **Target** decrypts envelope, verifies Exploit Owner signature (chain-of-custody), then signs execution arguments + expiration (has authorization, cannot decrypt exploit payload)
3. **Harness (Pentester)** verifies signatures, decrypts, executes (needs both authorizations + valid expiration)

**Result**: Execution requires exploit owner encryption + signature (control of payload) AND target signature (control of authorization). The envelope is encrypted to the target's public key (onion encryption), so an attacker with only the harness key cannot decrypt without also having the target key.

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
Exploit Owner → Encrypts payload, signs hash, encrypts to target's public key
    ↓
Target → Decrypts envelope, signs expiration + arguments
    ↓
Harness → Verifies signatures & expiration, decrypts, executes in WASM sandbox
```

**Execution requires all:**

- ✓ Exploit owner encryption + signature
- ✓ Target signature on payload hash + expiration + arguments
- ✓ Valid expiration

### Keystore Interface

Go interface ([`crypto/keystore/Keystore`](crypto/keystore/interface.go)) provides cryptographic operations without exposing private keys, allowing hardware-backed or cloud-based key storage:

```go
type KeyID string

type Keystore interface {
	PublicEd25519(id KeyID) (ed25519.PublicKey, error)
	PublicX25519(id KeyID) ([32]byte, error)
	SignDigest(id KeyID, digest []byte) ([]byte, error)
	ECDH(id KeyID, peerPublic [32]byte) (sharedSecret [32]byte, err error)
	SetPrivateKey(id KeyID, privateKey ed25519.PrivateKey) error
	ListKeys() ([]KeyID, error)
}
```

**KeyID**: Selects which local key in this keystore to use. It does NOT change algorithms – just which Ed25519/X25519 pair. Supports multiple keys per process (dev/prod, low/high risk, rotation).

**PublicEd25519**: Returns the Ed25519 public key for keyID.

**PublicX25519**: Returns the X25519 public key for keyID (32 bytes).

**SignDigest**: Signs a canonical digest with the Ed25519 private key for keyID. Returns raw Ed25519 signature (64 bytes). In HCEEP this is used for:
- EO: H_payload
- Target: H_target

**ECDH**: Computes X25519(shared = sk(id) ⊗ peerPublic). In HCEEP this is used for:
- Target: decrypt outer envelope E
- Harness: unwrap Enc_K_sym and Enc_args

Callers then run HKDF + AES-GCM using this shared secret.

**EnvelopeCipher**: HCEEP-specific encryption/decryption is handled by the [`crypto/hceepcrypto`](crypto/hceepcrypto/envelope.go) package, which uses the keystore's ECDH method internally. The EnvelopeCipher interface provides:

- `EncryptToPeer(peerPubX [32]byte, ctx Context, plaintext []byte) ([]byte, error)`
- `DecryptFromPeer(ctx Context, blob []byte) ([]byte, error)`

HKDF contexts are managed internally:
- `ContextSymmetricKey` for symmetric keys
- `ContextArgs` for execution arguments
- `ContextEnvelope` for envelopes (onion encryption)

**Platform Implementations:**

- **macOS**: Keychain Access (extensible to Secure Enclave)
- **Linux**: libsecret/keyring (extensible to TPM/cloud KMS)
- **Windows**: Credential Manager (extensible to TPM/Windows Key Storage Provider)

### Adding New Keystore Implementations

Harness uses a **registry pattern** for keystore implementations. To add a new keystore:

1. **Implement the `Keystore` interface** (e.g., `crypto/keystore/cloudkms.go`)
   - Implement `PublicEd25519`, `PublicX25519`, `SignDigest`, and `ECDH` methods
   - Private keys never leave secure storage - all operations happen through the keystore interface
2. **Register in `init()`**: `RegisterKeystore("cloudkms", NewCloudKMSKeystore)`
3. **Use automatically**: `NewKeystore()` looks up registered factories by platform

**Registry API:**

- `RegisterKeystore(platform string, factory KeystoreFactory)`
- `GetKeystoreFactory(platform string) (KeystoreFactory, error)`
- `ListRegisteredPlatforms() []string`

Registry is thread-safe; implementations auto-register when imported.

**Crypto Suite**: The keystore interface uses a fixed crypto suite (hard-coded, no algorithm agility):
- Ed25519 for signatures
- X25519 for key exchange
- HKDF-SHA256 for key derivation
- AES-256-GCM for authenticated encryption

This design allows keys to remain in secure storage (HSMs, cloud KMS, Secure Enclave, TPM) and never be loaded into host memory. Implementations can swap in hardware-backed or cloud-based key storage transparently.

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
  -target-key target_public.pem \
  -exploit-keystore-key "exploit-key" \
  -output exploit.encrypted
```

Plugin name is auto-loaded from the plugin. Exploit owner signs encrypted payload hash. Inner envelope encrypted to target's public key (onion encryption) - attacker needs both harness and target keys to decrypt.

### 4. Target Signs Execution Arguments

```bash
./bin/sign \
  -file exploit.encrypted \
  -target-keystore-key "target-key" \
  -exploit-key exploit_public.pem \
  -harness-key harness_public.pem \
  -args '{"target":"192.168.1.100","port":443}' \
  -expiration 72h \
  -output exploit.approved
```

Target decrypts envelope (proves key access), **verifies Exploit Owner signature** (ensures chain-of-custody), encrypts arguments with harness public key, signs payload hash + expiration + arguments. Default expiration: `72h` (examples: `24h`, `168h`, `30m`).

### 5. Execute Exploit

```bash
./bin/harness \
  -file exploit.approved \
  -harness-keystore-key "harness-key" \
  -target-key target_public.pem \
  -exploit-key exploit_public.pem
```

Arguments auto-extracted from approved package (signed by target). Cannot override.

## Execution Logging

All commands log cryptographic operations to stderr in JSON format (ISO 8601 timestamps, SHA256 hashes of signatures, keys, and payloads).

**Common fields:**

- `time`: ISO 8601 timestamp (nanosecond precision)
- `level`: Log level (INFO, ERROR)
- `msg`: Log identifier ("encryption log", "signing log", "verification log", "execution log")
- `*_hash_sha256`: SHA256 hashes of signatures, public keys, and payloads

**Command-specific fields:**

- **encrypt**: `exploit_owner_signature_hash_sha256`, `exploit_owner_public_key_hash_sha256`, `harness_public_key_hash_sha256`
- **sign**: `encrypted_payload_hash_sha256`, `target_public_key_hash_sha256`
- **verify**: All signature and key hashes from both exploit owner and target
- **harness**: All above plus `plugin_type`, `plugin_name`, `exploit_binary_hash_sha256`

Logs written to stderr (won't interfere with JSON stdout). Provides complete audit trail for compliance.

## OS Keystore Integration

Private keys stored in OS keystore, never written to disk.

**Platform Support:**

- **macOS**: Keychain Access (service: `harness`). Default: Login keychain. Custom: `export HARNESS_KEYCHAIN="harness-keys"`. Reduce prompts: Trust app in Keychain Access.
- **Linux**: libsecret/keyring (service: `harness`)
- **Windows**: Credential Manager (service: `harness`)

## Architecture

Harness implements the **HCEEP (Harness Cryptographic Execution Envelope Protocol)** which provides dual-authorization through cryptographic encryption and signatures. For complete protocol specifications, see [docs/RFC.md](docs/RFC.md).

### High-Level Flow

1. **Exploit Owner** encrypts the exploit payload and signs it, then encrypts the inner envelope to the target's public key (onion encryption)
2. **Target** decrypts the envelope, verifies Exploit Owner signature (ensures chain-of-custody), then signs execution arguments and expiration, creating an approved package
3. **Harness** verifies both signatures, checks expiration, decrypts the payload, and executes it in a WASM sandbox

### Key Components

- **Cryptographic Operations**: Ed25519 signatures, X25519 key exchange, AES-256-GCM encryption
- **Onion Encryption**: Inner envelope encrypted to target, reducing compromise risk
- **Keystore Interface**: Pluggable key storage (OS keystores, HSMs, cloud KMS)
- **Plugin System**: Pluggable execution environments (WASM via Extism, extensible to other formats)
- **Registry Pattern**: Both keystores and plugin loaders use registries for easy extension

For detailed file format specifications, cryptographic algorithms, and security properties, refer to the [RFC](docs/RFC.md).

## Plugin API

Harness uses **[Extism SDK](https://extism.org/)** for WASM execution. Exploits must use **[Extism PDK](https://extism.org/docs/quickstart/plugin-quickstart)** and export:

### Required Exported Functions

1. **`name()`** → exploit name (string)
2. **`description()`** → exploit description (string)
3. **`json_schema()`** → JSON schema for arguments (string)
4. **`execute()`** → executes with JSON args, returns JSON result

Extism PDK provides input/output handling, HTTP client, and WASI support (file I/O, networking, subject to host function grants).

### Example Plugins

| Example | Description |
|---------|-------------|
| [`examples/get-ip/`](examples/get-ip/) | Fetches IP information from ipconfig.io using HTTP requests |
| [`examples/hello-world/`](examples/hello-world/) | Simple hello world plugin demonstrating basic plugin structure |

Each includes complete Rust source, `Cargo.toml`, build instructions, and usage examples.

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

Harness uses a **registry pattern** for plugin loaders. To add a new loader:

1. **Create loader** implementing `Loader` interface (e.g., `plugin/python.go`)
2. **Register in `init()`**: `RegisterLoader("python", NewPythonLoader)`
3. **Implement `Plugin` interface** for your plugin type
4. **Use**: `payload.Type = "python"` (matches registered identifier)

**Registry API:**

- `RegisterLoader(typeIdentifier string, factory LoaderFactory)`
- `GetLoaderFactory(typeIdentifier string) (LoaderFactory, error)`
- `ListRegisteredPluginTypes() []string`

## Platform Notes

- **WASM**: Supported on all platforms via [Extism SDK](https://extism.org/) (wazero internally)
- **Keystore**: Platform-specific implementations (macOS Keychain, Linux libsecret, Windows Credential Manager)
- **Plugin Types**: Currently WASM only (extensible via registry pattern)

## Legal & Compliance

Helps meet compliance requirements (CREST, ISO 27001, SOC2, PCI DSS) through:

- **Authorization boundaries**: Dual-authorization (exploit owner + target signatures)
- **Chain-of-custody**: Cryptographic proof of approval
- **Audit trails**: Verifiable signatures and keystore access logs
- **Sandboxed execution**: WASM isolation boundaries

## Security Considerations

- Private keys in OS keystore (never on disk)
- Public keys: distribute securely
- Encrypted exploits: safe over insecure channels
- Signature verification: ensures payload authenticity and argument approval
- Onion encryption: requires both harness and target keys to decrypt
