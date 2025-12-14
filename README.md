# Harness — Dual-Authorization Exploit Execution System

Cryptographically secure framework for storing, transporting, approving, and executing sensitive payloads. Requires both Exploit Owner and Target approval before execution.

**Documentation:** https://pkg.go.dev/github.com/joncooperworks/harness  
**Protocol:** `docs/RFC.md` — HCEEP (Harness Cryptographic Execution Envelope Protocol)

---

## Features

- **Dual Authorization:** Exploit Owner + Target approval required  
- **Payload Confidentiality:** AES-256-GCM with X25519  
- **Chain-of-Custody:** EO + Target signatures tied to stable KeyIDs  
- **Time-Limited Approvals:** Target-signed expiration window  
- **Cross-Platform Execution:** WASM via Extism for consistent behavior across OS/arch  
- **OS Keystore Integration:** Keys never leave secure storage  

---

## How It Works

Three parties, each with limited capabilities:

1. **Exploit Owner** — Encrypts payload, signs digest. Cannot authorize execution.
2. **Target** — Decrypts outer envelope (E) to get inner envelope (E_inner), verifies EO signature, signs args + expiration. Cannot decrypt the encrypted payload itself (requires Harness key).
3. **Harness** — Verifies both signatures, checks expiration, decrypts and executes in WASM.

**Onion encryption:**
- Inner layer encrypted to Harness (symmetric key + payload)
- Outer layer encrypted to Target (inner envelope)

### Visibility by Party

Each party has limited visibility into the execution envelope:

- **Exploit Owner:** Can see plaintext payload during encryption phase. Signs the encrypted payload hash (commitment to the encrypted executable). Cannot decrypt envelopes or authorize execution.

- **Target:** Can decrypt the outer envelope (E) to access the inner envelope (E_inner). Sees the encrypted payload (metadata + encrypted symmetric key + encrypted plugin data) but **cannot decrypt the executable itself** — the symmetric key is encrypted to Harness's public key. Signs a commitment to: encrypted executable + execution arguments + expiration timestamp.

- **Harness:** Receives the approved package (A) containing E_inner + Target signature + expiration + encrypted args. Verifies both signatures, checks expiration, then decrypts the symmetric key, payload, and arguments. Only Harness can decrypt and execute the payload.

---

## Plugin System

### Plugin Interface

All plugins must implement the `Plugin` interface:

```go
type Plugin interface {
    Name() string
    Description() string
    JSONSchema() string
    Execute(ctx context.Context, args json.RawMessage) (interface{}, error)
}
```

**Methods:**
- `Name()` — Unique plugin identifier (e.g., "cve-2025-55182-exploit")
- `Description()` — Human-readable description
- `JSONSchema()` — JSON Schema string defining argument structure
- `Execute()` — Runs the plugin with JSON arguments, returns JSON-serializable result

### WASM Plugins (Default)

WASM is the default execution environment. Plugins use the Extism PDK and must export four functions:

| Function | Returns | Purpose |
|----------|---------|---------|
| `name()` | `String` | Unique plugin identifier |
| `description()` | `String` | Human-readable description |
| `json_schema()` | `String` | JSON Schema for arguments |
| `execute()` | `Json<Value>` | Execution logic |

**Examples:**

| Example | Directory | Description |
|---------|-----------|-------------|
| cve-2025-55182 | [`examples/cve-2025-55182/`](examples/cve-2025-55182/) | Next.js/React.js prototype pollution and command injection exploit |
| get-ip         | [`examples/get-ip/`](examples/get-ip/)                 | Simple HTTP request example |
| hello-world    | [`examples/hello-world/`](examples/hello-world/)       | Basic plugin template |

Each example includes source code, build instructions, and usage examples.

## Library Usage

Harness is designed as a library first, enabling integration with Identity Providers (IDPs), existing infrastructure, and custom workflows. The CLI tools in `./bin` are reference implementations that demonstrate how to use the library APIs.

**Key library components:**
- `executor.ExecutePlugin()` — Execute plugins with full hash-based audit logging
- `crypto.Encrypt()` — Encrypt payloads with dual-layer encryption
- `crypto.Sign()` — Sign execution arguments with expiration windows
- `crypto.VerifyAndDecrypt()` — Verify signatures and decrypt payloads
- `plugin.Registry` — Load and execute plugins from various runtimes

Use these APIs to integrate Harness into your existing systems, CI/CD pipelines, or security tooling. The library returns structured data (hashes, results) rather than performing logging directly, giving you full control over how audit logs are handled.

## CLI Tooling (Reference Implementation)

The CLI tools in `./bin` are reference implementations that demonstrate library usage:

- `./bin/genkeys` — Create Ed25519/X25519 keypairs inside the configured keystore. Use it once per principal.
- `./bin/listkeys` — Inspect which KeyIDs the keystore exposes and confirm provisioning succeeded.
- `./bin/store` — (Optional) Self-encrypt plugins to the exploit owner's key so they can be cached or ferried between systems without leaking payloads.
- `./bin/encrypt` — Wrap a plugin for a specific target + harness keypair, producing the dual-layer envelope.
- `./bin/sign` — Let the target review the envelope, attach execution arguments, and add the expiration window.
- `./bin/verify` — Non-destructive validation step to ensure an envelope has the expected signatures before execution.
- `./bin/harness` — Final executor that validates signatures, decrypts, and runs the plugin inside Extism.

## Quick Start

### 1. Generate Keys

```bash
./bin/genkeys -keystore-key "target-key" -public target_public.pem
./bin/genkeys -keystore-key "harness-key" -public harness_public.pem
./bin/genkeys -keystore-key "exploit-key" -public exploit_public.pem
./bin/listkeys
```

### 2. (Optional) Pre-store Plugin

Use the `store` command when you want to cache or transport a plugin without handing a raw payload to other teams. The output stays encrypted to your exploit owner key, so only you can recover it later.

```bash
./bin/store \
  -plugin exploit.wasm \
  -type wasm \
  -harness-key harness_public.pem \
  -exploit-keystore-key "exploit-key" \
  -output exploit.wasm.stored
```

You can hand the resulting `.stored` artifact to `./bin/encrypt` instead of the raw WASM whenever you're ready to target a specific environment.

### 3. Encrypt Payload

```bash
./bin/encrypt \
  -plugin exploit.wasm \
  -type wasm \
  -harness-key harness_public.pem \
  -target-key target_public.pem \
  -exploit-keystore-key "exploit-key" \
  -output exploit.encrypted
```

### 4. Target Signs Arguments

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

### 5. Execute

```bash
./bin/harness \
  -file exploit.approved \
  -harness-keystore-key "harness-key" \
  -target-key target_public.pem \
  -exploit-key exploit_public.pem
```

---

### Custom Execution Environments

Harness supports pluggable execution environments. You can implement custom loaders for any runtime (Python, Lua, JavaScript, etc.) or use confidential computing environments (Intel SGX, AMD SEV, AWS Nitro Enclaves, etc.).

To add support for a new runtime, implement the `Loader` interface:

```go
type Loader interface {
    Load(data []byte, name string) (Plugin, error)
}
```

**Steps:**

1. **Implement a Loader** that parses your plugin format and returns a `Plugin`:

```go
type PythonLoader struct {
    // Your runtime state
}

func (pl *PythonLoader) Load(data []byte, name string) (Plugin, error) {
    // Parse Python script, initialize interpreter, etc.
    // Return a Plugin implementation
}
```

2. **Implement the Plugin interface** for your runtime:

```go
type PythonPlugin struct {
    script *python.Script
    name   string
}

func (pp *PythonPlugin) Name() string {
    // Extract from script metadata or use provided name
}

func (pp *PythonPlugin) Description() string {
    // Extract from script docstring or metadata
}

func (pp *PythonPlugin) JSONSchema() string {
    // Extract from script metadata
}

func (pp *PythonPlugin) Execute(ctx context.Context, args json.RawMessage) (interface{}, error) {
    // Execute Python script with args, return result
}
```

3. **Register your loader** in an `init()` function:

```go
func init() {
    plugin.RegisterLoader("python", func() (plugin.Loader, error) {
        return NewPythonLoader()
    })
}
```

4. **Use your plugin type** when encrypting:

```bash
./bin/encrypt -plugin exploit.py -type python ...
```

The registry system automatically routes payloads to the correct loader based on the `-type` flag. See [`plugin/registry.go`](plugin/registry.go) and [`plugin/wasm.go`](plugin/wasm.go) for the WASM implementation reference.

**Full protocol details:** See [`docs/RFC.md`](docs/RFC.md) section 16 for the complete specification.

---

## Architecture

### Envelope Structure

```
EO_Signature = Sign_EO(SHA256("harness:payload-signature" || encrypted_payload))
where encrypted_payload = [metadata][encrypted_symmetric_key][encrypted_plugin_data]

Inner = Encrypt_X25519(TargetPub, [magic][version][flags][file_length][EO_Signature][encrypted_payload])

Target_Signature = Sign_Target(
    SHA256("harness:client-signature" || encrypted_payload || expiration || encrypted_args)
)

Approved Package (A) = Inner || Target_Signature || expiration || encrypted_args
```

**Note:** Target signs a commitment to the encrypted executable (not the plaintext), plus the execution arguments and expiration. The Target cannot decrypt the executable itself — only Harness can decrypt using its private key.

### Cryptographic Suite

- Ed25519 signatures
- X25519 key exchange
- HKDF-SHA256
- AES-256-GCM

Keys remain in OS keystores or HSMs.

---

## Threat Model

| Threat | Mitigation |
|--------|------------|
| Unauthorized execution | Target signature on encrypted payload + args + expiration |
| Payload disclosure | AES-256-GCM; keys in secure keystore |
| Chain-of-custody | EO + Target signatures with KeyIDs |
| Stale approvals | Signed expiration timestamp |
| Tampering | Signatures over SHA-256(context‖message) |
| Replay (within window) | Allowed until expiration; callers can implement replay prevention using returned hashes |

**Out of scope:**
- Compromised Target/Harness hosts
- Insider with both private keys
- Host-level malware or kernel exploits

> **Note on WASM:** WASM is used as a cross-platform execution environment for consistent behavior across operating systems and architectures — **not as a security sandbox**. Plugins have network access and can make HTTP requests. Run Harness on isolated, monitored systems appropriate for executing untrusted exploit code.

---

## Keystore Interface

```go
type Keystore interface {
    KeyID() KeyID
    PublicKey() (ed25519.PublicKey, error)
    PublicKeyX25519() ([32]byte, error)
    Sign(msg, context []byte) ([]byte, error)
    Verify(pub ed25519.PublicKey, msg, sig, context []byte) error
    EncryptFor(peer [32]byte, plaintext, context []byte) ([]byte, KeyID, error)
    Decrypt(ciphertext, context []byte) ([]byte, KeyID, error)
}
```

**Platform support:**
- macOS: Keychain Access
- Linux: libsecret
- Windows: Credential Manager
- Cloud KMS: AWS KMS, Azure Key Vault, Google Cloud KMS (via custom implementations)

The keystore interface is pluggable. Implement custom keystores for cloud KMS, HSMs, or other key management systems. Keys never leave secure storage.

---

## Execution Logging

Harness uses an API-based logging strategy. Library functions (like `executor.ExecutePlugin`) return structured data containing all relevant SHA-256 hashes rather than performing logging directly. This allows callers to control how and where logs are written.

The execution API returns `ExecutionHashes` containing:
- Encrypted payload hash
- Decrypted exploit binary hash
- Exploit owner signature hash
- Exploit owner public key hash
- Target signature hash
- Target public key hash
- Harness public key hash

The CLI tools log these hashes to stderr in structured JSON format, including timestamps, operation types, and KeyIDs. stdout remains clean for plugin output.

---

## Security Considerations

- Keys never exist outside secure storage
- WASM provides cross-platform consistency, **not sandboxing** — plugins can access the network
- Run Harness on isolated, monitored systems appropriate for executing untrusted code
- **Replay behavior:** Replays of approved packages are allowed within the expiration window. Callers can implement replay prevention by tracking execution of specific approved packages using the returned hashes:
  - `encrypted_payload_hash_sha256` — identifies the encrypted payload
  - `target_signature_hash_sha256` — identifies the Target's approval
  - `exploit_owner_signature_hash_sha256` — identifies the Exploit Owner's approval
- All cryptographic actions logged with KeyIDs

### KeyID Semantics

`KeyID` is a stable identifier (string) used for logging, rotation tracking, and chain-of-custody. It is **not** a cryptographic identifier — the cryptographic identity is the public key itself. KeyID is bound to a keystore entry and can be derived from config, file names, fingerprints, or any other stable source. Verifiers map KeyID to public keys through out-of-band key distribution (e.g., public key files, key servers, or configuration).

---
