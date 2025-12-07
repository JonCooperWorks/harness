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
- **WASM Sandboxing:** Deterministic execution with Extism  
- **OS Keystore Integration:** Keys never leave secure storage  

---

## How It Works

Three parties, each with limited capabilities:

1. **Exploit Owner** — Encrypts payload, signs digest. Cannot authorize execution.
2. **Target** — Decrypts inner envelope, verifies EO signature, signs args + expiration. Cannot decrypt payload.
3. **Harness** — Verifies both signatures, checks expiration, decrypts and executes in WASM.

**Onion encryption:**
- Inner layer encrypted to Target
- Outer layer encrypted to Harness

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

## Quick Start

### 1. Generate Keys

```bash
./bin/genkeys -keystore-key "target-key" -public target_public.pem
./bin/genkeys -keystore-key "harness-key" -public harness_public.pem
./bin/genkeys -keystore-key "exploit-key" -public exploit_public.pem
./bin/listkeys
```

### 2. Encrypt Payload

```bash
./bin/encrypt \
  -plugin exploit.wasm \
  -type wasm \
  -harness-key harness_public.pem \
  -target-key target_public.pem \
  -exploit-keystore-key "exploit-key" \
  -output exploit.encrypted
```

### 3. Target Signs Arguments

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

### 4. Execute

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
EO_Signature = Sign_EO(SHA256("harness:payload-signature" || payload))

Inner = Encrypt_X25519(TargetPub, payload || EO_Signature)

Target_Signature = Sign_Target(
    SHA256("harness:client-signature" || Hash(Inner) || args || expiration)
)

Outer = Encrypt_X25519(HarnessPub, Inner || Target_Signature || args || expiration)
```

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
| Unauthorized execution | Target signature on args + expiration |
| Payload disclosure | AES-256-GCM; keys in secure keystore |
| Chain-of-custody | EO + Target signatures with KeyIDs |
| Stale approvals | Signed expiration timestamp |
| Tampering | Signatures over SHA-256(context‖message) |
| Replay (within window) | Allowed; expiration limits risk |

**Out of scope:**
- Compromised Target/Harness hosts
- WASM sandbox escape vulnerabilities
- Insider with both private keys
- Malware outside WASM runtime

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

Structured logs to stderr include:
- Timestamp
- Operation type
- SHA-256 hashes of payloads, signatures, keys
- KeyIDs involved

stdout remains clean for plugin output.

---

## Security Considerations

- Keys never exist outside secure storage
- WASM sandbox provides isolation but not perfect containment
- Run Harness on isolated, monitored systems
- Replay allowed but expiration-bound
- All cryptographic actions logged with KeyIDs
