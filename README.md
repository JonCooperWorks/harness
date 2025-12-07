# Harness — Dual-Authorization Exploit Execution System

Harness is a cryptographically secure framework for storing, transporting, approving, and executing sensitive payloads such as zero-day exploits and high-risk penetration testing tools. It enforces **dual authorization** through encryption and signatures, ensuring no single party can execute an exploit unilaterally.

**Documentation:** https://pkg.go.dev/github.com/joncooperworks/harness  
**Protocol:** `docs/RFC.md` — HCEEP (Harness Cryptographic Execution Envelope Protocol)

Harness integrates with OS keystores, supports hardware-backed key storage, and executes exploits inside a sandboxed WASM runtime.

---

## Features

- **Dual Authorization:** Exploit Owner + Target approval required  
- **Payload Confidentiality:** AES-256-GCM with X25519  
- **Chain-of-Custody:** EO + Target signatures tied to stable KeyIDs  
- **Time-Limited Approvals:** Target-signed expiration window  
- **WASM Sandboxing:** Deterministic execution with Extism  
- **OS Keystore Integration:** Keys never leave secure storage  
- **Pluggable Architecture:** Custom keystores and plugin engines  

---

# 1. Overview

Harness provides a cryptographic execution layer for offensive security tooling. It guarantees:

- The **Exploit Owner** controls exploit payload content  
- The **Target** controls execution authorization  
- The **Pentester** cannot run exploits without both approvals  

---

# 2. Dual Authorization Model

Execution requires all of:

1. **Exploit Owner**
   - Encrypts payload  
   - Signs payload digest  
   - Cannot authorize execution  

2. **Target**
   - Decrypts inner envelope  
   - Verifies EO signature  
   - Signs arguments + expiration  
   - Cannot decrypt payload  

3. **Harness**
   - Verifies both signatures  
   - Checks expiration  
   - Decrypts and executes exploit in WASM  

## Onion Encryption

- Inner layer encrypted to **Target**  
- Outer layer encrypted to **Harness**  

---

# 3. Threat Model

## Threats Addressed

| Threat | Mitigation |
|--------|------------|
| Unauthorized execution | Target signature on args + expiration |
| Payload disclosure | AES-256-GCM; keys in secure keystore |
| Chain-of-custody | EO + Target signatures with KeyIDs |
| Stale approvals | Signed expiration timestamp |
| Tampering | Signatures over SHA-256(context‖message) |
| Replay (within window) | Allowed; expiration limits risk |

## Out of Scope

- Compromised Target/Harness hosts  
- WASM sandbox escape vulnerabilities  
- Insider with both private keys  
- Malware outside WASM runtime  

---

# 4. Why Hash Before Signing?

Harness signs:

Sign( SHA-256(context || message) )

This ensures:

1. **Strong domain separation** between signature types  
2. **Keystores never see private exploit data**  
3. **Canonicalization safety** across languages/platforms  
4. **Alignment with modern protocol design** (Signal, WireGuard)  

---

# 5. Architecture

## Envelope Structure (Pseudocode)

EO_Signature = Sign_EO(
SHA256(“harness:payload-signature” || payload)
)

Inner = Encrypt_X25519(TargetPub,
payload || EO_Signature
)

Target_Signature = Sign_Target(
SHA256(“harness:client-signature” ||
Hash(Inner) ||
args ||
expiration)
)

Outer = Encrypt_X25519(HarnessPub,
Inner || Target_Signature || args || expiration
)

---

# 6. Workflow

Exploit Owner → Encrypt payload + sign digest
↓
Target → Decrypt inner envelope, verify EO, sign args + expiration
↓
Harness → Verify signatures, check expiration, decrypt, execute in WASM

---

# 7. Plugin System (WASM)

Harness executes exploits compiled to WASM using Extism.

## Required Exports

| Function | Description |
|----------|-------------|
| `name()` | Exploit name |
| `description()` | Description text |
| `json_schema()` | Argument schema |
| `execute()` | Executes exploit, returns JSON |

## Plugin Interface (Go)

```go
type Plugin interface {
    Name() string
    Description() string
    JSONSchema() string
    Execute(ctx context.Context, args json.RawMessage) (interface{}, error)
}


⸻

8. Keystore Interface

type Keystore interface {
    KeyID() KeyID
    PublicKey() (ed25519.PublicKey, error)
    PublicKeyX25519() ([32]byte, error)

    Sign(msg, context []byte) ([]byte, error)
    Verify(pub ed25519.PublicKey, msg, sig, context []byte) error

    EncryptFor(peer [32]byte, plaintext, context []byte)
        ([]byte, KeyID, error)

    Decrypt(ciphertext, context []byte)
        ([]byte, KeyID, error)
}

Cryptographic Suite
	•	Ed25519 signatures
	•	X25519 key exchange
	•	HKDF-SHA256
	•	AES-256-GCM

Keys remain inside OS keystores or HSMs.

⸻

9. Security Considerations
	•	Keys never exist outside secure storage
	•	WASM sandbox provides isolation but not perfect containment
	•	Run Harness on isolated, monitored systems
	•	Replay allowed but expiration-bound
	•	All cryptographic actions logged with KeyIDs

⸻

10. Quick Start

Generate Keys

./bin/genkeys -keystore-key "target-key" -public target_public.pem
./bin/genkeys -keystore-key "harness-key" -public harness_public.pem
./bin/genkeys -keystore-key "exploit-key" -public exploit_public.pem
./bin/listkeys

Encrypt Exploit Payload

./bin/encrypt \
  -plugin exploit.wasm \
  -type wasm \
  -harness-key harness_public.pem \
  -target-key target_public.pem \
  -exploit-keystore-key "exploit-key" \
  -output exploit.encrypted

Target Signs Arguments

./bin/sign \
  -file exploit.encrypted \
  -target-keystore-key "target-key" \
  -exploit-key exploit_public.pem \
  -harness-key harness_public.pem \
  -args '{"target":"192.168.1.100","port":443}' \
  -expiration 72h \
  -output exploit.approved

Execute

./bin/harness \
  -file exploit.approved \
  -harness-keystore-key "harness-key" \
  -target-key target_public.pem \
  -exploit-key exploit_public.pem


⸻

11. Execution Logging

All cryptographic actions emit structured logs including:
	•	Timestamp
	•	Operation type
	•	SHA-256 hashes of payloads, signatures, and keys
	•	KeyIDs involved

Logs are written to stderr, keeping stdout clean for plugin output.

⸻

12. Platform Notes
	•	macOS: Keychain Access
	•	Linux: libsecret
	•	Windows: Credential Manager
	•	WASM: Extism (wazero-based), cross-platform
