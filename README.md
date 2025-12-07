Harness — Dual-Authorization Exploit Execution System

Harness is a cryptographically secure framework for storing, transporting, approving, and executing sensitive payloads such as zero-day exploits and high-risk penetration testing tools. It enforces dual authorization through encryption and signatures, ensuring no single party can execute an exploit unilaterally.

Documentation: https://pkg.go.dev/github.com/joncooperworks/harness
Protocol: docs/RFC.md — HCEEP (Harness Cryptographic Execution Envelope Protocol)

Harness integrates with OS keystores, supports hardware-backed key storage, and executes exploits inside a sandboxed WASM runtime.

Features
	•	Dual Authorization: Requires both Exploit Owner and Target signatures
	•	Payload Confidentiality: AES-256-GCM with X25519 key exchange
	•	Chain-of-Custody: EO and Target signatures tied to stable KeyIDs
	•	Time-Limited Approvals: Target-signed expiration window
	•	WASM Sandboxing: Deterministic, cross-platform execution via Extism
	•	OS Keystore Integration: Private keys never leave secure storage
	•	Pluggable Architecture: Add new keystores or plugin execution engines

1. Overview

Harness provides a cryptographic execution wrapper for offensive tooling. It guarantees:
	•	Exploit Owner controls the exploit payload
	•	Target controls authorization to run it
	•	Harness operator cannot run anything without both approvals

2. Dual Authorization Model

Execution requires all of the following:
	1.	Exploit Owner
	•	Encrypts payload
	•	Signs payload digest
	•	Cannot authorize execution
	2.	Target
	•	Decrypts inner envelope
	•	Verifies EO signature
	•	Signs arguments + expiration
	•	Cannot decrypt payload
	3.	Harness
	•	Verifies both signatures
	•	Checks expiration
	•	Decrypts and executes payload in WASM

Onion Encryption
	•	Inner: encrypted to Target
	•	Outer: encrypted to Harness

3. Threat Model

Threats Addressed

Threat	Mitigation
Unauthorized execution	Target signature on arguments + expiration
Payload disclosure	AES-256-GCM; private keys in secure keystore
Chain-of-custody	EO + Target signatures recorded with KeyIDs
Stale approvals	Target-signed expiration
Tampering	Signatures over SHA-256(context
Replay within window	Allowed by design; expiration limits scope

Out of Scope
	•	Compromise of Target/Harness machines
	•	WASM sandbox escapes
	•	Insider with both key materials
	•	Malware outside WASM runtime

4. Why Hash Before Signing?

Harness signs:

Sign( SHA-256(context || message) )

Reasons:
	1.	Strong domain separation between signature types
	2.	Keystores never receive or process exploit payloads
	3.	JSON and cross-language canonicalization safety
	4.	Matches modern protocol practice (Signal, WireGuard)

5. Architecture

Envelope Structure (Pseudocode)

EO_Signature = Sign_EO(
    SHA256("harness:payload-signature" || payload)
)

Inner = Encrypt_X25519(TargetPub,
    payload || EO_Signature
)

Target_Signature = Sign_Target(
    SHA256("harness:client-signature" ||
           Hash(Inner) ||
           args ||
           expiration)
)

Outer = Encrypt_X25519(HarnessPub,
    Inner || Target_Signature || args || expiration
)

6. Workflow

Exploit Owner → Encrypt payload + sign digest
      ↓
Target → Decrypt inner envelope, verify EO, sign args + expiration
      ↓
Harness → Verify, check expiration, decrypt, execute in WASM

7. Plugin System (WASM)

Harness executes exploits compiled to WASM using Extism.

Required Exported Functions

Function	Description
name()	Human-readable exploit name
description()	Description text
json_schema()	Arguments schema
execute()	Executes exploit, returns JSON

Plugin Interface (Go)

type Plugin interface {
    Name() string
    Description() string
    JSONSchema() string
    Execute(ctx context.Context, args json.RawMessage) (interface{}, error)
}

8. Keystore Interface

type Keystore interface {
    KeyID() KeyID
    PublicKey() (ed25519.PublicKey, error)
    PublicKeyX25519() ([32]byte, error)

    Sign(msg, context []byte) ([]byte, error)
    Verify(pub ed25519.PublicKey, msg, sig, context []byte) error

    EncryptFor(peer [32]byte, plaintext, context []byte) ([]byte, KeyID, error)
    Decrypt(ciphertext, context []byte) ([]byte, KeyID, error)
}

Cryptographic Suite
	•	Ed25519
	•	X25519
	•	HKDF-SHA256
	•	AES-256-GCM

9. Security Considerations
	•	Keys never leave secure keystores
	•	WASM sandbox provides isolation but not full containment
	•	Run Harness on isolated and monitored hosts
	•	Replay allowed but expiration-bound
	•	All cryptographic operations logged with KeyIDs

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

11. Execution Logging

All cryptographic operations emit structured logs including:
	•	Timestamp
	•	Operation type
	•	SHA256 hashes of payloads, signatures, and keys
	•	KeyIDs used

Logs are written to stderr.

12. Platform Notes
	•	macOS: Keychain Access
	•	Linux: libsecret
	•	Windows: Credential Manager
	•	WASM: Extism (wazero-based)