
# HCEEP — Harness Cryptographic Execution Envelope Protocol

**Draft RFC 0.2**

- **Status:** Draft  
- **Author:** Jonathan Cooper  
- **Intended Status:** Informational / Standards Track  
- **Expires:** TBD

### Changes from 0.1

- **Target Approval Phase (5.2)**: Target now verifies Exploit Owner signature before signing, ensuring cryptographic chain-of-custody. This prevents targets from approving payloads that were not signed by the expected Exploit Owner.

---

## Abstract

The Harness Cryptographic Execution Envelope Protocol (HCEEP) defines a dual-authorization, cryptographically verifiable, time-bounded mechanism for transporting, approving, and executing high-risk payloads such as penetration testing exploits. The protocol provides:

- Payload confidentiality
- Execution integrity
- Mutual authorization by independent parties
- Time-bounded approvals
- Deterministic audit and chain-of-custody
- Pluggable key storage
- Pluggable execution environments
- Support for paranoid deployments using HSM-only keys

Payloads are encrypted using X25519/AES-256-GCM with onion encryption: inner layer encrypted to Harness, outer layer encrypted to Target. Payloads are signed by exploit owners using Ed25519, and approved for execution by targets using Ed25519. Execution requires access to both Target and Harness private keys (which *MAY* reside in HSMs or remote RPC services). The protocol is stateless and interoperable.

---

## 1. Conventions and Terminology

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are to be interpreted as described in [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119).

### 1.1. Actors

| Actor                | Description                                              |
|----------------------|----------------------------------------------------------|
| Exploit Author (EA)  | Writes exploit source code.                              |
| Exploit Owner (EO)   | Cryptographically approves payload content. Holds `sk_EO`.|
| Target (T)           | Approves targeting parameters and expiration. Holds `sk_T`.|
| Harness (H)          | Executes payload. Holds `sk_H`.                         |
| Pentester (P)        | Operates Harness commands or RPC interface.              |
| HSM                  | Hardware Security Module, cloud or physical.            |

### 1.2. Objects

| Object               | Description                                                   |
|----------------------|--------------------------------------------------------------|
| Payload (P)          | The exploit binary (e.g., WASM).                             |
| Inner Envelope       | Encrypted payload plus EO signature (not encrypted to target).|
| (E_inner)            |                                                              |
| Envelope (E)         | Inner envelope encrypted to target's public key (onion encryption).|
| Approved Package (A) | Decrypted inner envelope plus Target signature, expiration, and encrypted args.|


## 2. Goals

HCEEP provides:

- Cryptographic dual-authorization
- Payload confidentiality
- Time-bounded execution
- Zero-trust transport
- Stateless operation
- Pluggable keystore interfaces
- Pluggable plugin loaders
- Optional paranoid mode eliminating key exposure

---

## 3. High-Level Protocol Overview

- **Exploit Owner:** produces encrypted payload envelope (E), encrypted to target's public key  
- **Target:** decrypts E, verifies EO signature, produces approved package (A)  
- **Harness:** verifies, decrypts, executes

### Execution requires:

1. Valid EO signature (`sig_EO`)
2. Valid Target signature (`sig_T`)
3. Target decryption key (`sk_T`) to decrypt envelope E
4. Harness decryption key (`sk_H`) to decrypt payload
5. Unexpired timestamp (`now ≤ exp`)

_No single party can bypass the others. Onion encryption ensures E + `sk_H` alone is insufficient — attacker also requires `sk_T`._

---

## 4. Key Material

### 4.1. Exploit Owner Key

EO holds an Ed25519 private key `sk_EO`.  
Used solely for signing encrypted payload hashes.

### 4.2. Target Key

T holds an Ed25519/X25519 dual keypair `sk_T`.  
Used for:

- Decrypting envelopes encrypted to target's public key (X25519)
- Authorizing arguments and expiration (Ed25519 signatures)

### 4.3. Harness Key

H holds an X25519/Ed25519 dual keypair `sk_H`.  
Used for decrypting:

- Symmetric keys
- Encrypted payloads
- Encrypted arguments

### 4.4. Key Summary

| Key      | Type            | Holder         | Usage                                                        |
|----------|-----------------|---------------|---------------------------------------------------------------|
| sk_EO    | Ed25519         | Exploit Owner  | Signing encrypted payload hashes                             |
| sk_T     | Ed25519/X25519  | Target         | Decrypting envelopes (X25519), authorizing arguments & expiration (Ed25519) |
| sk_H     | X25519/Ed25519  | Harness        | Decrypting symmetric keys, payloads, and arguments           |


### 4.5. Key Storage

Keys **SHOULD** reside in:

- OS keystores, OR
- Cloud KMS, OR
- Hardware HSMs

Keys **MUST NOT** be written to disk in raw form.

---

## 5. Envelope Construction

### 5.1. EO Encryption Phase

Given **P** and target public key `pk_T`:

1. Generate AES-256 symmetric key `K_sym`.
2. Encrypt **P** with AES-GCM → `Enc_P`.
3. Encrypt `K_sym` for Harness:  
   - Ephemeral X25519  
   - HKDF-SHA256  
   - AES-256-GCM
4. Construct metadata.
5. Compute payload hash:
   ```
   H_payload = SHA256(metadata || Enc_K_sym || Enc_P)
   ```
6. EO signs:
   ```
   sig_EO = Ed25519_sign(sk_EO, H_payload)
   ```
7. Construct inner envelope  
   ```
   E_inner = (magic || version || flags || file_length || sig_EO || metadata || Enc_K_sym || Enc_P)
   ```
8. Encrypt `E_inner` to target's public key (onion encryption):  
   - Ephemeral X25519  
   - HKDF-SHA256 with context "harness-envelope-v1"
   - AES-256-GCM
9. Output encrypted envelope **E** (encrypted to `pk_T`).

### 5.2. Target Approval Phase

Given encrypted envelope **E** and Exploit Owner public key `pk_EO`:

1. Target decrypts **E** using `sk_T` → `E_inner`.
2. Extract `sig_EO` and `H_payload` from `E_inner`.
3. **Verify Exploit Owner signature** (ensures chain-of-custody):
   ```
   Ed25519_verify(pk_EO, H_payload, sig_EO)
   ```
   If verification fails, reject the envelope (payload not signed by expected Exploit Owner).
4. Encrypt arguments for Harness → `Enc_args` (X25519 + AES-256-GCM).
5. Choose expiration `exp` (Unix seconds).
6. Compute:
   ```
   H_target = SHA256(H_payload || exp || Enc_args)
   ```
7. T signs:
   ```
   sig_T = Ed25519_sign(sk_T, H_target)
   ```
8. Append to `E_inner` → produce approved package **A**.

### 5.3. Harness Execution Phase

Given **A**, Harness:

1. Verifies `sig_EO`.
2. Verifies `sig_T`.
3. Checks `now ≤ exp`.
4. Decrypts `Enc_K_sym` → `K_sym` (using `sk_H`).
5. Decrypts `Enc_P` → **P** (using `K_sym`).
6. Decrypts `Enc_args` → `args` (using `sk_H`).
7. Loads **P** into sandbox.
8. Executes and logs results.

**Note:** Harness never sees the encrypted envelope **E** — it only receives the decrypted approved package **A** (which contains `E_inner`).

---

## 6. File Format Specification

### 6.1. Encrypted Envelope Format (E)

The envelope **E** is encrypted to the target's public key. Format (encrypted, in order):

| Field                        | Size     | Description                              |
|------------------------------|----------|------------------------------------------|
| ephemeral_x25519_public_key  | 32       | Ephemeral X25519 public key for key exchange |
| nonce                        | 12       | Random nonce for AES-GCM                 |
| ciphertext+tag               | variable | AES-256-GCM encrypted inner envelope     |

**Inner envelope format (E_inner, after decryption by target):**

| Field                 | Size     | Description                              |
|-----------------------|----------|------------------------------------------|
| magic                 | 4        | Literal "HARN"                           |
| version               | 1        | MUST be 1                                |
| flags                 | 1        | Reserved                                 |
| file_length           | 4        | Total size                               |
| exploit_owner_sig_len | 4        | MUST be 64                               |
| sig_EO                | 64       | EO signature                             |
| metadata_length       | 4        | Length of metadata JSON                  |
| metadata              | variable | Metadata                                 |
| Enc_K_sym             | variable | Wrapped symmetric key (for Harness)      |
| Enc_P                 | variable | Encrypted payload                        |

### 6.2. Approved Package Format (A)

The approved package **A** contains the decrypted inner envelope plus target authorization:

| Field              | Size     | Description                              |
|--------------------|----------|------------------------------------------|
| [E_inner fields]   | —        | All fields from inner envelope (above)   |
| target_sig_len     | 4        | MUST be 64                               |
| sig_T              | 64       | Target signature                         |
| expiration         | 8        | Unix seconds                             |
| args_len           | 4        | Length of encrypted args                 |
| Enc_args           | variable | Encrypted arguments (for Harness)        |

---

## 7. Security Properties

### 7.1. Confidentiality

Payloads remain confidential under X25519+AES-GCM with onion encryption:

- **Inner layer:** Payload encrypted to Harness (X25519 + AES-256-GCM)
- **Outer layer:** Envelope encrypted to Target (X25519 + AES-256-GCM)
- Both layers **MUST** be decrypted before execution

### 7.2. Integrity

EO signatures prevent tampering of payloads.

### 7.3. Authorization

Target signatures prevent unauthorized execution contexts.

### 7.4. Dual Authorization

Both EO and T **MUST** sign before execution is possible.

### 7.5. Onion Encryption Security

The envelope **E** is encrypted to the target's public key, providing:

- E + `sk_H` alone is insufficient — attacker also requires `sk_T`
- Target **MUST** decrypt E before signing (proves target has `sk_T`)
- Reduces risk of envelope compromise in stockpiles
- Each envelope is target-specific (cannot be reused for different targets without re-encryption)

### 7.6. Time Bounding

Execution **MUST** be denied when `now > exp`.

### 7.7. Replay Policy

Replays of the approved package are allowed until expiration.  
Upper layers **MAY** restrict this further.

### 7.8. Chain of Custody

Harness **MUST** log:

- Hashes of payloads
- EO signature hashes
- Target signature hashes
- Decryption operations
- Execution timestamps

This provides reproducible forensic traceability.

---

## 8. Delegation Model

HCEEP treats private keys as capabilities.

### 8.1. Capabilities by Key

| Key Held | Capability                                  |
|----------|---------------------------------------------|
| sk_EO    | Approve payloads                            |
| sk_T     | Decrypt envelopes, approve arguments & expiration |
| sk_H     | Decrypt & execute approved packages         |

### 8.2. Role Merging

Multi-key holders have merged capabilities:

| Keys Held        | Capability                                             |
|------------------|-------------------------------------------------------|
| sk_H + sk_T      | Decrypts envelopes, approves target & executes        |
| sk_H + sk_EO     | Approves payload & executes (cannot decrypt E without sk_T) |
| sk_EO + sk_T     | Approves payload & decrypts envelopes (cannot execute without sk_H) |
| sk_EO + sk_T + sk_H | Full authority                                   |

### 8.3. Tiered Keys

Organizations **MAY** issue:

- `sk_H_low`
- `sk_H_high`

to define risk tiers.

---

## 9. Key Compromise Analysis

Assumes only one key compromised:

| Compromised Key | Attacker Capabilities                      | Limitations                                         |
|-----------------|--------------------------------------------|-----------------------------------------------------|
| sk_EO           | Approve payloads                           | Cannot decrypt or execute                           |
| sk_T            | Decrypt envelopes (E) and approve targets  | Cannot decrypt payload or execute (requires sk_H)   |
| sk_H            | Decrypt approved packages (A) and execute  | Cannot decrypt envelopes (E) without sk_T; cannot forge EO/T signatures |

### 9.4. Full Compromise Requirement

Execution requires:

- `sk_T` to decrypt envelope **E** → `E_inner`
- `sk_H` to decrypt payload from `E_inner`
- `sk_EO` signature (or ability to forge it)

Forgery requires:

- `sk_EO` to forge payload signatures
- `sk_T` to forge target signatures

_No subset suffices for full execution capability._

---

## 10. Fully Paranoid Deployment Profile

This section defines a maximal-security configuration where:

- All long-term private keys reside in HSMs.
- Exploit Owner never sees plaintext payloads.
- Pentester never sees ciphertext or plaintext payloads.
- Target never handles ciphertext.
- Only remote Harness compute enclaves see transient plaintext.
- The pentester interacts only with an RPC/Lambda interface.

### 10.1. Actors and HSM Boundaries

- EO-HSM holds `sk_EO`.
- Target-HSM/KMS holds `sk_T`.
- Harness-HSM holds `sk_H`.
- Build Enclave handles plaintext only transiently.
- Execution Enclave handles plaintext only transiently.

### 10.2. Phase 0 — Build & Sealing

1. EA submits source → Build Enclave.
2. Build Enclave compiles to **P**.
3. Build Enclave obtains `K_sym` via HSM-mediated generation.
4. Build Enclave encrypts **P** → `Enc_P` and immediately wipes plaintext.
5. Build Enclave requests EO-HSM to compute `sig_EO` over `H_payload`.
6. Build Enclave encrypts inner envelope `E_inner` to target's public key `pk_T` → **E**.
7. Encrypted envelope **E** is stored securely.
8. EO never sees plaintext.
9. **E** cannot be decrypted without `sk_T`.

### 10.3. Phase 1 — Target Approval

1. Pentester selects exploit by name/version (metadata only).
2. Control plane fetches **E** without exposing ciphertext to the client.
3. Target-HSM decrypts **E** using `sk_T` → `E_inner`.
4. Control plane verifies Exploit Owner signature using `pk_EO` (ensures chain-of-custody).
5. Client provides arguments in a UI.
6. Control plane encrypts args using `pk_H` (via HSM).
7. Control plane computes `H_target` from `E_inner`.
8. Target-HSM signs `H_target`.
9. Produce approved package **A** from `E_inner` + `sig_T` + expiration + `Enc_args`.
10. Target never sees plaintext payload.
11. `E_inner` is discarded after **A** is created.

### 10.4. Phase 2 — Execution (Remote)

1. Pentester triggers execution via RPC.
2. Harness Execution Enclave fetches **A**.
3. Verifies both signatures.
4. Calls Harness-HSM to decrypt:  
   - `Enc_K_sym` → `K_sym`  
   - `Enc_P` → **P**  
   - `Enc_args` → `args`
5. Loads **P** into sandbox (no disk write).
6. Executes exploit.
7. Wipes plaintext from memory.
8. Returns structured results.

*Pentester never interacts with ciphertext or plaintext.*

---

## 11. Threat Model

**HCEEP ASSUMES:**
- Cryptographic primitives are secure.
- HSMs enforce key isolation.
- Execution enclaves are hardened.

**HCEEP DOES NOT ASSUME:**
- Pentester hosts are secure.
- EO or client workstations are secure.

*Yet confidentiality and authorization remain intact.*

---

## 12. Security Considerations

- EO, T, and H **SHOULD** use separate HSMs.
- Transport-layer security **SHOULD** be applied for RPC paths.
- Logs **SHOULD** be centrally aggregated and tamper-evident.
- Payload plaintext **SHOULD NEVER** be written to disk outside an enclave.
- Expiration **SHOULD** be kept tight (hours to days).
- Cross-tenant attacks are mitigated via explicit key usage contexts.
- Onion encryption reduces risk of envelope compromise: E + `sk_H` alone is insufficient — attacker also requires `sk_T` to decrypt and execute.
- Envelopes (E) encrypted to target public keys **SHOULD** be stored with access controls appropriate for their sensitivity.

---

## 13. IANA Considerations

None.

---

## 14. Appendix A — Example Operation Log

Example fields:

| Field                         | Value                  |
|-------------------------------|------------------------|
| time                          | 2025-12-02T20:37:04Z   |
| event                         | execution              |
| encrypted_payload_hash_sha256 | 06bb1577...            |
| exploit_binary_hash_sha256    | c30694d8...            |
| exploit_owner_signature_hash_sha256 | 30811a6e...    |
| target_signature_hash_sha256  | 5a20602b...            |
| harness_public_key_hash_sha256| 1fc9ce73...            |
| args_hash_sha256              | 14fa991e...            |

---

## 15. Appendix B — Rationale

**Avoiding ASN.1**  
Ed25519 signatures are fixed-length and avoid parsing issues.

**Statelessness**  
State belongs in the organization’s orchestration/CMS system.  
HCEEP supplies only the cryptographic proofs.

**Replay Policy**  
Time-bounded replay is essential for multi-step exploitation.  
Upper layers can tighten if desired.

---

## 16. Appendix C — Summary

HCEEP is a dual-authorization, onion-encrypted, stateless, auditable execution envelope that:

- Preserves payload confidentiality via onion encryption (encrypted to both Target and Harness)
- Enforces cryptographic approval (EO + Target signatures required)
- Reduces envelope compromise risk (E + `sk_H` alone is insufficient — requires `sk_T`)
- Offers explicit key-based delegation
- Provides perfect chain-of-custody
- Supports HSM-only paranoid deployments
- Allows arbitrary payload formats via loaders
- Avoids key leakage entirely

*This is the first protocol designed to govern high-risk exploit execution with cryptographic guarantees and onion encryption for enhanced security.*

