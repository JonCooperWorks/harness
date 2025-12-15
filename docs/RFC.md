
# HCEEP — Harness Cryptographic Execution Envelope Protocol

**Draft RFC 0.3**

- **Status:** Draft  
- **Author:** Jonathan Cooper  
- **Intended Status:** Informational / Standards Track  
- **Expires:** TBD

### Changes from 0.2

- **Canonical Transcript Encoding (5.0)**: Added explicit canonical encoding specification requiring length-prefixed fields, explicit field order, fixed endianness (big-endian), and rejection of non-canonical encodings to prevent transcript ambiguity attacks.

- **Identity Binding (5.1, 5.2)**: Signature transcripts now include SHA-256 hashes of `pk_EO`, `pk_T`, and `pk_H` to cryptographically bind identities and prevent key substitution attacks. KeyIDs remain operational identifiers; cryptographic identity is established via public key hashes.

- **Direct Transcript Signing (5.1, 5.2)**: Replaced hash-then-sign semantics (`Ed25519_sign(SHA256(...))`) with direct transcript signing (`Ed25519_sign(sk, canonical_transcript_bytes)`). Domain separation achieved by prepending context string as first field of transcript.

- **Explicit Transcript Definitions (5.1, 5.2)**: Defined exact byte-level transcript structures for both EO and Target signatures with normative field ordering and encoding requirements.

- **Approved Package Authorization Model (5.3.1)**: Added explicit clarification that Approved Package **A** is NOT a bearer token. Execution requires `sk_H` and, in remote deployments, authenticated access to Harness service.

- **AEAD Authentication (5.1, 5.2)**: Specified Associated Authenticated Data (AAD) requirements for all encryption operations to prevent header manipulation and ciphertext substitution attacks.

- **Threat Model Updates (11)**: Explicitly closed key substitution attacks, identity confusion, and transcript ambiguity attacks with detailed mitigation descriptions.

- **Replay Semantics Clarification (7.7)**: Clarified that replay within expiration is intentional and enables multi-step exploitation, while noting higher layers may impose additional restrictions.

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
- Optional paranoid mode eliminating key exposure, with split architecture where approved package **A** and `sk_H` are separated: `sk_H` is held by a remote ephemeral service provided by EO, accessible only to the pentester, and the service is useless without **A**

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
Used for signing canonical transcripts that include encrypted payload, identity hashes, and metadata (see section 5.1 for exact transcript definition).

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
| sk_EO    | Ed25519         | Exploit Owner  | Signing canonical transcripts with identity binding         |
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

### 5.0. Canonical Transcript Encoding

All signed material in HCEEP **MUST** use a canonical byte encoding to ensure deterministic signature verification and prevent transcript ambiguity attacks. This section defines the canonical encoding rules that apply to all signature transcripts.

**Encoding Rules:**

1. **Length Prefixing:** All variable-length fields **MUST** be prefixed with their length as a uint32 (4 bytes, big-endian). Fixed-length fields do not require length prefixes.

2. **Field Order:** Fields **MUST** appear in the exact order specified in the transcript definition. Any deviation invalidates the signature.

3. **Endianness:** All multi-byte integers **MUST** use big-endian byte order (network byte order).

4. **String Encoding:** Context strings and other text fields **MUST** be encoded as UTF-8 bytes and length-prefixed.

5. **Rejection of Non-Canonical Encodings:** Implementations **MUST** reject any signature verification attempt where the transcript does not match the canonical encoding exactly.

**Example Canonical Encoding:**

For a variable-length string field:
```
[length:4][string_bytes:variable]
```

Where `length` is a uint32 (big-endian) containing the byte length of `string_bytes`.

For fixed-length fields like public key hashes (32 bytes):
```
[hash_bytes:32]
```

No length prefix is required for fixed-length fields.

**Reference:** All signature transcript definitions in sections 5.1 and 5.2 reference this canonical encoding specification.

### 5.1. EO Encryption Phase

Given **P** and target public key `pk_T`:

1. Generate AES-256 symmetric key `K_sym`.
2. Encrypt **P** with AES-GCM → `Enc_P`.
   
   **AAD:** The encryption context **MUST** include metadata about the payload (e.g., plugin type, name) as Associated Authenticated Data to prevent ciphertext substitution attacks.

3. Encrypt `K_sym` for Harness:  
   - Ephemeral X25519  
   - HKDF-SHA256 with context "harness-symmetric-key-v1"
   - AES-256-GCM
   
   **AAD:** The encryption context "harness-symmetric-key-v1" **MUST** be used as AAD to authenticate the key encryption operation and prevent key substitution attacks.
4. Construct metadata.
5. Build encrypted payload:
   ```
   encrypted_payload = [metadata_length:4][metadata][Enc_K_sym][Enc_P]
   ```
6. Compute identity hashes for cryptographic binding:
   - `H(pk_EO) = SHA-256(pk_EO)` (32 bytes)
   - `H(pk_T) = SHA-256(pk_T)` (32 bytes)
   - `H(pk_H) = SHA-256(pk_H)` (32 bytes)
   
   These hashes cryptographically bind the signature to the intended Exploit Owner, Target, and Harness identities, preventing key substitution attacks.

7. Build canonical EO signature transcript (see section 5.0 for encoding rules):
   
   The EO signature transcript **MUST** be constructed exactly as follows, in order:
   1. Context string (length-prefixed): `"harness-payload-signature-v1"`
   2. Protocol version (uint32, big-endian): `version`
   3. Flags (uint32, big-endian): `flags`
   4. `H(pk_EO)` (32 bytes, fixed-length): SHA-256 hash of Exploit Owner public key
   5. `H(pk_T)` (32 bytes, fixed-length): SHA-256 hash of Target public key
   6. `H(pk_H)` (32 bytes, fixed-length): SHA-256 hash of Harness public key
   7. Metadata (length-prefixed): `[metadata_length:4][metadata]`
   8. Encrypted payload blob (length-prefixed): `[encrypted_payload_length:4][encrypted_payload]`
   
   Domain separation is achieved by prepending the context string as the first field of the transcript, not via pre-hashing.

8. Sign the canonical transcript:
   ```
   sig_EO = Ed25519_sign(sk_EO, canonical_transcript_bytes)
   ```
   
   The signature is computed directly over the canonical transcript bytes. Any mismatch in field order, encoding, or content invalidates the signature.

9. Construct inner envelope  
   ```
   E_inner = (magic || version || flags || file_length || sig_EO || metadata || Enc_K_sym || Enc_P)
   ```
   
   Note: The inner envelope format does not include identity hashes in the wire format; they are only part of the signed transcript.

10. Encrypt `E_inner` to target's public key (onion encryption):  
    - Ephemeral X25519  
    - HKDF-SHA256 with context "harness-envelope-v1"
    - AES-256-GCM
    - **AAD:** The encryption context "harness-envelope-v1" **MUST** be used as AAD. Additionally, the magic bytes, version, and flags from `E_inner` **MUST** be authenticated either via AAD or via signature binding (the EO signature covers these fields in the transcript) to prevent header manipulation attacks.

11. Output encrypted envelope **E** (encrypted to `pk_T`).

### 5.2. Target Approval Phase

Given encrypted envelope **E**, Exploit Owner public key `pk_EO`, Target public key `pk_T`, and Harness public key `pk_H`:

1. Target decrypts **E** using `sk_T` → `E_inner`.
   
   **AAD:** The magic bytes, version, and flags from `E_inner` **MUST** be authenticated via the AEAD decryption to prevent header manipulation.

2. Extract `sig_EO` and `encrypted_payload` from `E_inner`.

3. Compute identity hashes for signature verification:
   - `H(pk_EO) = SHA-256(pk_EO)` (32 bytes)
   - `H(pk_T) = SHA-256(pk_T)` (32 bytes)
   - `H(pk_H) = SHA-256(pk_H)` (32 bytes)

4. **Verify Exploit Owner signature** (ensures chain-of-custody):
   
   Reconstruct the canonical EO signature transcript exactly as specified in section 5.1, step 7, using the extracted `encrypted_payload`, `version`, `flags`, and the computed identity hashes. Verify:
   ```
   Ed25519_verify(pk_EO, canonical_transcript_bytes, sig_EO)
   ```
   
   If verification fails, reject the envelope (payload not signed by expected Exploit Owner or transcript mismatch).

5. Encrypt arguments for Harness → `Enc_args` (X25519 + AES-256-GCM).
   
   **AAD:** The encryption context "harness-args-v1" **MUST** be used as AAD to authenticate the encryption operation.

6. Choose expiration `exp` (Unix seconds, uint64, big-endian).

7. Build canonical Target signature transcript (see section 5.0 for encoding rules):
   
   The Target signature transcript **MUST** be constructed exactly as follows, in order:
   1. Context string (length-prefixed): `"harness-client-signature-v1"`
   2. Protocol version (uint32, big-endian): `version`
   3. Flags (uint32, big-endian): `flags`
   4. `H(pk_EO)` (32 bytes, fixed-length): SHA-256 hash of Exploit Owner public key
   5. `H(pk_T)` (32 bytes, fixed-length): SHA-256 hash of Target public key
   6. `H(pk_H)` (32 bytes, fixed-length): SHA-256 hash of Harness public key
   7. Encrypted payload blob (length-prefixed): `[encrypted_payload_length:4][encrypted_payload]`
   8. Encrypted arguments (length-prefixed): `[encrypted_args_length:4][Enc_args]`
   9. Expiration timestamp (uint64, big-endian): `exp`
   
   Domain separation is achieved by prepending the context string as the first field of the transcript, not via pre-hashing.

8. Sign the canonical transcript:
   ```
   sig_T = Ed25519_sign(sk_T, canonical_transcript_bytes)
   ```
   
   The signature is computed directly over the canonical transcript bytes. Any mismatch in field order, encoding, or content invalidates the signature.

9. The Target signature explicitly scopes approval to:
   - This specific encrypted payload
   - These specific encrypted arguments
   - This specific time window (expiration)
   - These specific identities (bound via `H(pk_EO)`, `H(pk_T)`, `H(pk_H)`)

10. Append to `E_inner` → produce approved package **A**.

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

### 5.3.1. Approved Package Authorization Model

The Approved Package **A** is **NOT** a bearer token. This section clarifies the authorization model to explicitly reject the "bearer token" characterization.

**Authorization Requirements:**

1. **Execution Requires `sk_H`:** The Approved Package **A** **MUST NOT** be executed without access to the Harness private key `sk_H`. Possession of **A** alone does **NOT** grant execution capability.

2. **Decryption Dependency:** Execution requires decryption operations that depend on `sk_H`:
   - Decryption of `Enc_K_sym` → `K_sym` (requires `sk_H`)
   - Decryption of `Enc_P` → **P** (requires `K_sym`, which requires `sk_H`)
   - Decryption of `Enc_args` → `args` (requires `sk_H`)

3. **Remote Harness Deployments:** In remote Harness deployments where **A** is transmitted over a network:
   - Callers **MUST** authenticate to the Harness service using orthogonal authentication mechanisms (e.g., TLS client certificates, API keys, OAuth tokens)
   - Authorization to invoke Harness is a control plane concern separate from the cryptographic authorization provided by **A**
   - The Harness service **MUST** verify both the cryptographic signatures in **A** and the caller's authenticated identity before processing

4. **Replay Within Expiration:** Replay of **A** within the expiration window is intentional and by design (see section 7.7). This enables multi-step exploitation workflows. However, replay does not grant new capabilities — each execution still requires:
   - Valid signatures (`sig_EO` and `sig_T`)
   - Access to `sk_H` for decryption
   - Unexpired timestamp
   - Authenticated access to the Harness service (in remote deployments)

**Security Properties:**

- **A** + `sk_H` together enable execution, but **A** alone is insufficient
- Key substitution attacks are prevented by identity hashes in signature transcripts (see sections 5.1 and 5.2)
- The dual-authorization model ensures both EO and Target must approve before execution is possible
- Onion encryption ensures that even with **A**, an attacker cannot decrypt the payload without `sk_H`

**Explicit Rejection of Bearer Token Model:**

The Approved Package **A** does **NOT** function as a bearer token because:
- Execution requires cryptographic operations that depend on `sk_H`, which is not contained in **A**
- Possession of **A** does not grant the ability to execute without additional authorization (access to `sk_H` and, in remote deployments, authenticated access to the Harness service)
- The protocol's security model relies on the separation of **A** and `sk_H`, not on the secrecy of **A** itself

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
| version               | 1        | Version: 2 (with version/flags binding) |
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

Replay of approved packages within the expiration window is **intentional and by design**. This enables multi-step exploitation workflows where the same approved package may need to be executed multiple times as part of a coordinated attack sequence.

**Replay Semantics:**

- Approved packages **MAY** be executed multiple times as long as `now ≤ exp`
- Each execution still requires:
  - Valid EO signature (`sig_EO`)
  - Valid Target signature (`sig_T`)
  - Access to `sk_H` for decryption
  - Authenticated access to Harness (in remote deployments)
- Replay does **NOT** grant new capabilities beyond what was originally authorized

**Higher-Layer Controls:**

Upper layers **MAY** impose additional restrictions:
- One-time execution policies (tracking executed packages by signature hash)
- Rate-limited execution policies (limiting executions per time window)
- Per-caller execution quotas
- Other application-specific controls

However, these controls are **orthogonal** to the HCEEP protocol itself. HCEEP provides the cryptographic foundation; higher layers provide operational controls.

**Rationale:**

Time-bounded replay is essential for multi-step exploitation where:
- Initial reconnaissance may require multiple executions
- Exploitation steps may need to be retried
- Post-exploitation activities may span multiple sessions
- Coordination between different tools may require shared approved packages

The expiration window provides the time boundary; higher layers provide the operational boundaries.

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
- In paranoid mode, the approved package **A** and `sk_H` are split: `sk_H` is held by a remote ephemeral service provided by EO, accessible only to the pentester.

### 10.1. Actors and HSM Boundaries

- EO-HSM holds `sk_EO`.
- Target-HSM/KMS holds `sk_T`.
- Harness-HSM holds `sk_H` (in standard mode).
- Remote Ephemeral Service (provided by EO) holds `sk_H` (in paranoid mode).
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

**Standard Mode:**
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

**Paranoid Mode:**
1. Pentester sends approved package **A** to remote ephemeral service (provided by EO).
2. Remote ephemeral service verifies both signatures (`sig_EO` and `sig_T`).
3. Remote ephemeral service checks expiration (`now ≤ exp`).
4. Remote ephemeral service uses `sk_H` to decrypt:  
   - `Enc_K_sym` → `K_sym`  
   - `Enc_P` → **P**  
   - `Enc_args` → `args`
5. Remote ephemeral service loads **P** into sandbox (no disk write).
6. Remote ephemeral service executes exploit.
7. Remote ephemeral service wipes plaintext from memory.
8. Remote ephemeral service returns structured results to pentester.

**Security Properties of Paranoid Mode:**
- The remote ephemeral service is useless without **A** — it can only decrypt and run approved packages.
- `sk_H` never leaves the remote ephemeral service.
- Pentester never has access to `sk_H` or plaintext payloads.
- The service can only be used by the pentester (access-controlled by EO).
- **A** and `sk_H` are cryptographically split: execution requires both.

*Pentester never interacts with ciphertext or plaintext, and never has access to `sk_H`.*

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

### 11.1. Mitigated Threats

HCEEP explicitly mitigates the following attack vectors:

**Key Substitution Attacks:**
- **Threat:** An attacker attempts to substitute a different public key (`pk_EO'`, `pk_T'`, or `pk_H'`) while keeping the same KeyID, allowing them to use their own keypair to forge signatures or decrypt content intended for a different party.
- **Mitigation:** Identity hashes (`H(pk_EO)`, `H(pk_T)`, `H(pk_H)`) are cryptographically bound into signature transcripts (sections 5.1 and 5.2). Any attempt to substitute a key results in a signature verification failure, as the identity hash in the transcript will not match the hash of the substituted key.
- **Result:** Signatures are explicitly bound to specific public keys, not just KeyIDs. KeyIDs remain operational identifiers for logging and key management, but cryptographic identity is established via public key hashes in transcripts.

**Identity Confusion:**
- **Threat:** An attacker attempts to reuse an approved package **A** with a different Harness, Target, or Exploit Owner by exploiting ambiguity about which identities the approval applies to.
- **Mitigation:** All three identity hashes (`H(pk_EO)`, `H(pk_T)`, `H(pk_H)`) are included in both EO and Target signature transcripts. The Target signature explicitly scopes approval to these three identities (section 5.2, step 9).
- **Result:** Approved packages are cryptographically bound to the specific Exploit Owner, Target, and Harness identities. Reuse with different identities is cryptographically prevented.

**Transcript Ambiguity:**
- **Threat:** An attacker attempts to exploit ambiguity in how signature transcripts are encoded, allowing the same signature to be valid for multiple different messages (e.g., by changing field boundaries, endianness, or encoding).
- **Mitigation:** Canonical transcript encoding (section 5.0) requires:
  - Length-prefixed variable-length fields (uint32, big-endian)
  - Explicit field order
  - Fixed endianness (big-endian)
  - Rejection of non-canonical encodings
- **Result:** There is exactly one valid encoding for any given transcript content. Any deviation from canonical encoding results in signature verification failure.

**Header Manipulation:**
- **Threat:** An attacker attempts to modify magic bytes, version, or flags fields to change protocol behavior or exploit version-specific vulnerabilities.
- **Mitigation:** 
  - Magic bytes, version, and flags are authenticated via AEAD AAD or signature binding (sections 5.1 and 5.2)
  - Version and flags are included in signature transcripts, binding them to signatures
- **Result:** Header manipulation is cryptographically detected and rejected.

### 11.2. Out-of-Scope Threats

The following threats remain out of scope for HCEEP:

- **Compromised Harness Hosts:** If a Harness host is fully compromised (including `sk_H`), the attacker can execute approved packages. HCEEP does not protect against host-level compromise.
- **Compromised Target or Exploit Owner Hosts:** If a Target or Exploit Owner host is compromised (including `sk_T` or `sk_EO`), the attacker can create or approve packages. HCEEP does not protect against host-level compromise.
- **Insider Threats:** If an insider has access to multiple keys (e.g., both `sk_T` and `sk_H`), they can execute packages. HCEEP's dual-authorization model assumes keys are held by independent parties.
- **Host-Level Malware:** Kernel exploits, rootkits, or other host-level malware that can intercept keys or modify execution are out of scope.
- **Social Engineering:** Attacks that convince key holders to perform unauthorized operations are out of scope.

HCEEP provides cryptographic guarantees assuming the underlying host security model. Operational security (host hardening, access controls, monitoring) is the responsibility of deployment organizations.

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
- Supports paranoid mode where approved package **A** and `sk_H` are split: `sk_H` is held by a remote ephemeral service provided by EO, accessible only to the pentester, and the service is useless without **A** (can only decrypt and run approved packages)
- Allows arbitrary payload formats via loaders
- Avoids key leakage entirely

*This is the first protocol designed to govern high-risk exploit execution with cryptographic guarantees and onion encryption for enhanced security.*

