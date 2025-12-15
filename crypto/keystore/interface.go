// Package keystore provides a unified interface for cryptographic operations without exposing private keys.
// This design allows keys to remain in secure storage (HSMs, cloud KMS, Secure Enclave, TPM)
// and never be loaded into host memory. Implementations can swap in hardware-backed
// or cloud-based key storage transparently.
//
// The Keystore interface exposes primitives only, not workflows. Higher-level operations
// (like signing encrypted payloads, verifying chains of custody) should be composed
// from these primitives by the caller.
package keystore

import "crypto/ed25519"

// KeyID is a stable identifier for a key in the keystore.
// It can be derived from config, file name, fingerprint, or any other stable source.
// KeyID is used for logging, rotation, and chain-of-custody tracking.
type KeyID string

// Context specifies domain separation / Additional Authenticated Data (AAD) for cryptographic operations.
// Using different contexts for different operations prevents cross-protocol attacks.
//
// Example contexts:
//   - "harness:payload" for encrypting/decrypting plugin payloads
//   - "harness:payload-signature" for signing/verifying payload signatures
//   - "harness:args" for encrypting/decrypting execution arguments
//   - "harness:envelope" for encrypting/decrypting onion envelope layers
type Context []byte

// Keystore represents a cryptographic backend bound to a specific key identity.
//
// Implementations may be:
//   - OS keystore (macOS Keychain, Linux keyring, Windows Credential Manager)
//   - HSM / cloud KMS
//   - in-memory (for dev/tests)
//
// The interface exposes primitives only (SignDirect, VerifyDirect, EncryptFor, Decrypt).
// Higher-level workflows should compose these primitives explicitly, making
// verification targets clear (e.g., "verify EO signature" vs "verify client signature").
//
// Platform-specific implementations are available for:
//   - macOS: Keychain Access
//   - Linux: libsecret/keyring
//   - Windows: Credential Manager
//
// Custom implementations can be registered using RegisterKeystore to support
// additional platforms or keystore backends (e.g., cloud KMS, TPM).
type Keystore interface {
	// KeyID returns the stable identifier for this keystore's key.
	// This is used for logging, rotation tracking, and chain-of-custody.
	KeyID() KeyID

	// PublicKey returns the Ed25519 public key for this keystore's key.
	// The returned slice is 32 bytes (ed25519.PublicKeySize).
	PublicKey() (ed25519.PublicKey, error)

	// PublicKeyX25519 returns the X25519 public key derived from this keystore's Ed25519 key.
	// The returned array is 32 bytes, suitable for X25519 key exchange.
	// This is the Montgomery-form public key converted from the Ed25519 public key.
	PublicKeyX25519() ([32]byte, error)

	// SignDirect creates an Ed25519 signature directly over the message bytes without hashing.
	//
	// This method is used for HCEEP v0.3+ canonical transcript signing, where the transcript
	// already includes domain separation (context string as first field) and identity binding.
	// The message bytes are signed directly with Ed25519 without any pre-hashing.
	//
	// Returns a 64-byte Ed25519 signature.
	SignDirect(msg []byte) (sig []byte, err error)

	// VerifyDirect checks an Ed25519 signature directly against the message bytes without hashing.
	//
	// This method is used for HCEEP v0.3+ canonical transcript verification, where the transcript
	// already includes domain separation and identity binding. The signature is verified directly
	// against the message bytes without any pre-hashing.
	//
	// Returns nil if the signature is valid, or an error if verification fails.
	VerifyDirect(pubKey ed25519.PublicKey, msg, sig []byte) error

	// EncryptFor encrypts plaintext for a recipient using hybrid encryption.
	//
	// The encryption process:
	//   1. Generates an ephemeral X25519 keypair
	//   2. Computes shared secret: X25519(ephemeral_private, recipient_public)
	//   3. Derives AES-256 key using HKDF-SHA256 with the context as info
	//   4. Encrypts plaintext with AES-256-GCM
	//
	// Wire format: [ephemeral_x25519_public_key:32][nonce:12][ciphertext+tag]
	//
	// The context parameter provides domain separation for key derivation.
	// Different contexts produce different encryption keys from the same shared secret.
	//
	// Returns the ciphertext and this keystore's KeyID (for logging/chain-of-custody).
	// The recipientPub should be a 32-byte X25519 public key.
	EncryptFor(recipientPub [32]byte, plaintext []byte, context Context) (ciphertext []byte, senderKeyID KeyID, err error)

	// Decrypt decrypts ciphertext that was encrypted to this keystore's key.
	//
	// The decryption process:
	//   1. Extracts ephemeral public key from ciphertext
	//   2. Computes shared secret: X25519(this_key_private, ephemeral_public)
	//   3. Derives AES-256 key using HKDF-SHA256 with the context as info
	//   4. Decrypts with AES-256-GCM
	//
	// The context parameter MUST match the context used during encryption.
	//
	// Returns the plaintext and this keystore's KeyID (for logging/chain-of-custody).
	Decrypt(ciphertext []byte, context Context) (plaintext []byte, receiverKeyID KeyID, err error)
}

// KeyManager provides key management operations (creation, import, listing).
// This is separate from Keystore to allow for different access patterns -
// key management may require elevated privileges or different auth than
// normal cryptographic operations.
type KeyManager interface {
	// SetPrivateKey stores a private key in the keystore (for key generation/import).
	// Note: For hardware-backed keystores, this may generate a key pair in hardware
	// and only store a reference. The actual private key material may never be accessible.
	SetPrivateKey(id KeyID, privateKey ed25519.PrivateKey) error

	// ListKeys returns all key IDs stored in the keystore.
	// This can be used to discover available keys or verify key existence.
	ListKeys() ([]KeyID, error)
}
