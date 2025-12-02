// Package keystore provides a unified interface for cryptographic operations without exposing private keys.
// This design allows keys to remain in secure storage (HSMs, cloud KMS, Secure Enclave, TPM)
// and never be loaded into host memory. Implementations can swap in hardware-backed
// or cloud-based key storage transparently.
package keystore

import "crypto/ed25519"

// Keystore interface for cryptographic operations without exposing private keys.
//
// This design allows keys to remain in secure storage (HSMs, cloud KMS, Secure Enclave, TPM)
// and never be loaded into host memory. Implementations can swap in hardware-backed
// or cloud-based key storage transparently.
//
// Platform-specific implementations are available for:
//   - macOS: Keychain Access
//   - Linux: libsecret/keyring
//   - Windows: Credential Manager
//
// Custom implementations can be registered using RegisterKeystore to support
// additional platforms or keystore backends (e.g., cloud KMS, TPM).
type Keystore interface {
	// GetPublicKey retrieves the public key associated with a key ID.
	// This is safe to expose as public keys are not sensitive.
	GetPublicKey(keyID string) (ed25519.PublicKey, error)

	// Sign signs the provided data hash using the private key associated with keyID.
	// The private key never leaves secure storage (HSM, cloud KMS, Secure Enclave, TPM).
	// Returns the raw Ed25519 signature (64 bytes).
	Sign(keyID string, hash []byte) ([]byte, error)

	// DecryptWithContext decrypts data encrypted via X25519 with a specific HKDF context.
	//
	// The encryptedKey format is: [ephemeral_public_key:32][nonce:12][ciphertext+tag]
	// The private key never leaves secure storage - X25519 computation happens in hardware/cloud.
	//
	// The context parameter specifies the HKDF context string used for key derivation:
	//   - "harness-symmetric-key-v1" for decrypting symmetric keys
	//   - "harness-args-v1" for decrypting execution arguments
	//
	// Returns the decrypted data.
	DecryptWithContext(keyID string, encryptedKey []byte, context string) ([]byte, error)

	// SetPrivateKey stores a private key in the keystore (for key generation/import).
	// Note: For hardware-backed keystores, this may generate a key pair in hardware
	// and only store a reference. The actual private key material may never be accessible.
	SetPrivateKey(keyID string, privateKey ed25519.PrivateKey) error

	// ListKeys returns all key IDs stored in the keystore.
	// This can be used to discover available keys or verify key existence.
	ListKeys() ([]string, error)
}
