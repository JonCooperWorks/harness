package keystore

import "crypto/ecdsa"

// Keystore interface for cryptographic operations without exposing private keys
// This design allows keys to remain in secure storage (HSMs, cloud KMS, Secure Enclave, TPM)
// and never be loaded into host memory. Implementations can swap in hardware-backed
// or cloud-based key storage transparently.
type Keystore interface {
	// GetPublicKey retrieves the public key associated with a key ID
	// This is safe to expose as public keys are not sensitive
	GetPublicKey(keyID string) (*ecdsa.PublicKey, error)

	// Sign signs the provided data hash using the private key associated with keyID
	// The private key never leaves secure storage (HSM, cloud KMS, Secure Enclave, TPM)
	// Returns the ASN.1 DER-encoded ECDSA signature (R, S values)
	Sign(keyID string, hash []byte) ([]byte, error)

	// DecryptWithContext decrypts data encrypted via ECDH with a specific HKDF context
	// The encryptedKey format is: [ephemeral_public_key:65][nonce:12][ciphertext+tag]
	// The private key never leaves secure storage - ECDH computation happens in hardware/cloud
	// Returns the decrypted data
	// context specifies the HKDF context string (e.g., "harness-args-v1" for arguments)
	DecryptWithContext(keyID string, encryptedKey []byte, context string) ([]byte, error)

	// SetPrivateKey stores a private key in the keystore (for key generation/import)
	// Note: For hardware-backed keystores, this may generate a key pair in hardware
	// and only store a reference. The actual private key material may never be accessible.
	SetPrivateKey(keyID string, privateKey *ecdsa.PrivateKey) error

	// ListKeys returns all key IDs stored in the keystore
	ListKeys() ([]string, error)
}
