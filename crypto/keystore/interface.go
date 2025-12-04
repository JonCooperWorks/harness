// Package keystore provides a unified interface for cryptographic operations without exposing private keys.
// This design allows keys to remain in secure storage (HSMs, cloud KMS, Secure Enclave, TPM)
// and never be loaded into host memory. Implementations can swap in hardware-backed
// or cloud-based key storage transparently.
package keystore

import "crypto/ed25519"

// KeyID selects which local key in this keystore to use.
// It does NOT change algorithms – just which Ed25519/X25519 pair.
type KeyID string

// Keystore represents this program's cryptographic backend.
//
// Implementations may be:
//   - OS keystore
//   - HSM / cloud KMS
//   - in-memory (for dev/tests)
//
// It never exposes private keys. It only:
//   - returns public keys for a given keyID
//   - signs digests with Ed25519
//   - does X25519 ECDH with the peer's public key
//
// Platform-specific implementations are available for:
//   - macOS: Keychain Access
//   - Linux: libsecret/keyring
//   - Windows: Credential Manager
//
// Custom implementations can be registered using RegisterKeystore to support
// additional platforms or keystore backends (e.g., cloud KMS, TPM).
type Keystore interface {
	// PublicEd25519 returns the Ed25519 public key for keyID.
	PublicEd25519(id KeyID) (ed25519.PublicKey, error)

	// PublicX25519 returns the X25519 public key for keyID (32 bytes).
	PublicX25519(id KeyID) ([32]byte, error)

	// SignDigest signs a canonical digest with the Ed25519 private key for keyID.
	//
	// In HCEEP this is used for:
	//   - EO: H_payload
	//   - Target: H_target
	//
	// Callers are responsible for constructing the correct digest as per the RFC.
	SignDigest(id KeyID, digest []byte) ([]byte, error)

	// ECDH computes X25519(shared = sk(id) ⊗ peerPublic).
	//
	// In HCEEP this is used for:
	//   - Target: decrypt outer envelope E
	//   - Harness: unwrap Enc_K_sym and Enc_args
	//
	// Callers then run HKDF + AES-GCM using this shared secret.
	ECDH(id KeyID, peerPublic [32]byte) (sharedSecret [32]byte, err error)

	// SetPrivateKey stores a private key in the keystore (for key generation/import).
	// Note: For hardware-backed keystores, this may generate a key pair in hardware
	// and only store a reference. The actual private key material may never be accessible.
	SetPrivateKey(id KeyID, privateKey ed25519.PrivateKey) error

	// ListKeys returns all key IDs stored in the keystore.
	// This can be used to discover available keys or verify key existence.
	ListKeys() ([]KeyID, error)
}
