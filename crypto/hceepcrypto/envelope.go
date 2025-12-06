// Package hceepcrypto provides HCEEP-specific cryptographic operations built on top of the keystore.
// It implements the envelope encryption format used for HCEEP protocol.
package hceepcrypto

import (
	"github.com/joncooperworks/harness/crypto/keystore"
)

// Context specifies the HKDF context string used for key derivation.
// These are the standard contexts used in the HCEEP protocol.
type Context = keystore.Context

// Standard contexts for HCEEP protocol operations.
var (
	// ContextSymmetricKey is used for encrypting/decrypting symmetric keys.
	ContextSymmetricKey Context = []byte("harness-symmetric-key-v1")
	// ContextArgs is used for encrypting/decrypting execution arguments.
	ContextArgs Context = []byte("harness-args-v1")
	// ContextEnvelope is used for encrypting/decrypting envelopes (onion encryption).
	ContextEnvelope Context = []byte("harness-envelope-v1")
	// ContextPayloadSignature is used for signing/verifying encrypted payload hashes.
	// EO (exploit owner) signs with this context when encrypting.
	ContextPayloadSignature Context = []byte("harness-payload-signature-v1")
	// ContextClientSignature is used for signing/verifying client approval.
	// Target/client signs with this context when approving execution.
	ContextClientSignature Context = []byte("harness-client-signature-v1")
)

// EnvelopeCipher uses a bound Keystore to encrypt/decrypt blobs for HCEEP.
//
// This is a thin wrapper around the Keystore interface, providing
// context-aware encryption/decryption for the HCEEP protocol.
//
// Wire format (for each blob) is:
//
//	[ephemeral_x25519_public_key:32][nonce:12][ciphertext+tag]
type EnvelopeCipher interface {
	// EncryptToPeer encrypts plaintext for peerPubX using this keystore's identity
	// as the sender, with the given HKDF context.
	//
	// Steps (inside impl):
	//  - generate ephemeral X25519 keypair locally
	//  - shared = X25519(ephemeral_priv, peerPubX)
	//  - derive AES-GCM key with HKDF(shared, ctx)
	//  - encrypt plaintext with AES-256-GCM
	//  - output: ephPub || nonce || ciphertext+tag
	EncryptToPeer(peerPubX [32]byte, ctx Context, plaintext []byte) ([]byte, error)

	// DecryptFromPeer decrypts a blob that was encrypted to us (this keystore's key).
	//
	// Steps (inside impl):
	//  - parse ephPub, nonce from blob
	//  - shared = keystore.ECDH(localKeyID, ephPub)
	//  - derive AES-GCM key with HKDF(shared, ctx)
	//  - AES-GCM decrypt ciphertext+tag
	DecryptFromPeer(ctx Context, blob []byte) ([]byte, error)

	// Keystore returns the underlying bound keystore for this cipher.
	// This allows access to Sign/Verify operations when needed.
	Keystore() keystore.Keystore
}

type envelopeCipher struct {
	ks keystore.Keystore
}

// NewEnvelopeCipher creates a new EnvelopeCipher using the specified bound keystore.
// The keystore must already be bound to a specific key ID.
func NewEnvelopeCipher(ks keystore.Keystore) EnvelopeCipher {
	return &envelopeCipher{
		ks: ks,
	}
}

// EncryptToPeer encrypts plaintext for peerPubX using ephemeral key exchange.
func (e *envelopeCipher) EncryptToPeer(peerPubX [32]byte, ctx Context, plaintext []byte) ([]byte, error) {
	ciphertext, _, err := e.ks.EncryptFor(peerPubX, plaintext, ctx)
	return ciphertext, err
}

// DecryptFromPeer decrypts a blob that was encrypted to us.
func (e *envelopeCipher) DecryptFromPeer(ctx Context, blob []byte) ([]byte, error) {
	plaintext, _, err := e.ks.Decrypt(blob, ctx)
	return plaintext, err
}

// Keystore returns the underlying bound keystore for this cipher.
func (e *envelopeCipher) Keystore() keystore.Keystore {
	return e.ks
}
