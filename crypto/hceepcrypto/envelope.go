// Package hceepcrypto provides HCEEP-specific cryptographic operations built on top of the keystore.
// It implements the envelope encryption format used for HCEEP protocol.
package hceepcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/joncooperworks/harness/crypto/keystore"
	"golang.org/x/crypto/curve25519"
)

// Context specifies the HKDF context string used for key derivation.
type Context string

const (
	// ContextSymmetricKey is used for encrypting/decrypting symmetric keys.
	ContextSymmetricKey Context = "harness-symmetric-key-v1"
	// ContextArgs is used for encrypting/decrypting execution arguments.
	ContextArgs Context = "harness-args-v1"
	// ContextEnvelope is used for encrypting/decrypting envelopes (onion encryption).
	ContextEnvelope Context = "harness-envelope-v1"
)

// EnvelopeCipher uses one local key (keyID) from a Keystore
// to encrypt/decrypt blobs for HCEEP.
//
// Wire format (for each blob) is:
//   [ephemeral_x25519_public_key:32][nonce:12][ciphertext+tag]
type EnvelopeCipher interface {
	// EncryptToPeer encrypts plaintext for peerPubX, using this keystore keyID
	// as the sender identity, and the given HKDF context.
	//
	// Steps (inside impl):
	//  - generate ephemeral X25519 keypair locally
	//  - shared = X25519(ephemeral_priv, peerPubX)
	//  - derive AES-GCM key with HKDF(shared, ctx)
	//  - encrypt plaintext with AES-256-GCM
	//  - output: ephPub || nonce || ciphertext+tag
	EncryptToPeer(peerPubX [32]byte, ctx Context, plaintext []byte) ([]byte, error)

	// DecryptFromPeer decrypts a blob that was encrypted to us (this keyID).
	//
	// Steps (inside impl):
	//  - parse ephPub, nonce from blob
	//  - shared = keystore.ECDH(localKeyID, ephPub)
	//  - derive AES-GCM key with HKDF(shared, ctx)
	//  - AES-GCM decrypt ciphertext+tag
	DecryptFromPeer(ctx Context, blob []byte) ([]byte, error)
}

type envelopeCipher struct {
	ks    keystore.Keystore
	keyID keystore.KeyID
}

// NewEnvelopeCipher creates a new EnvelopeCipher using the specified keystore and key ID.
func NewEnvelopeCipher(ks keystore.Keystore, id keystore.KeyID) EnvelopeCipher {
	return &envelopeCipher{
		ks:    ks,
		keyID: id,
	}
}

// EncryptToPeer encrypts plaintext for peerPubX using ephemeral key exchange.
func (e *envelopeCipher) EncryptToPeer(peerPubX [32]byte, ctx Context, plaintext []byte) ([]byte, error) {
	// Generate ephemeral Ed25519 key pair
	ephemeralPublic, ephemeralPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	// Convert Ed25519 keys to X25519 for key exchange
	ephemeralX25519Private, err := keystore.Ed25519ToX25519PrivateKey(ephemeralPrivate)
	if err != nil {
		return nil, fmt.Errorf("failed to convert ephemeral private key to X25519: %w", err)
	}

	// Compute shared secret using X25519
	var sharedSecret [32]byte
	curve25519.ScalarMult(&sharedSecret, (*[32]byte)(ephemeralX25519Private), &peerPubX)

	// Derive AES key from shared secret using HKDF
	aesKey, err := deriveKey(sharedSecret[:], string(ctx))
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}

	// Encrypt with AES-GCM
	nonce := make([]byte, 12) // GCM standard nonce size
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	block, err := aes.NewCipher(aesKey[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// Encode ephemeral X25519 public key (32 bytes)
	ephemeralX25519PubBytes, err := keystore.Ed25519ToX25519PublicKey(ephemeralPublic)
	if err != nil {
		return nil, fmt.Errorf("failed to convert ephemeral public key to X25519: %w", err)
	}

	// Build result: [ephemeral_x25519_public_key:32][nonce:12][ciphertext+tag]
	result := make([]byte, 0, 32+12+len(ciphertext))
	result = append(result, ephemeralX25519PubBytes...)
	result = append(result, nonce...)
	result = append(result, ciphertext...)

	return result, nil
}

// DecryptFromPeer decrypts a blob that was encrypted to us.
func (e *envelopeCipher) DecryptFromPeer(ctx Context, blob []byte) ([]byte, error) {
	if len(blob) < 32+12+16 { // Need at least ephemeral key (32) + nonce (12) + tag (16)
		return nil, errors.New("encrypted blob too short")
	}

	// Extract ephemeral X25519 public key (32 bytes)
	var ephemeralX25519PubKey [32]byte
	copy(ephemeralX25519PubKey[:], blob[:32])

	// Compute shared secret using keystore ECDH
	sharedSecret, err := e.ks.ECDH(e.keyID, ephemeralX25519PubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to compute shared secret: %w", err)
	}

	// Derive AES key from shared secret using HKDF
	aesKey, err := deriveKey(sharedSecret[:], string(ctx))
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}

	// Extract nonce and ciphertext
	encryptedData := blob[32:]
	if len(encryptedData) < 12+16 { // Need at least nonce (12) + tag (16)
		return nil, errors.New("encrypted data too short")
	}

	nonce := encryptedData[:12]
	ciphertext := encryptedData[12:]

	block, err := aes.NewCipher(aesKey[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Decrypt and verify authentication tag
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

// padSharedSecret pads a shared secret to exactly 32 bytes for consistent key derivation
func padSharedSecret(secret []byte) []byte {
	const keySize = 32
	if len(secret) >= keySize {
		return secret[len(secret)-keySize:]
	}
	padded := make([]byte, keySize)
	copy(padded[keySize-len(secret):], secret)
	return padded
}

// deriveKey derives a 32-byte AES key using HKDF-SHA256
func deriveKey(sharedSecret []byte, context string) ([32]byte, error) {
	paddedSecret := padSharedSecret(sharedSecret)
	keyBytes, err := hkdf.Key(sha256.New, paddedSecret, nil, context, 32)
	if err != nil {
		var key [32]byte
		return key, fmt.Errorf("failed to derive key: %w", err)
	}
	var key [32]byte
	copy(key[:], keyBytes)
	return key, nil
}

