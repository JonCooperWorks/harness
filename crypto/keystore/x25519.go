package keystore

import (
	"crypto/ed25519"
	"crypto/sha512"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/curve25519"
)

// Ed25519ToX25519PrivateKey converts an Ed25519 private key to an X25519 private key.
// Ed25519 private keys are 64 bytes (32-byte seed + 32-byte public key).
// X25519 private keys are 32 bytes.
func Ed25519ToX25519PrivateKey(ed25519PrivateKey ed25519.PrivateKey) ([]byte, error) {
	if len(ed25519PrivateKey) != ed25519.PrivateKeySize {
		return nil, ErrInvalidKeySize
	}

	// Ed25519 private key is [seed (32 bytes) | public key (32 bytes)]
	// Extract the seed (first 32 bytes)
	seed := ed25519PrivateKey[:32]

	// Use SHA-512 to derive the X25519 private key from the Ed25519 seed
	// This follows RFC 8032 section 5.1.5
	digest := sha512.Sum512(seed)
	digest[0] &= 248  // Clear the bottom 3 bits
	digest[31] &= 127 // Clear the top bit
	digest[31] |= 64  // Set the second-highest bit

	return digest[:32], nil
}

// Ed25519ToX25519PublicKey converts an Ed25519 public key to an X25519 public key.
// This uses the standard conversion from Ed25519 (Edwards curve) to X25519 (Montgomery curve).
func Ed25519ToX25519PublicKey(ed25519PublicKey ed25519.PublicKey) ([]byte, error) {
	if len(ed25519PublicKey) != ed25519.PublicKeySize {
		return nil, ErrInvalidKeySize
	}

	// Convert Ed25519 public key (Edwards curve point) to X25519 public key (Montgomery curve)
	// Using BytesMontgomery() which directly converts to Montgomery format
	var edwardsPoint edwards25519.Point
	if _, err := edwardsPoint.SetBytes(ed25519PublicKey); err != nil {
		return nil, err
	}

	// BytesMontgomery() returns the Montgomery u coordinate (32 bytes)
	return edwardsPoint.BytesMontgomery(), nil
}

// x25519SharedSecret computes a shared secret using X25519 key exchange.
func x25519SharedSecret(privateKey, publicKey []byte) ([]byte, error) {
	if len(privateKey) != 32 {
		return nil, ErrInvalidKeySize
	}
	if len(publicKey) != 32 {
		return nil, ErrInvalidKeySize
	}

	var sharedSecret [32]byte
	curve25519.ScalarMult(&sharedSecret, (*[32]byte)(privateKey), (*[32]byte)(publicKey))
	return sharedSecret[:], nil
}

var ErrInvalidKeySize = &keySizeError{}

type keySizeError struct{}

func (e *keySizeError) Error() string {
	return "invalid key size"
}
