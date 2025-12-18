package keystore

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"math/big"
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
// Conversion formula: u = (1 + y) / (1 - y) mod p where p = 2^255 - 19
// This implementation uses only standard library functions.
func Ed25519ToX25519PublicKey(ed25519PublicKey ed25519.PublicKey) ([]byte, error) {
	if len(ed25519PublicKey) != ed25519.PublicKeySize {
		return nil, ErrInvalidKeySize
	}

	// Ed25519 public key is the y-coordinate (little-endian, 32 bytes) with a sign bit for x
	// in the most significant bit of the last byte. We must clear this bit before extracting y.
	pubKeyCopy := make([]byte, 32)
	copy(pubKeyCopy, ed25519PublicKey)
	pubKeyCopy[31] &= 0x7F // Clear the sign bit (MSB of last byte)

	// Extract y coordinate from the public key bytes
	y := new(big.Int).SetBytes(reverseBytes(pubKeyCopy)) // Convert from little-endian

	// Curve25519 prime: p = 2^255 - 19
	p := new(big.Int)
	p.Exp(big.NewInt(2), big.NewInt(255), nil)
	p.Sub(p, big.NewInt(19))

	// Calculate u = (1 + y) / (1 - y) mod p
	// First compute (1 + y) mod p
	onePlusY := new(big.Int).Add(big.NewInt(1), y)
	onePlusY.Mod(onePlusY, p)

	// Compute (1 - y) mod p
	oneMinusY := new(big.Int).Sub(big.NewInt(1), y)
	oneMinusY.Mod(oneMinusY, p)

	// Handle edge case: if (1 - y) is 0, this would be division by zero
	// In practice, this should never happen for valid Ed25519 public keys
	if oneMinusY.Sign() == 0 {
		return nil, errors.New("invalid Ed25519 public key: would result in division by zero")
	}

	// Compute modular inverse of (1 - y) mod p
	oneMinusYInv := new(big.Int).ModInverse(oneMinusY, p)
	if oneMinusYInv == nil {
		return nil, errors.New("failed to compute modular inverse")
	}

	// u = (1 + y) * inv(1 - y) mod p
	u := new(big.Int).Mul(onePlusY, oneMinusYInv)
	u.Mod(u, p)

	// Convert u to 32-byte little-endian representation
	result := make([]byte, 32)
	uBytes := u.Bytes()
	// Handle case where u is less than 32 bytes
	if len(uBytes) > 32 {
		return nil, errors.New("converted X25519 public key exceeds 32 bytes")
	}
	// u.Bytes() returns big-endian with no leading zeros, so we need to
	// right-align it in the 32-byte buffer before reversing to little-endian
	copy(result[32-len(uBytes):], uBytes)
	reverseBytesInPlace(result) // Convert to little-endian

	return result, nil
}

// reverseBytes reverses the byte order of a byte slice and returns a new slice.
func reverseBytes(b []byte) []byte {
	result := make([]byte, len(b))
	for i := 0; i < len(b); i++ {
		result[i] = b[len(b)-1-i]
	}
	return result
}

// reverseBytesInPlace reverses the byte order of a byte slice in place.
func reverseBytesInPlace(b []byte) {
	for i := 0; i < len(b)/2; i++ {
		j := len(b) - 1 - i
		b[i], b[j] = b[j], b[i]
	}
}

// ScalarBaseMult computes the X25519 public key from a private key scalar.
// This replaces the deprecated curve25519.ScalarBaseMult function.
func ScalarBaseMult(privScalar []byte) ([32]byte, error) {
	if len(privScalar) != 32 {
		return [32]byte{}, ErrInvalidKeySize
	}

	privKey, err := ecdh.X25519().NewPrivateKey(privScalar)
	if err != nil {
		return [32]byte{}, err
	}

	pubKey := privKey.PublicKey()
	pubKeyBytes := pubKey.Bytes()
	if len(pubKeyBytes) != 32 {
		return [32]byte{}, errors.New("invalid public key size")
	}

	var result [32]byte
	copy(result[:], pubKeyBytes)
	return result, nil
}

// ScalarMult computes the X25519 shared secret using scalar multiplication.
// This replaces the deprecated curve25519.ScalarMult function.
func ScalarMult(privScalar []byte, peerPubKey [32]byte) ([32]byte, error) {
	if len(privScalar) != 32 {
		return [32]byte{}, ErrInvalidKeySize
	}

	privKey, err := ecdh.X25519().NewPrivateKey(privScalar)
	if err != nil {
		return [32]byte{}, err
	}

	peerKey, err := ecdh.X25519().NewPublicKey(peerPubKey[:])
	if err != nil {
		return [32]byte{}, err
	}

	sharedSecret, err := privKey.ECDH(peerKey)
	if err != nil {
		return [32]byte{}, err
	}

	if len(sharedSecret) != 32 {
		return [32]byte{}, errors.New("invalid shared secret size")
	}

	var result [32]byte
	copy(result[:], sharedSecret)
	return result, nil
}

// hceepHKDFSalt is a protocol-specific salt for HKDF key derivation.
// Using a fixed, protocol-specific salt provides:
// - Domain separation from other applications using the same key material
// - Defense against pre-computation attacks on HKDF
// - Compliance with cryptographic best practices (RFC 5869 recommends non-empty salt)
var hceepHKDFSalt = []byte("HCEEP-v2")

// DeriveKeyFromSecret derives a 32-byte AES key using HKDF-SHA256 with context and protocol salt.
// This is a shared implementation used by all keystore backends.
func DeriveKeyFromSecret(sharedSecret []byte, context Context) ([32]byte, error) {
	paddedSecret := padSharedSecret(sharedSecret)
	keyBytes, err := hkdf.Key(sha256.New, paddedSecret, hceepHKDFSalt, string(context), 32)
	if err != nil {
		var key [32]byte
		return key, fmt.Errorf("failed to derive key: %w", err)
	}
	var key [32]byte
	copy(key[:], keyBytes)
	return key, nil
}

// padSharedSecret pads a shared secret to exactly 32 bytes for consistent key derivation.
// This is a shared implementation used by all keystore backends.
func padSharedSecret(secret []byte) []byte {
	const keySize = 32
	if len(secret) >= keySize {
		return secret[len(secret)-keySize:]
	}
	padded := make([]byte, keySize)
	copy(padded[keySize-len(secret):], secret)
	return padded
}

var ErrInvalidKeySize = &keySizeError{}

type keySizeError struct{}

func (e *keySizeError) Error() string {
	return "invalid key size"
}
