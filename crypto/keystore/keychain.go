//go:build darwin
// +build darwin

package keystore

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/99designs/keyring"
	"golang.org/x/crypto/curve25519"
)

func init() {
	RegisterKeystore("darwin", NewKeychainKeystore)
}

// KeychainKeystore implements Keystore for macOS using Keychain
type KeychainKeystore struct {
	ring keyring.Keyring
}

// NewKeychainKeystore creates a new macOS Keychain keystore
// Uses HARNESS_KEYCHAIN environment variable if set, otherwise uses default login keychain
// Set HARNESS_KEYCHAIN="harness-keys" to use custom keychain, or "" for default login keychain
func NewKeychainKeystore() (Keystore, error) {
	keychainName := os.Getenv("HARNESS_KEYCHAIN")
	// If not set, default to empty (login keychain) to avoid double password prompts
	// Set HARNESS_KEYCHAIN="harness-keys" to use the custom keychain

	ring, err := keyring.Open(keyring.Config{
		ServiceName:              "harness",
		KeychainName:             keychainName, // Empty = default login keychain, "harness-keys" = custom keychain
		KeychainPasswordFunc:     nil,          // Use default keychain
		KeychainTrustApplication: true,
		// Use login keychain by default (unlocked when logged in, fewer prompts)
		// Only prompt if using a custom keychain that requires unlocking
	})
	if err != nil {
		return nil, fmt.Errorf("failed to open keychain: %w", err)
	}

	return &KeychainKeystore{ring: ring}, nil
}

// GetPrivateKey retrieves an Ed25519 private key from macOS Keychain (internal helper)
func (k *KeychainKeystore) GetPrivateKey(keyID KeyID) (ed25519.PrivateKey, error) {
	item, err := k.ring.Get(string(keyID))
	if err != nil {
		return nil, fmt.Errorf("failed to get key from keychain: %w", err)
	}

	// Parse PEM format
	block, _ := pem.Decode(item.Data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// Try PKCS8 format
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		if ed25519Key, ok := key.(ed25519.PrivateKey); ok {
			return ed25519Key, nil
		}
		return nil, fmt.Errorf("key is not Ed25519")
	}

	// Try raw Ed25519 private key (64 bytes)
	if len(block.Bytes) == ed25519.PrivateKeySize {
		return ed25519.PrivateKey(block.Bytes), nil
	}

	return nil, fmt.Errorf("failed to parse private key: unsupported format")
}

// SetPrivateKey stores an Ed25519 private key in macOS Keychain
func (k *KeychainKeystore) SetPrivateKey(id KeyID, privateKey ed25519.PrivateKey) error {
	// Encode private key to PEM format (PKCS8)
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Store in keychain
	err = k.ring.Set(keyring.Item{
		Key:  string(id),
		Data: privateKeyPEM,
	})
	if err != nil {
		return fmt.Errorf("failed to store key in keychain: %w", err)
	}

	return nil
}

// PublicEd25519 returns the Ed25519 public key for keyID
func (k *KeychainKeystore) PublicEd25519(id KeyID) (ed25519.PublicKey, error) {
	privateKey, err := k.GetPrivateKey(id)
	if err != nil {
		return nil, err
	}
	return privateKey.Public().(ed25519.PublicKey), nil
}

// PublicX25519 returns the X25519 public key for keyID (32 bytes)
func (k *KeychainKeystore) PublicX25519(id KeyID) ([32]byte, error) {
	privateKey, err := k.GetPrivateKey(id)
	if err != nil {
		return [32]byte{}, err
	}

	// Convert Ed25519 private key to X25519
	x25519PrivateKey, err := Ed25519ToX25519PrivateKey(privateKey)
	if err != nil {
		return [32]byte{}, fmt.Errorf("failed to convert private key to X25519: %w", err)
	}

	// Compute X25519 public key from private key
	// X25519 public key = X25519(private_key, base_point)
	var x25519Pub [32]byte
	curve25519.ScalarBaseMult(&x25519Pub, (*[32]byte)(x25519PrivateKey))

	return x25519Pub, nil
}

// SignDigest signs a canonical digest with the Ed25519 private key for keyID
func (k *KeychainKeystore) SignDigest(id KeyID, digest []byte) ([]byte, error) {
	privateKey, err := k.GetPrivateKey(id)
	if err != nil {
		return nil, err
	}

	// Ed25519.Sign returns a 64-byte signature
	signature := ed25519.Sign(privateKey, digest)
	return signature, nil
}

// ECDH computes X25519(shared = sk(id) ⊗ peerPublic)
func (k *KeychainKeystore) ECDH(id KeyID, peerPublic [32]byte) (sharedSecret [32]byte, err error) {
	privateKey, err := k.GetPrivateKey(id)
	if err != nil {
		return [32]byte{}, err
	}

	// Convert Ed25519 private key to X25519
	x25519PrivateKey, err := Ed25519ToX25519PrivateKey(privateKey)
	if err != nil {
		return [32]byte{}, fmt.Errorf("failed to convert private key to X25519: %w", err)
	}

	// Compute shared secret using X25519
	curve25519.ScalarMult(&sharedSecret, (*[32]byte)(x25519PrivateKey), &peerPublic)
	return sharedSecret, nil
}

// ListKeys returns all key IDs stored in macOS Keychain
func (k *KeychainKeystore) ListKeys() ([]KeyID, error) {
	keys, err := k.ring.Keys()
	if err != nil {
		return nil, fmt.Errorf("failed to list keys from keychain: %w", err)
	}
	result := make([]KeyID, len(keys))
	for i, key := range keys {
		result[i] = KeyID(key)
	}
	return result, nil
}
