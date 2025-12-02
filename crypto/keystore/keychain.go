//go:build darwin
// +build darwin

package keystore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/99designs/keyring"
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

// GetPrivateKey retrieves an Ed25519 private key from macOS Keychain
func (k *KeychainKeystore) GetPrivateKey(keyID string) (ed25519.PrivateKey, error) {
	item, err := k.ring.Get(keyID)
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
func (k *KeychainKeystore) SetPrivateKey(keyID string, privateKey ed25519.PrivateKey) error {
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
		Key:  keyID,
		Data: privateKeyPEM,
	})
	if err != nil {
		return fmt.Errorf("failed to store key in keychain: %w", err)
	}

	return nil
}

// GetPublicKey retrieves the public key associated with a key ID
func (k *KeychainKeystore) GetPublicKey(keyID string) (ed25519.PublicKey, error) {
	privateKey, err := k.GetPrivateKey(keyID)
	if err != nil {
		return nil, err
	}
	return privateKey.Public().(ed25519.PublicKey), nil
}

// Sign signs the provided data hash using the private key associated with keyID
func (k *KeychainKeystore) Sign(keyID string, hash []byte) ([]byte, error) {
	privateKey, err := k.GetPrivateKey(keyID)
	if err != nil {
		return nil, err
	}

	// Ed25519.Sign returns a 64-byte signature
	signature := ed25519.Sign(privateKey, hash)
	return signature, nil
}

// DecryptWithContext decrypts data encrypted via X25519 with a specific HKDF context
func (k *KeychainKeystore) DecryptWithContext(keyID string, encryptedKey []byte, context string) ([]byte, error) {
	if len(encryptedKey) < 32 {
		return nil, fmt.Errorf("encrypted key too short")
	}

	privateKey, err := k.GetPrivateKey(keyID)
	if err != nil {
		return nil, err
	}

	// Extract ephemeral X25519 public key (32 bytes)
	ephemeralX25519PubKey := encryptedKey[:32]

	// Convert Ed25519 private key to X25519
	x25519PrivateKey, err := Ed25519ToX25519PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to convert private key to X25519: %w", err)
	}

	// Compute shared secret using X25519
	sharedSecret, err := x25519SharedSecret(x25519PrivateKey, ephemeralX25519PubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to compute shared secret: %w", err)
	}

	// Derive AES key from shared secret using HKDF with specified context
	aesKey, err := deriveKey(sharedSecret, context)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}

	// Decrypt the data
	encryptedData := encryptedKey[32:]
	if len(encryptedData) < 12+16 {
		return nil, fmt.Errorf("encrypted data too short")
	}

	// Extract nonce (first 12 bytes)
	nonce := encryptedData[:12]
	ciphertext := encryptedData[12:]

	block, err := aes.NewCipher(aesKey[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
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

// ListKeys returns all key IDs stored in macOS Keychain
func (k *KeychainKeystore) ListKeys() ([]string, error) {
	keys, err := k.ring.Keys()
	if err != nil {
		return nil, fmt.Errorf("failed to list keys from keychain: %w", err)
	}
	return keys, nil
}
