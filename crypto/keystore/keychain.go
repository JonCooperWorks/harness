//go:build darwin
// +build darwin

package keystore

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/99designs/keyring"
)

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

// GetPrivateKey retrieves an ECDSA private key from macOS Keychain
func (k *KeychainKeystore) GetPrivateKey(keyID string) (*ecdsa.PrivateKey, error) {
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
		if ecdsaKey, ok := key.(*ecdsa.PrivateKey); ok {
			return ecdsaKey, nil
		}
		return nil, fmt.Errorf("key is not ECDSA")
	}

	// Try EC private key format
	ecKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return ecKey, nil
}

// SetPrivateKey stores an ECDSA private key in macOS Keychain
func (k *KeychainKeystore) SetPrivateKey(keyID string, privateKey *ecdsa.PrivateKey) error {
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

// ListKeys returns all key IDs stored in macOS Keychain
func (k *KeychainKeystore) ListKeys() ([]string, error) {
	keys, err := k.ring.Keys()
	if err != nil {
		return nil, fmt.Errorf("failed to list keys from keychain: %w", err)
	}
	return keys, nil
}
