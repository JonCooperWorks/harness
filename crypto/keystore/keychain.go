//go:build darwin
// +build darwin

package keystore

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/99designs/keyring"
)

// KeychainKeystore implements Keystore for macOS using Keychain
type KeychainKeystore struct {
	ring keyring.Keyring
}

// NewKeychainKeystore creates a new macOS Keychain keystore
func NewKeychainKeystore() (Keystore, error) {
	ring, err := keyring.Open(keyring.Config{
		ServiceName:              "harness",
		KeychainName:             "harness-keys",
		KeychainPasswordFunc:     nil, // Use default keychain
		KeychainTrustApplication: true,
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

