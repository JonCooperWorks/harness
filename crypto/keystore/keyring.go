//go:build linux
// +build linux

package keystore

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/99designs/keyring"
)

// KeyringKeystore implements Keystore for Linux using libsecret/keyring
type KeyringKeystore struct {
	ring keyring.Keyring
}

// NewKeyringKeystore creates a new Linux keyring keystore
func NewKeyringKeystore() (Keystore, error) {
	ring, err := keyring.Open(keyring.Config{
		ServiceName: "harness",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to open keyring: %w", err)
	}

	return &KeyringKeystore{ring: ring}, nil
}

// GetPrivateKey retrieves an ECDSA private key from Linux keyring
func (k *KeyringKeystore) GetPrivateKey(keyID string) (*ecdsa.PrivateKey, error) {
	item, err := k.ring.Get(keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get key from keyring: %w", err)
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

