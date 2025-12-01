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

// SetPrivateKey stores an ECDSA private key in Linux keyring
func (k *KeyringKeystore) SetPrivateKey(keyID string, privateKey *ecdsa.PrivateKey) error {
	// Encode private key to PEM format (PKCS8)
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Store in keyring
	err = k.ring.Set(keyring.Item{
		Key:  keyID,
		Data: privateKeyPEM,
	})
	if err != nil {
		return fmt.Errorf("failed to store key in keyring: %w", err)
	}

	return nil
}

// ListKeys returns all key IDs stored in Linux keyring
func (k *KeyringKeystore) ListKeys() ([]string, error) {
	keys, err := k.ring.Keys()
	if err != nil {
		return nil, fmt.Errorf("failed to list keys from keyring: %w", err)
	}
	return keys, nil
}

