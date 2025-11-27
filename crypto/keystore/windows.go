//go:build windows
// +build windows

package keystore

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/99designs/keyring"
)

// WindowsKeystore implements Keystore for Windows using Credential Manager
type WindowsKeystore struct {
	ring keyring.Keyring
}

// NewWindowsKeystore creates a new Windows Credential Store keystore
func NewWindowsKeystore() (Keystore, error) {
	ring, err := keyring.Open(keyring.Config{
		ServiceName: "harness",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to open credential store: %w", err)
	}

	return &WindowsKeystore{ring: ring}, nil
}

// GetPrivateKey retrieves an ECDSA private key from Windows Credential Store
func (w *WindowsKeystore) GetPrivateKey(keyID string) (*ecdsa.PrivateKey, error) {
	item, err := w.ring.Get(keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get key from credential store: %w", err)
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

