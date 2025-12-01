package keystore

import "crypto/ecdsa"

// Keystore interface for accessing OS keystores
type Keystore interface {
	// GetPrivateKey retrieves an ECDSA private key from the keystore by key ID
	GetPrivateKey(keyID string) (*ecdsa.PrivateKey, error)
	// SetPrivateKey stores an ECDSA private key in the keystore with the given key ID
	SetPrivateKey(keyID string, privateKey *ecdsa.PrivateKey) error
	// ListKeys returns all key IDs stored in the keystore
	ListKeys() ([]string, error)
}
