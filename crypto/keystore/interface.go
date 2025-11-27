package keystore

import "crypto/ecdsa"

// Keystore interface for accessing OS keystores
type Keystore interface {
	// GetPrivateKey retrieves an ECDSA private key from the keystore by key ID
	GetPrivateKey(keyID string) (*ecdsa.PrivateKey, error)
}

