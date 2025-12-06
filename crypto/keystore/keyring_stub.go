//go:build !linux
// +build !linux

package keystore

import "fmt"

// NewKeyringKeyManager creates a new Linux keyring key manager (stub for non-Linux platforms)
func NewKeyringKeyManager() (KeyManager, error) {
	return nil, fmt.Errorf("linux keyring keystore is only available on Linux")
}
