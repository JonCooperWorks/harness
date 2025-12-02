//go:build !linux
// +build !linux

package keystore

import "fmt"

// NewKeyringKeystore creates a new Linux keyring keystore (stub for non-Linux platforms)
func NewKeyringKeystore() (Keystore, error) {
	return nil, fmt.Errorf("Linux keyring keystore is only available on Linux")
}
