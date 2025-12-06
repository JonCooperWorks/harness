//go:build !windows
// +build !windows

package keystore

import "fmt"

// NewWindowsKeyManager creates a new Windows Credential Store key manager (stub for non-Windows platforms)
func NewWindowsKeyManager() (KeyManager, error) {
	return nil, fmt.Errorf("Windows keystore is only available on Windows")
}
