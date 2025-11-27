//go:build !windows
// +build !windows

package keystore

import "fmt"

// NewWindowsKeystore creates a new Windows Credential Store keystore (stub for non-Windows platforms)
func NewWindowsKeystore() (Keystore, error) {
	return nil, fmt.Errorf("Windows keystore is only available on Windows")
}

