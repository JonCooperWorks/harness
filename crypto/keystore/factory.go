package keystore

import (
	"fmt"
	"runtime"
)

// NewKeystore creates a platform-specific keystore implementation
func NewKeystore() (Keystore, error) {
	switch runtime.GOOS {
	case "darwin":
		return NewKeychainKeystore()
	case "linux":
		return NewKeyringKeystore()
	case "windows":
		return NewWindowsKeystore()
	default:
		return nil, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}
