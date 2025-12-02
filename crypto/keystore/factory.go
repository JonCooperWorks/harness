package keystore

import (
	"fmt"
	"runtime"
)

// NewKeystore creates a platform-specific keystore implementation
// Uses the registry to find the appropriate factory for the current platform
func NewKeystore() (Keystore, error) {
	factory, err := GetKeystoreFactory(runtime.GOOS)
	if err != nil {
		return nil, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
	return factory()
}
