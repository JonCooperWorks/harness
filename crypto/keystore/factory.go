package keystore

import (
	"fmt"
	"runtime"
)

// NewKeystore creates a platform-specific keystore implementation.
//
// Uses the registry to find the appropriate factory for the current platform (runtime.GOOS).
// Platform-specific implementations are automatically registered:
//   - "darwin" -> KeychainKeystore (macOS)
//   - "linux" -> KeyringKeystore (Linux)
//   - "windows" -> WindowsKeystore (Windows)
//
// Custom keystore implementations can be registered using RegisterKeystore to override
// the default for a platform or add support for new platforms.
//
// Returns an error if no keystore factory is registered for the current platform.
func NewKeystore() (Keystore, error) {
	factory, err := GetKeystoreFactory(runtime.GOOS)
	if err != nil {
		return nil, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
	return factory()
}
