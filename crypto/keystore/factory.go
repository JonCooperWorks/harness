package keystore

import (
	"fmt"
	"runtime"
)

// NewKeystore creates a platform-specific KeyManager for key management operations.
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
func NewKeystore() (KeyManager, error) {
	factory, err := GetKeystoreFactory(runtime.GOOS)
	if err != nil {
		return nil, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
	return factory()
}

// NewKeystoreForKey creates a platform-specific Keystore bound to the specified key ID.
//
// This is the primary way to get a Keystore for cryptographic operations. The returned
// Keystore is bound to the specified key - all operations (Sign, Verify, EncryptFor, Decrypt)
// use this key identity.
//
// Uses the registry to find the appropriate factory for the current platform (runtime.GOOS).
//
// Returns an error if no keystore factory is registered for the current platform,
// or if the key does not exist in the keystore.
func NewKeystoreForKey(id KeyID) (Keystore, error) {
	factory, err := GetKeystoreFactory(runtime.GOOS)
	if err != nil {
		return nil, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
	km, err := factory()
	if err != nil {
		return nil, err
	}

	// The KeyManager implementations also implement keystoreWithKey
	if ks, ok := km.(keystoreWithKey); ok {
		return ks.ForKey(id)
	}

	return nil, fmt.Errorf("keystore implementation does not support ForKey")
}

// keystoreWithKey is an internal interface for implementations that can be bound to a key.
type keystoreWithKey interface {
	KeyManager
	ForKey(id KeyID) (Keystore, error)
}
