package keystore

import (
	"fmt"
	"sync"
)

// KeystoreFactory is a function that creates a new Keystore instance.
//
// Factory functions are registered with RegisterKeystore and are called when
// a keystore for that platform is needed.
type KeystoreFactory func() (Keystore, error)

var (
	// registry stores keystore factories by platform identifier
	registry = make(map[string]KeystoreFactory)
	// registryMu protects concurrent access to the registry
	registryMu sync.RWMutex
)

// RegisterKeystore registers a keystore factory for a given platform identifier.
//
// This should be called from init() functions in platform-specific implementations.
// The platform parameter should match runtime.GOOS values (e.g., "darwin", "linux", "windows")
// or custom platform identifiers for specialized keystores (e.g., "cloudkms").
//
// Example:
//
//	func init() {
//	    RegisterKeystore("darwin", NewKeychainKeystore)
//	}
func RegisterKeystore(platform string, factory KeystoreFactory) {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry[platform] = factory
}

// GetKeystoreFactory retrieves a keystore factory for the given platform.
//
// Returns an error if no factory is registered for the platform.
// This is used internally by NewKeystore to find the appropriate factory.
func GetKeystoreFactory(platform string) (KeystoreFactory, error) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	factory, ok := registry[platform]
	if !ok {
		return nil, fmt.Errorf("no keystore factory registered for platform: %s", platform)
	}
	return factory, nil
}

// ListRegisteredPlatforms returns all registered platform identifiers.
//
// This can be used to discover what keystore implementations are available at runtime.
func ListRegisteredPlatforms() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	platforms := make([]string, 0, len(registry))
	for platform := range registry {
		platforms = append(platforms, platform)
	}
	return platforms
}

