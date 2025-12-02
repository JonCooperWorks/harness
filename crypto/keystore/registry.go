package keystore

import (
	"fmt"
	"sync"
)

// KeystoreFactory is a function that creates a new Keystore instance
type KeystoreFactory func() (Keystore, error)

var (
	// registry stores keystore factories by platform identifier
	registry = make(map[string]KeystoreFactory)
	// registryMu protects concurrent access to the registry
	registryMu sync.RWMutex
)

// RegisterKeystore registers a keystore factory for a given platform identifier
// This should be called from init() functions in platform-specific implementations
func RegisterKeystore(platform string, factory KeystoreFactory) {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry[platform] = factory
}

// GetKeystoreFactory retrieves a keystore factory for the given platform
// Returns an error if no factory is registered for the platform
func GetKeystoreFactory(platform string) (KeystoreFactory, error) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	factory, ok := registry[platform]
	if !ok {
		return nil, fmt.Errorf("no keystore factory registered for platform: %s", platform)
	}
	return factory, nil
}

// ListRegisteredPlatforms returns all registered platform identifiers
func ListRegisteredPlatforms() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	platforms := make([]string, 0, len(registry))
	for platform := range registry {
		platforms = append(platforms, platform)
	}
	return platforms
}

