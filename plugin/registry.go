package plugin

import (
	"fmt"
	"sync"
)

// LoaderFactory is a function that creates a new Loader instance.
//
// Factory functions are registered with RegisterLoader and are called when
// a plugin of that type needs to be loaded.
type LoaderFactory func() (Loader, error)

var (
	// loaderRegistry stores loader factories by plugin type identifier
	loaderRegistry = make(map[string]LoaderFactory)
	// loaderRegistryMu protects concurrent access to the registry
	loaderRegistryMu sync.RWMutex
)

// RegisterLoader registers a loader factory for a given plugin type identifier.
//
// This should be called from init() functions in plugin loader implementations.
// The typeIdentifier is a string like "wasm", "python", etc. that will be used
// in Payload.Type to identify which loader to use.
//
// Example:
//
//	func init() {
//	    RegisterLoader("python", func() (Loader, error) {
//	        return NewPythonLoader()
//	    })
//	}
func RegisterLoader(typeIdentifier string, factory LoaderFactory) {
	loaderRegistryMu.Lock()
	defer loaderRegistryMu.Unlock()
	loaderRegistry[typeIdentifier] = factory
}

// GetLoaderFactory retrieves a loader factory for the given plugin type identifier.
//
// Returns an error if no factory is registered for the type.
// This is used internally by LoadPlugin to find the appropriate loader.
func GetLoaderFactory(typeIdentifier string) (LoaderFactory, error) {
	loaderRegistryMu.RLock()
	defer loaderRegistryMu.RUnlock()
	factory, ok := loaderRegistry[typeIdentifier]
	if !ok {
		return nil, fmt.Errorf("no loader factory registered for plugin type: %s", typeIdentifier)
	}
	return factory, nil
}

// ListRegisteredPluginTypes returns all registered plugin type identifiers.
//
// This can be used to discover what plugin types are available at runtime.
func ListRegisteredPluginTypes() []string {
	loaderRegistryMu.RLock()
	defer loaderRegistryMu.RUnlock()
	types := make([]string, 0, len(loaderRegistry))
	for typeIdentifier := range loaderRegistry {
		types = append(types, typeIdentifier)
	}
	return types
}

