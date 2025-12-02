package plugin

import (
	"fmt"

	"github.com/joncooperworks/harness/crypto"
)

// Loader loads plugins based on their type.
//
// Each plugin type (WASM, Python, etc.) has a corresponding Loader implementation
// that knows how to parse the plugin binary data and create a Plugin instance.
type Loader interface {
	// Load creates a Plugin instance from the raw plugin binary data.
	// The data parameter contains the plugin binary (e.g., WASM module bytes).
	// The name parameter is the plugin name, typically extracted from the plugin itself.
	Load(data []byte, name string) (Plugin, error)
}

// LoadPlugin loads a plugin from a Payload.
//
// This function uses the registry to find the appropriate loader for the payload type.
// The payload.Type must match a registered plugin loader type (e.g., "wasm", "python").
//
// Returns an error if no loader is registered for the payload type or if loading fails.
func LoadPlugin(payload *crypto.Payload) (Plugin, error) {
	typeStr := payload.Type.String()
	factory, err := GetLoaderFactory(typeStr)
	if err != nil {
		return nil, fmt.Errorf("unsupported plugin type: %s", typeStr)
	}

	loader, err := factory()
	if err != nil {
		return nil, fmt.Errorf("failed to create loader: %w", err)
	}

	return loader.Load(payload.Data, payload.Name)
}
