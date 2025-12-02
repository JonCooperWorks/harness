package plugin

import (
	"fmt"

	"github.com/joncooperworks/harness/crypto"
)

// Loader loads plugins based on their type
type Loader interface {
	Load(data []byte, name string) (Plugin, error)
}

// LoadPlugin loads a plugin from a Payload
// Uses the registry to find the appropriate loader for the payload type
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
