package plugin

import (
	"fmt"

	"github.com/joncooperworks/harness/crypto"
	"github.com/joncooperworks/harness/plugin/wasm"
)

// Loader loads plugins based on their type
type Loader interface {
	Load(data []byte, name string) (Plugin, error)
}

// LoadPlugin loads a plugin from a Payload
func LoadPlugin(payload *crypto.Payload) (Plugin, error) {
	if payload.Type != crypto.WASM {
		return nil, fmt.Errorf("unsupported plugin type: %d (only WASM is supported)", payload.Type)
	}

	loader, err := wasm.NewWASMLoader()
	if err != nil {
		return nil, fmt.Errorf("failed to create WASM loader: %w", err)
	}

	return loader.Load(payload.Data, payload.Name)
}
