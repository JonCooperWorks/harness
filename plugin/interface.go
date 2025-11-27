package plugin

import (
	"context"
	"encoding/json"
)

// Plugin defines the interface that all plugins must implement
type Plugin interface {
	// Name returns the name of the plugin
	Name() string

	// Description returns a description of what the plugin does
	Description() string

	// JSONSchema returns the JSON schema for the plugin's arguments
	JSONSchema() string

	// Execute runs the plugin with the given context and JSON arguments
	Execute(ctx context.Context, args json.RawMessage) (interface{}, error)
}

