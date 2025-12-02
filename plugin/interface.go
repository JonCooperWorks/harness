// Package plugin provides a unified interface for loading and executing plugins.
// It supports multiple plugin formats (WASM, Python, etc.) through a registry-based loader system.
package plugin

import (
	"context"
	"encoding/json"
)

// Plugin defines the interface that all plugins must implement.
//
// Plugins are executable code modules that can be encrypted, signed, and executed
// through the harness system. Each plugin must provide metadata (name, description,
// argument schema) and an execution function.
type Plugin interface {
	// Name returns the name of the plugin.
	// This is typically a unique identifier like "cve-2024-xxxx-exploit".
	Name() string

	// Description returns a description of what the plugin does.
	// This should provide context about the plugin's purpose and behavior.
	Description() string

	// JSONSchema returns the JSON schema for the plugin's arguments.
	// This schema defines what arguments are required and their types.
	// The schema should be a valid JSON Schema string.
	JSONSchema() string

	// Execute runs the plugin with the given context and JSON arguments.
	// The args parameter contains the JSON execution arguments that were
	// signed by the client and encrypted for the pentester.
	// Returns the execution result as an interface{} (typically a JSON-serializable value).
	Execute(ctx context.Context, args json.RawMessage) (interface{}, error)
}
