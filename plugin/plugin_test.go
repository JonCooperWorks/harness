package plugin

import (
	"context"
	"encoding/json"
)

// MockPlugin is a mock implementation of the Plugin interface for testing.
type MockPlugin struct {
	name        string
	description string
	schema      json.RawMessage
	executeFunc func(ctx context.Context, args json.RawMessage) (interface{}, error)
}

// NewMockPlugin creates a new mock plugin with the specified parameters.
func NewMockPlugin(name, description string, schema json.RawMessage) *MockPlugin {
	return &MockPlugin{
		name:        name,
		description: description,
		schema:      schema,
		executeFunc: func(ctx context.Context, args json.RawMessage) (interface{}, error) {
			return map[string]interface{}{"result": "success"}, nil
		},
	}
}

// NewMockPluginWithExecute creates a new mock plugin with a custom execute function.
func NewMockPluginWithExecute(name, description string, schema json.RawMessage, executeFunc func(ctx context.Context, args json.RawMessage) (interface{}, error)) *MockPlugin {
	return &MockPlugin{
		name:        name,
		description: description,
		schema:      schema,
		executeFunc: executeFunc,
	}
}

// Name returns the plugin name.
func (m *MockPlugin) Name() string {
	return m.name
}

// Description returns the plugin description.
func (m *MockPlugin) Description() string {
	return m.description
}

// JSONSchema returns the plugin's JSON schema.
func (m *MockPlugin) JSONSchema() json.RawMessage {
	return m.schema
}

// Execute executes the plugin with the given arguments.
func (m *MockPlugin) Execute(ctx context.Context, args json.RawMessage) (interface{}, error) {
	if m.executeFunc != nil {
		return m.executeFunc(ctx, args)
	}
	return map[string]interface{}{"result": "success"}, nil
}

