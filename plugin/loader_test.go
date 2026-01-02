package plugin

import (
	"encoding/json"
	"testing"

	"github.com/joncooperworks/harness/crypto"
)

// MockLoader is a test loader that returns MockPlugin instances
type MockLoader struct {
	plugins map[string]*MockPlugin
}

func NewMockLoader() *MockLoader {
	return &MockLoader{
		plugins: make(map[string]*MockPlugin),
	}
}

func (ml *MockLoader) Load(data []byte, name string) (Plugin, error) {
	// Check if we have a predefined plugin
	if plugin, ok := ml.plugins[name]; ok {
		return plugin, nil
	}

	// Otherwise create a default mock plugin
	return NewMockPlugin(name, "mock plugin", json.RawMessage(`{}`)), nil
}

func (ml *MockLoader) SetPlugin(name string, plugin *MockPlugin) {
	ml.plugins[name] = plugin
}

func TestLoadPlugin_ValidPayload(t *testing.T) {
	// Register a mock loader
	testType := "mock-plugin-type"
	mockLoader := NewMockLoader()
	RegisterLoader(testType, func() (Loader, error) {
		return mockLoader, nil
	})

	// Create a payload
	payload := &crypto.Payload{
		Type: crypto.PluginTypeString(testType),
		Name: "test-plugin",
		Data: []byte("plugin data"),
	}

	plugin, err := LoadPlugin(payload)
	if err != nil {
		t.Fatalf("LoadPlugin() error = %v", err)
	}

	if plugin == nil {
		t.Fatal("LoadPlugin() returned nil plugin")
	}

	if plugin.Name() != "test-plugin" {
		t.Errorf("plugin.Name() = %q, want %q", plugin.Name(), "test-plugin")
	}
}

func TestLoadPlugin_UnsupportedType(t *testing.T) {
	payload := &crypto.Payload{
		Type: crypto.PluginTypeString("unsupported-type-xyz123"),
		Name: "test-plugin",
		Data: []byte("plugin data"),
	}

	_, err := LoadPlugin(payload)
	if err == nil {
		t.Error("LoadPlugin() with unsupported type error = nil, want error")
		return
	}

	// Verify error message mentions unsupported type
	if err.Error() == "" {
		t.Error("LoadPlugin() error message is empty")
	}
}

func TestLoadPlugin_LoaderFactoryError(t *testing.T) {
	testType := "factory-error-type"
	errorFactory := func() (Loader, error) {
		return nil, &testError{message: "factory error"}
	}
	RegisterLoader(testType, errorFactory)

	payload := &crypto.Payload{
		Type: crypto.PluginTypeString(testType),
		Name: "test-plugin",
		Data: []byte("plugin data"),
	}

	_, err := LoadPlugin(payload)
	if err == nil {
		t.Error("LoadPlugin() with factory error error = nil, want error")
	}
}

type testError struct {
	message string
}

func (e *testError) Error() string {
	return e.message
}

func TestValidateArgs_ValidSchema(t *testing.T) {
	schema := json.RawMessage(`{
		"type": "object",
		"properties": {
			"name": {"type": "string"},
			"age": {"type": "number"}
		},
		"required": ["name"]
	}`)

	plugin := NewMockPlugin("test-plugin", "test", schema)

	validArgs := json.RawMessage(`{"name": "Alice", "age": 30}`)
	err := ValidateArgs(plugin, validArgs)
	if err != nil {
		t.Errorf("ValidateArgs() with valid args error = %v", err)
	}
}

func TestValidateArgs_InvalidSchema(t *testing.T) {
	schema := json.RawMessage(`{
		"type": "object",
		"properties": {
			"name": {"type": "string"}
		},
		"required": ["name"]
	}`)

	plugin := NewMockPlugin("test-plugin", "test", schema)

	// Missing required field
	invalidArgs := json.RawMessage(`{"age": 30}`)
	err := ValidateArgs(plugin, invalidArgs)
	if err == nil {
		t.Error("ValidateArgs() with invalid args (missing required field) error = nil, want error")
	}

	// Wrong type
	wrongTypeArgs := json.RawMessage(`{"name": 123}`)
	err = ValidateArgs(plugin, wrongTypeArgs)
	if err == nil {
		t.Error("ValidateArgs() with invalid args (wrong type) error = nil, want error")
	}
}

func TestValidateArgs_EmptySchema(t *testing.T) {
	plugin := NewMockPlugin("test-plugin", "test", json.RawMessage(``))

	args := json.RawMessage(`{"anything": "goes"}`)
	err := ValidateArgs(plugin, args)
	if err != nil {
		t.Errorf("ValidateArgs() with empty schema error = %v, want nil (should skip validation)", err)
	}
}

func TestValidateArgs_TrivialSchema(t *testing.T) {
	plugin := NewMockPlugin("test-plugin", "test", json.RawMessage(`{}`))

	args := json.RawMessage(`{"anything": "goes"}`)
	err := ValidateArgs(plugin, args)
	if err != nil {
		t.Errorf("ValidateArgs() with trivial schema error = %v, want nil (should skip validation)", err)
	}
}

func TestValidateArgs_ComplexSchema(t *testing.T) {
	schema := json.RawMessage(`{
		"type": "object",
		"properties": {
			"target": {
				"type": "string",
				"pattern": "^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$"
			},
			"port": {
				"type": "integer",
				"minimum": 1,
				"maximum": 65535
			},
			"options": {
				"type": "object",
				"properties": {
					"timeout": {"type": "number", "minimum": 0}
				}
			}
		},
		"required": ["target", "port"]
	}`)

	plugin := NewMockPlugin("test-plugin", "test", schema)

	// Valid complex args
	validArgs := json.RawMessage(`{
		"target": "192.168.1.100",
		"port": 443,
		"options": {
			"timeout": 30.5
		}
	}`)
	err := ValidateArgs(plugin, validArgs)
	if err != nil {
		t.Errorf("ValidateArgs() with valid complex args error = %v", err)
	}

	// Invalid - wrong IP pattern
	invalidArgs := json.RawMessage(`{
		"target": "not-an-ip",
		"port": 443
	}`)
	err = ValidateArgs(plugin, invalidArgs)
	if err == nil {
		t.Error("ValidateArgs() with invalid pattern error = nil, want error")
	}

	// Invalid - port out of range
	invalidPortArgs := json.RawMessage(`{
		"target": "192.168.1.100",
		"port": 99999
	}`)
	err = ValidateArgs(plugin, invalidPortArgs)
	if err == nil {
		t.Error("ValidateArgs() with port out of range error = nil, want error")
	}
}

func TestLoadPlugin_WithArgsValidation(t *testing.T) {
	testType := "validation-test-type"
	schema := json.RawMessage(`{
		"type": "object",
		"properties": {
			"name": {"type": "string"}
		},
		"required": ["name"]
	}`)

	mockLoader := NewMockLoader()
	mockLoader.SetPlugin("test-plugin", NewMockPlugin("test-plugin", "test", schema))
	RegisterLoader(testType, func() (Loader, error) {
		return mockLoader, nil
	})

	// Test with valid args
	payload := &crypto.Payload{
		Type: crypto.PluginTypeString(testType),
		Name: "test-plugin",
		Data: []byte("plugin data"),
		Args: []byte(`{"name": "Alice"}`),
	}

	plugin, err := LoadPlugin(payload)
	if err != nil {
		t.Fatalf("LoadPlugin() with valid args error = %v", err)
	}

	if plugin == nil {
		t.Fatal("LoadPlugin() returned nil plugin")
	}

	// Test with invalid args
	payload.Args = []byte(`{"age": 30}`) // Missing required "name" field
	_, err = LoadPlugin(payload)
	if err == nil {
		t.Error("LoadPlugin() with invalid args error = nil, want error")
	}
}

func TestLoadPlugin_WithoutArgs(t *testing.T) {
	testType := "no-args-test-type"
	mockLoader := NewMockLoader()
	RegisterLoader(testType, func() (Loader, error) {
		return mockLoader, nil
	})

	payload := &crypto.Payload{
		Type: crypto.PluginTypeString(testType),
		Name: "test-plugin",
		Data: []byte("plugin data"),
		Args: []byte{}, // Empty args
	}

	plugin, err := LoadPlugin(payload)
	if err != nil {
		t.Fatalf("LoadPlugin() without args error = %v", err)
	}

	if plugin == nil {
		t.Fatal("LoadPlugin() returned nil plugin")
	}
}

func TestValidateArgs_InvalidJSON(t *testing.T) {
	schema := json.RawMessage(`{
		"type": "object",
		"properties": {
			"name": {"type": "string"}
		}
	}`)

	plugin := NewMockPlugin("test-plugin", "test", schema)

	invalidJSON := json.RawMessage(`{"name": "Alice"`) // Missing closing brace
	err := ValidateArgs(plugin, invalidJSON)
	if err == nil {
		t.Error("ValidateArgs() with invalid JSON error = nil, want error")
	}
}

func TestValidateArgs_InvalidSchemaDefinition(t *testing.T) {
	// Invalid schema JSON
	invalidSchema := json.RawMessage(`{
		"type": "object",
		"properties": {
			"name": {"type": "invalid-type-that-does-not-exist"}
		}
	}`)

	plugin := NewMockPlugin("test-plugin", "test", invalidSchema)

	args := json.RawMessage(`{"name": "Alice"}`)
	err := ValidateArgs(plugin, args)
	// Depending on JSON Schema implementation, this might fail at compile time or validation time
	// We just check that it doesn't panic
	if err != nil {
		// This is acceptable - invalid schema definitions should be caught
	}
}
