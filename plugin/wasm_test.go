package plugin

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/joncooperworks/harness/testdata"
)

func TestNewWASMLoader(t *testing.T) {
	loader, err := NewWASMLoader()
	if err != nil {
		t.Fatalf("NewWASMLoader() error = %v", err)
	}

	if loader == nil {
		t.Fatal("NewWASMLoader() returned nil loader")
	}
}

func TestWASMLoader_Load_InvalidWASM(t *testing.T) {
	loader, err := NewWASMLoader()
	if err != nil {
		t.Fatalf("NewWASMLoader() error = %v", err)
	}

	// Test with invalid WASM data (not actual WASM bytes)
	invalidWASM := []byte("this is not valid WASM data")
	_, err = loader.Load(invalidWASM, "test-plugin")

	// Extism will fail to parse invalid WASM, but the exact error depends on Extism
	// We just verify it returns an error
	if err == nil {
		t.Error("WASMLoader.Load() with invalid WASM error = nil, want error")
	}
}

func TestWASMLoader_Structure(t *testing.T) {
	loader, err := NewWASMLoader()
	if err != nil {
		t.Fatalf("NewWASMLoader() error = %v", err)
	}

	// Verify loader implements Loader interface
	var _ Loader = loader

	// Verify it's not nil
	if loader == nil {
		t.Fatal("loader is nil")
	}

	// Test loading actual WASM file
	plugin, err := loader.Load(testdata.HelloWorldWASM, "test-plugin")
	if err != nil {
		t.Fatalf("loader.Load() with real WASM error = %v", err)
	}

	if plugin == nil {
		t.Fatal("loader.Load() returned nil plugin")
	}

	// Verify plugin implements Plugin interface
	var _ Plugin = plugin

	// Clean up
	if wp, ok := plugin.(*WASMPlugin); ok {
		wp.Close()
	}
}

// TestWASMLoader_EmptyData tests loading with empty data
func TestWASMLoader_EmptyData(t *testing.T) {
	loader, err := NewWASMLoader()
	if err != nil {
		t.Fatalf("NewWASMLoader() error = %v", err)
	}

	_, err = loader.Load([]byte{}, "empty-plugin")
	// Empty data should fail to load
	if err == nil {
		t.Error("WASMLoader.Load() with empty data error = nil, want error")
	}
}

// TestWASMLoader_NilData tests loading with nil data (should panic or error)
func TestWASMLoader_NilData(t *testing.T) {
	loader, err := NewWASMLoader()
	if err != nil {
		t.Fatalf("NewWASMLoader() error = %v", err)
	}

	// Note: nil slice vs nil interface - []byte(nil) is a valid zero-length slice
	_, err = loader.Load(nil, "nil-plugin")
	// This should fail - nil is equivalent to empty slice for []byte
	if err == nil {
		t.Error("WASMLoader.Load() with nil data error = nil, want error")
	}
}

// loadTestWASMPlugin loads the embedded hello-world WASM plugin for testing.
// It returns a plugin instance that should be closed after use.
func loadTestWASMPlugin(t *testing.T) Plugin {
	t.Helper()
	loader, err := NewWASMLoader()
	if err != nil {
		t.Fatalf("NewWASMLoader() error = %v", err)
	}

	plugin, err := loader.Load(testdata.HelloWorldWASM, "test-plugin")
	if err != nil {
		t.Fatalf("failed to load test WASM plugin: %v", err)
	}

	return plugin
}

// closePlugin safely closes a plugin if it implements the Close() method.
func closePlugin(plugin Plugin) {
	if wp, ok := plugin.(*WASMPlugin); ok {
		wp.Close()
	}
}

func TestWASMPlugin_Name(t *testing.T) {
	plugin := loadTestWASMPlugin(t)
	defer closePlugin(plugin)

	name := plugin.Name()
	if name != "hello-world-plugin" {
		t.Errorf("plugin.Name() = %q, want %q", name, "hello-world-plugin")
	}
}

func TestWASMPlugin_Description(t *testing.T) {
	plugin := loadTestWASMPlugin(t)
	defer closePlugin(plugin)

	description := plugin.Description()
	expected := "A simple hello world plugin that echoes back a greeting message"
	if description != expected {
		t.Errorf("plugin.Description() = %q, want %q", description, expected)
	}
}

func TestWASMPlugin_JSONSchema(t *testing.T) {
	plugin := loadTestWASMPlugin(t)
	defer closePlugin(plugin)

	schema := plugin.JSONSchema()
	if len(schema) == 0 {
		t.Error("plugin.JSONSchema() returned empty schema")
	}

	// Verify it's valid JSON
	var schemaObj map[string]interface{}
	if err := json.Unmarshal(schema, &schemaObj); err != nil {
		t.Errorf("plugin.JSONSchema() returned invalid JSON: %v", err)
	}

	// Verify it has expected structure
	if schemaObj["type"] != "object" {
		t.Errorf("schema type = %v, want %q", schemaObj["type"], "object")
	}
}

func TestWASMPlugin_Execute(t *testing.T) {
	plugin := loadTestWASMPlugin(t)
	defer closePlugin(plugin)

	ctx := context.Background()

	// Test with message argument
	args := json.RawMessage(`{"message": "Hello from test"}`)
	result, err := plugin.Execute(ctx, args)
	if err != nil {
		t.Fatalf("plugin.Execute() error = %v", err)
	}

	// Verify result structure
	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("plugin.Execute() returned unexpected type: %T", result)
	}

	if greeting, ok := resultMap["greeting"].(string); !ok || greeting != "Hello from test" {
		t.Errorf("result.greeting = %v, want %q", resultMap["greeting"], "Hello from test")
	}

	if pluginName, ok := resultMap["plugin"].(string); !ok || pluginName != "hello-world" {
		t.Errorf("result.plugin = %v, want %q", resultMap["plugin"], "hello-world")
	}
}

func TestWASMPlugin_Execute_WithoutMessage(t *testing.T) {
	plugin := loadTestWASMPlugin(t)
	defer closePlugin(plugin)

	ctx := context.Background()

	// Test without message argument (should use default)
	args := json.RawMessage(`{}`)
	result, err := plugin.Execute(ctx, args)
	if err != nil {
		t.Fatalf("plugin.Execute() error = %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("plugin.Execute() returned unexpected type: %T", result)
	}

	// Should use default message "Hello, World!"
	if greeting, ok := resultMap["greeting"].(string); !ok || greeting != "Hello, World!" {
		t.Errorf("result.greeting = %v, want %q", resultMap["greeting"], "Hello, World!")
	}
}

func TestWASMPlugin_Close(t *testing.T) {
	plugin := loadTestWASMPlugin(t)

	// Type assert to WASMPlugin to access Close()
	wp, ok := plugin.(*WASMPlugin)
	if !ok {
		t.Fatal("plugin is not a WASMPlugin")
	}

	// Close should not panic or error
	if err := wp.Close(); err != nil {
		t.Errorf("plugin.Close() error = %v", err)
	}

	// Closing again should be safe (idempotent)
	if err := wp.Close(); err != nil {
		t.Errorf("plugin.Close() second call error = %v", err)
	}
}
