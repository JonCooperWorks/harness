package plugin

import (
	"testing"
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

// Note: Testing actual WASM plugin functionality (Name, Description, JSONSchema, Execute)
// would require either:
// 1. A real WASM file (which we're avoiding per the plan)
// 2. Mocking the Extism SDK (complex)
// 
// For now, we test the loader creation and invalid data handling.
// Full integration tests with actual WASM files would be in integration_test.go
// if needed later.

// The following tests verify structure but don't fully exercise WASM functionality
// without actual WASM files. These are placeholders that demonstrate the testing
// approach that would be used with real WASM files.

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

// Note: Full WASM plugin tests (Name, Description, JSONSchema, Execute methods)
// would require actual WASM files or extensive Extism mocking.
// These are integration-level tests that would go in wasm_integration_test.go
// if real WASM files are available for testing.

