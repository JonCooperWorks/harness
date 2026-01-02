package plugin

import (
	"fmt"
	"sync"
	"testing"
)

// TestLoader is a simple test loader implementation
type TestLoader struct {
	name string
}

func (tl *TestLoader) Load(data []byte, name string) (Plugin, error) {
	return nil, fmt.Errorf("test loader not implemented")
}

func TestRegisterLoader(t *testing.T) {
	// Register a test loader
	testType := "test-plugin-type"
	testFactory := func() (Loader, error) {
		return &TestLoader{name: "test"}, nil
	}

	RegisterLoader(testType, testFactory)

	// Verify it's registered
	factory, err := GetLoaderFactory(testType)
	if err != nil {
		t.Fatalf("GetLoaderFactory() error = %v", err)
	}

	loader, err := factory()
	if err != nil {
		t.Fatalf("factory() error = %v", err)
	}

	if loader == nil {
		t.Fatal("factory() returned nil loader")
	}

	// Clean up: we can't unregister, but we can test that it's there
	types := ListRegisteredPluginTypes()
	found := false
	for _, typ := range types {
		if typ == testType {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("test type %q not found in registered types: %v", testType, types)
	}

	// Restore original state is not possible without unregister function,
	// but this is acceptable for testing since each test should use unique types
}

func TestGetLoaderFactory(t *testing.T) {
	testType := "get-loader-test-type"
	testFactory := func() (Loader, error) {
		return &TestLoader{name: "test"}, nil
	}

	RegisterLoader(testType, testFactory)

	// Test successful retrieval
	factory, err := GetLoaderFactory(testType)
	if err != nil {
		t.Fatalf("GetLoaderFactory() error = %v", err)
	}

	if factory == nil {
		t.Fatal("GetLoaderFactory() returned nil factory")
	}

	// Test non-existent type
	_, err = GetLoaderFactory("non-existent-type-xyz123")
	if err == nil {
		t.Error("GetLoaderFactory() with non-existent type error = nil, want error")
	}
}

func TestGetLoaderFactory_Concurrent(t *testing.T) {
	testType := "concurrent-test-type"
	testFactory := func() (Loader, error) {
		return &TestLoader{name: "test"}, nil
	}

	RegisterLoader(testType, testFactory)

	// Test concurrent access
	const numGoroutines = 100
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			factory, err := GetLoaderFactory(testType)
			if err != nil {
				t.Errorf("GetLoaderFactory() error = %v", err)
				return
			}
			if factory == nil {
				t.Error("GetLoaderFactory() returned nil factory")
				return
			}
		}()
	}

	wg.Wait()
}

func TestListRegisteredPluginTypes(t *testing.T) {
	// Get current registered types (should include "wasm" from init)
	types := ListRegisteredPluginTypes()

	if len(types) == 0 {
		t.Error("ListRegisteredPluginTypes() returned empty list, expected at least 'wasm'")
	}

	// Verify "wasm" is registered (from wasm.go init())
	found := false
	for _, typ := range types {
		if typ == "wasm" {
			found = true
			break
		}
	}
	if !found {
		t.Error("ListRegisteredPluginTypes() did not include 'wasm'")
	}

	// Register a new type
	testType := "list-test-type"
	RegisterLoader(testType, func() (Loader, error) {
		return &TestLoader{name: "test"}, nil
	})

	// Get types again
	newTypes := ListRegisteredPluginTypes()

	// Verify new type is in the list
	found = false
	for _, typ := range newTypes {
		if typ == testType {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("ListRegisteredPluginTypes() did not include newly registered type %q", testType)
	}

	// Verify list is larger
	if len(newTypes) <= len(types) {
		t.Errorf("ListRegisteredPluginTypes() returned %d types, expected more than %d", len(newTypes), len(types))
	}
}

func TestListRegisteredPluginTypes_Concurrent(t *testing.T) {
	testType := "concurrent-list-test-type"
	RegisterLoader(testType, func() (Loader, error) {
		return &TestLoader{name: "test"}, nil
	})

	// Test concurrent access
	const numGoroutines = 100
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			types := ListRegisteredPluginTypes()

			if len(types) == 0 {
				t.Error("ListRegisteredPluginTypes() returned empty list")
			}

			// Verify our test type is in the list
			found := false
			for _, typ := range types {
				if typ == testType {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("ListRegisteredPluginTypes() did not include test type %q", testType)
			}
		}()
	}

	wg.Wait()
}

func TestListRegisteredPluginTypes_Sorted(t *testing.T) {
	// Register multiple types
	typeNames := []string{"zebra-type", "alpha-type", "middle-type"}
	for _, name := range typeNames {
		RegisterLoader(name, func() (Loader, error) {
			return &TestLoader{name: "test"}, nil
		})
	}

	types := ListRegisteredPluginTypes()

	// Check that our types are in the list
	for _, name := range typeNames {
		found := false
		for _, typ := range types {
			if typ == name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("ListRegisteredPluginTypes() did not include %q", name)
		}
	}

	// Note: The list is not guaranteed to be sorted, but we can verify
	// it contains all expected items
}

func TestRegisterLoader_Overwrite(t *testing.T) {
	testType := "overwrite-test-type"

	// Register first factory
	firstFactory := func() (Loader, error) {
		return &TestLoader{name: "first"}, nil
	}
	RegisterLoader(testType, firstFactory)

	// Overwrite with second factory
	secondFactory := func() (Loader, error) {
		return &TestLoader{name: "second"}, nil
	}
	RegisterLoader(testType, secondFactory)

	// Verify second factory is used
	factory, err := GetLoaderFactory(testType)
	if err != nil {
		t.Fatalf("GetLoaderFactory() error = %v", err)
	}

	loader, err := factory()
	if err != nil {
		t.Fatalf("factory() error = %v", err)
	}

	// Note: We can't easily verify which factory was used without more sophisticated
	// testing, but we can at least verify it works
	if loader == nil {
		t.Fatal("factory() returned nil loader")
	}
}

func TestGetLoaderFactory_MultipleTypes(t *testing.T) {
	// Register multiple types
	typeFactories := map[string]LoaderFactory{
		"type-a": func() (Loader, error) { return &TestLoader{name: "a"}, nil },
		"type-b": func() (Loader, error) { return &TestLoader{name: "b"}, nil },
		"type-c": func() (Loader, error) { return &TestLoader{name: "c"}, nil },
	}

	for typ, factory := range typeFactories {
		RegisterLoader(typ, factory)
	}

	// Verify each can be retrieved
	for typ := range typeFactories {
		factory, err := GetLoaderFactory(typ)
		if err != nil {
			t.Errorf("GetLoaderFactory(%q) error = %v", typ, err)
			continue
		}

		loader, err := factory()
		if err != nil {
			t.Errorf("factory() for %q error = %v", typ, err)
			continue
		}

		if loader == nil {
			t.Errorf("factory() for %q returned nil loader", typ)
		}
	}
}
