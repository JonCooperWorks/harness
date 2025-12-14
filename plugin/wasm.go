package plugin

import (
	"context"
	"encoding/json"
	"fmt"

	extism "github.com/extism/go-sdk"
)

func init() {
	RegisterLoader("wasm", func() (Loader, error) {
		return NewWASMLoader()
	})
}

// WASMLoader loads WASM plugins using Extism SDK.
type WASMLoader struct{}

// NewWASMLoader creates a new WASM loader.
func NewWASMLoader() (*WASMLoader, error) {
	return &WASMLoader{}, nil
}

// Load compiles and instantiates a WASM plugin from raw bytes.
func (wl *WASMLoader) Load(data []byte, name string) (Plugin, error) {
	manifest := extism.Manifest{
		Wasm: []extism.Wasm{
			extism.WasmData{Data: data},
		},
		AllowedHosts: []string{"*"},
	}

	ctx := context.Background()
	config := extism.PluginConfig{
		EnableWasi: true,
	}
	
	// Note: Extism should provide extism_input_length, extism_input_load, and extism_output_set
	// automatically, but they may need to be registered. For now, we'll try without explicit
	// registration first, as Extism's runtime should handle these.
	plugin, err := extism.NewPlugin(ctx, manifest, config, []extism.HostFunction{})
	if err != nil {
		return nil, fmt.Errorf("failed to create Extism plugin: %w", err)
	}

	return &WASMPlugin{
		name:   name,
		plugin: plugin,
		ctx:    ctx,
	}, nil
}

// WASMPlugin implements the Plugin interface for WASM modules.
type WASMPlugin struct {
	name   string
	plugin *extism.Plugin
	ctx    context.Context
}

// Close shuts down the plugin instance and releases resources.
func (wp *WASMPlugin) Close() error {
	if wp.plugin != nil {
		return wp.plugin.Close(wp.ctx)
	}
	return nil
}

// Name returns the plugin name, preferring the WASM exported name().
func (wp *WASMPlugin) Name() string {
	result, err := wp.callStringFunction("name")
	if err == nil && result != "" {
		return result
	}
	return wp.name
}

// Description returns the plugin description by calling description().
func (wp *WASMPlugin) Description() string {
	result, err := wp.callStringFunction("description")
	if err != nil {
		return "WASM plugin"
	}
	return result
}

// JSONSchema fetches the plugin schema via json_schema().
func (wp *WASMPlugin) JSONSchema() string {
	result, err := wp.callStringFunction("json_schema")
	if err != nil {
		return "{}"
	}
	return result
}

// Execute calls the exported execute() function using Extism's input/output pattern.
// The function reads JSON args from input and writes JSON result to output.
func (wp *WASMPlugin) Execute(ctx context.Context, args json.RawMessage) (interface{}, error) {
	argsBytes := []byte(string(args))

	// Call execute function with JSON args as input data
	// The function reads input via extism_input_load and writes output via extism_output_set
	exitCode, resultBytes, err := wp.plugin.Call("execute", argsBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to execute WASM function: %w", err)
	}
	if exitCode != 0 {
		return nil, fmt.Errorf("execute function returned non-zero exit code: %d", exitCode)
	}

	// Extism's Call() returns the output bytes directly (set via extism_output_set)
	if len(resultBytes) == 0 {
		return nil, fmt.Errorf("execute function returned empty result")
	}

	// Parse JSON result
	var result interface{}
	if err := json.Unmarshal(resultBytes, &result); err != nil {
		return nil, fmt.Errorf("failed to parse JSON result: %w", err)
	}

	return result, nil
}

// callStringFunction calls a WASM function that uses Extism's input/output pattern.
// The function reads no input and writes output directly using extism_output_set.
func (wp *WASMPlugin) callStringFunction(functionName string) (string, error) {
	exitCode, resultBytes, err := wp.plugin.Call(functionName, nil)
	if err != nil {
		return "", fmt.Errorf("failed to call function %s: %w", functionName, err)
	}
	if exitCode != 0 {
		return "", fmt.Errorf("function %s returned non-zero exit code: %d", functionName, exitCode)
	}

	// Extism's Call() returns the output bytes directly (set via extism_output_set)
	if len(resultBytes) == 0 {
		return "", nil
	}

	return string(resultBytes), nil
}
