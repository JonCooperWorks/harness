package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/joncooperworks/harness/plugin"
)

func main() {
	// Load the compiled WASM plugin
	wasmPath := "target/wasm32-wasip1/release/udp_example_plugin.wasm"
	wasmData, err := os.ReadFile(wasmPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read WASM file: %v\n", err)
		os.Exit(1)
	}

	// Create WASM loader
	loader, err := plugin.NewWASMLoader()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create WASM loader: %v\n", err)
		os.Exit(1)
	}

	// Load the plugin
	p, err := loader.Load(wasmData, "udp-example-test")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load plugin: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		if wp, ok := p.(*plugin.WASMPlugin); ok {
			wp.Close()
		}
	}()

	// Prepare arguments for localhost:6000
	args := map[string]interface{}{
		"target":  "127.0.0.1",
		"port":    6000,
		"message": "Hello from UDP plugin!",
	}
	argsJSON, err := json.Marshal(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to marshal args: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Plugin Name: %s\n", p.Name())
	fmt.Printf("Plugin Description: %s\n", p.Description())
	fmt.Printf("Sending UDP datagram to localhost:6000\n")
	fmt.Printf("Arguments: %s\n\n", string(argsJSON))

	// Execute the plugin
	ctx := context.Background()
	result, err := p.Execute(ctx, argsJSON)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Plugin execution failed: %v\n", err)
		os.Exit(1)
	}

	// Print result
	resultJSON, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to marshal result: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Execution Result:")
	fmt.Println(string(resultJSON))
}

