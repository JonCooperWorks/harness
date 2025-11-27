package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
)

// Plugin is the exported symbol that the harness will look for
var Plugin = &TestPlugin{}

// TestPlugin is a simple test plugin that prints JSON
type TestPlugin struct{}

func (p *TestPlugin) Name() string {
	return "test-plugin"
}

func (p *TestPlugin) Description() string {
	return "A test plugin that prints the JSON arguments it receives"
}

func (p *TestPlugin) JSONSchema() string {
	return `{
  "type": "object",
  "properties": {
    "message": {
      "type": "string",
      "description": "A message to print"
    },
    "count": {
      "type": "number",
      "description": "Number of times to print"
    }
  }
}`
}

func (p *TestPlugin) Execute(ctx context.Context, args json.RawMessage) (interface{}, error) {
	// Parse arguments
	var argMap map[string]interface{}
	if err := json.Unmarshal(args, &argMap); err != nil {
		return nil, fmt.Errorf("failed to parse arguments: %w", err)
	}

	// Print the JSON to stdout
	fmt.Fprintf(os.Stdout, "Plugin received arguments:\n")
	prettyJSON, err := json.MarshalIndent(argMap, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal arguments: %w", err)
	}
	fmt.Fprintf(os.Stdout, "%s\n", string(prettyJSON))

	// Return a result
	result := map[string]interface{}{
		"status":  "success",
		"message": "Plugin executed successfully",
		"args":    argMap,
	}

	return result, nil
}

