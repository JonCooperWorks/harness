package plugin

import (
	"fmt"
	"strings"

	"github.com/joncooperworks/harness/crypto"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// Loader loads plugins based on their type.
//
// Each plugin type (WASM, Python, etc.) has a corresponding Loader implementation
// that knows how to parse the plugin binary data and create a Plugin instance.
type Loader interface {
	// Load creates a Plugin instance from the raw plugin binary data.
	// The data parameter contains the plugin binary (e.g., WASM module bytes).
	// The name parameter is the plugin name, typically extracted from the plugin itself.
	Load(data []byte, name string) (Plugin, error)
}

// LoadPlugin loads a plugin from a Payload and validates the args against its JSON schema.
//
// This function uses the registry to find the appropriate loader for the payload type.
// The payload.Type must match a registered plugin loader type (e.g., "wasm", "python").
//
// After loading the plugin, if payload.Args is non-empty, the args are validated against
// the plugin's JSON schema before the plugin is returned. This ensures execution only
// proceeds with valid arguments.
//
// Returns an error if:
// - No loader is registered for the payload type
// - Loading fails
// - The plugin's JSON schema is invalid
// - The args do not conform to the schema
func LoadPlugin(payload *crypto.Payload) (Plugin, error) {
	typeStr := payload.Type.String()
	factory, err := GetLoaderFactory(typeStr)
	if err != nil {
		return nil, fmt.Errorf("unsupported plugin type: %s", typeStr)
	}

	loader, err := factory()
	if err != nil {
		return nil, fmt.Errorf("failed to create loader: %w", err)
	}

	plugin, err := loader.Load(payload.Data, payload.Name)
	if err != nil {
		return nil, err
	}

	// Validate args against the plugin's JSON schema if args are present
	if len(payload.Args) > 0 {
		if err := ValidateArgs(plugin, payload.Args); err != nil {
			return nil, fmt.Errorf("argument validation failed: %w", err)
		}
	}

	return plugin, nil
}

// ValidateArgs validates the provided args against the plugin's JSON schema.
//
// If the plugin's schema is empty or "{}", validation is skipped and nil is returned.
// This allows plugins that don't require arguments to work without a schema.
//
// Returns an error if:
// - The plugin's JSON schema is invalid
// - The args do not conform to the schema
func ValidateArgs(plugin Plugin, args []byte) error {
	schemaStr := plugin.JSONSchema()

	// Skip validation if schema is empty or trivial
	schemaStr = strings.TrimSpace(schemaStr)
	if schemaStr == "" || schemaStr == "{}" {
		return nil
	}

	// Parse the schema JSON
	schemaDoc, err := jsonschema.UnmarshalJSON(strings.NewReader(schemaStr))
	if err != nil {
		return fmt.Errorf("failed to parse plugin JSON schema: %w", err)
	}

	// Compile the JSON schema
	compiler := jsonschema.NewCompiler()
	const schemaURL = "schema://plugin/args"
	if err := compiler.AddResource(schemaURL, schemaDoc); err != nil {
		return fmt.Errorf("failed to add schema resource: %w", err)
	}

	schema, err := compiler.Compile(schemaURL)
	if err != nil {
		return fmt.Errorf("invalid plugin JSON schema: %w", err)
	}

	// Parse the args using jsonschema.UnmarshalJSON to preserve number precision
	argsData, err := jsonschema.UnmarshalJSON(strings.NewReader(string(args)))
	if err != nil {
		return fmt.Errorf("failed to parse args as JSON: %w", err)
	}

	// Validate args against the schema
	if err := schema.Validate(argsData); err != nil {
		return fmt.Errorf("args do not match plugin schema: %w", err)
	}

	return nil
}
