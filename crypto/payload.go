package crypto

import (
	"encoding/json"
	"fmt"
	"strconv"
)

// PluginTypeString represents a plugin type identifier (e.g., "wasm", "python").
//
// It handles both legacy numeric types and new string types for backward
// compatibility with existing encrypted files. Legacy numeric types are
// automatically converted: 0 -> "wasm".
type PluginTypeString string

// UnmarshalJSON implements custom JSON unmarshaling to support both:
// - Legacy format: numeric type (0 = WASM)
// - New format: string type ("wasm", "python", etc.)
func (pt *PluginTypeString) UnmarshalJSON(data []byte) error {
	// Try to unmarshal as string first (new format)
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		*pt = PluginTypeString(s)
		return nil
	}

	// Try to unmarshal as number (legacy format)
	var n uint8
	if err := json.Unmarshal(data, &n); err == nil {
		// Convert legacy numeric types to string identifiers
		switch n {
		case 0:
			*pt = PluginTypeString("wasm")
		default:
			*pt = PluginTypeString(strconv.Itoa(int(n)))
		}
		return nil
	}

	return fmt.Errorf("cannot unmarshal plugin type: expected string or number, got %s", string(data))
}

// MarshalJSON implements custom JSON marshaling to always output strings
func (pt PluginTypeString) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(pt))
}

// String returns the string representation
func (pt PluginTypeString) String() string {
	return string(pt)
}

// Payload represents the decrypted payload structure.
//
// This is the structure that results from decrypting an encrypted plugin.
// The Type field identifies which plugin loader should be used to load the Data.
type Payload struct {
	// Type is the plugin type identifier (e.g., "wasm", "python").
	// This must match a registered plugin loader type.
	Type PluginTypeString `json:"type"`
	// Name is the name of the plugin, typically extracted from the plugin itself.
	Name string `json:"name"`
	// Data is the raw plugin binary data (e.g., WASM module bytes).
	// This is base64-encoded when marshaled to JSON.
	Data []byte `json:"data"`
}
