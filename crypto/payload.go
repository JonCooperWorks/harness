package crypto

import (
	"encoding/json"
	"fmt"
)

// PluginTypeString represents a plugin type identifier (e.g., "wasm", "python").
type PluginTypeString string

// UnmarshalJSON implements custom JSON unmarshaling for string types.
func (pt *PluginTypeString) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("cannot unmarshal plugin type: expected string, got %s", string(data))
	}
	*pt = PluginTypeString(s)
	return nil
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
	// Args contains the JSON execution arguments that were signed by the client
	// and encrypted for the pentester. This field is populated during decryption
	// and is not part of the serialized payload format.
	Args []byte `json:"-"`
}
