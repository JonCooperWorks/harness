package crypto

import (
	"encoding/json"
	"fmt"
	"strconv"
)

// PluginTypeString handles both legacy numeric types and new string types
// for backward compatibility with existing encrypted files
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

// Payload represents the decrypted payload structure
type Payload struct {
	Type PluginTypeString `json:"type"` // Plugin type identifier (e.g., "wasm", "python")
	Name string           `json:"name"`
	Data []byte           `json:"data"`
}
