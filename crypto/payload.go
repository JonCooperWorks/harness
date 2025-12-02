package crypto

// PluginType represents the type of plugin
type PluginType uint8

const (
	// WASM represents a WebAssembly plugin
	WASM PluginType = iota
)

// Payload represents the decrypted payload structure
type Payload struct {
	Type PluginType `json:"type"`
	Name string     `json:"name"`
	Data []byte     `json:"data"`
}
