package crypto

import (
	"encoding/json"
	"testing"
)

func TestPluginTypeString_MarshalJSON(t *testing.T) {
	tests := []struct {
		name string
		pt   PluginTypeString
		want string
	}{
		{"wasm type", PluginTypeString("wasm"), `"wasm"`},
		{"python type", PluginTypeString("python"), `"python"`},
		{"empty type", PluginTypeString(""), `""`},
		{"custom type", PluginTypeString("custom-plugin"), `"custom-plugin"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := json.Marshal(tt.pt)
			if err != nil {
				t.Fatalf("json.Marshal() error = %v", err)
			}
			if string(got) != tt.want {
				t.Errorf("json.Marshal() = %q, want %q", string(got), tt.want)
			}
		})
	}
}

func TestPluginTypeString_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		want    PluginTypeString
		wantErr bool
	}{
		{"valid wasm", `"wasm"`, PluginTypeString("wasm"), false},
		{"valid python", `"python"`, PluginTypeString("python"), false},
		{"empty string", `""`, PluginTypeString(""), false},
		{"custom type", `"custom-plugin"`, PluginTypeString("custom-plugin"), false},
		{"invalid json - number", `123`, PluginTypeString(""), true},
		{"invalid json - object", `{}`, PluginTypeString(""), true},
		{"invalid json - array", `[]`, PluginTypeString(""), true},
		{"invalid json - null", `null`, PluginTypeString(""), false}, // null is valid JSON, unmarshals to empty string
		{"invalid json - boolean", `true`, PluginTypeString(""), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var pt PluginTypeString
			err := json.Unmarshal([]byte(tt.data), &pt)
			if (err != nil) != tt.wantErr {
				t.Errorf("json.Unmarshal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && pt != tt.want {
				t.Errorf("json.Unmarshal() = %q, want %q", pt, tt.want)
			}
		})
	}
}

func TestPluginTypeString_String(t *testing.T) {
	tests := []struct {
		name string
		pt   PluginTypeString
		want string
	}{
		{"wasm", PluginTypeString("wasm"), "wasm"},
		{"python", PluginTypeString("python"), "python"},
		{"empty", PluginTypeString(""), ""},
		{"custom", PluginTypeString("custom-plugin"), "custom-plugin"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.pt.String()
			if got != tt.want {
				t.Errorf("PluginTypeString.String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPluginTypeString_Roundtrip(t *testing.T) {
	tests := []PluginTypeString{
		"wasm",
		"python",
		"",
		"custom-plugin",
		"plugin-with-special-chars_123",
	}

	for _, tt := range tests {
		t.Run(string(tt), func(t *testing.T) {
			// Marshal
			data, err := json.Marshal(tt)
			if err != nil {
				t.Fatalf("json.Marshal() error = %v", err)
			}

			// Unmarshal
			var pt PluginTypeString
			err = json.Unmarshal(data, &pt)
			if err != nil {
				t.Fatalf("json.Unmarshal() error = %v", err)
			}

			// Verify roundtrip
			if pt != tt {
				t.Errorf("roundtrip failed: got %q, want %q", pt, tt)
			}
		})
	}
}
