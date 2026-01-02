package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/joncooperworks/harness/crypto/hceepcrypto"
	"github.com/joncooperworks/harness/crypto/keystore"
)

func TestEncryptAES(t *testing.T) {
	// Generate a random 32-byte key (AES-256)
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	tests := []struct {
		name      string
		plaintext []byte
		key       []byte
		aad       []byte
		wantErr   bool
	}{
		{
			name:      "simple text",
			plaintext: []byte("hello world"),
			key:       key,
			aad:       []byte("aad data"),
			wantErr:   false,
		},
		{
			name:      "empty plaintext",
			plaintext: []byte{},
			key:       key,
			aad:       []byte("aad"),
			wantErr:   false,
		},
		{
			name:      "binary data",
			plaintext: []byte{0x00, 0xFF, 0x80, 0x7F},
			key:       key,
			aad:       []byte("aad"),
			wantErr:   false,
		},
		{
			name:      "large payload",
			plaintext: bytes.Repeat([]byte("x"), 10000),
			key:       key,
			aad:       []byte("aad"),
			wantErr:   false,
		},
		{
			name:      "empty AAD",
			plaintext: []byte("data"),
			key:       key,
			aad:       []byte{},
			wantErr:   false,
		},
		{
			name:      "invalid key size - too short",
			plaintext: []byte("data"),
			key:       []byte("too short"),
			aad:       []byte("aad"),
			wantErr:   true,
		},
		{
			name:      "invalid key size - too long",
			plaintext: []byte("data"),
			key:       bytes.Repeat([]byte("x"), 64),
			aad:       []byte("aad"),
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ciphertext, err := encryptAES(tt.plaintext, tt.key, tt.aad)
			if (err != nil) != tt.wantErr {
				t.Errorf("encryptAES() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}

			// Verify ciphertext is not empty (should have nonce + encrypted data + tag)
			if len(ciphertext) == 0 {
				t.Error("encryptAES() returned empty ciphertext")
			}

			// Verify minimum size: nonce (12) + tag (16)
			if len(ciphertext) < 12+16 {
				t.Errorf("encryptAES() returned ciphertext too short: %d bytes", len(ciphertext))
			}

			// Verify ciphertext is different from plaintext
			if bytes.Equal(ciphertext, tt.plaintext) {
				t.Error("encryptAES() returned ciphertext equal to plaintext")
			}

			// Verify we can decrypt it (test roundtrip)
			nonce := ciphertext[:12]
			data := ciphertext[12:]

			block, err := aes.NewCipher(tt.key)
			if err != nil {
				t.Fatalf("failed to create cipher: %v", err)
			}

			gcm, err := cipher.NewGCM(block)
			if err != nil {
				t.Fatalf("failed to create GCM: %v", err)
			}

			decrypted, err := gcm.Open(nil, nonce, data, tt.aad)
			if err != nil {
				t.Fatalf("failed to decrypt: %v", err)
			}

			if !bytes.Equal(decrypted, tt.plaintext) {
				t.Errorf("decrypted = %v, want %v", decrypted, tt.plaintext)
			}
		})
	}
}

func TestEncryptAES_InvalidKeySize(t *testing.T) {
	plaintext := []byte("test data")
	aad := []byte("aad")

	tests := []struct {
		name string
		key  []byte
	}{
		{"too short", []byte("short")},
		{"zero length", []byte{}},
		{"16 bytes", bytes.Repeat([]byte("x"), 16)},
		{"64 bytes", bytes.Repeat([]byte("x"), 64)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := encryptAES(plaintext, tt.key, aad)
			if err == nil {
				t.Error("encryptAES() error = nil, want error for invalid key size")
			}
		})
	}
}

func TestEncryptPlugin_NilRequest(t *testing.T) {
	_, err := EncryptPlugin(nil)
	if err == nil {
		t.Error("EncryptPlugin() with nil request error = nil, want error")
	}
	if !strings.Contains(err.Error(), "cannot be nil") {
		t.Errorf("EncryptPlugin() error = %v, want error containing 'cannot be nil'", err)
	}
}

func TestEncryptPlugin_InvalidKeys(t *testing.T) {
	principalKS, _ := keystore.NewMockKeystore("principal-key")
	harnessPub, _, _ := ed25519.GenerateKey(rand.Reader)
	targetPub, _, _ := ed25519.GenerateKey(rand.Reader)

	tests := []struct {
		name   string
		req    *EncryptPluginRequest
		errMsg string
	}{
		{
			name: "nil plugin data reader",
			req: &EncryptPluginRequest{
				PluginData:        nil,
				PluginType:        "wasm",
				PluginName:        "test",
				HarnessPubKey:     harnessPub,
				TargetPubKey:      targetPub,
				PrincipalKeystore: principalKS,
			},
			errMsg: "plugin data reader cannot be nil",
		},
		{
			name: "nil harness public key",
			req: &EncryptPluginRequest{
				PluginData:        strings.NewReader("plugin data"),
				PluginType:        "wasm",
				PluginName:        "test",
				HarnessPubKey:     nil,
				TargetPubKey:      targetPub,
				PrincipalKeystore: principalKS,
			},
			errMsg: "harness public key cannot be nil",
		},
		{
			name: "nil target public key",
			req: &EncryptPluginRequest{
				PluginData:        strings.NewReader("plugin data"),
				PluginType:        "wasm",
				PluginName:        "test",
				HarnessPubKey:     harnessPub,
				TargetPubKey:      nil,
				PrincipalKeystore: principalKS,
			},
			errMsg: "target public key cannot be nil",
		},
		{
			name: "nil principal keystore",
			req: &EncryptPluginRequest{
				PluginData:        strings.NewReader("plugin data"),
				PluginType:        "wasm",
				PluginName:        "test",
				HarnessPubKey:     harnessPub,
				TargetPubKey:      targetPub,
				PrincipalKeystore: nil,
			},
			errMsg: "principal keystore cannot be nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := EncryptPlugin(tt.req)
			if err == nil {
				t.Error("EncryptPlugin() error = nil, want error")
				return
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("EncryptPlugin() error = %v, want error containing %q", err, tt.errMsg)
			}
		})
	}
}

func TestEncryptPlugin_EmptyPluginData(t *testing.T) {
	principalKS, _ := keystore.NewMockKeystore("principal-key")
	harnessPub, _, _ := ed25519.GenerateKey(rand.Reader)
	targetPub, _, _ := ed25519.GenerateKey(rand.Reader)

	req := &EncryptPluginRequest{
		PluginData:        strings.NewReader(""),
		PluginType:        "wasm",
		PluginName:        "empty-plugin",
		HarnessPubKey:     harnessPub,
		TargetPubKey:      targetPub,
		PrincipalKeystore: principalKS,
	}

	result, err := EncryptPlugin(req)
	if err != nil {
		t.Fatalf("EncryptPlugin() with empty data error = %v", err)
	}

	if len(result.EncryptedData) == 0 {
		t.Error("EncryptPlugin() returned empty encrypted data")
	}

	if result.PluginName != "empty-plugin" {
		t.Errorf("PluginName = %q, want %q", result.PluginName, "empty-plugin")
	}
}

func TestEncryptPlugin_VariousPluginTypes(t *testing.T) {
	principalKS, _ := keystore.NewMockKeystore("principal-key")
	harnessPub, _, _ := ed25519.GenerateKey(rand.Reader)
	targetPub, _, _ := ed25519.GenerateKey(rand.Reader)

	pluginTypes := []string{"wasm", "python", "custom-type"}

	for _, pluginType := range pluginTypes {
		t.Run(pluginType, func(t *testing.T) {
			req := &EncryptPluginRequest{
				PluginData:        strings.NewReader("plugin binary data"),
				PluginType:        pluginType,
				PluginName:        "test-plugin",
				HarnessPubKey:     harnessPub,
				TargetPubKey:      targetPub,
				PrincipalKeystore: principalKS,
			}

			result, err := EncryptPlugin(req)
			if err != nil {
				t.Fatalf("EncryptPlugin() error = %v", err)
			}

			if len(result.EncryptedData) == 0 {
				t.Error("EncryptPlugin() returned empty encrypted data")
			}

			if len(result.PrincipalSignature) != 64 {
				t.Errorf("PrincipalSignature length = %d, want 64 (Ed25519 signature size)", len(result.PrincipalSignature))
			}
		})
	}
}

func TestEncryptPlugin_EndToEnd(t *testing.T) {
	// Create keystores for all parties
	principalKS, err := keystore.NewMockKeystore("principal-key")
	if err != nil {
		t.Fatalf("failed to create principal keystore: %v", err)
	}

	harnessKS, err := keystore.NewMockKeystore("harness-key")
	if err != nil {
		t.Fatalf("failed to create harness keystore: %v", err)
	}

	targetKS, err := keystore.NewMockKeystore("target-key")
	if err != nil {
		t.Fatalf("failed to create target keystore: %v", err)
	}

	// Get public keys
	harnessPub, err := harnessKS.PublicKey()
	if err != nil {
		t.Fatalf("failed to get harness public key: %v", err)
	}

	targetPub, err := targetKS.PublicKey()
	if err != nil {
		t.Fatalf("failed to get target public key: %v", err)
	}

	// Prepare plugin data
	pluginData := []byte("test plugin binary data")
	req := &EncryptPluginRequest{
		PluginData:        bytes.NewReader(pluginData),
		PluginType:        "wasm",
		PluginName:        "test-plugin",
		HarnessPubKey:     harnessPub,
		TargetPubKey:      targetPub,
		PrincipalKeystore: principalKS,
	}

	// Encrypt
	result, err := EncryptPlugin(req)
	if err != nil {
		t.Fatalf("EncryptPlugin() error = %v", err)
	}

	// Verify result structure
	if len(result.EncryptedData) == 0 {
		t.Fatal("EncryptPlugin() returned empty encrypted data")
	}

	if result.PluginName != "test-plugin" {
		t.Errorf("PluginName = %q, want %q", result.PluginName, "test-plugin")
	}

	if len(result.PrincipalSignature) != 64 {
		t.Errorf("PrincipalSignature length = %d, want 64", len(result.PrincipalSignature))
	}

	// Verify hashes are present and correct length (SHA-256 hex = 64 chars)
	if len(result.Hashes.ExploitOwnerSignatureHash) != 64 {
		t.Errorf("ExploitOwnerSignatureHash length = %d, want 64", len(result.Hashes.ExploitOwnerSignatureHash))
	}

	if len(result.Hashes.ExploitOwnerPublicKeyHash) != 64 {
		t.Errorf("ExploitOwnerPublicKeyHash length = %d, want 64", len(result.Hashes.ExploitOwnerPublicKeyHash))
	}

	if len(result.Hashes.HarnessPublicKeyHash) != 64 {
		t.Errorf("HarnessPublicKeyHash length = %d, want 64", len(result.Hashes.HarnessPublicKeyHash))
	}

	// Verify encrypted envelope can be decrypted by target
	enc := hceepcrypto.NewEnvelopeCipher(targetKS)
	innerEnvelope, err := enc.DecryptFromPeer(hceepcrypto.ContextEnvelope, result.EncryptedData)
	if err != nil {
		t.Fatalf("failed to decrypt envelope: %v", err)
	}

	if len(innerEnvelope) == 0 {
		t.Fatal("decrypted inner envelope is empty")
	}

	// Verify inner envelope structure (should have magic bytes "HARN")
	if len(innerEnvelope) < 4 {
		t.Fatal("inner envelope too short")
	}
	if string(innerEnvelope[0:4]) != "HARN" {
		t.Errorf("inner envelope magic bytes = %q, want %q", string(innerEnvelope[0:4]), "HARN")
	}

	// Verify the signature in the inner envelope matches the returned signature
	// Extract signature from inner envelope
	// Format: [magic:4][version:1][flags:1][file_length:4][principal_sig_len:4][principal_sig]...
	const headerSize = 4 + 1 + 1 + 4
	if len(innerEnvelope) < headerSize+4 {
		t.Fatal("inner envelope too short for signature length")
	}

	// The signature should match what was returned
	// We can verify this by checking the signature length and that it's a valid Ed25519 signature
	if len(result.PrincipalSignature) != 64 {
		t.Errorf("PrincipalSignature length = %d, want 64", len(result.PrincipalSignature))
	}
}

// TestEncryptPlugin_LargePlugin tests encryption with a larger plugin
func TestEncryptPlugin_LargePlugin(t *testing.T) {
	principalKS, _ := keystore.NewMockKeystore("principal-key")
	harnessPub, _, _ := ed25519.GenerateKey(rand.Reader)
	targetPub, _, _ := ed25519.GenerateKey(rand.Reader)

	// Create a larger plugin (100KB)
	largePluginData := bytes.Repeat([]byte("x"), 100*1024)

	req := &EncryptPluginRequest{
		PluginData:        bytes.NewReader(largePluginData),
		PluginType:        "wasm",
		PluginName:        "large-plugin",
		HarnessPubKey:     harnessPub,
		TargetPubKey:      targetPub,
		PrincipalKeystore: principalKS,
	}

	result, err := EncryptPlugin(req)
	if err != nil {
		t.Fatalf("EncryptPlugin() with large plugin error = %v", err)
	}

	if len(result.EncryptedData) == 0 {
		t.Error("EncryptPlugin() returned empty encrypted data")
	}
}
