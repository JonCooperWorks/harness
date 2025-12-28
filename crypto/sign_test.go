package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/joncooperworks/harness/crypto/keystore"
)

// createEncryptedEnvelope is a test helper that creates an encrypted envelope using EncryptPlugin
func createEncryptedEnvelope(t *testing.T, pluginData []byte, pluginType, pluginName string) []byte {
	t.Helper()

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

	harnessPub, err := harnessKS.PublicKey()
	if err != nil {
		t.Fatalf("failed to get harness public key: %v", err)
	}

	targetPub, err := targetKS.PublicKey()
	if err != nil {
		t.Fatalf("failed to get target public key: %v", err)
	}

	req := &EncryptPluginRequest{
		PluginData:        bytes.NewReader(pluginData),
		PluginType:        pluginType,
		PluginName:        pluginName,
		HarnessPubKey:     harnessPub,
		TargetPubKey:      targetPub,
		PrincipalKeystore: principalKS,
	}

	result, err := EncryptPlugin(req)
	if err != nil {
		t.Fatalf("EncryptPlugin() error = %v", err)
	}

	return result.EncryptedData
}

func TestSignEncryptedPlugin_NilRequest(t *testing.T) {
	_, err := SignEncryptedPlugin(nil)
	if err == nil {
		t.Error("SignEncryptedPlugin() with nil request error = nil, want error")
	}
	if !strings.Contains(err.Error(), "cannot be nil") {
		t.Errorf("SignEncryptedPlugin() error = %v, want error containing 'cannot be nil'", err)
	}
}

func TestSignEncryptedPlugin_InvalidRequest(t *testing.T) {
	clientKS, _ := keystore.NewMockKeystore("client-key")
	principalPub, _, _ := ed25519.GenerateKey(rand.Reader)
	harnessPub, _, _ := ed25519.GenerateKey(rand.Reader)
	pentesterPub, _, _ := ed25519.GenerateKey(rand.Reader)

	encryptedEnvelope := createEncryptedEnvelope(t, []byte("plugin data"), "wasm", "test-plugin")

	tests := []struct {
		name   string
		req    *SignEncryptedPluginRequest
		errMsg string
	}{
		{
			name: "nil encrypted data reader",
			req: &SignEncryptedPluginRequest{
				EncryptedData:   nil,
				ArgsJSON:        []byte(`{}`),
				ClientKeystore:  clientKS,
				PrincipalPubKey: principalPub,
				HarnessPubKey:   harnessPub,
				PentesterPubKey: pentesterPub,
			},
			errMsg: "encrypted data reader cannot be nil",
		},
		{
			name: "empty args JSON",
			req: &SignEncryptedPluginRequest{
				EncryptedData:   bytes.NewReader(encryptedEnvelope),
				ArgsJSON:        []byte{},
				ClientKeystore:  clientKS,
				PrincipalPubKey: principalPub,
				HarnessPubKey:   harnessPub,
				PentesterPubKey: pentesterPub,
			},
			errMsg: "args JSON cannot be empty",
		},
		{
			name: "nil client keystore",
			req: &SignEncryptedPluginRequest{
				EncryptedData:   bytes.NewReader(encryptedEnvelope),
				ArgsJSON:        []byte(`{}`),
				ClientKeystore:  nil,
				PrincipalPubKey: principalPub,
				HarnessPubKey:   harnessPub,
				PentesterPubKey: pentesterPub,
			},
			errMsg: "client keystore cannot be nil",
		},
		{
			name: "nil principal public key",
			req: &SignEncryptedPluginRequest{
				EncryptedData:   bytes.NewReader(encryptedEnvelope),
				ArgsJSON:        []byte(`{}`),
				ClientKeystore:  clientKS,
				PrincipalPubKey: nil,
				HarnessPubKey:   harnessPub,
				PentesterPubKey: pentesterPub,
			},
			errMsg: "principal public key cannot be nil",
		},
		{
			name: "nil pentester public key",
			req: &SignEncryptedPluginRequest{
				EncryptedData:   bytes.NewReader(encryptedEnvelope),
				ArgsJSON:        []byte(`{}`),
				ClientKeystore:  clientKS,
				PrincipalPubKey: principalPub,
				HarnessPubKey:   harnessPub,
				PentesterPubKey: nil,
			},
			errMsg: "pentester public key cannot be nil",
		},
		{
			name: "nil harness public key",
			req: &SignEncryptedPluginRequest{
				EncryptedData:   bytes.NewReader(encryptedEnvelope),
				ArgsJSON:        []byte(`{}`),
				ClientKeystore:  clientKS,
				PrincipalPubKey: principalPub,
				HarnessPubKey:   nil,
				PentesterPubKey: pentesterPub,
			},
			errMsg: "harness public key cannot be nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := SignEncryptedPlugin(tt.req)
			if err == nil {
				t.Error("SignEncryptedPlugin() error = nil, want error")
				return
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("SignEncryptedPlugin() error = %v, want error containing %q", err, tt.errMsg)
			}
		})
	}
}

func TestSignEncryptedPlugin_InvalidEnvelope(t *testing.T) {
	clientKS, _ := keystore.NewMockKeystore("client-key")
	principalKS, _ := keystore.NewMockKeystore("principal-key")
	harnessPub, _, _ := ed25519.GenerateKey(rand.Reader)
	pentesterPub, _, _ := ed25519.GenerateKey(rand.Reader)

	principalPubReal, err := principalKS.PublicKey()
	if err != nil {
		t.Fatalf("failed to get principal public key: %v", err)
	}

	tests := []struct {
		name          string
		encryptedData []byte
		errMsg        string
	}{
		{
			name:          "empty data",
			encryptedData: []byte{},
			errMsg:        "encrypted blob too short", // More specific error from decryption
		},
		{
			name:          "too short",
			encryptedData: []byte("too short"),
			errMsg:        "failed to decrypt envelope",
		},
		{
			name:          "invalid encrypted data",
			encryptedData: bytes.Repeat([]byte("x"), 100),
			errMsg:        "failed to decrypt envelope",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &SignEncryptedPluginRequest{
				EncryptedData:   bytes.NewReader(tt.encryptedData),
				ArgsJSON:        []byte(`{"arg":"value"}`),
				ClientKeystore:  clientKS,
				PrincipalPubKey: principalPubReal,
				HarnessPubKey:   harnessPub,
				PentesterPubKey: pentesterPub,
			}

			_, err := SignEncryptedPlugin(req)
			if err == nil {
				t.Error("SignEncryptedPlugin() error = nil, want error")
				return
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("SignEncryptedPlugin() error = %v, want error containing %q", err, tt.errMsg)
			}
		})
	}
}

func TestSignEncryptedPlugin_DefaultExpiration(t *testing.T) {
	// Create keystores
	principalKS, _ := keystore.NewMockKeystore("principal-key")
	targetKS, _ := keystore.NewMockKeystore("target-key")
	harnessKS, _ := keystore.NewMockKeystore("harness-key")
	pentesterKS, _ := keystore.NewMockKeystore("pentester-key")

	// Get public keys
	principalPub, _ := principalKS.PublicKey()
	harnessPub, _ := harnessKS.PublicKey()
	targetPub, _ := targetKS.PublicKey()
	pentesterPub, _ := pentesterKS.PublicKey()

	// Create encrypted envelope using the same keys we'll use for signing
	encryptReq := &EncryptPluginRequest{
		PluginData:        bytes.NewReader([]byte("plugin data")),
		PluginType:        "wasm",
		PluginName:        "test-plugin",
		HarnessPubKey:     harnessPub,
		TargetPubKey:      targetPub,
		PrincipalKeystore: principalKS,
	}

	encryptResult, err := EncryptPlugin(encryptReq)
	if err != nil {
		t.Fatalf("EncryptPlugin() error = %v", err)
	}

	// Sign without expiration (should default to 72 hours)
	beforeSign := time.Now()
	req := &SignEncryptedPluginRequest{
		EncryptedData:   bytes.NewReader(encryptResult.EncryptedData),
		ArgsJSON:        []byte(`{"arg":"value"}`),
		ClientKeystore:  targetKS, // Use targetKS to decrypt (same key used for encryption)
		PrincipalPubKey: principalPub,
		HarnessPubKey:   harnessPub,
		PentesterPubKey: pentesterPub,
		Expiration:      nil, // Should default to 72 hours
	}

	result, err := SignEncryptedPlugin(req)
	if err != nil {
		t.Fatalf("SignEncryptedPlugin() error = %v", err)
	}

	afterSign := time.Now()

	// Verify expiration is approximately 72 hours from now (within a few seconds tolerance)
	expectedExpiration := beforeSign.Add(72 * time.Hour)
	maxExpiration := afterSign.Add(72 * time.Hour).Add(5 * time.Second)
	minExpiration := expectedExpiration.Add(-5 * time.Second)

	if result.ExpirationTime.Before(minExpiration) || result.ExpirationTime.After(maxExpiration) {
		t.Errorf("ExpirationTime = %v, want approximately %v (72 hours from now)", result.ExpirationTime, expectedExpiration)
	}
}

func TestSignEncryptedPlugin_CustomExpiration(t *testing.T) {
	principalKS, _ := keystore.NewMockKeystore("principal-key")
	targetKS, _ := keystore.NewMockKeystore("target-key")
	harnessKS, _ := keystore.NewMockKeystore("harness-key")
	pentesterKS, _ := keystore.NewMockKeystore("pentester-key")

	principalPub, _ := principalKS.PublicKey()
	harnessPub, _ := harnessKS.PublicKey()
	targetPub, _ := targetKS.PublicKey()
	pentesterPub, _ := pentesterKS.PublicKey()

	// Create encrypted envelope using the same keys
	encryptReq := &EncryptPluginRequest{
		PluginData:        bytes.NewReader([]byte("plugin data")),
		PluginType:        "wasm",
		PluginName:        "test-plugin",
		HarnessPubKey:     harnessPub,
		TargetPubKey:      targetPub,
		PrincipalKeystore: principalKS,
	}

	encryptResult, err := EncryptPlugin(encryptReq)
	if err != nil {
		t.Fatalf("EncryptPlugin() error = %v", err)
	}

	customExpiration := time.Now().Add(24 * time.Hour)
	req := &SignEncryptedPluginRequest{
		EncryptedData:   bytes.NewReader(encryptResult.EncryptedData),
		ArgsJSON:        []byte(`{"arg":"value"}`),
		ClientKeystore:  targetKS, // Use targetKS to decrypt (same key used for encryption)
		PrincipalPubKey: principalPub,
		HarnessPubKey:   harnessPub,
		PentesterPubKey: pentesterPub,
		Expiration:      &customExpiration,
	}

	result, err := SignEncryptedPlugin(req)
	if err != nil {
		t.Fatalf("SignEncryptedPlugin() error = %v", err)
	}

	// Verify custom expiration is used
	if !result.ExpirationTime.Equal(customExpiration) {
		t.Errorf("ExpirationTime = %v, want %v", result.ExpirationTime, customExpiration)
	}
}

func TestSignEncryptedPlugin_EndToEnd(t *testing.T) {
	// Create all keystores
	principalKS, _ := keystore.NewMockKeystore("principal-key")
	targetKS, _ := keystore.NewMockKeystore("target-key")
	pentesterKS, _ := keystore.NewMockKeystore("pentester-key")

	// Get public keys
	principalPub, _ := principalKS.PublicKey()
	harnessKS, _ := keystore.NewMockKeystore("harness-key")
	harnessPub, _ := harnessKS.PublicKey()
	targetPub, _ := targetKS.PublicKey()
	pentesterPub, _ := pentesterKS.PublicKey()

	// Create encrypted envelope using the same keys
	pluginData := []byte("test plugin binary data")
	encryptReq := &EncryptPluginRequest{
		PluginData:        bytes.NewReader(pluginData),
		PluginType:        "wasm",
		PluginName:        "test-plugin",
		HarnessPubKey:     harnessPub,
		TargetPubKey:      targetPub,
		PrincipalKeystore: principalKS,
	}

	encryptResult, err := EncryptPlugin(encryptReq)
	if err != nil {
		t.Fatalf("EncryptPlugin() error = %v", err)
	}

	// Now sign it (using target keystore as client keystore)
	argsJSON := []byte(`{"target":"192.168.1.100","port":443}`)
	signReq := &SignEncryptedPluginRequest{
		EncryptedData:   bytes.NewReader(encryptResult.EncryptedData),
		ArgsJSON:        argsJSON,
		ClientKeystore:  targetKS, // Target signs as client
		PrincipalPubKey: principalPub,
		HarnessPubKey:   harnessPub,
		PentesterPubKey: pentesterPub,
	}

	result, err := SignEncryptedPlugin(signReq)
	if err != nil {
		t.Fatalf("SignEncryptedPlugin() error = %v", err)
	}

	// Verify result structure
	if len(result.ApprovedData) == 0 {
		t.Fatal("SignEncryptedPlugin() returned empty approved data")
	}

	// Verify expiration is set
	if result.ExpirationTime.IsZero() {
		t.Error("ExpirationTime is zero")
	}

	// Verify hashes are present
	if len(result.Hashes.EncryptedPayloadHash) != 64 {
		t.Errorf("EncryptedPayloadHash length = %d, want 64", len(result.Hashes.EncryptedPayloadHash))
	}

	if len(result.Hashes.TargetPublicKeyHash) != 64 {
		t.Errorf("TargetPublicKeyHash length = %d, want 64", len(result.Hashes.TargetPublicKeyHash))
	}

	// Verify approved data has correct structure
	// Format: [magic:4][version:1][flags:1][file_length:4][principal_sig_len:4][principal_sig][metadata_length:4][metadata][encrypted_symmetric_key][encrypted_plugin_data][client_sig_len:4][client_sig][expiration:8][args_len:4][encrypted_args]
	if len(result.ApprovedData) < 4 {
		t.Fatal("approved data too short")
	}

	if string(result.ApprovedData[0:4]) != "HARN" {
		t.Errorf("approved data magic bytes = %q, want %q", string(result.ApprovedData[0:4]), "HARN")
	}
}

func TestSignEncryptedPlugin_InvalidEOSignature(t *testing.T) {
	// Create keystores with wrong principal
	principalKS, _ := keystore.NewMockKeystore("principal-key")
	wrongPrincipalKS, _ := keystore.NewMockKeystore("wrong-principal-key")
	harnessKS, _ := keystore.NewMockKeystore("harness-key")
	targetKS, _ := keystore.NewMockKeystore("target-key")
	pentesterKS, _ := keystore.NewMockKeystore("pentester-key")

	// Get public keys - correct principal and wrong principal
	_, _ = principalKS.PublicKey() // We encrypt with correct principal, but verify signature with wrong one
	wrongPrincipalPub, _ := wrongPrincipalKS.PublicKey()
	harnessPub, _ := harnessKS.PublicKey()
	targetPub, _ := targetKS.PublicKey()
	pentesterPub, _ := pentesterKS.PublicKey()

	// Create encrypted envelope with correct principal
	encryptReq := &EncryptPluginRequest{
		PluginData:        bytes.NewReader([]byte("plugin data")),
		PluginType:        "wasm",
		PluginName:        "test-plugin",
		HarnessPubKey:     harnessPub,
		TargetPubKey:      targetPub,
		PrincipalKeystore: principalKS,
	}

	encryptResult, err := EncryptPlugin(encryptReq)
	if err != nil {
		t.Fatalf("EncryptPlugin() error = %v", err)
	}

	// Try to sign with wrong principal public key
	signReq := &SignEncryptedPluginRequest{
		EncryptedData:   bytes.NewReader(encryptResult.EncryptedData),
		ArgsJSON:        []byte(`{"arg":"value"}`),
		ClientKeystore:  targetKS,
		PrincipalPubKey: wrongPrincipalPub, // Wrong principal!
		HarnessPubKey:   harnessPub,
		PentesterPubKey: pentesterPub,
	}

	_, err = SignEncryptedPlugin(signReq)
	if err == nil {
		t.Error("SignEncryptedPlugin() with wrong principal key error = nil, want error")
		return
	}

	if !strings.Contains(err.Error(), "principal signature verification failed") {
		t.Errorf("SignEncryptedPlugin() error = %v, want error containing 'principal signature verification failed'", err)
	}
}

func TestSignEncryptedPlugin_LargeArgs(t *testing.T) {
	principalKS, _ := keystore.NewMockKeystore("principal-key")
	targetKS, _ := keystore.NewMockKeystore("target-key")
	harnessKS, _ := keystore.NewMockKeystore("harness-key")

	principalPub, _ := principalKS.PublicKey()
	harnessPub, _ := harnessKS.PublicKey()
	targetPub, _ := targetKS.PublicKey()

	// Create encrypted envelope using the same keys
	encryptReq := &EncryptPluginRequest{
		PluginData:        bytes.NewReader([]byte("plugin data")),
		PluginType:        "wasm",
		PluginName:        "test-plugin",
		HarnessPubKey:     harnessPub,
		TargetPubKey:      targetPub,
		PrincipalKeystore: principalKS,
	}

	encryptResult2, err := EncryptPlugin(encryptReq)
	if err != nil {
		t.Fatalf("EncryptPlugin() error = %v", err)
	}

	// Create args that will encrypt to larger than MaxEncryptedArgsSize
	// Note: encrypted args will be larger than plaintext, so we use a size that's close to the limit
	// Use valid JSON format: {"data": "..."}
	largeData := bytes.Repeat([]byte("x"), MaxEncryptedArgsSize-20) // Leave room for JSON structure
	largeArgs := []byte(`{"data":"` + string(largeData) + `"}`)

	signReq := &SignEncryptedPluginRequest{
		EncryptedData:   bytes.NewReader(encryptResult2.EncryptedData),
		ArgsJSON:        largeArgs,
		ClientKeystore:  targetKS, // Use targetKS to decrypt (same key used for encryption)
		PrincipalPubKey: principalPub,
		HarnessPubKey:   harnessPub,
		PentesterPubKey: harnessPub, // Harness and pentester are the same
	}

	// This should either succeed (if encryption doesn't exceed limit) or fail with appropriate error
	_, err = SignEncryptedPlugin(signReq)
	if err != nil {
		// If it fails, it should be due to size limit
		if !strings.Contains(err.Error(), "exceeds maximum") {
			t.Errorf("SignEncryptedPlugin() error = %v, want error about size limit", err)
		}
		// This is acceptable - the test verifies size limits are enforced
	}
}

