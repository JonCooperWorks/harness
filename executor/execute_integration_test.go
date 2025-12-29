// +build integration

package executor

import (
	"bytes"
	"context"
	"testing"

	"github.com/joncooperworks/harness/crypto"
	"github.com/joncooperworks/harness/crypto/keystore"
	"github.com/joncooperworks/harness/testdata"
)

func TestExecutePlugin_WASM_EndToEnd(t *testing.T) {
	// Create all keystores
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
	principalPub, err := principalKS.PublicKey()
	if err != nil {
		t.Fatalf("failed to get principal public key: %v", err)
	}

	harnessPub, err := harnessKS.PublicKey()
	if err != nil {
		t.Fatalf("failed to get harness public key: %v", err)
	}

	targetPub, err := targetKS.PublicKey()
	if err != nil {
		t.Fatalf("failed to get target public key: %v", err)
	}

	// Use real WASM plugin data
	pluginData := testdata.HelloWorldWASM
	if len(pluginData) == 0 {
		t.Fatal("embedded WASM plugin data is empty")
	}

	// Encrypt plugin
	encryptReq := &crypto.EncryptPluginRequest{
		PluginData:        bytes.NewReader(pluginData),
		PluginType:        "wasm",
		PluginName:        "hello-world-plugin", // Will be overridden by plugin's actual name
		HarnessPubKey:     harnessPub,
		TargetPubKey:      targetPub,
		PrincipalKeystore: principalKS,
	}

	encryptResult, err := crypto.EncryptPlugin(encryptReq)
	if err != nil {
		t.Fatalf("EncryptPlugin() error = %v", err)
	}

	// Sign it with execution arguments
	// Note: HarnessPubKey and PentesterPubKey should be the same (harness and pentester are the same entity)
	argsJSON := []byte(`{"message": "Hello from integration test"}`)
	signReq := &crypto.SignEncryptedPluginRequest{
		EncryptedData:   bytes.NewReader(encryptResult.EncryptedData),
		ArgsJSON:        argsJSON,
		ClientKeystore:  targetKS,
		PrincipalPubKey: principalPub,
		HarnessPubKey:   harnessPub,
		PentesterPubKey: harnessPub, // Same as harness - they're the same entity
	}

	signResult, err := crypto.SignEncryptedPlugin(signReq)
	if err != nil {
		t.Fatalf("SignEncryptedPlugin() error = %v", err)
	}

	// Execute
	execReq := &ExecutePluginRequest{
		EncryptedData:   signResult.ApprovedData,
		HarnessKeystore: harnessKS,
		TargetPubKey:    targetPub,
		ExploitPubKey:   principalPub,
	}

	result, err := ExecutePlugin(context.Background(), execReq)
	if err != nil {
		t.Fatalf("ExecutePlugin() error = %v", err)
	}

	// Verify result
	if result == nil {
		t.Fatal("ExecutePlugin() returned nil result")
	}

	// Verify plugin name matches the actual WASM plugin
	if result.PluginName != "hello-world-plugin" {
		t.Errorf("PluginName = %q, want %q", result.PluginName, "hello-world-plugin")
	}

	if result.PluginType != "wasm" {
		t.Errorf("PluginType = %q, want %q", result.PluginType, "wasm")
	}

	// Verify hashes are present
	if len(result.Hashes.EncryptedPayloadHash) != 64 {
		t.Errorf("EncryptedPayloadHash length = %d, want 64", len(result.Hashes.EncryptedPayloadHash))
	}

	if len(result.Hashes.ExploitBinaryHash) != 64 {
		t.Errorf("ExploitBinaryHash length = %d, want 64", len(result.Hashes.ExploitBinaryHash))
	}

	if len(result.Hashes.ExploitOwnerSignatureHash) != 64 {
		t.Errorf("ExploitOwnerSignatureHash length = %d, want 64", len(result.Hashes.ExploitOwnerSignatureHash))
	}

	if len(result.Hashes.ExploitOwnerPublicKeyHash) != 64 {
		t.Errorf("ExploitOwnerPublicKeyHash length = %d, want 64", len(result.Hashes.ExploitOwnerPublicKeyHash))
	}

	if len(result.Hashes.TargetSignatureHash) != 64 {
		t.Errorf("TargetSignatureHash length = %d, want 64", len(result.Hashes.TargetSignatureHash))
	}

	if len(result.Hashes.TargetPublicKeyHash) != 64 {
		t.Errorf("TargetPublicKeyHash length = %d, want 64", len(result.Hashes.TargetPublicKeyHash))
	}

	if len(result.Hashes.HarnessPublicKeyHash) != 64 {
		t.Errorf("HarnessPublicKeyHash length = %d, want 64", len(result.Hashes.HarnessPublicKeyHash))
	}

	// Verify plugin result is present and contains expected data
	if result.PluginResult == nil {
		t.Fatal("PluginResult is nil")
	}

	// Verify the plugin actually executed and returned the expected result
	resultMap, ok := result.PluginResult.(map[string]interface{})
	if !ok {
		t.Fatalf("PluginResult is not a map, got %T", result.PluginResult)
	}

	// Verify greeting field matches our input
	if greeting, ok := resultMap["greeting"].(string); !ok || greeting != "Hello from integration test" {
		t.Errorf("result.greeting = %v, want %q", resultMap["greeting"], "Hello from integration test")
	}

	// Verify plugin name in result
	if pluginName, ok := resultMap["plugin"].(string); !ok || pluginName != "hello-world" {
		t.Errorf("result.plugin = %v, want %q", resultMap["plugin"], "hello-world")
	}

	// Verify timestamp field exists
	if _, ok := resultMap["timestamp"]; !ok {
		t.Error("result.timestamp field is missing")
	}
}

func TestExecutePlugin_WASM_WithDefaultMessage(t *testing.T) {
	// Create all keystores
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
	principalPub, _ := principalKS.PublicKey()
	harnessPub, _ := harnessKS.PublicKey()
	targetPub, _ := targetKS.PublicKey()

	// Encrypt plugin
	encryptReq := &crypto.EncryptPluginRequest{
		PluginData:        bytes.NewReader(testdata.HelloWorldWASM),
		PluginType:        "wasm",
		PluginName:        "hello-world-plugin",
		HarnessPubKey:     harnessPub,
		TargetPubKey:      targetPub,
		PrincipalKeystore: principalKS,
	}

	encryptResult, err := crypto.EncryptPlugin(encryptReq)
	if err != nil {
		t.Fatalf("EncryptPlugin() error = %v", err)
	}

	// Sign with empty args (should use default message)
	// Note: HarnessPubKey and PentesterPubKey should be the same (harness and pentester are the same entity)
	argsJSON := []byte(`{}`)
	signReq := &crypto.SignEncryptedPluginRequest{
		EncryptedData:   bytes.NewReader(encryptResult.EncryptedData),
		ArgsJSON:        argsJSON,
		ClientKeystore:  targetKS,
		PrincipalPubKey: principalPub,
		HarnessPubKey:   harnessPub,
		PentesterPubKey: harnessPub, // Same as harness - they're the same entity
	}

	signResult, err := crypto.SignEncryptedPlugin(signReq)
	if err != nil {
		t.Fatalf("SignEncryptedPlugin() error = %v", err)
	}

	// Execute
	execReq := &ExecutePluginRequest{
		EncryptedData:   signResult.ApprovedData,
		HarnessKeystore: harnessKS,
		TargetPubKey:    targetPub,
		ExploitPubKey:   principalPub,
	}

	result, err := ExecutePlugin(context.Background(), execReq)
	if err != nil {
		t.Fatalf("ExecutePlugin() error = %v", err)
	}

	// Verify plugin executed and used default message
	resultMap, ok := result.PluginResult.(map[string]interface{})
	if !ok {
		t.Fatalf("PluginResult is not a map, got %T", result.PluginResult)
	}

	// Should use default message "Hello, World!"
	if greeting, ok := resultMap["greeting"].(string); !ok || greeting != "Hello, World!" {
		t.Errorf("result.greeting = %v, want %q", resultMap["greeting"], "Hello, World!")
	}
}

