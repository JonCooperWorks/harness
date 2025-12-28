// +build integration

package executor

import (
	"bytes"
	"context"
	"testing"

	"github.com/joncooperworks/harness/crypto"
	"github.com/joncooperworks/harness/crypto/keystore"
	"github.com/joncooperworks/harness/plugin"
)

func TestExecutePlugin_EndToEnd(t *testing.T) {
	// Create all keystores
	principalKS, err := keystore.NewMockKeystore("principal-key")
	if err != nil {
		t.Fatalf("failed to create principal keystore: %v", err)
	}

	clientKS, err := keystore.NewMockKeystore("client-key")
	if err != nil {
		t.Fatalf("failed to create client keystore: %v", err)
	}

	harnessKS, err := keystore.NewMockKeystore("harness-key")
	if err != nil {
		t.Fatalf("failed to create harness keystore: %v", err)
	}

	targetKS, err := keystore.NewMockKeystore("target-key")
	if err != nil {
		t.Fatalf("failed to create target keystore: %v", err)
	}

	pentesterKS, err := keystore.NewMockKeystore("pentester-key")
	if err != nil {
		t.Fatalf("failed to create pentester keystore: %v", err)
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

	pentesterPub, err := pentesterKS.PublicKey()
	if err != nil {
		t.Fatalf("failed to get pentester public key: %v", err)
	}

	// Register a mock plugin loader for testing
	testType := "mock-executor-test-type"
	mockLoader := plugin.NewMockLoader()
	mockPlugin := plugin.NewMockPlugin(
		"test-plugin",
		"test plugin description",
		[]byte(`{"type":"object","properties":{"arg":{"type":"string"}}}`),
	)
	mockLoader.SetPlugin("test-plugin", mockPlugin)
	plugin.RegisterLoader(testType, func() (plugin.Loader, error) {
		return mockLoader, nil
	})

	// Create plugin data (just metadata, since we're using mock loader)
	pluginData := []byte("mock plugin data")

	// Encrypt plugin
	encryptReq := &crypto.EncryptPluginRequest{
		PluginData:        bytes.NewReader(pluginData),
		PluginType:        testType,
		PluginName:        "test-plugin",
		HarnessPubKey:     harnessPub,
		TargetPubKey:      targetPub,
		PrincipalKeystore: principalKS,
	}

	encryptResult, err := crypto.EncryptPlugin(encryptReq)
	if err != nil {
		t.Fatalf("EncryptPlugin() error = %v", err)
	}

	// Sign it
	argsJSON := []byte(`{"arg":"value"}`)
	signReq := &crypto.SignEncryptedPluginRequest{
		EncryptedData:   bytes.NewReader(encryptResult.EncryptedData),
		ArgsJSON:        argsJSON,
		ClientKeystore:  targetKS,
		PrincipalPubKey: principalPub,
		HarnessPubKey:   harnessPub,
		PentesterPubKey: pentesterPub,
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

	if result.PluginName != "test-plugin" {
		t.Errorf("PluginName = %q, want %q", result.PluginName, "test-plugin")
	}

	if result.PluginType != testType {
		t.Errorf("PluginType = %q, want %q", result.PluginType, testType)
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

	// Verify plugin result is present
	if result.PluginResult == nil {
		t.Error("PluginResult is nil")
	}
}

