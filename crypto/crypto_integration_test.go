// +build integration

package crypto

import (
	"bytes"
	"testing"
	"time"

	"github.com/joncooperworks/harness/crypto/keystore"
)

func TestEncryptSignVerifyDecrypt_EndToEnd(t *testing.T) {
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

	// Original plugin data
	originalPluginData := []byte("test plugin binary data")
	originalArgs := []byte(`{"target":"192.168.1.100","port":443}`)

	// Step 1: Encrypt
	encryptReq := &EncryptPluginRequest{
		PluginData:        bytes.NewReader(originalPluginData),
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

	// Step 2: Sign
	signReq := &SignEncryptedPluginRequest{
		EncryptedData:   bytes.NewReader(encryptResult.EncryptedData),
		ArgsJSON:        originalArgs,
		ClientKeystore:  targetKS,
		PrincipalPubKey: principalPub,
		HarnessPubKey:   harnessPub,
		PentesterPubKey: pentesterPub,
	}

	signResult, err := SignEncryptedPlugin(signReq)
	if err != nil {
		t.Fatalf("SignEncryptedPlugin() error = %v", err)
	}

	// Step 3: Verify and Decrypt
	po, err := NewPresidentialOrderFromKeystore(harnessKS, targetPub, principalPub, harnessPub)
	if err != nil {
		t.Fatalf("NewPresidentialOrderFromKeystore() error = %v", err)
	}

	decryptResult, err := po.VerifyAndDecrypt(signResult.ApprovedData)
	if err != nil {
		t.Fatalf("VerifyAndDecrypt() error = %v", err)
	}

	// Step 4: Verify decrypted data matches original
	if !bytes.Equal(decryptResult.Payload.Data, originalPluginData) {
		t.Errorf("decrypted plugin data = %v, want %v", decryptResult.Payload.Data, originalPluginData)
	}

	if !bytes.Equal(decryptResult.Args, originalArgs) {
		t.Errorf("decrypted args = %v, want %v", decryptResult.Args, originalArgs)
	}

	if decryptResult.Payload.Type != "wasm" {
		t.Errorf("Payload.Type = %q, want %q", decryptResult.Payload.Type, "wasm")
	}

	if decryptResult.Payload.Name != "test-plugin" {
		t.Errorf("Payload.Name = %q, want %q", decryptResult.Payload.Name, "test-plugin")
	}

	// Verify hashes match between encrypt, sign, and decrypt phases
	encryptSigHash := encryptResult.Hashes.ExploitOwnerSignatureHash
	// We can extract signature hash from decrypt result if needed
	// For now, we just verify signatures are present
	if len(decryptResult.PrincipalSignature) != 64 {
		t.Errorf("PrincipalSignature length = %d, want 64", len(decryptResult.PrincipalSignature))
	}

	if len(decryptResult.ClientSignature) != 64 {
		t.Errorf("ClientSignature length = %d, want 64", len(decryptResult.ClientSignature))
	}

	// Verify encrypt signature hash is correct length
	if len(encryptSigHash) != 64 {
		t.Errorf("EncryptResult.Hashes.ExploitOwnerSignatureHash length = %d, want 64", len(encryptSigHash))
	}
}

func TestEncryptSignVerifyDecrypt_DifferentKeys(t *testing.T) {
	// Create different keypairs for each role
	principalKS1, _ := keystore.NewMockKeystore("principal-key-1")
	principalKS2, _ := keystore.NewMockKeystore("principal-key-2")
	targetKS1, _ := keystore.NewMockKeystore("target-key-1")
	targetKS2, _ := keystore.NewMockKeystore("target-key-2")
	harnessKS1, _ := keystore.NewMockKeystore("harness-key-1")
	harnessKS2, _ := keystore.NewMockKeystore("harness-key-2")
	pentesterKS, _ := keystore.NewMockKeystore("pentester-key")

	principalPub1, _ := principalKS1.PublicKey()
	principalPub2, _ := principalKS2.PublicKey()
	targetPub1, _ := targetKS1.PublicKey()
	targetPub2, _ := targetKS2.PublicKey()
	harnessPub1, _ := harnessKS1.PublicKey()
	harnessPub2, _ := harnessKS2.PublicKey()
	pentesterPub, _ := pentesterKS.PublicKey()

	// Encrypt with principal1, target1, harness1
	encryptReq := &EncryptPluginRequest{
		PluginData:        bytes.NewReader([]byte("plugin data")),
		PluginType:        "wasm",
		PluginName:        "test-plugin",
		HarnessPubKey:     harnessPub1,
		TargetPubKey:      targetPub1,
		PrincipalKeystore: principalKS1,
	}

	encryptResult, err := EncryptPlugin(encryptReq)
	if err != nil {
		t.Fatalf("EncryptPlugin() error = %v", err)
	}

	// Sign with target1 (correct)
	signReq := &SignEncryptedPluginRequest{
		EncryptedData:   bytes.NewReader(encryptResult.EncryptedData),
		ArgsJSON:        []byte(`{}`),
		ClientKeystore:  targetKS1,
		PrincipalPubKey: principalPub1,
		HarnessPubKey:   harnessPub1,
		PentesterPubKey: pentesterPub,
	}

	signResult, err := SignEncryptedPlugin(signReq)
	if err != nil {
		t.Fatalf("SignEncryptedPlugin() error = %v", err)
	}

	// Verify with harness1 (correct)
	po, err := NewPresidentialOrderFromKeystore(harnessKS1, targetPub1, principalPub1, harnessPub1)
	if err != nil {
		t.Fatalf("NewPresidentialOrderFromKeystore() error = %v", err)
	}

	_, err = po.VerifyAndDecrypt(signResult.ApprovedData)
	if err != nil {
		t.Fatalf("VerifyAndDecrypt() with correct keys error = %v", err)
	}

	// Try to verify with wrong principal key - should fail
	poWrong, err := NewPresidentialOrderFromKeystore(harnessKS1, targetPub1, principalPub2, harnessPub1)
	if err != nil {
		t.Fatalf("NewPresidentialOrderFromKeystore() error = %v", err)
	}

	_, err = poWrong.VerifyAndDecrypt(signResult.ApprovedData)
	if err == nil {
		t.Error("VerifyAndDecrypt() with wrong principal key error = nil, want error")
	}
}

func TestEncryptSignVerifyDecrypt_ExpirationHandling(t *testing.T) {
	principalKS, _ := keystore.NewMockKeystore("principal-key")
	targetKS, _ := keystore.NewMockKeystore("target-key")
	harnessKS, _ := keystore.NewMockKeystore("harness-key")
	pentesterKS, _ := keystore.NewMockKeystore("pentester-key")

	principalPub, _ := principalKS.PublicKey()
	harnessPub, _ := harnessKS.PublicKey()
	targetPub, _ := targetKS.PublicKey()
	pentesterPub, _ := pentesterKS.PublicKey()

	// Encrypt
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

	// Sign with future expiration (1 hour from now)
	futureExpiration := time.Now().Add(1 * time.Hour)
	signReq := &SignEncryptedPluginRequest{
		EncryptedData:   bytes.NewReader(encryptResult.EncryptedData),
		ArgsJSON:        []byte(`{}`),
		ClientKeystore:  targetKS,
		PrincipalPubKey: principalPub,
		HarnessPubKey:   harnessPub,
		PentesterPubKey: pentesterPub,
		Expiration:      &futureExpiration,
	}

	signResult, err := SignEncryptedPlugin(signReq)
	if err != nil {
		t.Fatalf("SignEncryptedPlugin() error = %v", err)
	}

	// Verify - should succeed (not expired)
	po, err := NewPresidentialOrderFromKeystore(harnessKS, targetPub, principalPub, harnessPub)
	if err != nil {
		t.Fatalf("NewPresidentialOrderFromKeystore() error = %v", err)
	}

	_, err = po.VerifyAndDecrypt(signResult.ApprovedData)
	if err != nil {
		t.Fatalf("VerifyAndDecrypt() with future expiration error = %v", err)
	}
}

func TestEncryptSignVerifyDecrypt_SignatureTampering(t *testing.T) {
	principalKS, _ := keystore.NewMockKeystore("principal-key")
	targetKS, _ := keystore.NewMockKeystore("target-key")
	harnessKS, _ := keystore.NewMockKeystore("harness-key")
	pentesterKS, _ := keystore.NewMockKeystore("pentester-key")

	principalPub, _ := principalKS.PublicKey()
	harnessPub, _ := harnessKS.PublicKey()
	targetPub, _ := targetKS.PublicKey()
	pentesterPub, _ := pentesterKS.PublicKey()

	// Encrypt and sign normally
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

	signReq := &SignEncryptedPluginRequest{
		EncryptedData:   bytes.NewReader(encryptResult.EncryptedData),
		ArgsJSON:        []byte(`{}`),
		ClientKeystore:  targetKS,
		PrincipalPubKey: principalPub,
		HarnessPubKey:   harnessPub,
		PentesterPubKey: pentesterPub,
	}

	signResult, err := SignEncryptedPlugin(signReq)
	if err != nil {
		t.Fatalf("SignEncryptedPlugin() error = %v", err)
	}

	// Tamper with the signature
	// Find the client signature position (after principal sig + encrypted payload)
	// Format: [magic:4][version:1][flags:1][file_length:4][principal_sig_len:4][principal_sig:64][payload...][client_sig_len:4][client_sig:64]...
	const headerSize = 4 + 1 + 1 + 4
	if len(signResult.ApprovedData) < headerSize+4+64+4+64 {
		t.Fatal("approved data too short")
	}

	// Find client signature start (skip header + principal sig len + principal sig + payload)
	// This is approximate - in real code we'd parse properly
	// For this test, we'll just flip some bits near the end where the client signature should be
	signedDataCopy := make([]byte, len(signResult.ApprovedData))
	copy(signedDataCopy, signResult.ApprovedData)

	// Tamper with a byte near the end (likely in signature or expiration area)
	if len(signedDataCopy) > 100 {
		signedDataCopy[len(signedDataCopy)-50] ^= 0xFF
	}

	// Verify - should fail due to signature tampering
	po, err := NewPresidentialOrderFromKeystore(harnessKS, targetPub, principalPub, harnessPub)
	if err != nil {
		t.Fatalf("NewPresidentialOrderFromKeystore() error = %v", err)
	}

	_, err = po.VerifyAndDecrypt(signedDataCopy)
	if err == nil {
		t.Error("VerifyAndDecrypt() with tampered data error = nil, want error")
	}
}

