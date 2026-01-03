package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"github.com/joncooperworks/harness/crypto/keystore"
)

// createSignedPackage is a test helper that creates a complete signed package
// (encrypted + signed) that can be used for testing VerifyAndDecrypt
func createSignedPackage(t *testing.T) ([]byte, keystore.Keystore, ed25519.PublicKey, ed25519.PublicKey, ed25519.PublicKey) {
	t.Helper()

	// Create all keystores
	// Note: harness and pentester are the same entity, so they share the same keystore
	principalKS, _ := keystore.NewMockKeystore("principal-key")
	harnessKS, _ := keystore.NewMockKeystore("harness-key") // This is also the pentester keystore
	targetKS, _ := keystore.NewMockKeystore("target-key")

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

	// Encrypt plugin
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

	// Sign it - arguments are encrypted to harness/pentester public key
	argsJSON := []byte(`{"target":"192.168.1.100","port":443}`)
	signReq := &SignEncryptedPluginRequest{
		EncryptedData:   bytes.NewReader(encryptResult.EncryptedData),
		ArgsJSON:        argsJSON,
		ClientKeystore:  targetKS, // Target signs as client
		PrincipalPubKey: principalPub,
		HarnessPubKey:   harnessPub,
		PentesterPubKey: harnessPub, // Harness and pentester are the same
	}

	signResult, err := SignEncryptedPlugin(signReq)
	if err != nil {
		t.Fatalf("SignEncryptedPlugin() error = %v", err)
	}

	return signResult.ApprovedData, harnessKS, targetPub, principalPub, harnessPub
}

func TestNewPresidentialOrderFromKeystore(t *testing.T) {
	harnessKS, err := keystore.NewMockKeystore("harness-key")
	if err != nil {
		t.Fatalf("failed to create harness keystore: %v", err)
	}

	clientPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate client key: %v", err)
	}

	principalPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate principal key: %v", err)
	}

	harnessPub, err := harnessKS.PublicKey()
	if err != nil {
		t.Fatalf("failed to get harness public key: %v", err)
	}

	po, err := NewPresidentialOrderFromKeystore(harnessKS, clientPub, principalPub, harnessPub)
	if err != nil {
		t.Fatalf("NewPresidentialOrderFromKeystore() error = %v", err)
	}

	if po == nil {
		t.Fatal("NewPresidentialOrderFromKeystore() returned nil")
	}
}

func TestNewPresidentialOrderFromKeystore_InvalidInputs(t *testing.T) {
	harnessKS, err := keystore.NewMockKeystore("harness-key")
	if err != nil {
		t.Fatalf("failed to create harness keystore: %v", err)
	}

	clientPub, _, _ := ed25519.GenerateKey(rand.Reader)
	principalPub, _, _ := ed25519.GenerateKey(rand.Reader)
	harnessPub, _ := harnessKS.PublicKey()

	tests := []struct {
		name         string
		harnessKS    keystore.Keystore
		clientPub    ed25519.PublicKey
		principalPub ed25519.PublicKey
		harnessPub   ed25519.PublicKey
		errMsg       string
	}{
		{
			name:         "nil harness keystore",
			harnessKS:    nil,
			clientPub:    clientPub,
			principalPub: principalPub,
			harnessPub:   harnessPub,
			errMsg:       "harness keystore cannot be nil",
		},
		{
			name:         "empty client public key",
			harnessKS:    harnessKS,
			clientPub:    nil,
			principalPub: principalPub,
			harnessPub:   harnessPub,
			errMsg:       "client public key cannot be empty",
		},
		{
			name:         "empty principal public key",
			harnessKS:    harnessKS,
			clientPub:    clientPub,
			principalPub: nil,
			harnessPub:   harnessPub,
			errMsg:       "principal public key cannot be empty",
		},
		{
			name:         "empty harness public key",
			harnessKS:    harnessKS,
			clientPub:    clientPub,
			principalPub: principalPub,
			harnessPub:   nil,
			errMsg:       "harness public key cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewPresidentialOrderFromKeystore(tt.harnessKS, tt.clientPub, tt.principalPub, tt.harnessPub)
			if err == nil {
				t.Error("NewPresidentialOrderFromKeystore() error = nil, want error")
				return
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("NewPresidentialOrderFromKeystore() error = %v, want error containing %q", err, tt.errMsg)
			}
		})
	}
}

func TestPresidentialOrderImpl_VerifyAndDecrypt_Valid(t *testing.T) {
	signedPackage, harnessKS, targetPub, principalPub, harnessPub := createSignedPackage(t)

	po, err := NewPresidentialOrderFromKeystore(harnessKS, targetPub, principalPub, harnessPub)
	if err != nil {
		t.Fatalf("NewPresidentialOrderFromKeystore() error = %v", err)
	}

	result, err := po.VerifyAndDecrypt(signedPackage)
	if err != nil {
		t.Fatalf("VerifyAndDecrypt() error = %v", err)
	}

	if result == nil {
		t.Fatal("VerifyAndDecrypt() returned nil result")
	}

	if result.Payload == nil {
		t.Fatal("Payload is nil")
	}

	if result.Payload.Type != "wasm" {
		t.Errorf("Payload.Type = %q, want %q", result.Payload.Type, "wasm")
	}

	if result.Payload.Name != "test-plugin" {
		t.Errorf("Payload.Name = %q, want %q", result.Payload.Name, "test-plugin")
	}

	if len(result.Payload.Data) == 0 {
		t.Error("Payload.Data is empty")
	}

	if len(result.Args) == 0 {
		t.Error("Args is empty")
	}

	if len(result.PrincipalSignature) != 64 {
		t.Errorf("PrincipalSignature length = %d, want 64", len(result.PrincipalSignature))
	}

	if len(result.ClientSignature) != 64 {
		t.Errorf("ClientSignature length = %d, want 64", len(result.ClientSignature))
	}
}

func TestPresidentialOrderImpl_VerifyAndDecrypt_InvalidMagic(t *testing.T) {
	signedPackage, harnessKS, targetPub, principalPub, harnessPub := createSignedPackage(t)

	// Corrupt magic bytes
	signedPackage[0] = 'X'

	po, err := NewPresidentialOrderFromKeystore(harnessKS, targetPub, principalPub, harnessPub)
	if err != nil {
		t.Fatalf("NewPresidentialOrderFromKeystore() error = %v", err)
	}

	_, err = po.VerifyAndDecrypt(signedPackage)
	if err == nil {
		t.Error("VerifyAndDecrypt() with invalid magic bytes error = nil, want error")
		return
	}
	if !strings.Contains(err.Error(), "invalid magic bytes") {
		t.Errorf("VerifyAndDecrypt() error = %v, want error containing 'invalid magic bytes'", err)
	}
}

func TestPresidentialOrderImpl_VerifyAndDecrypt_InvalidVersion(t *testing.T) {
	signedPackage, harnessKS, targetPub, principalPub, harnessPub := createSignedPackage(t)

	// Corrupt version (should be 2)
	signedPackage[4] = 99

	po, err := NewPresidentialOrderFromKeystore(harnessKS, targetPub, principalPub, harnessPub)
	if err != nil {
		t.Fatalf("NewPresidentialOrderFromKeystore() error = %v", err)
	}

	_, err = po.VerifyAndDecrypt(signedPackage)
	if err == nil {
		t.Error("VerifyAndDecrypt() with invalid version error = nil, want error")
		return
	}
	if !strings.Contains(err.Error(), "unsupported file format version") {
		t.Errorf("VerifyAndDecrypt() error = %v, want error containing 'unsupported file format version'", err)
	}
}

func TestPresidentialOrderImpl_VerifyAndDecrypt_Expired(t *testing.T) {
	// Create package with expired timestamp
	principalKS, _ := keystore.NewMockKeystore("principal-key")
	harnessKS, _ := keystore.NewMockKeystore("harness-key") // Harness and pentester are the same
	targetKS, _ := keystore.NewMockKeystore("target-key")

	principalPub, _ := principalKS.PublicKey()
	harnessPub, _ := harnessKS.PublicKey()
	targetPub, _ := targetKS.PublicKey()

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

	// Sign with expired timestamp (1 hour ago)
	expiredTime := time.Now().Add(-1 * time.Hour)
	signReq := &SignEncryptedPluginRequest{
		EncryptedData:   bytes.NewReader(encryptResult.EncryptedData),
		ArgsJSON:        []byte(`{}`),
		ClientKeystore:  targetKS,
		PrincipalPubKey: principalPub,
		HarnessPubKey:   harnessPub,
		PentesterPubKey: harnessPub, // Harness and pentester are the same
		Expiration:      &expiredTime,
	}

	signResult, err := SignEncryptedPlugin(signReq)
	if err != nil {
		t.Fatalf("SignEncryptedPlugin() error = %v", err)
	}

	po, err := NewPresidentialOrderFromKeystore(harnessKS, targetPub, principalPub, harnessPub)
	if err != nil {
		t.Fatalf("NewPresidentialOrderFromKeystore() error = %v", err)
	}

	_, err = po.VerifyAndDecrypt(signResult.ApprovedData)
	if err == nil {
		t.Error("VerifyAndDecrypt() with expired package error = nil, want error")
		return
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("VerifyAndDecrypt() error = %v, want error containing 'expired'", err)
	}
}

func TestPresidentialOrderImpl_VerifyAndDecrypt_ExpirationSafetyMargin(t *testing.T) {
	// Create package that expires within the safety margin (15 seconds from now)
	// This should be rejected because it's too close to expiration
	principalKS, _ := keystore.NewMockKeystore("principal-key")
	harnessKS, _ := keystore.NewMockKeystore("harness-key")
	targetKS, _ := keystore.NewMockKeystore("target-key")

	principalPub, _ := principalKS.PublicKey()
	harnessPub, _ := harnessKS.PublicKey()
	targetPub, _ := targetKS.PublicKey()

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

	// Sign with timestamp that expires within safety margin (15 seconds from now)
	// Since ExpirationSafetyMargin is 30 seconds, this should be rejected
	withinSafetyMargin := time.Now().Add(15 * time.Second)
	signReq := &SignEncryptedPluginRequest{
		EncryptedData:   bytes.NewReader(encryptResult.EncryptedData),
		ArgsJSON:        []byte(`{}`),
		ClientKeystore:  targetKS,
		PrincipalPubKey: principalPub,
		HarnessPubKey:   harnessPub,
		PentesterPubKey: harnessPub,
		Expiration:      &withinSafetyMargin,
	}

	signResult, err := SignEncryptedPlugin(signReq)
	if err != nil {
		t.Fatalf("SignEncryptedPlugin() error = %v", err)
	}

	po, err := NewPresidentialOrderFromKeystore(harnessKS, targetPub, principalPub, harnessPub)
	if err != nil {
		t.Fatalf("NewPresidentialOrderFromKeystore() error = %v", err)
	}

	_, err = po.VerifyAndDecrypt(signResult.ApprovedData)
	if err == nil {
		t.Error("VerifyAndDecrypt() with expiration within safety margin error = nil, want error")
		return
	}
	if !strings.Contains(err.Error(), "expired") && !strings.Contains(err.Error(), "close to expiration") {
		t.Errorf("VerifyAndDecrypt() error = %v, want error containing 'expired' or 'close to expiration'", err)
	}
}

func TestPresidentialOrderImpl_VerifyAndDecrypt_InvalidPrincipalSig(t *testing.T) {
	signedPackage, harnessKS, targetPub, principalPub, harnessPub := createSignedPackage(t)

	// Corrupt principal signature
	const headerSize = 4 + 1 + 1 + 4 // magic + version + flags + file_length
	if len(signedPackage) < headerSize+4+64 {
		t.Fatal("package too short")
	}
	// Flip some bits in the signature
	for i := headerSize + 4; i < headerSize+4+64; i += 10 {
		signedPackage[i] ^= 0xFF
	}

	po, err := NewPresidentialOrderFromKeystore(harnessKS, targetPub, principalPub, harnessPub)
	if err != nil {
		t.Fatalf("NewPresidentialOrderFromKeystore() error = %v", err)
	}

	_, err = po.VerifyAndDecrypt(signedPackage)
	if err == nil {
		t.Error("VerifyAndDecrypt() with invalid principal signature error = nil, want error")
		return
	}
	if !strings.Contains(err.Error(), "principal signature verification failed") {
		t.Errorf("VerifyAndDecrypt() error = %v, want error containing 'principal signature verification failed'", err)
	}
}

func TestDecryptAES_InvalidKeySize(t *testing.T) {
	ciphertext := bytes.Repeat([]byte("x"), 50) // Some dummy ciphertext
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
			_, err := decryptAES(ciphertext, tt.key, aad)
			if err == nil {
				t.Error("decryptAES() error = nil, want error for invalid key size")
			}
		})
	}
}

func TestDecryptAES_TamperedCiphertext(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	plaintext := []byte("test data")
	aad := []byte("aad data")

	// Encrypt
	ciphertext, err := encryptAES(plaintext, key, aad)
	if err != nil {
		t.Fatalf("encryptAES() error = %v", err)
	}

	// Tamper with ciphertext (change a byte in the encrypted portion)
	if len(ciphertext) > 20 {
		ciphertext[20] ^= 0xFF
	}

	// Decrypt should fail
	_, err = decryptAES(ciphertext, key, aad)
	if err == nil {
		t.Error("decryptAES() with tampered ciphertext error = nil, want error")
	}
}

func TestDecryptAES_WrongAAD(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	plaintext := []byte("test data")
	correctAAD := []byte("correct aad")
	wrongAAD := []byte("wrong aad")

	// Encrypt with correct AAD
	ciphertext, err := encryptAES(plaintext, key, correctAAD)
	if err != nil {
		t.Fatalf("encryptAES() error = %v", err)
	}

	// Try to decrypt with wrong AAD - should fail
	_, err = decryptAES(ciphertext, key, wrongAAD)
	if err == nil {
		t.Error("decryptAES() with wrong AAD error = nil, want error")
	}
}

func TestDecryptAES_TooShort(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	aad := []byte("aad")

	tests := []struct {
		name       string
		ciphertext []byte
	}{
		{"empty", []byte{}},
		{"too short - no nonce", bytes.Repeat([]byte("x"), 10)},
		{"too short - no tag", bytes.Repeat([]byte("x"), 15)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := decryptAES(tt.ciphertext, key, aad)
			if err == nil {
				t.Error("decryptAES() error = nil, want error for too short ciphertext")
			}
		})
	}
}

func TestVerifyAndDecryptWithHashes(t *testing.T) {
	signedPackage, harnessKS, targetPub, principalPub, harnessPub := createSignedPackage(t)

	po, err := NewPresidentialOrderFromKeystore(harnessKS, targetPub, principalPub, harnessPub)
	if err != nil {
		t.Fatalf("NewPresidentialOrderFromKeystore() error = %v", err)
	}

	result, err := VerifyAndDecryptWithHashes(po, signedPackage, harnessPub, targetPub, principalPub)
	if err != nil {
		t.Fatalf("VerifyAndDecryptWithHashes() error = %v", err)
	}

	if result == nil {
		t.Fatal("VerifyAndDecryptWithHashes() returned nil result")
	}

	// Verify hashes are present and correct length (SHA-256 hex = 64 chars)
	if len(result.Hashes.EncryptedPayloadHash) != 64 {
		t.Errorf("EncryptedPayloadHash length = %d, want 64", len(result.Hashes.EncryptedPayloadHash))
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
}

func TestPresidentialOrderImpl_VerifyAndDecrypt_InvalidFileLength(t *testing.T) {
	signedPackage, harnessKS, targetPub, principalPub, harnessPub := createSignedPackage(t)

	// Corrupt file length field (set it to wrong value)
	// File length is at offset 6 (after magic:4 + version:1 + flags:1)
	actualLength := uint32(len(signedPackage))
	wrongLength := actualLength + 100
	binary.BigEndian.PutUint32(signedPackage[6:10], wrongLength)

	po, err := NewPresidentialOrderFromKeystore(harnessKS, targetPub, principalPub, harnessPub)
	if err != nil {
		t.Fatalf("NewPresidentialOrderFromKeystore() error = %v", err)
	}

	_, err = po.VerifyAndDecrypt(signedPackage)
	if err == nil {
		t.Error("VerifyAndDecrypt() with wrong file length error = nil, want error")
		return
	}
	// Note: file length 0 is treated as "not set", so we set a non-zero wrong value
	if !strings.Contains(err.Error(), "file length mismatch") {
		t.Errorf("VerifyAndDecrypt() error = %v, want error containing 'file length mismatch'", err)
	}
}

// TestPresidentialOrderImpl_VerifyAndDecrypt_TooShort tests various too-short scenarios
func TestPresidentialOrderImpl_VerifyAndDecrypt_TooShort(t *testing.T) {
	harnessKS, _ := keystore.NewMockKeystore("harness-key")
	targetPub, _, _ := ed25519.GenerateKey(rand.Reader)
	principalPub, _, _ := ed25519.GenerateKey(rand.Reader)
	harnessPub, _ := harnessKS.PublicKey()

	po, err := NewPresidentialOrderFromKeystore(harnessKS, targetPub, principalPub, harnessPub)
	if err != nil {
		t.Fatalf("NewPresidentialOrderFromKeystore() error = %v", err)
	}

	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"too short for magic", []byte{0, 1, 2}},
		{"too short for header", bytes.Repeat([]byte("x"), 10)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := po.VerifyAndDecrypt(tt.data)
			if err == nil {
				t.Error("VerifyAndDecrypt() error = nil, want error")
			}
		})
	}
}
