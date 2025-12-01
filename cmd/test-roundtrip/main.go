package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"github.com/joncooperworks/harness/crypto"
)

func main() {
	// Generate test keys
	presidentPrivate, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	harnessPrivate, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Create test payload
	originalPayload := &crypto.Payload{
		Type: crypto.WASM,
		Name: "test-plugin",
		Data: []byte("test plugin data"),
	}

	fmt.Println("Testing encryption/decryption round-trip...")
	fmt.Println("✓ Keys generated")
	fmt.Println("✓ Payload created")

	// Marshal payload
	payloadJSON, err := json.Marshal(originalPayload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling payload: %v\n", err)
		os.Exit(1)
	}

	// Generate symmetric key for AES encryption
	symmetricKey := make([]byte, 32) // AES-256
	if _, err := rand.Read(symmetricKey); err != nil {
		fmt.Fprintf(os.Stderr, "Error generating symmetric key: %v\n", err)
		os.Exit(1)
	}

	// Encrypt plugin data with AES
	encryptedPluginData, err := encryptAES(payloadJSON, symmetricKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error encrypting plugin data: %v\n", err)
		os.Exit(1)
	}

	// Encrypt symmetric key using ECDH with harness's public key
	encryptedSymmetricKey, err := encryptSymmetricKey(symmetricKey, &harnessPrivate.PublicKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error encrypting symmetric key: %v\n", err)
		os.Exit(1)
	}

	// Create metadata
	metadata := map[string]interface{}{
		"symmetric_key_len": len(encryptedSymmetricKey),
		"plugin_data_len":   len(encryptedPluginData),
		"algorithm":         "ECDSA-P256+AES-256-CBC",
	}
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling metadata: %v\n", err)
		os.Exit(1)
	}

	// Create data to sign: metadata + encrypted data
	dataToSign := append(metadataJSON, encryptedSymmetricKey...)
	dataToSign = append(dataToSign, encryptedPluginData...)

	// Sign the data with president's private key
	hash := sha256.Sum256(dataToSign)
	r, s, err := ecdsa.Sign(rand.Reader, presidentPrivate, hash[:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error signing data: %v\n", err)
		os.Exit(1)
	}

	// Encode signature
	signature, err := asn1.Marshal(struct {
		R, S *big.Int
	}{R: r, S: s})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding signature: %v\n", err)
		os.Exit(1)
	}

	// Build final encrypted file structure:
	// [signature_length:4][signature][metadata_length:4][metadata][encrypted_symmetric_key][encrypted_plugin_data]
	var encryptedData []byte

	// Write signature length
	sigLenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(sigLenBuf, uint32(len(signature)))
	encryptedData = append(encryptedData, sigLenBuf...)

	// Write signature
	encryptedData = append(encryptedData, signature...)

	// Write metadata length
	metadataLenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(metadataLenBuf, uint32(len(metadataJSON)))
	encryptedData = append(encryptedData, metadataLenBuf...)

	// Write metadata
	encryptedData = append(encryptedData, metadataJSON...)

	// Write encrypted symmetric key
	encryptedData = append(encryptedData, encryptedSymmetricKey...)

	// Write encrypted plugin data
	encryptedData = append(encryptedData, encryptedPluginData...)

	fmt.Println("✓ Payload encrypted and signed")

	// Create PresidentialOrder for decryption
	po, err := crypto.NewPresidentialOrderFromKeys(harnessPrivate, &presidentPrivate.PublicKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating PresidentialOrder: %v\n", err)
		os.Exit(1)
	}

	// Decrypt and verify
	// For test-roundtrip, we need to provide args - use empty args for testing
	decryptedPayload, err := po.VerifyAndDecrypt(encryptedData, []byte("{}"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error verifying and decrypting: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("✓ Payload decrypted and verified")

	// Compare results
	if originalPayload.Type != decryptedPayload.Type {
		fmt.Fprintf(os.Stderr, "Type mismatch: original=%v, decrypted=%v\n", originalPayload.Type, decryptedPayload.Type)
		os.Exit(1)
	}
	if originalPayload.Name != decryptedPayload.Name {
		fmt.Fprintf(os.Stderr, "Name mismatch: original=%s, decrypted=%s\n", originalPayload.Name, decryptedPayload.Name)
		os.Exit(1)
	}
	if len(originalPayload.Data) != len(decryptedPayload.Data) {
		fmt.Fprintf(os.Stderr, "Data length mismatch: original=%d, decrypted=%d\n", len(originalPayload.Data), len(decryptedPayload.Data))
		os.Exit(1)
	}
	for i := range originalPayload.Data {
		if originalPayload.Data[i] != decryptedPayload.Data[i] {
			fmt.Fprintf(os.Stderr, "Data mismatch at index %d\n", i)
			os.Exit(1)
		}
	}

	fmt.Println("✓ Round-trip test passed!")
	fmt.Printf("\nOriginal payload: Type=%v, Name=%s, Data size=%d bytes\n", originalPayload.Type, originalPayload.Name, len(originalPayload.Data))
	fmt.Printf("Decrypted payload: Type=%v, Name=%s, Data size=%d bytes\n", decryptedPayload.Type, decryptedPayload.Name, len(decryptedPayload.Data))
}

// encryptSymmetricKey encrypts the symmetric key using ECDH
func encryptSymmetricKey(symmetricKey []byte, publicKey *ecdsa.PublicKey) ([]byte, error) {
	// Generate ephemeral key pair for ECDH
	ephemeralPrivate, err := ecdsa.GenerateKey(publicKey.Curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	// Compute shared secret using ECDH
	sharedX, _ := publicKey.Curve.ScalarMult(publicKey.X, publicKey.Y, ephemeralPrivate.D.Bytes())
	sharedSecret := sharedX.Bytes()

	// Derive AES key from shared secret
	aesKey := sha256.Sum256(sharedSecret)

	// Encrypt symmetric key with AES
	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("failed to generate IV: %w", err)
	}

	block, err := aes.NewCipher(aesKey[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Pad symmetric key
	paddedKey := padPKCS7(symmetricKey, block.BlockSize())

	// Encrypt
	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(paddedKey))
	mode.CryptBlocks(ciphertext, paddedKey)

	// Build result: [ephemeral_public_key:65][iv:16][ciphertext]
	result := make([]byte, 0, 65+16+len(ciphertext))

	// Encode ephemeral public key (uncompressed: 0x04 || x || y)
	ephemeralPubBytes := make([]byte, 65)
	ephemeralPubBytes[0] = 0x04
	xBytes := ephemeralPrivate.PublicKey.X.Bytes()
	yBytes := ephemeralPrivate.PublicKey.Y.Bytes()
	// Pad to 32 bytes if needed
	copy(ephemeralPubBytes[1+32-len(xBytes):33], xBytes)
	copy(ephemeralPubBytes[33+32-len(yBytes):65], yBytes)
	result = append(result, ephemeralPubBytes...)

	// Append IV
	result = append(result, iv...)

	// Append ciphertext
	result = append(result, ciphertext...)

	return result, nil
}

// encryptAES encrypts data using AES-256-CBC
func encryptAES(plaintext, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes for AES-256")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Generate IV
	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("failed to generate IV: %w", err)
	}

	// Pad plaintext
	paddedPlaintext := padPKCS7(plaintext, block.BlockSize())

	// Encrypt
	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(paddedPlaintext))
	mode.CryptBlocks(ciphertext, paddedPlaintext)

	// Prepend IV
	result := append(iv, ciphertext...)

	return result, nil
}

// padPKCS7 adds PKCS7 padding
func padPKCS7(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padtext := make([]byte, padding)
	for i := range padtext {
		padtext[i] = byte(padding)
	}
	return append(data, padtext...)
}
