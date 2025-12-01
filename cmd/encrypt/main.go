package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"

	"github.com/joncooperworks/harness/crypto"
)

func main() {
	var (
		pluginFile        = flag.String("plugin", "", "Path to plugin file to encrypt")
		pluginType        = flag.String("type", "wasm", "Plugin type: wasm")
		pluginName        = flag.String("name", "test-plugin", "Plugin name")
		harnessPubKeyPath = flag.String("harness-key", "", "Path to pentester's public key (for encryption - this is the harness key)")
		outputPath        = flag.String("output", "plugin.encrypted", "Path to save encrypted plugin")
	)
	flag.Parse()

	if *pluginFile == "" {
		fmt.Fprintf(os.Stderr, "Error: -plugin is required\n")
		os.Exit(1)
	}

	if *harnessPubKeyPath == "" {
		fmt.Fprintf(os.Stderr, "Error: -harness-key is required\n")
		os.Exit(1)
	}

	// Load pentester's public key (for encryption - this is the harness key)
	// The exploit is encrypted with the pentester's public key so they can decrypt and execute
	harnessPubKey, err := loadPublicKey(*harnessPubKeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading pentester's public key: %v\n", err)
		os.Exit(1)
	}

	// Load plugin file
	pluginData, err := os.ReadFile(*pluginFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading plugin file: %v\n", err)
		os.Exit(1)
	}

	// Determine plugin type
	var pluginTypeEnum crypto.PluginType
	switch *pluginType {
	case "wasm":
		pluginTypeEnum = crypto.WASM
	default:
		fmt.Fprintf(os.Stderr, "Error: invalid plugin type %s (must be wasm)\n", *pluginType)
		os.Exit(1)
	}

	// Create payload
	payload := crypto.Payload{
		Type: pluginTypeEnum,
		Name: *pluginName,
		Data: pluginData,
	}

	// Marshal payload
	payloadJSON, err := json.Marshal(payload)
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
	encryptedSymmetricKey, err := encryptSymmetricKey(symmetricKey, harnessPubKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error encrypting symmetric key: %v\n", err)
		os.Exit(1)
	}

	// Create metadata
	metadata := map[string]interface{}{
		"symmetric_key_len": len(encryptedSymmetricKey),
		"plugin_data_len":   len(encryptedPluginData),
		"algorithm":         "ECDSA-P256+AES-256-GCM",
	}
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling metadata: %v\n", err)
		os.Exit(1)
	}

	// Build encrypted file structure (without signature):
	// [metadata_length:4][metadata][encrypted_symmetric_key][encrypted_plugin_data]
	var output []byte

	// Write metadata length
	metadataLenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(metadataLenBuf, uint32(len(metadataJSON)))
	output = append(output, metadataLenBuf...)

	// Write metadata
	output = append(output, metadataJSON...)

	// Write encrypted symmetric key
	output = append(output, encryptedSymmetricKey...)

	// Write encrypted plugin data
	output = append(output, encryptedPluginData...)

	// Write to file
	if err := os.WriteFile(*outputPath, output, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing encrypted file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Plugin encrypted successfully:\n")
	fmt.Printf("  Input: %s\n", *pluginFile)
	fmt.Printf("  Output: %s\n", *outputPath)
	fmt.Printf("  Type: %s\n", *pluginType)
	fmt.Printf("  Name: %s\n", *pluginName)
	fmt.Printf("\nNext step: Sign the encrypted file with ./bin/sign\n")
}

// loadPublicKey loads an ECDSA public key from a file
func loadPublicKey(path string) (*ecdsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key file: %w", err)
	}

	// Try PEM format first
	block, _ := pem.Decode(data)
	if block != nil {
		data = block.Bytes
	}

	// Parse public key
	pubKey, err := x509.ParsePKIXPublicKey(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not ECDSA")
	}

	return ecdsaPubKey, nil
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

	// Encrypt symmetric key with AES-GCM
	nonce := make([]byte, 12) // GCM standard nonce size
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	block, err := aes.NewCipher(aesKey[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Encrypt with GCM
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, symmetricKey, nil)

	// Build result: [ephemeral_public_key:65][nonce:12][ciphertext+tag]
	result := make([]byte, 0, 65+12+len(ciphertext))

	// Encode ephemeral public key (uncompressed: 0x04 || x || y)
	ephemeralPubBytes := make([]byte, 65)
	ephemeralPubBytes[0] = 0x04
	copy(ephemeralPubBytes[1:33], ephemeralPrivate.PublicKey.X.Bytes())
	copy(ephemeralPubBytes[33:65], ephemeralPrivate.PublicKey.Y.Bytes())
	result = append(result, ephemeralPubBytes...)

	// Append nonce
	result = append(result, nonce...)

	// Append ciphertext (includes authentication tag)
	result = append(result, ciphertext...)

	return result, nil
}

// encryptAES encrypts data using AES-256-GCM
func encryptAES(plaintext, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes for AES-256")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate nonce (12 bytes is standard for GCM)
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt and authenticate (ciphertext includes authentication tag)
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// Prepend nonce
	result := append(nonce, ciphertext...)

	return result, nil
}
