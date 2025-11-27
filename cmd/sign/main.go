package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"

	"github.com/joncooperworks/harness/crypto"
)

func main() {
	var (
		pluginFile         = flag.String("plugin", "", "Path to plugin file to encrypt")
		pluginType         = flag.String("type", "wasm", "Plugin type: wasm")
		pluginName         = flag.String("name", "test-plugin", "Plugin name")
		presidentKeyPath   = flag.String("president-key", "", "Path to president's private key (for signing)")
		harnessPubKeyPath  = flag.String("harness-key", "", "Path to harness's public key (for encryption)")
		outputPath         = flag.String("output", "plugin.encrypted", "Path to save encrypted plugin")
	)
	flag.Parse()

	if *pluginFile == "" {
		fmt.Fprintf(os.Stderr, "Error: -plugin is required\n")
		os.Exit(1)
	}

	if *presidentKeyPath == "" {
		fmt.Fprintf(os.Stderr, "Error: -president-key is required\n")
		os.Exit(1)
	}

	if *harnessPubKeyPath == "" {
		fmt.Fprintf(os.Stderr, "Error: -harness-key is required\n")
		os.Exit(1)
	}

	// Load president's private key (for signing)
	presidentKey, err := loadPrivateKey(*presidentKeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading president's private key: %v\n", err)
		os.Exit(1)
	}

	// Load harness's public key (for encryption)
	harnessPubKey, err := loadPublicKey(*harnessPubKeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading harness's public key: %v\n", err)
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
	r, s, err := ecdsa.Sign(rand.Reader, presidentKey, hash[:])
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
	var output []byte

	// Write signature length
	sigLenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(sigLenBuf, uint32(len(signature)))
	output = append(output, sigLenBuf...)

	// Write signature
	output = append(output, signature...)

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

	fmt.Printf("Plugin encrypted and signed successfully:\n")
	fmt.Printf("  Input: %s\n", *pluginFile)
	fmt.Printf("  Output: %s\n", *outputPath)
	fmt.Printf("  Type: %s\n", *pluginType)
	fmt.Printf("  Name: %s\n", *pluginName)
}

// loadPrivateKey loads an ECDSA private key from a file
func loadPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}

	// Try PEM format first
	block, _ := pem.Decode(data)
	if block != nil {
		data = block.Bytes
	}

	// Try PKCS8 format
	key, err := x509.ParsePKCS8PrivateKey(data)
	if err == nil {
		if ecdsaKey, ok := key.(*ecdsa.PrivateKey); ok {
			return ecdsaKey, nil
		}
		return nil, fmt.Errorf("key is not ECDSA")
	}

	// Try EC private key format
	ecKey, err := x509.ParseECPrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return ecKey, nil
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
	copy(ephemeralPubBytes[1:33], ephemeralPrivate.PublicKey.X.Bytes())
	copy(ephemeralPubBytes[33:65], ephemeralPrivate.PublicKey.Y.Bytes())
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

