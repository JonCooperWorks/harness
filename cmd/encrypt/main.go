package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/joncooperworks/harness/crypto"
	"github.com/joncooperworks/harness/crypto/keystore"
	"github.com/joncooperworks/harness/plugin"
)

func main() {
	var (
		pluginFile           = flag.String("plugin", "", "Path to plugin file to encrypt")
		pluginType           = flag.String("type", "wasm", "Plugin type: wasm")
		harnessPubKeyPath    = flag.String("harness-key", "", "Path to pentester's public key (for encryption - this is the harness key)")
		principalKeystoreKey = flag.String("principal-keystore-key", "", "Key ID in OS keystore for principal's private key (for signing unencrypted payload)")
		outputPath           = flag.String("output", "plugin.encrypted", "Path to save encrypted plugin")
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

	if *principalKeystoreKey == "" {
		fmt.Fprintf(os.Stderr, "Error: -principal-keystore-key is required\n")
		os.Exit(1)
	}

	// Load pentester's public key (for encryption - this is the harness key)
	// The exploit is encrypted with the pentester's public key so they can decrypt and execute
	harnessPubKey, err := loadPublicKey(*harnessPubKeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading pentester's public key: %v\n", err)
		os.Exit(1)
	}

	// Load keystore for principal signature
	ks, err := keystore.NewKeystore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating keystore: %v\n", err)
		os.Exit(1)
	}

	// Read plugin file to extract name
	pluginData, err := os.ReadFile(*pluginFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading plugin file: %v\n", err)
		os.Exit(1)
	}

	// Load plugin to get its name
	tempPayload := &crypto.Payload{
		Type: crypto.PluginTypeString(*pluginType),
		Name: "", // Temporary - plugin will provide its own name
		Data: pluginData,
	}
	plg, err := plugin.LoadPlugin(tempPayload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading plugin: %v\n", err)
		os.Exit(1)
	}
	pluginName := plg.Name()
	// Note: Plugin interface doesn't have Close(), but implementations may have cleanup
	// For WASM plugins, resources are managed by the plugin loader

	// Get principal public key for logging
	principalPubKey, err := ks.GetPublicKey(*principalKeystoreKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting principal public key: %v\n", err)
		os.Exit(1)
	}

	// Encrypt plugin using library function
	encryptReq := &crypto.EncryptPluginRequest{
		PluginData:        bytes.NewReader(pluginData),
		PluginType:        *pluginType,
		PluginName:        pluginName,
		HarnessPubKey:     harnessPubKey,
		PrincipalKeystore: ks,
		PrincipalKeyID:    *principalKeystoreKey,
	}

	result, err := crypto.EncryptPlugin(encryptReq)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error encrypting plugin: %v\n", err)
		os.Exit(1)
	}

	// Calculate hash of principal signature for logging
	// Extract principal signature from encrypted data
	// Format: [magic:4][version:1][flags:1][file_length:4][principal_sig_len:4][principal_sig]...
	const headerSize = 4 + 1 + 1 + 4 // magic + version + flags + file_length
	if len(result.EncryptedData) < headerSize+4 {
		fmt.Fprintf(os.Stderr, "Error: encrypted data too short\n")
		os.Exit(1)
	}
	principalSigLen := int(binary.BigEndian.Uint32(result.EncryptedData[headerSize : headerSize+4]))
	if len(result.EncryptedData) < headerSize+4+principalSigLen {
		fmt.Fprintf(os.Stderr, "Error: encrypted data too short for principal signature\n")
		os.Exit(1)
	}
	principalSignature := result.EncryptedData[headerSize+4 : headerSize+4+principalSigLen]
	principalSigHash := sha256.Sum256(principalSignature)
	principalSigHashHex := hex.EncodeToString(principalSigHash[:])

	// Calculate hash of principal public key for logging
	principalPubKeyBytes, err := x509.MarshalPKIXPublicKey(principalPubKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling principal public key: %v\n", err)
		os.Exit(1)
	}
	principalPubKeyHash := sha256.Sum256(principalPubKeyBytes)
	principalPubKeyHashHex := hex.EncodeToString(principalPubKeyHash[:])

	// Calculate hash of pentester's public key for logging
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(harnessPubKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling public key: %v\n", err)
		os.Exit(1)
	}
	pubKeyHash := sha256.Sum256(pubKeyBytes)
	pubKeyHashHex := hex.EncodeToString(pubKeyHash[:])

	// Log encryption details
	fmt.Fprintf(os.Stderr, "[ENCRYPTION LOG] %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(os.Stderr, "[ENCRYPTION LOG] Principal Signature Hash (SHA256): %s\n", principalSigHashHex)
	fmt.Fprintf(os.Stderr, "[ENCRYPTION LOG] Principal Public Key Hash (SHA256): %s\n", principalPubKeyHashHex)
	fmt.Fprintf(os.Stderr, "[ENCRYPTION LOG] Pentester Public Key Hash (SHA256): %s\n", pubKeyHashHex)

	output := result.EncryptedData

	// Write to file
	if err := os.WriteFile(*outputPath, output, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing encrypted file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Plugin encrypted successfully:\n")
	fmt.Printf("  Input: %s\n", *pluginFile)
	fmt.Printf("  Output: %s\n", *outputPath)
	fmt.Printf("  Type: %s\n", *pluginType)
	fmt.Printf("  Name: %s\n", result.PluginName)
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
