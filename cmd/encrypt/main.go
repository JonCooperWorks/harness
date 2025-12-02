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
		pluginFile         = flag.String("plugin", "", "Path to plugin file to encrypt")
		pluginType         = flag.String("type", "wasm", "Plugin type: wasm")
		harnessPubKeyPath  = flag.String("harness-key", "", "Path to harness (pentester) public key file (required, for encrypting exploit)")
		exploitKeystoreKey = flag.String("exploit-keystore-key", "", "Key ID in OS keystore for exploit owner's private key (required, for signing encrypted payload)")
		outputPath         = flag.String("output", "plugin.encrypted", "Path to save encrypted plugin")
	)
	flag.Parse()

	if *pluginFile == "" {
		fmt.Fprintf(os.Stderr, "Error: -plugin is required\n")
		os.Exit(1)
	}

	if *harnessPubKeyPath == "" {
		fmt.Fprintf(os.Stderr, "Error: -harness-key is required (harness public key for encrypting exploit)\n")
		os.Exit(1)
	}

	if *exploitKeystoreKey == "" {
		fmt.Fprintf(os.Stderr, "Error: -exploit-keystore-key is required (exploit owner's private key for signing encrypted payload)\n")
		os.Exit(1)
	}

	// Load pentester's public key (for encryption - this is the harness key)
	// The exploit is encrypted with the pentester's public key so they can decrypt and execute
	harnessPubKey, err := loadPublicKey(*harnessPubKeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading pentester's public key: %v\n", err)
		os.Exit(1)
	}

	// Load keystore for exploit owner signature
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

	// Get exploit owner public key for logging
	exploitPubKey, err := ks.GetPublicKey(*exploitKeystoreKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting exploit owner public key: %v\n", err)
		os.Exit(1)
	}

	// Encrypt plugin using library function
	encryptReq := &crypto.EncryptPluginRequest{
		PluginData:        bytes.NewReader(pluginData),
		PluginType:        *pluginType,
		PluginName:        pluginName,
		HarnessPubKey:     harnessPubKey,
		PrincipalKeystore: ks,
		PrincipalKeyID:    *exploitKeystoreKey,
	}

	result, err := crypto.EncryptPlugin(encryptReq)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error encrypting plugin: %v\n", err)
		os.Exit(1)
	}

	// Calculate hash of exploit owner signature for logging
	// Extract exploit owner signature from encrypted data
	// Format: [magic:4][version:1][flags:1][file_length:4][principal_sig_len:4][principal_sig]...
	const headerSize = 4 + 1 + 1 + 4 // magic + version + flags + file_length
	if len(result.EncryptedData) < headerSize+4 {
		fmt.Fprintf(os.Stderr, "Error: encrypted data too short\n")
		os.Exit(1)
	}
	exploitSigLen := int(binary.BigEndian.Uint32(result.EncryptedData[headerSize : headerSize+4]))
	if len(result.EncryptedData) < headerSize+4+exploitSigLen {
		fmt.Fprintf(os.Stderr, "Error: encrypted data too short for exploit owner signature\n")
		os.Exit(1)
	}
	exploitSignature := result.EncryptedData[headerSize+4 : headerSize+4+exploitSigLen]
	exploitSigHash := sha256.Sum256(exploitSignature)
	exploitSigHashHex := hex.EncodeToString(exploitSigHash[:])

	// Calculate hash of exploit owner public key for logging
	exploitPubKeyBytes, err := x509.MarshalPKIXPublicKey(exploitPubKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling exploit owner public key: %v\n", err)
		os.Exit(1)
	}
	exploitPubKeyHash := sha256.Sum256(exploitPubKeyBytes)
	exploitPubKeyHashHex := hex.EncodeToString(exploitPubKeyHash[:])

	// Calculate hash of harness public key for logging
	harnessPubKeyBytes, err := x509.MarshalPKIXPublicKey(harnessPubKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling harness public key: %v\n", err)
		os.Exit(1)
	}
	harnessPubKeyHash := sha256.Sum256(harnessPubKeyBytes)
	harnessPubKeyHashHex := hex.EncodeToString(harnessPubKeyHash[:])

	// Log encryption details
	fmt.Fprintf(os.Stderr, "[ENCRYPTION LOG] %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(os.Stderr, "[ENCRYPTION LOG] Exploit Owner Signature Hash (SHA256): %s\n", exploitSigHashHex)
	fmt.Fprintf(os.Stderr, "[ENCRYPTION LOG] Exploit Owner Public Key Hash (SHA256): %s\n", exploitPubKeyHashHex)
	fmt.Fprintf(os.Stderr, "[ENCRYPTION LOG] Harness Public Key Hash (SHA256): %s\n", harnessPubKeyHashHex)

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
