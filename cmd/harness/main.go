package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/joncooperworks/harness/crypto"
	"github.com/joncooperworks/harness/plugin"
)

func main() {
	var (
		encryptedFile       = flag.String("file", "", "Path to approved plugin file (with signature)")
		keystoreKeyID       = flag.String("keystore-key", "", "Key ID in OS keystore for private key (required)")
		signaturePubKeyFile = flag.String("signature-key", "", "Path to public key file for verifying signature (required)")
	)
	flag.Parse()

	if *encryptedFile == "" {
		fmt.Fprintf(os.Stderr, "Error: -file is required\n")
		os.Exit(1)
	}

	if *keystoreKeyID == "" {
		fmt.Fprintf(os.Stderr, "Error: -keystore-key is required (private key must be stored in OS keystore)\n")
		os.Exit(1)
	}

	if *signaturePubKeyFile == "" {
		fmt.Fprintf(os.Stderr, "Error: -signature-key is required (public key for verifying signature)\n")
		os.Exit(1)
	}

	// Load public key for signature verification
	signaturePubKey, err := loadPublicKey(*signaturePubKeyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading signature public key: %v\n", err)
		os.Exit(1)
	}

	// Create PresidentialOrder from keystore
	po, err := crypto.NewPresidentialOrderFromKeystore(*keystoreKeyID, signaturePubKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating PresidentialOrder from keystore: %v\n", err)
		os.Exit(1)
	}

	// Load approved file (contains encrypted payload + client signature + args)
	fileData, err := os.ReadFile(*encryptedFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading approved file: %v\n", err)
		os.Exit(1)
	}

	// Verify client signature on arguments and decrypt
	result, err := po.VerifyAndDecrypt(fileData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error verifying and decrypting: %v\n", err)
		os.Exit(1)
	}

	// Calculate hash of decrypted exploit binary for logging
	exploitHash := sha256.Sum256(result.Payload.Data)
	exploitHashHex := hex.EncodeToString(exploitHash[:])

	// Log execution details
	fmt.Fprintf(os.Stderr, "[EXECUTION LOG] %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(os.Stderr, "[EXECUTION LOG] Plugin Type: %s\n", result.Payload.Type.String())
	fmt.Fprintf(os.Stderr, "[EXECUTION LOG] Plugin Name: %s\n", result.Payload.Name)
	fmt.Fprintf(os.Stderr, "[EXECUTION LOG] Exploit Binary Hash (SHA256): %s\n", exploitHashHex)
	fmt.Fprintf(os.Stderr, "[EXECUTION LOG] Execution Arguments: %s\n", string(result.Args))

	// Load plugin
	plg, err := plugin.LoadPlugin(result.Payload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading plugin: %v\n", err)
		os.Exit(1)
	}

	// Use arguments from the package (extracted from the file)
	var args json.RawMessage
	if err := json.Unmarshal(result.Args, &args); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing arguments JSON: %v\n", err)
		os.Exit(1)
	}

	// Execute plugin
	ctx := context.Background()
	execResult, err := plg.Execute(ctx, args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error executing plugin: %v\n", err)
		os.Exit(1)
	}

	// Print result
	resultJSON, err := json.MarshalIndent(execResult, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling result: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(resultJSON))
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
