package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"

	"github.com/joncooperworks/harness/crypto"
	"github.com/joncooperworks/harness/plugin"
)

func main() {
	var (
		encryptedFile      = flag.String("file", "", "Path to encrypted plugin file")
		keystoreKeyID      = flag.String("keystore-key", "", "Key ID in OS keystore (required)")
		presidentPubKeyFile = flag.String("president-key", "", "Path to president's public key file")
		argsJSON           = flag.String("args", "{}", "JSON arguments to pass to the plugin")
	)
	flag.Parse()

	if *encryptedFile == "" {
		fmt.Fprintf(os.Stderr, "Error: -file is required\n")
		os.Exit(1)
	}

	if *keystoreKeyID == "" {
		fmt.Fprintf(os.Stderr, "Error: -keystore-key is required (private keys must be stored in OS keystore)\n")
		os.Exit(1)
	}

	if *presidentPubKeyFile == "" {
		fmt.Fprintf(os.Stderr, "Error: -president-key is required\n")
		os.Exit(1)
	}

	// Load president's public key
	presidentPubKey, err := loadPublicKey(*presidentPubKeyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading president's public key: %v\n", err)
		os.Exit(1)
	}

	// Create PresidentialOrder from keystore
	po, err := crypto.NewPresidentialOrderFromKeystore(*keystoreKeyID, presidentPubKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating PresidentialOrder from keystore: %v\n", err)
		os.Exit(1)
	}

	// Load encrypted file
	encryptedData, err := os.ReadFile(*encryptedFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading encrypted file: %v\n", err)
		os.Exit(1)
	}

	// Verify and decrypt
	payload, err := po.VerifyAndDecrypt(encryptedData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error verifying and decrypting: %v\n", err)
		os.Exit(1)
	}

	// Load plugin
	plg, err := plugin.LoadPlugin(payload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading plugin: %v\n", err)
		os.Exit(1)
	}

	// Parse arguments
	var args json.RawMessage
	if err := json.Unmarshal([]byte(*argsJSON), &args); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing arguments JSON: %v\n", err)
		os.Exit(1)
	}

	// Execute plugin
	ctx := context.Background()
	result, err := plg.Execute(ctx, args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error executing plugin: %v\n", err)
		os.Exit(1)
	}

	// Print result
	resultJSON, err := json.MarshalIndent(result, "", "  ")
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

