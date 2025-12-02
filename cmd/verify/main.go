package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"

	"github.com/joncooperworks/harness/crypto"
)

func main() {
	var (
		encryptedFile    = flag.String("file", "", "Path to approved plugin file (with client signature)")
		keystoreKeyID    = flag.String("keystore-key", "", "Key ID in OS keystore for pentester's private key (required)")
		clientPubKeyFile = flag.String("client-key", "", "Path to client's public key file (required)")
	)
	flag.Parse()

	if *encryptedFile == "" {
		fmt.Fprintf(os.Stderr, "Error: -file is required\n")
		os.Exit(1)
	}

	if *keystoreKeyID == "" {
		fmt.Fprintf(os.Stderr, "Error: -keystore-key is required (pentester's private key must be stored in OS keystore)\n")
		os.Exit(1)
	}

	if *clientPubKeyFile == "" {
		fmt.Fprintf(os.Stderr, "Error: -client-key is required (client's public key for verifying argument signature)\n")
		os.Exit(1)
	}

	// Load client's public key
	clientPubKey, err := loadPublicKey(*clientPubKeyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading client's public key: %v\n", err)
		os.Exit(1)
	}

	// Create PresidentialOrder from keystore (pentester's private key + client's public key)
	po, err := crypto.NewPresidentialOrderFromKeystore(*keystoreKeyID, clientPubKey)
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

	fmt.Printf("✓ Client signature on arguments verified successfully\n")
	fmt.Printf("✓ Plugin decrypted successfully\n")
	fmt.Printf("\nPlugin details:\n")
	fmt.Printf("  Type: %v\n", result.Payload.Type)
	fmt.Printf("  Name: %s\n", result.Payload.Name)
	fmt.Printf("  Data size: %d bytes\n", len(result.Payload.Data))
	fmt.Printf("  Arguments: %s\n", string(result.Args))

	if result.Payload.Type == crypto.WASM {
		fmt.Printf("  Note: WASM plugin ready to execute\n")
	} else {
		fmt.Printf("  Warning: Unknown plugin type\n")
	}
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
